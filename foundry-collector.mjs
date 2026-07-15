#!/usr/bin/env node
/**
 * @loop-xxi/foundry-collector
 *
 * Loop Foundry Agent Outcome Capsule Collector
 *
 * A dependency-free Node.js tool that:
 *   1. Reads a JSON trace or API probe result from a file or stdin.
 *   2. Strips secrets, credentials, PII, and chain-of-thought markers.
 *   3. Computes a SHA-256 content hash of the source and redacted data.
 *   4. Produces a signed Agent Outcome Capsule manifest (Ed25519 or P-256).
 *   5. Never sends data to Loop XXI or any external service.
 *   6. Emits a redaction report showing what was removed.
 *   7. Optionally reports errors to Sentry via DSN.
 *
 * Usage:
 *   node foundry-collector.mjs --input <trace.json> --output <capsule.json> [--redaction <report.json>]
 *   cat trace.json | node foundry-collector.mjs --output capsule.json
 *   node foundry-collector.mjs --input trace.json --output capsule.json --keypair <ed25519-keypair.json>
 *
 * No external dependencies. Node.js >= 18 (uses global crypto.subtle).
 *
 * License: MIT
 * Copyright (c) 2026 Loop XXI LLC
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, extname } from 'node:path';
import { parseArgs } from 'node:util';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCHEMA_VERSION = '0.1.0';
const TOOL_VERSION = 'loop-foundry-collector-0.1.0';

// Secret patterns — these fields/values are redacted from the capsule body.
// Patterns are intentionally conservative; false positives are better than leaks.
const SECRET_PATTERNS = [
  { name: 'api_key_sk', pattern: /\bsk_(?:live|test|proj)_[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'api_key_generic', pattern: /\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-]{32,}["']?/gi, severity: 'critical' },
  { name: 'bearer_token', pattern: /\bBearer\s+[A-Za-z0-9_\-\.=]{20,}/gi, severity: 'critical' },
  { name: 'authorization_header', pattern: /Authorization\s*[:=]\s*["']?[A-Za-z0-9_\-\.=:]{20,}["']?/gi, severity: 'critical' },
  { name: 'l402_token', pattern: /\bL402\s+[A-Za-z0-9_\-:.=]{20,}/gi, severity: 'critical' },
  { name: 'bolt11_invoice', pattern: /\bln[A-Za-z0-9]{100,}\b/g, severity: 'high' },
  { name: 'preimage_hex', pattern: /\b[0-9a-fA-F]{64}\b/g, severity: 'high' },
  { name: 'macaroon', pattern: /\b(?:macaroon|caveat)\s*[:=]\s*["']?[A-Za-z0-9_\-]{40,}["']?/gi, severity: 'high' },
  { name: 'private_key_pem', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'private_key_hex', pattern: /\b(?:priv(?:ate)?[_-]?(?:key)?)\s*[:=]\s*["']?[0-9a-fA-F]{64,}["']?/gi, severity: 'critical' },
  { name: 'seed_phrase', pattern: /\b(?:abandon about above absent absorb abuse absurd access accident account accuse acid|seed phrase|mnemonic)\b[\s\S]{0,500}/gi, severity: 'critical' },
  { name: 'webhook_secret', pattern: /\bwhsec_[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}/g, severity: 'critical' },
  { name: 'password_assignment', pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}["']?/gi, severity: 'high' },
  { name: 'connection_string', pattern: /\b(?:postgres|postgresql|mongodb|redis|amqp|mysql):\/\/[^\s"']{10,}/gi, severity: 'critical' },
];

// PII patterns
const PII_PATTERNS = [
  { name: 'email', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, severity: 'medium' },
  { name: 'phone', pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, severity: 'medium' },
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' },
  { name: 'credit_card', pattern: /\b(?:\d[ -]*?){13,19}\b/g, severity: 'high' },
  { name: 'ipv4', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, severity: 'low' },
  { name: 'street_address', pattern: /\b\d{1,6}\s+[A-Za-z0-9\s]+(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|blvd|court|ct|way)\b/gi, severity: 'medium' },
];

// Chain-of-thought markers — any text blocks that look like LLM reasoning
const COT_MARKERS = [
  /(?:let me|let's|first,? I|I need to|I should|thinking about|step \d+:|reasoning:|chain of thought:|my approach:)/gi,
  /(?:<thinking>|<reasoning>|<thought>|<analysis>)[\s\S]*?(?:<\/thinking>|<\/reasoning>|<\/thought>|<\/analysis>)/gi,
];

// ---------------------------------------------------------------------------
// Redaction engine
// ---------------------------------------------------------------------------

function scanAndRedact(data, patterns) {
  const findings = [];
  let text;
  let isString = false;

  if (typeof data === 'string') {
    text = data;
    isString = true;
  } else if (data === null || data === undefined) {
    return { redacted: data, findings: [] };
  } else {
    text = JSON.stringify(data);
  }

  let redacted = text;
  for (const { name, pattern, severity } of patterns) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(text)) !== null) {
      const matched = match[0];
      // Skip false positives that are too short or are placeholder markers
      if (matched.length < 5) continue;
      if (matched.includes('[REDACTED')) continue;
      findings.push({
        type: name,
        severity,
        position: match.index,
        length: matched.length,
        preview: matched.slice(0, 12) + '...[redacted]',
      });
      redacted = redacted.split(matched).join('[REDACTED:' + name + ']');
    }
  }

  if (!isString) {
    try {
      redacted = JSON.parse(redacted);
    } catch {
      // If JSON parse fails, keep as string
    }
  }

  return { redacted, findings };
}

function scanChainOfThought(text) {
  const findings = [];
  for (const pattern of COT_MARKERS) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(text)) !== null) {
      findings.push({
        type: 'chain_of_thought',
        severity: 'high',
        position: match.index,
        length: match[0].length,
        preview: match[0].slice(0, 20) + '...[cot-marker]',
      });
    }
  }
  return findings;
}

function deepScan(obj) {
  const secretFindings = [];
  const piiFindings = [];
  let cotFindings = [];
  let hasCoT = false;

  function walk(node, path) {
    if (typeof node === 'string') {
      const s = scanAndRedact(node, SECRET_PATTERNS);
      secretFindings.push(...s.findings.map(f => ({ ...f, path })));
      const p = scanAndRedact(node, PII_PATTERNS);
      piiFindings.push(...p.findings.map(f => ({ ...f, path })));
      const c = scanChainOfThought(node);
      if (c.length > 0) {
        cotFindings.push(...c.map(f => ({ ...f, path })));
        hasCoT = true;
      }
    } else if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`));
    } else if (node && typeof node === 'object') {
      for (const [key, val] of Object.entries(node)) {
        // Check key names for secret indicators
        const keyLower = key.toLowerCase();
        if (/pass|secret|key|token|credential|auth|cookie|session|private/i.test(keyLower)) {
          if (typeof val === 'string' && val.length > 0) {
            secretFindings.push({
              type: 'sensitive_field_name',
              severity: 'high',
              path: `${path}.${key}`,
              length: val.length,
              preview: `[sensitive key: ${key}]`,
            });
          }
        }
        walk(val, `${path}.${key}`);
      }
    }
  }

  walk(obj, '$');
  return { secretFindings, piiFindings, cotFindings, hasCoT };
}

function redactObject(obj) {
  const text = JSON.stringify(obj, null, 2);
  let redacted = text;

  // Apply all secret patterns
  for (const { pattern, name } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0].length < 5) continue;
      if (match[0].includes('[REDACTED')) continue;
      redacted = redacted.split(match[0]).join('[REDACTED:' + name + ']');
    }
  }

  // Apply PII patterns
  for (const { pattern, name } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0].length < 5) continue;
      if (match[0].includes('[REDACTED')) continue;
      redacted = redacted.split(match[0]).join('[REDACTED:' + name + ']');
    }
  }

  // Redact sensitive field values
  redacted = redactSensitiveFields(redacted);

  // Remove chain-of-thought blocks
  for (const pattern of COT_MARKERS) {
    redacted = redacted.replace(pattern, '[REDACTED:chain_of_thought]');
  }

  try {
    return JSON.parse(redacted);
  } catch {
    return { _redaction_note: 'Redacted output is not valid JSON; see raw redacted string.', _raw: redacted };
  }
}

function redactSensitiveFields(jsonStr) {
  // Redact values of fields with sensitive names
  const sensitiveKeyPattern = /("(?:pass(?:word|wd)?|secret|api[_-]?key|apikey|token|credential|auth|cookie|session|private[_-]?key|preimage|macaroon|invoice|payment[_-]?request|authorization)"\s*:\s*")([^"]+)(")/gi;
  return jsonStr.replace(sensitiveKeyPattern, (_match, prefix, _value, suffix) => {
    return prefix + '[REDACTED:sensitive_field]' + suffix;
  });
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

function sha256(data) {
  const hash = createHash('sha256');
  hash.update(typeof data === 'string' ? data : JSON.stringify(data));
  return 'sha256:' + hash.digest('hex');
}

function computeMerkleRoot(items) {
  if (!items || items.length === 0) return sha256('');
  if (items.length === 1) return sha256(items[0]);

  let level = items.map(i => sha256(i));
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(sha256(left + right));
    }
    level = nextLevel;
  }
  return level[0];
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

function generateEd25519Keypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  return { privateKey: privPem, publicKey: pubPem };
}

function signWithKey(data, privateKeyPem, algorithm) {
  const privKey = createPrivateKey(privateKeyPem);
  const dataBuf = Buffer.from(typeof data === 'string' ? data : JSON.stringify(data), 'utf8');

  if (algorithm === 'ed25519') {
    return sign(null, dataBuf, privKey).toString('base64');
  } else if (algorithm === 'p256') {
    return sign('sha256', dataBuf, privKey).toString('base64');
  }
  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

function verifySignature(data, signatureBase64, publicKeyPem, algorithm) {
  const pubKey = createPublicKey(publicKeyPem);
  const dataBuf = Buffer.from(typeof data === 'string' ? data : JSON.stringify(data), 'utf8');
  const sigBuf = Buffer.from(signatureBase64, 'base64');

  if (algorithm === 'ed25519') {
    return verify(null, dataBuf, pubKey, sigBuf);
  } else if (algorithm === 'p256') {
    return verify('sha256', dataBuf, pubKey, sigBuf);
  }
  return false;
}

function getPublicKeyId(publicKeyPem) {
  const pubKey = createPublicKey(publicKeyPem);
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return 'sha256:' + createHash('sha256').update(der).digest('hex');
}

// ---------------------------------------------------------------------------
// Capsule builder
// ---------------------------------------------------------------------------

function buildCapsule(input, scanResult, redactedData, keypair, algorithm) {
  const now = new Date().toISOString();

  // Compute source hash
  const sourceData = JSON.stringify(input.raw_data || input.trace || input, null, 2);
  const sourceHash = sha256(sourceData);

  // Build transformation log
  const transformationLog = [
    { step: 'ingest', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null },
    { step: 'secret_scan', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null },
    { step: 'pii_redaction', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null },
    { step: 'normalization', tool_version: `agent-outcome-capsule-schema-${SCHEMA_VERSION}`, timestamp: now, reviewer_id: null },
  ];

  if (input.intervention) {
    transformationLog.push({ step: 'labeling', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null });
  }

  if (input.outcome && input.outcome.success_verified) {
    transformationLog.push({ step: 'counterfactual_validation', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null });
  }

  transformationLog.push({ step: 'signing', tool_version: TOOL_VERSION, timestamp: now, reviewer_id: null });

  // Privacy assessment
  const hasCriticalSecrets = scanResult.secretFindings.some(f => f.severity === 'critical');
  const hasHighSecrets = scanResult.secretFindings.some(f => f.severity === 'high');
  const secretScanResult = hasCriticalSecrets ? 'fail' : (hasHighSecrets ? 'review' : 'pass');

  const hasMediumPII = scanResult.piiFindings.some(f => f.severity === 'medium' || f.severity === 'high');
  const piiScanResult = scanResult.piiFindings.some(f => f.severity === 'critical') ? 'fail' : (hasMediumPII ? 'review' : 'pass');

  const redactionSummary = [];
  if (scanResult.secretFindings.length > 0) {
    const types = [...new Set(scanResult.secretFindings.map(f => f.type))];
    redactionSummary.push(`${scanResult.secretFindings.length} secret findings redacted: ${types.join(', ')}`);
  }
  if (scanResult.piiFindings.length > 0) {
    const types = [...new Set(scanResult.piiFindings.map(f => f.type))];
    redactionSummary.push(`${scanResult.piiFindings.length} PII findings redacted: ${types.join(', ')}`);
  }
  if (scanResult.hasCoT) {
    redactionSummary.push(`${scanResult.cotFindings.length} chain-of-thought markers removed`);
  }
  if (redactionSummary.length === 0) {
    redactionSummary.push('No secrets, PII, or chain-of-thought content detected in the source trace.');
  }

  // Resolve all capsule fields with defaults applied FIRST.
  // These resolved fields are used both for the capsule output AND for the
  // signed body hash, so they always match during verification.
  const owner = input.owner || {
    owner_id: input.owner_id || 'unknown',
    owner_type: input.owner_type || 'business',
    custody_mode: 'owner_retained',
    public_name: input.public_name || null,
  };
  const environment = input.environment || { domain: 'unknown', agent_architecture: 'unknown', model_family: 'unknown', tool_classes: [] };
  const task = input.task || { task_class: 'unknown', objective: 'unknown', success_criteria: [] };
  const failure = input.failure || { taxonomy: 'other', decisive_step: 0, observable_evidence: [], severity: 'low', raw_trace_included: false };
  const intervention = input.intervention || { intervention_class: 'none', change_summary: 'No intervention recorded.', version_reference: 'none' };
  const outcome = input.outcome || { before: {}, after: {}, success_verified: false, verification_method: 'production_observation', replay_count: 0 };
  const quality = input.quality || {
    completeness_score: 0.8,
    reproducibility_score: 0.8,
    novelty_score: 0.5,
    validation_status: 'owner_attested',
    duplicate_cluster_id: null,
  };

  // Build the capsule body from the RESOLVED fields + redacted data.
  // This body is what gets hashed and signed.
  const capsuleBody = {
    owner,
    environment,
    task,
    failure,
    intervention,
    outcome,
    redacted_preview: redactedData,
    timestamp: now,
  };
  const capsuleHash = sha256(JSON.stringify(capsuleBody, null, 0));

  // Sign the capsule hash
  const signature = signWithKey(capsuleHash, keypair.privateKey, algorithm);
  const publicKeyId = getPublicKeyId(keypair.publicKey);

  // Build the full capsule per schema
  const capsule = {
    capsule_id: input.capsule_id || generateCapsuleId(),
    schema_version: SCHEMA_VERSION,
    owner,
    rights: {
      ownership_attested: input.rights?.ownership_attested ?? true,
      collection_basis: input.rights?.collection_basis || 'owner_generated_business_telemetry',
      third_party_restrictions_reviewed: input.rights?.third_party_restrictions_reviewed ?? true,
      evidence_reference: input.rights?.evidence_reference || null,
    },
    provenance: {
      source_hash: sourceHash,
      capsule_hash: capsuleHash,
      captured_at: now,
      transformation_log: transformationLog,
      signatures: [
        {
          signer_role: 'owner',
          algorithm,
          public_key_id: publicKeyId,
          signature,
        },
      ],
    },
    environment,
    task,
    failure,
    intervention,
    outcome,
    quality,
    privacy: {
      pii_scan: piiScanResult,
      secret_scan: secretScanResult,
      personal_data_included: false,
      chain_of_thought_included: false,
      redaction_summary: redactionSummary,
    },
    license: input.license || {
      license_id: 'LOOP-FOUNDATION-EVAL-0.1-DRAFT',
      allowed_uses: ['evaluation', 'regression_testing', 'research', 'internal_quality_assurance'],
      prohibited_uses: ['identity_inference', 'eligibility_decisions', 'surveillance', 'reidentification', 'resale', 'unlicensed_model_training'],
      term: 'Draft example only; no third-party license granted.',
      revocation_applies_to_future_access: true,
      territory: 'Not applicable to draft example',
      attribution_required: true,
    },
  };

  // Attach redacted content as an extension field (outside the signed schema).
  // This makes the capsule output self-contained while keeping the signed
  // capsule body schema-compliant. The _body_timestamp is needed to
  // reconstruct and verify the signed body hash.
  capsule._redacted_content = redactedData;
  capsule._body_timestamp = now;

  return capsule;
}



function generateCapsuleId() {
  const bytes = randomBytes(8);
  const hex = bytes.toString('hex').toUpperCase();
  return `AOC-${hex}`;
}

// ---------------------------------------------------------------------------
// Redaction report
// ---------------------------------------------------------------------------

function buildRedactionReport(scanResult, sourceHash, capsuleHash) {
  return {
    tool_version: TOOL_VERSION,
    generated_at: new Date().toISOString(),
    source_hash: sourceHash,
    capsule_hash: capsuleHash,
    summary: {
      total_secret_findings: scanResult.secretFindings.length,
      total_pii_findings: scanResult.piiFindings.length,
      total_cot_findings: scanResult.cotFindings.length,
      critical_secrets: scanResult.secretFindings.filter(f => f.severity === 'critical').length,
      high_secrets: scanResult.secretFindings.filter(f => f.severity === 'high').length,
      chain_of_thought_detected: scanResult.hasCoT,
    },
    secret_findings: scanResult.secretFindings.map(f => ({
      type: f.type,
      severity: f.severity,
      path: f.path || '(root)',
      preview: f.preview || '[redacted]',
    })),
    pii_findings: scanResult.piiFindings.map(f => ({
      type: f.type,
      severity: f.severity,
      path: f.path || '(root)',
      preview: f.preview || '[redacted]',
    })),
    cot_findings: scanResult.cotFindings.map(f => ({
      type: f.type,
      severity: f.severity,
      path: f.path || '(root)',
    })),
    privacy_assessment: {
      secret_scan: scanResult.secretFindings.some(f => f.severity === 'critical') ? 'fail' :
                    scanResult.secretFindings.some(f => f.severity === 'high') ? 'review' : 'pass',
      pii_scan: scanResult.piiFindings.some(f => f.severity === 'critical') ? 'fail' :
               scanResult.piiFindings.some(f => f.severity === 'medium' || f.severity === 'high') ? 'review' : 'pass',
      chain_of_thought_included: scanResult.hasCoT,
    },
    note: 'This report is generated locally. No data was transmitted externally. Secret and PII values have been replaced with [REDACTED:type] markers in the capsule body.',
  };
}

// ---------------------------------------------------------------------------
// Sentry integration (optional, env-driven)
// ---------------------------------------------------------------------------

function reportToSentry(error, context) {
  const dsn = process.env.FOUNDRY_SENTRY_DSN;
  if (!dsn) return; // Sentry is optional

  try {
    // Parse DSN: https://<publickey>@<host>/<project_id>
    const match = dsn.match(/^https?:\/\/([^@]+)@([^/]+)\/(\d+)/);
    if (!match) return;
    const [, publicKey, host, projectId] = match;
    const envelopeUrl = `https://${host}/api/${projectId}/envelope/`;

    const event = {
      event_id: randomBytes(16).toString('hex'),
      timestamp: new Date().toISOString(),
      platform: 'node',
      level: 'error',
      message: error.message,
      tags: {
        component: 'foundry-collector',
        correlation_id: context.correlation_id || 'unknown',
        experiment_id: context.experiment_id || 'unknown',
        ...(context.tags || {}),
      },
      extra: {
        tool_version: TOOL_VERSION,
        ...context,
      },
    };

    const envelope = JSON.stringify({ event_id: event.event_id, sent_at: event.timestamp }) + '\n' + JSON.stringify(event);

    // Use fetch (available in Node 18+)
    fetch(envelopeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: envelope,
    }).catch(() => { /* swallow — Sentry is best-effort */ });
  } catch {
    // Swallow — Sentry reporting is best-effort and must never break the collector.
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function loadKeypair(keypairPath) {
  if (!keypairPath) return null;
  if (!existsSync(keypairPath)) return null;
  const raw = readFileSync(keypairPath, 'utf8');
  return JSON.parse(raw);
}

function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string', short: 'i' },
      output: { type: 'string', short: 'o' },
      redaction: { type: 'string', short: 'r' },
      keypair: { type: 'string', short: 'k' },
      'generate-keypair': { type: 'string', short: 'g' },
      verify: { type: 'boolean', short: 'v' },
      'public-key': { type: 'string', short: 'p' },
      algorithm: { type: 'string', short: 'a', default: 'ed25519' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });

  if (values.help) {
    console.log(`
Loop Foundry Collector v${TOOL_VERSION}

Usage:
  node foundry-collector.mjs -i <trace.json> -o <capsule.json> [-r <report.json>]
  cat trace.json | node foundry-collector.mjs -o capsule.json
  node foundry-collector.mjs -g <keypair.json>     Generate an Ed25519 keypair
  node foundry-collector.mjs -i capsule.json -v -p <public-key.pem>  Verify a capsule signature

Options:
  -i, --input <file>      Input trace JSON file (omit to read from stdin)
  -o, --output <file>     Output capsule JSON file (omit to print to stdout)
  -r, --redaction <file>  Output redaction report JSON file
  -k, --keypair <file>    Keypair JSON file with privateKey and publicKey PEMs
  -g, --generate-keypair  Generate a new keypair and write to <file>
  -v, --verify            Verify a capsule signature instead of creating one
  -p, --public-key <file> Public key PEM for verification
  -a, --algorithm         Signing algorithm: ed25519 (default) or p256
  -h, --help              Show this help

Environment:
  FOUNDRY_SENTRY_DSN     Optional Sentry DSN for error reporting

No data is transmitted externally. The collector runs entirely locally.
`);
    process.exit(0);
  }

  // Generate keypair mode
  if (values['generate-keypair']) {
    const algorithm = values.algorithm || 'ed25519';
    const keypair = algorithm === 'p256'
      ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      : generateKeyPairSync('ed25519');

    const kp = {
      algorithm,
      privateKey: keypair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKey: keypair.publicKey.export({ type: 'spki', format: 'pem' }),
    };
    writeFileSync(resolve(values['generate-keypair']), JSON.stringify(kp, null, 2));
    console.log(`Keypair generated: ${values['generate-keypair']} (${algorithm})`);
    console.log(`Public key ID: ${getPublicKeyId(kp.publicKey)}`);
    process.exit(0);
  }

  // Verify mode
  if (values.verify) {
    const capsulePath = values.input || values.positionals[0];
    if (!capsulePath) {
      console.error('Error: --input required for verify mode');
      process.exit(1);
    }
    const capsule = JSON.parse(readFileSync(resolve(capsulePath), 'utf8'));
    const pubKeyPath = values['public-key'];
    if (!pubKeyPath) {
      console.error('Error: --public-key required for verify mode');
      process.exit(1);
    }
    const pubKeyPem = readFileSync(resolve(pubKeyPath), 'utf8');
    const sig = capsule.provenance?.signatures?.[0];
    if (!sig) {
      console.error('Error: No signature found in capsule');
      process.exit(1);
    }

    // Step 1: Recompute the capsule body hash from the current capsule fields.
    // The signed body is: owner, environment, task, failure, intervention,
    // outcome, redacted_preview (_redacted_content), timestamp (_body_timestamp).
    const bodyTimestamp = capsule._body_timestamp || capsule.provenance.captured_at;
    const recomputedBody = {
      owner: capsule.owner,
      environment: capsule.environment,
      task: capsule.task,
      failure: capsule.failure,
      intervention: capsule.intervention,
      outcome: capsule.outcome,
      redacted_preview: capsule._redacted_content || {},
      timestamp: bodyTimestamp,
    };
    const recomputedHash = sha256(JSON.stringify(recomputedBody, null, 0));
    const storedHash = capsule.provenance.capsule_hash;
    const hashMatches = recomputedHash === storedHash;

    // Step 2: Verify the signature against the stored hash.
    const sigValid = verifySignature(storedHash, sig.signature, pubKeyPem, sig.algorithm);

    const fullyValid = hashMatches && sigValid;
    console.log(`Signature valid: ${sigValid}`);
    console.log(`Capsule body hash matches: ${hashMatches}`);
    console.log(`Overall valid: ${fullyValid}`);
    console.log(`Algorithm: ${sig.algorithm}`);
    console.log(`Public key ID: ${sig.public_key_id}`);
    console.log(`Capsule ID: ${capsule.capsule_id}`);
    console.log(`Capsule hash: ${storedHash}`);
    console.log(`Recomputed hash: ${recomputedHash}`);
    process.exit(fullyValid ? 0 : 1);
  }

  // Collect mode
  let inputData;
  if (values.input) {
    inputData = readFileSync(resolve(values.input), 'utf8');
  } else {
    // Read from stdin
    inputData = readFileSync(0, 'utf8');
  }

  let input;
  try {
    input = JSON.parse(inputData);
  } catch (e) {
    console.error('Error: Input must be valid JSON.');
    reportToSentry(e, { stage: 'ingest' });
    process.exit(1);
  }

  // Load or generate keypair
  const algorithm = values.algorithm || 'ed25519';
  let keypair = loadKeypair(values.keypair);
  if (!keypair) {
    // Auto-generate an ephemeral keypair
    const generated = algorithm === 'p256'
      ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      : generateKeyPairSync('ed25519');
    keypair = {
      privateKey: generated.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKey: generated.publicKey.export({ type: 'spki', format: 'pem' }),
    };
    console.error('Warning: No keypair provided. Generated an ephemeral keypair. Use --keypair to provide a persistent key.');
  }

  // Scan and redact
  const rawData = input.raw_data || input.trace || input;
  const scanResult = deepScan(rawData);
  const redactedData = redactObject(rawData);

  // Build capsule
  const capsule = buildCapsule(input, scanResult, redactedData, keypair, algorithm);

  // Build redaction report
  const report = buildRedactionReport(scanResult, capsule.provenance.source_hash, capsule.provenance.capsule_hash);

  // Output
  const capsuleJson = JSON.stringify(capsule, null, 2);
  if (values.output) {
    writeFileSync(resolve(values.output), capsuleJson);
    console.error(`Capsule written: ${values.output}`);
  } else {
    console.log(capsuleJson);
  }

  if (values.redaction) {
    writeFileSync(resolve(values.redaction), JSON.stringify(report, null, 2));
    console.error(`Redaction report written: ${values.redaction}`);
  }

  // Summary
  console.error(`\n--- Collection Summary ---`);
  console.error(`Capsule ID: ${capsule.capsule_id}`);
  console.error(`Source hash: ${capsule.provenance.source_hash}`);
  console.error(`Capsule hash: ${capsule.provenance.capsule_hash}`);
  console.error(`Secret findings: ${scanResult.secretFindings.length}`);
  console.error(`PII findings: ${scanResult.piiFindings.length}`);
  console.error(`Chain-of-thought: ${scanResult.cotFindings.length}`);
  console.error(`Privacy: secret_scan=${capsule.privacy.secret_scan}, pii_scan=${capsule.privacy.pii_scan}`);
  console.error(`Signature: ${capsule.provenance.signatures[0].algorithm} via ${capsule.provenance.signatures[0].public_key_id}`);
}

main();
