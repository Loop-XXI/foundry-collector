#!/usr/bin/env node
/**
 * Foundry Collector → LoopXXI Vault Capsule exporter.
 *
 * Takes a signed Agent Outcome Capsule (AOC v0.1.0, produced by
 * foundry-collector.mjs) and seals it into a `loopxxi.vault.capsule` v1.0.0
 * envelope that is byte-compatible with the live Vault (vault.loopxxi.com).
 *
 * Design constraints (match the live Vault primitives exactly):
 *   - Per-capsule DEK (AES-GCM 256) encrypts the sealed payload.
 *   - DEK is WRAPPED under a client-held vault key (AES-GCM), never emitted raw.
 *   - The vault key NEVER enters the capsule. It is derived from a passphrase
 *     (PBKDF2-SHA256, 250k iters) or supplied as raw base64; it stays on the
 *     owner's machine. Only the WRAPPED dek + iv are in the envelope.
 *   - ECDSA P-256 user signing key signs canonicalJson(envelope).
 *   - SHA-256 integrity hashes over sealed payload, ciphertext, and envelope.
 *   - Structural quality receipt v1 (shape only; no truth/ownership claims).
 *   - PoC-local attestation (server_public + server_signature) by default;
 *     production attestation is fetched from the Vault attest Edge Function
 *     when --attest-url is given (that path posts only hashes + public keys).
 *
 * PRIVACY BOUNDARY (honest): Foundry Collector already redacts secrets/PII/CoT
 * locally, on the owner's machine, and transmits nothing. This exporter also
 * runs locally. LoopXXI Vault infra only ever sees the opaque envelope. That
 * makes this producer legitimately zero-knowledge from the infra's point of
 * view — the AOC itself was produced from plaintext the OWNER processed on
 * their OWN machine, which is disclosed in the discovery manifest.
 *
 * The exporter refuses to seal an AOC whose privacy gate did not pass
 * (secret_scan === 'fail' or personal_data_included !== false), unless
 * --allow-review is passed for a 'review' status. It NEVER emits plaintext,
 * the DEK, or any private key into the capsule.
 *
 * No external dependencies. Node.js >= 18 (uses node:crypto.webcrypto).
 * License: MIT. Copyright (c) 2026 Loop XXI LLC. Contact: business@loopxxi.com
 */

import { webcrypto, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

const subtle = webcrypto.subtle;
const enc = new TextEncoder();

export const CONTRACT = 'loopxxi.vault.capsule';
export const CONTRACT_VERSION = '1.0.0';
export const APP_ID = 'loopxxi.foundry-collector';
export const APP_VERSION = '0.1.0';
export const APP_TYPE = 'agent_outcome';
export const OPAQUE_TITLE = 'Encrypted capsule';
export const SEALED_SCHEMA_VERSION = 3;
export const KDF_ITERATIONS = 250_000;

/** Allowlisted attestation modes. Any other value MUST fail verification. */
export const ATTEST_MODES = ['poc_local', 'production_server'];
/** Allowlisted provenance levels.
 *  - local_export: honest label for a locally self-signed (poc_local) receipt.
 *    It does NOT claim an authenticated Vault session — the exporter signed it
 *    with its own local key, not a JWT-authenticated server session.
 *  - authenticated_session: ONLY legitimate for production_server receipts,
 *    where the Vault attest Edge Function verified a real Supabase JWT.
 *  - verified_human: reserved (stronger production provenance). */
export const PROVENANCE_LEVELS = ['local_export', 'authenticated_session', 'verified_human'];
export const LOCAL_PROVENANCE_LEVEL = 'local_export';

/** Pinned production attest public key (SPKI base64). Public, not secret.
 *  Matches PRODUCTION_ATTEST_PUBLIC_SPKI in src/lib/attest-verify.ts. May be
 *  overridden via LOOP_ATTEST_PUBLIC_SPKI env on rotation (not a schema change). */
export const PRODUCTION_ATTEST_PUBLIC_SPKI =
  process.env.LOOP_ATTEST_PUBLIC_SPKI ||
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKmMVRYcMZAl9wO51jDbBX1Tc1ZqfUbxnixZTZE0keV30IKGfkxOOpdZtEUafGyOM6h2QKO1CN5y01Yg/UBE6ew==';

// ---------- encoding helpers (match src/lib/crypto.ts) ----------

function bufToBase64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return Buffer.from(bin, 'binary').toString('base64');
}
function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
function bufToHex(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function randomBytes(len) {
  const a = new Uint8Array(len);
  webcrypto.getRandomValues(a);
  return a;
}
function randomId() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = bufToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? enc.encode(data) : data;
  const digest = await subtle.digest('SHA-256', buf);
  return bufToHex(digest);
}

/** Canonical JSON: recursive key-sorted stringify (matches src/lib/crypto.ts). */
export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

// ---------- vault key + DEK (match src/lib/crypto.ts) ----------

async function derivePassphraseKey(passphrase, salt, iterations = KDF_ITERATIONS) {
  const baseKey = await subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}

async function resolveVaultKey(opts) {
  if (opts.vaultKeyB64) {
    const raw = base64ToBytes(opts.vaultKeyB64);
    return subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']);
  }
  if (opts.passphrase) {
    const salt = opts.saltB64 ? base64ToBytes(opts.saltB64) : randomBytes(16);
    const key = await derivePassphraseKey(opts.passphrase, salt);
    return { key, salt };
  }
  // No key material supplied → generate an ephemeral vault key (owner must
  // persist it to reopen; printed to stderr, never into the capsule).
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']);
  return { key, ephemeral: true };
}

/** Encrypt payload under a fresh DEK, wrap DEK under the vault key. */
async function encryptPayload(plaintext, vaultKey) {
  const dek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = randomBytes(12);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, dek, enc.encode(plaintext));
  const wrapIv = randomBytes(12);
  const wrappedDek = await subtle.wrapKey('raw', dek, vaultKey, { name: 'AES-GCM', iv: wrapIv });
  return {
    ciphertext: bufToBase64(ciphertext),
    iv: bufToBase64(iv),
    wrappedDek: bufToBase64(wrappedDek),
    wrapIv: bufToBase64(wrapIv),
  };
}

async function decryptPayload(encPayload, vaultKey) {
  const dek = await subtle.unwrapKey(
    'raw', base64ToBytes(encPayload.wrappedDek).buffer, vaultKey,
    { name: 'AES-GCM', iv: base64ToBytes(encPayload.wrapIv) },
    { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const plainBuf = await subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(encPayload.iv) }, dek,
    base64ToBytes(encPayload.ciphertext).buffer,
  );
  return new TextDecoder().decode(plainBuf);
}

// ---------- signing (ECDSA P-256, matches src/lib/crypto.ts) ----------

async function generateSigningKeyPair() {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function exportPublicKeySpki(key) {
  return bufToBase64(await subtle.exportKey('spki', key));
}
async function importSigningPrivateKey(pkcs8Base64) {
  return subtle.importKey('pkcs8', base64ToBytes(pkcs8Base64).buffer, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
}
async function signEnvelope(privateKey, data) {
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, enc.encode(data));
  return bufToBase64(sig);
}
async function verifyEnvelope(publicKeySpkiBase64, signatureBase64, data) {
  const pub = await subtle.importKey('spki', base64ToBytes(publicKeySpkiBase64).buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, base64ToBytes(signatureBase64), enc.encode(data));
}

async function resolveSigningKeys(opts) {
  if (opts.signingPrivPkcs8B64 && opts.signingPubSpkiB64) {
    const privateKey = await importSigningPrivateKey(opts.signingPrivPkcs8B64);
    return { privateKey, publicKeySpki: opts.signingPubSpkiB64 };
  }
  const kp = await generateSigningKeyPair();
  return { privateKey: kp.privateKey, publicKeySpki: await exportPublicKeySpki(kp.publicKey), ephemeral: true, publicKeyObj: kp.publicKey, privateKeyObj: kp.privateKey };
}

// ---------- structural quality receipt (matches src/lib/quality.ts) ----------

function rate(n, d) { if (d <= 0) return 0; return Math.round((n / d) * 1e6) / 1e6; }
function isNonempty(s) { return typeof s === 'string' && s.length > 0; }

export async function computeQualityReceipt(sealedPayload) {
  let o;
  try { o = JSON.parse(sealedPayload); } catch { return null; }
  if (!o || typeof o !== 'object') return null;
  const sourceType = o.appType || APP_TYPE;
  const title = typeof o.title === 'string' ? o.title : '';
  const content = typeof o.content === 'string' ? o.content : '';
  const createdAt = typeof o.createdAt === 'string' ? o.createdAt : '';
  const updatedAt = typeof o.updatedAt === 'string' ? o.updatedAt : '';
  const contentByteCount = enc.encode(sealedPayload).length;
  const contentCommitment = await sha256Hex(sealedPayload);
  const timeRange = { min: createdAt || updatedAt, max: updatedAt || createdAt };
  // agent_outcome: a single structured record with required fields title + content.
  const fieldTotal = 2;
  const nonempty = (isNonempty(title) ? 1 : 0) + (isNonempty(content) ? 1 : 0);
  return {
    version: 1,
    source_type: sourceType,
    record_count: 1,
    turn_count: 1,
    time_range: timeRange,
    required_field_nonempty_rate: rate(nonempty, fieldTotal),
    empty_count: fieldTotal - nonempty,
    duplicate_rate: 0,
    content_byte_count: contentByteCount,
    content_commitment: contentCommitment,
  };
}

// ---------- attestation (PoC-local; matches src/lib/attestation.ts attestLocal) ----------

async function attestLocal(req) {
  const kp = await generateSigningKeyPair();
  const timestamp = new Date().toISOString();
  const unsigned = {
    capsuleHash: req.capsuleHash,
    userIdHash: req.userIdHash,
    appId: req.appId,
    appVersion: req.appVersion,
    timestamp,
    provenanceLevel: req.provenanceLevel,
    qualityReceipt: req.qualityReceipt,
  };
  const data = canonicalJson(unsigned);
  const serverSignature = await signEnvelope(kp.privateKey, data);
  return { ...unsigned, serverPublicKey: await exportPublicKeySpki(kp.publicKey), serverSignature, mode: 'poc_local' };
}

/**
 * Validate a production_server attestation returned by the Vault attest Edge
 * Function BEFORE we emit it. Fails closed unless: mode is production_server,
 * capsuleHash equals our envelope hash, the serverPublicKey equals the pinned
 * production key, and the signature verifies under the pinned key. `expectedHash`
 * is the envelope hash we asked to be attested.
 */
export async function verifyProductionAttestation(att, expectedHash) {
  const problems = [];
  if (!att || typeof att !== 'object') { problems.push('attest response missing attestation object'); return { ok: false, problems }; }
  if (att.mode !== 'production_server') problems.push(`expected mode production_server, got ${att.mode}`);
  if (att.capsuleHash !== expectedHash) problems.push('attestation capsuleHash does not match the envelope hash we submitted');
  if (att.serverPublicKey !== PRODUCTION_ATTEST_PUBLIC_SPKI) problems.push('attestation serverPublicKey does not match the pinned production key');
  if (att.provenanceLevel && !PROVENANCE_LEVELS.includes(att.provenanceLevel)) problems.push(`unknown provenanceLevel ${att.provenanceLevel}`);
  if (problems.length === 0) {
    const { serverSignature, serverPublicKey, mode, ...rest } = att;
    const sigOk = await verifyEnvelope(PRODUCTION_ATTEST_PUBLIC_SPKI, serverSignature, canonicalJson(rest));
    if (!sigOk) problems.push('attestation signature failed to verify under the pinned production key');
  }
  return { ok: problems.length === 0, problems };
}

async function attestServer(req, attestUrl, bearer) {
  const body = {
    capsuleHash: req.capsuleHash, userIdHash: req.userIdHash,
    appId: req.appId, appVersion: req.appVersion,
    envelopeCanonical: req.envelopeCanonical, userSignature: req.userSignature,
    userPublicKey: req.userPublicKey, qualityReceipt: req.qualityReceipt,
  };
  const headers = { 'Content-Type': 'application/json' };
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  const res = await fetch(attestUrl, { method: 'POST', headers, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`Attestation failed (${res.status}): ${(await res.text().catch(() => '')).slice(0, 160)}`);
  return (await res.json()).attestation;
}

// ---------- AOC → sealed payload projection ----------

/**
 * Project a signed AOC into the sealed v3 payload. The FULL signed AOC is
 * carried as the content so the buyer, after local decrypt, can independently
 * re-verify the AOC's own owner signature and hashes. No new plaintext is
 * introduced; the AOC was already privacy-reviewed by the collector.
 */
export function aocToSealedPayload(aoc) {
  const createdAt = aoc?.provenance?.captured_at || new Date().toISOString();
  const title = `Agent Outcome Capsule ${aoc.capsule_id} — ${aoc?.task?.task_class ?? 'unknown'}`;
  return JSON.stringify({
    schemaVersion: SEALED_SCHEMA_VERSION,
    appType: APP_TYPE,
    title,
    content: JSON.stringify(aoc),
    createdAt,
    updatedAt: createdAt,
  });
}

// ---------- inner AOC verification (reuses Foundry Collector verify logic) ----------

/**
 * Recompute a Foundry AOC's signed body hash exactly as foundry-collector.mjs
 * does (buildCapsule / verify mode): the signed body is
 *   { owner, environment, task, failure, intervention, outcome,
 *     redacted_preview: _redacted_content || {}, timestamp: _body_timestamp }
 * serialized with JSON.stringify(body, null, 0) and hashed 'sha256:'+hex.
 */
function aocSha256(data) {
  const h = createHash('sha256');
  h.update(typeof data === 'string' ? data : JSON.stringify(data));
  return 'sha256:' + h.digest('hex');
}

export function recomputeAocBodyHash(aoc) {
  const bodyTimestamp = aoc?._body_timestamp || aoc?.provenance?.captured_at;
  const body = {
    owner: aoc.owner,
    environment: aoc.environment,
    task: aoc.task,
    failure: aoc.failure,
    intervention: aoc.intervention,
    outcome: aoc.outcome,
    redacted_preview: aoc._redacted_content || {},
    timestamp: bodyTimestamp,
  };
  return aocSha256(JSON.stringify(body, null, 0));
}

/**
 * Verify a signed AOC's stored hash and owner signature BEFORE sealing.
 * `aocPublicKeyPem` is the owner's public key (PEM) that signed the AOC; it is
 * REQUIRED when the AOC carries an owner signature. Fails closed on any
 * missing/mismatched/invalid field. Returns { ok, problems, recomputedHash }.
 */
export function verifyAocSignature(aoc, aocPublicKeyPem) {
  const problems = [];
  const storedHash = aoc?.provenance?.capsule_hash;
  const sig = aoc?.provenance?.signatures?.[0];
  if (!storedHash) problems.push('AOC provenance.capsule_hash missing');
  if (!sig) problems.push('AOC provenance.signatures[0] missing');

  let recomputedHash = null;
  if (storedHash) {
    recomputedHash = recomputeAocBodyHash(aoc);
    if (recomputedHash !== storedHash) {
      problems.push(`AOC capsule_hash mismatch (stored ${storedHash} != recomputed ${recomputedHash})`);
    }
  }

  if (sig) {
    if (!aocPublicKeyPem) {
      problems.push('AOC is signed but no --aoc-pubkey was supplied; refusing to seal an unverified signed AOC');
    } else {
      const algo = sig.algorithm;
      if (algo !== 'ed25519' && algo !== 'p256') {
        problems.push(`Unsupported AOC signature algorithm: ${algo}`);
      } else {
        try {
          const pubKey = createPublicKey(aocPublicKeyPem);
          const dataBuf = Buffer.from(storedHash, 'utf8');
          const sigBuf = Buffer.from(sig.signature, 'base64');
          const ok = algo === 'ed25519'
            ? nodeVerify(null, dataBuf, pubKey, sigBuf)
            : nodeVerify('sha256', dataBuf, pubKey, sigBuf);
          if (!ok) problems.push('AOC owner signature failed to verify under the supplied public key');
        } catch (e) {
          problems.push('AOC signature verification error: ' + e.message);
        }
      }
    }
  }
  return { ok: problems.length === 0, problems, recomputedHash };
}

// ---------- privacy gate ----------

export function privacyGate(aoc, { allowReview = false } = {}) {
  const p = aoc?.privacy ?? {};
  const problems = [];
  if (p.personal_data_included !== false) problems.push('privacy.personal_data_included is not false');
  if (p.chain_of_thought_included !== false) problems.push('privacy.chain_of_thought_included is not false');
  if (p.secret_scan === 'fail') problems.push('privacy.secret_scan === "fail"');
  if (p.pii_scan === 'fail') problems.push('privacy.pii_scan === "fail"');
  if (!allowReview) {
    if (p.secret_scan === 'review') problems.push('privacy.secret_scan === "review" (pass --allow-review to seal anyway)');
    if (p.pii_scan === 'review') problems.push('privacy.pii_scan === "review" (pass --allow-review to seal anyway)');
  }
  return { ok: problems.length === 0, problems };
}

// ---------- main seal ----------

export async function sealAocToVaultCapsule(aoc, opts = {}) {
  // Fail closed: verify the inner AOC's stored hash + owner signature before
  // doing any sealing work. A signed AOC requires a supplied public key.
  const aocCheck = verifyAocSignature(aoc, opts.aocPublicKeyPem);
  if (!aocCheck.ok) {
    throw new Error('inner AOC verification failed: ' + aocCheck.problems.join('; '));
  }
  const sealedPayload = aocToSealedPayload(aoc);
  const vk = await resolveVaultKey(opts);
  const vaultKey = vk.key ?? vk; // resolveVaultKey may return CryptoKey or {key,...}
  const sk = await resolveSigningKeys(opts);

  const id = randomId();
  const createdAt = aoc?.provenance?.captured_at || new Date().toISOString();

  const encPayload = await encryptPayload(sealedPayload, vaultKey);
  const payloadHash = await sha256Hex(sealedPayload);
  const ciphertextHash = await sha256Hex(encPayload.ciphertext);
  const qualityReceipt = await computeQualityReceipt(sealedPayload);

  const envelope = {
    id,
    appType: APP_TYPE,
    appVersion: APP_VERSION,
    createdAt,
    title: OPAQUE_TITLE,
    payloadHash,
    ciphertextHash,
    enc: encPayload,
    userPublicKey: sk.publicKeySpki,
  };
  const envelopeCanonical = canonicalJson(envelope);
  const envelopeHash = await sha256Hex(envelopeCanonical);
  const userSignature = await signEnvelope(sk.privateKey, envelopeCanonical);
  const userIdHash = await sha256Hex(sk.publicKeySpki);

  // Local (poc_local) receipts use the honest local-only provenance level.
  // The server (production_server) sets its own provenance and we re-verify it.
  const attestReq = {
    capsuleHash: envelopeHash, userIdHash, appId: APP_ID, appVersion: APP_VERSION,
    provenanceLevel: LOCAL_PROVENANCE_LEVEL, envelopeCanonical, userSignature,
    userPublicKey: sk.publicKeySpki, qualityReceipt,
  };
  let attestation;
  if (opts.attestUrl) {
    attestation = await attestServer(attestReq, opts.attestUrl, opts.attestBearer);
    // Fail closed: a bad or mismatched production response must not be emitted.
    const prodCheck = await verifyProductionAttestation(attestation, envelopeHash);
    if (!prodCheck.ok) {
      throw new Error('production attestation rejected: ' + prodCheck.problems.join('; '));
    }
  } else {
    attestation = await attestLocal(attestReq);
  }

  const capsule = {
    contract: CONTRACT,
    contractVersion: CONTRACT_VERSION,
    id,
    appType: APP_TYPE,
    appVersion: APP_VERSION,
    createdAt,
    updatedAt: createdAt,
    title: OPAQUE_TITLE,
    enc: encPayload,
    payloadHash,
    ciphertextHash,
    userPublicKey: sk.publicKeySpki,
    userSignature,
    envelopeHash,
    attestation,
    qualityReceipt,
  };

  // Return key material out-of-band ONLY (never inside the capsule) so the
  // owner can persist their vault key / signing key to reopen or list later.
  const keyMaterial = {};
  if (vk.ephemeral) keyMaterial.vaultKeyB64 = bufToBase64(await subtle.exportKey('raw', vaultKey));
  if (vk.salt) keyMaterial.saltB64 = bufToBase64(vk.salt);
  if (sk.ephemeral) {
    keyMaterial.signingPubSpkiB64 = sk.publicKeySpki;
    keyMaterial.signingPrivPkcs8B64 = bufToBase64(await subtle.exportKey('pkcs8', sk.privateKeyObj));
  }
  return { capsule, keyMaterial, sealedPayload };
}

// ---------- verification helpers (buyer / conformance) ----------

export async function verifyVaultCapsule(capsule, { vaultKeyB64, passphrase, saltB64 } = {}) {
  const results = {};
  // 1. signed envelope shape + signature
  const envelope = {
    id: capsule.id, appType: capsule.appType, appVersion: capsule.appVersion,
    createdAt: capsule.createdAt, title: capsule.title, payloadHash: capsule.payloadHash,
    ciphertextHash: capsule.ciphertextHash, enc: capsule.enc, userPublicKey: capsule.userPublicKey,
  };
  const envelopeCanonical = canonicalJson(envelope);
  results.envelopeHashMatches = (await sha256Hex(envelopeCanonical)) === capsule.envelopeHash;
  results.userSignatureValid = await verifyEnvelope(capsule.userPublicKey, capsule.userSignature, envelopeCanonical);
  results.ciphertextHashMatches = (await sha256Hex(capsule.enc.ciphertext)) === capsule.ciphertextHash;
  // 2. attestation. Mode is an explicit allowlist; unknown/misspelled modes
  //    fail closed. Pinned-key rule (matches src/lib/attest-verify.ts):
  //    production_server MUST match the pinned key and verify under it; a
  //    self-minted key claiming production must never verify as production.
  //    poc_local receipts verify with their embedded key AND must carry an
  //    allowlisted, non-authenticated_session provenance level.
  if (capsule.attestation) {
    const { serverSignature, serverPublicKey, mode, ...rest } = capsule.attestation;
    results.attestationCapsuleHashMatches = capsule.attestation.capsuleHash === capsule.envelopeHash;
    results.attestationModeAllowed = ATTEST_MODES.includes(mode);
    const provOk = PROVENANCE_LEVELS.includes(capsule.attestation.provenanceLevel);
    if (!results.attestationModeAllowed) {
      // Unknown/misspelled mode: fail closed, do not attempt any verification.
      results.attestationSignatureValid = false;
    } else if (mode === 'production_server') {
      results.attestationSignatureValid =
        provOk &&
        serverPublicKey === PRODUCTION_ATTEST_PUBLIC_SPKI &&
        (await verifyEnvelope(PRODUCTION_ATTEST_PUBLIC_SPKI, serverSignature, canonicalJson(rest)));
    } else {
      // poc_local: must NOT claim authenticated_session; verify with embedded key.
      results.attestationSignatureValid =
        provOk &&
        capsule.attestation.provenanceLevel !== 'authenticated_session' &&
        (await verifyEnvelope(serverPublicKey, serverSignature, canonicalJson(rest)));
    }
  }
  // 3. payload decrypt + quality recompute (needs the vault key or passphrase+salt)
  let vaultKey = null;
  if (vaultKeyB64) {
    vaultKey = await subtle.importKey('raw', base64ToBytes(vaultKeyB64), { name: 'AES-GCM', length: 256 }, true, ['unwrapKey', 'decrypt']);
  } else if (passphrase && saltB64) {
    vaultKey = await derivePassphraseKey(passphrase, base64ToBytes(saltB64));
  }
  if (vaultKey) {
    try {
      const plain = await decryptPayload(capsule.enc, vaultKey);
      results.payloadHashMatches = (await sha256Hex(plain)) === capsule.payloadHash;
      const recomputed = await computeQualityReceipt(plain);
      results.qualityReceiptMatches = canonicalJson(recomputed) === canonicalJson(capsule.qualityReceipt);
      results.decryptedPayload = plain;
    } catch {
      // AES-GCM auth failure on tamper / wrong key: report as failed checks,
      // never crash.
      results.payloadHashMatches = false;
      results.qualityReceiptMatches = false;
    }
  }
  return results;
}

/** Privacy gate: no plaintext, DEK, or private key may appear in the capsule. */
export function scanCapsuleForLeaks(capsule) {
  const problems = [];
  const s = JSON.stringify(capsule);
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) problems.push('PEM private key present in capsule');
  if (/"(?:privateKey|priv_jwk|privJwk|dek|rawDek|vaultKey|passphrase)"\s*:/.test(s)) problems.push('private-key/DEK/vault-key field present in capsule');
  // The sealed content must only appear as ciphertext, never as plaintext AOC JSON.
  if (/"schema_version"\s*:\s*"0\.1\.0"/.test(s)) problems.push('plaintext AOC (schema_version 0.1.0) present in capsule');
  if (/"capsule_id"\s*:\s*"AOC-/.test(s)) problems.push('plaintext AOC capsule_id present in capsule');
  return { ok: problems.length === 0, problems };
}

// ---------- CLI ----------

function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string', short: 'i' },
      output: { type: 'string', short: 'o' },
      'key-out': { type: 'string' },
      passphrase: { type: 'string' },
      salt: { type: 'string' },
      'vault-key': { type: 'string' },
      'signing-priv': { type: 'string' },
      'signing-pub': { type: 'string' },
      'aoc-pubkey': { type: 'string' },
      'attest-url': { type: 'string' },
      'attest-bearer': { type: 'string' },
      'allow-review': { type: 'boolean', default: false },
      verify: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: true,
  });

  if (values.help) {
    console.log(`Foundry → LoopXXI Vault Capsule exporter

Usage:
  node vault/foundry-vault-export.mjs -i <aoc.json> -o <vault-capsule.json> [--key-out keys.json]
  node vault/foundry-vault-export.mjs -i <vault-capsule.json> --verify [--vault-key <b64>]

Options:
  -i, --input <file>      Signed AOC (seal mode) or capsule (verify mode)
  -o, --output <file>     Output vault capsule JSON
      --key-out <file>    Where to write out-of-band key material (never in the capsule)
      --passphrase <str>  Derive the vault key from a passphrase (PBKDF2)
      --vault-key <b64>   Supply a raw AES-256 vault key (base64)
      --signing-priv <b64> Reuse an ECDSA P-256 signing private key (pkcs8 base64)
      --signing-pub <b64>  Matching signing public key (spki base64)
      --aoc-pubkey <file> PEM public key that signed the source AOC. REQUIRED to
                          seal a signed AOC; the inner hash + owner signature are
                          verified before sealing (fails closed on mismatch).
      --attest-url <url>  Use the production attest Edge Function (posts hashes + pubkeys only).
                          The returned production_server receipt is verified
                          (hash + pinned key + signature) before the capsule is emitted.
      --attest-bearer <t> Supabase JWT for the attest call
      --allow-review      Seal even if privacy scan is 'review' (never seals 'fail')
  -v, --verify            Verify a capsule (envelope, signature, attestation, leaks)
  -h, --help              Show help

Nothing is transmitted unless --attest-url is given (and that posts only hashes + public keys).`);
    process.exit(0);
  }

  if (!values.input) { console.error('Error: --input required'); process.exit(1); }
  const raw = readFileSync(resolve(values.input), 'utf8');
  const obj = JSON.parse(raw);

  if (values.verify) {
    verifyVaultCapsule(obj, { vaultKeyB64: values['vault-key'], passphrase: values.passphrase, saltB64: values.salt }).then((r) => {
      const leaks = scanCapsuleForLeaks(obj);
      const { decryptedPayload, ...checks } = r;
      for (const [k, v] of Object.entries(checks)) console.log(`${k}: ${v}`);
      console.log(`noLeaks: ${leaks.ok}${leaks.ok ? '' : ' — ' + leaks.problems.join('; ')}`);
      const allChecks = Object.values(checks).every((v) => v === true) && leaks.ok;
      console.log(`overallValid: ${allChecks}`);
      process.exit(allChecks ? 0 : 1);
    });
    return;
  }

  // seal mode
  const gate = privacyGate(obj, { allowReview: values['allow-review'] });
  if (!gate.ok) {
    console.error('Privacy gate FAILED — refusing to seal:');
    for (const p of gate.problems) console.error('  - ' + p);
    process.exit(2);
  }

  const aocPublicKeyPem = values['aoc-pubkey'] ? readFileSync(resolve(values['aoc-pubkey']), 'utf8') : undefined;
  sealAocToVaultCapsule(obj, {
    passphrase: values.passphrase,
    vaultKeyB64: values['vault-key'],
    signingPrivPkcs8B64: values['signing-priv'],
    signingPubSpkiB64: values['signing-pub'],
    aocPublicKeyPem,
    attestUrl: values['attest-url'],
    attestBearer: values['attest-bearer'],
  }).then(async ({ capsule, keyMaterial }) => {
    const leaks = scanCapsuleForLeaks(capsule);
    if (!leaks.ok) { console.error('LEAK CHECK FAILED: ' + leaks.problems.join('; ')); process.exit(3); }
    const out = JSON.stringify(capsule, null, 2);
    if (values.output) { writeFileSync(resolve(values.output), out); console.error(`Capsule written: ${values.output}`); }
    else console.log(out);
    if (Object.keys(keyMaterial).length > 0) {
      if (values['key-out']) { writeFileSync(resolve(values['key-out']), JSON.stringify(keyMaterial, null, 2)); console.error(`Key material written (KEEP PRIVATE): ${values['key-out']}`); }
      else console.error('Warning: ephemeral key material generated. Re-run with --key-out to persist it, or you cannot reopen this capsule.');
    }
    console.error(`\n--- Vault Export Summary ---`);
    console.error(`Contract: ${capsule.contract} v${capsule.contractVersion}`);
    console.error(`Capsule id: ${capsule.id}`);
    console.error(`Envelope hash: ${capsule.envelopeHash}`);
    console.error(`Attestation mode: ${capsule.attestation.mode}`);
    console.error(`Quality: record_count=${capsule.qualityReceipt.record_count}, bytes=${capsule.qualityReceipt.content_byte_count}`);
    console.error(`Leak scan: ${leaks.ok ? 'clean (no plaintext/DEK/private key)' : 'FAILED'}`);
  }).catch((e) => { console.error('Seal failed: ' + e.message); process.exit(1); });
}

// Run as CLI only when invoked directly.
import { fileURLToPath } from 'node:url';
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
