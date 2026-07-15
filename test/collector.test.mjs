import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { strict as assert } from 'node:assert';

const NODE = process.execPath;
import { fileURLToPath } from 'node:url';
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const COLLECTOR = resolve(__dirname, '..', 'foundry-collector.mjs');
const TMP = join(tmpdir(), `foundry-test-${Date.now()}`);

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    testsPassed++;
  } catch (e) {
    console.error(`  FAIL: ${name}: ${e.message}`);
    testsFailed++;
  }
}

function runCollector(args) {
  const result = execSync(`${NODE} ${COLLECTOR} ${args}`, {
    encoding: 'utf8',
    cwd: TMP,
    stderr: 'pipe',
  });
  return result;
}

console.log('Loop Foundry Collector — Test Suite\n');

// Setup
mkdirSync(TMP, { recursive: true });

// Generate a keypair for tests
const kp = generateKeyPairSync('ed25519');
const keypairFile = join(TMP, 'keypair.json');
writeFileSync(keypairFile, JSON.stringify({
  algorithm: 'ed25519',
  privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }),
}));
const pubKeyFile = join(TMP, 'pub.pem');
writeFileSync(pubKeyFile, kp.publicKey.export({ type: 'spki', format: 'pem' }));

// --- Test 1: Basic capsule generation ---
test('generates a valid capsule from minimal input', () => {
  const input = {
    owner: { owner_id: 'test-co', owner_type: 'business', custody_mode: 'owner_retained' },
    environment: { domain: 'test', agent_architecture: 'test', model_family: 'test', tool_classes: ['test'] },
    task: { task_class: 'test', objective: 'test', success_criteria: ['pass'] },
    failure: { taxonomy: 'other', decisive_step: 0, observable_evidence: ['evidence'], severity: 'low' },
    raw_data: { message: 'hello world' },
  };
  const inputFile = join(TMP, 'input1.json');
  const outputFile = join(TMP, 'output1.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -k ${keypairFile}`);
  const capsule = JSON.parse(readFileSync(outputFile, 'utf8'));
  assert.equal(capsule.schema_version, '0.1.0');
  assert.ok(capsule.capsule_id.startsWith('AOC-'));
  assert.equal(capsule.owner.owner_id, 'test-co');
  assert.ok(capsule.provenance.source_hash.startsWith('sha256:'));
  assert.ok(capsule.provenance.capsule_hash.startsWith('sha256:'));
  assert.equal(capsule.provenance.signatures[0].algorithm, 'ed25519');
  assert.equal(capsule.privacy.personal_data_included, false);
  assert.equal(capsule.privacy.chain_of_thought_included, false);
});

// --- Test 2: Secret redaction ---
test('redacts BOLT11 invoices, API keys, and passwords', () => {
  const input = {
    raw_data: {
      invoice: 'lnbc100n1p3qqdpz0d5q2pp5xq8j5q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9q0q1q2q3q4q5q6q7q8q9',
      api_key: 'sk_live_abcdefghijklmnopqrstuv',
      password: 'mySecretPassword123',
      github_token: 'ghp_abcdef1234567890abcdefghijklmnopqrstuvwxyzABCD',
    },
  };
  const inputFile = join(TMP, 'input2.json');
  const outputFile = join(TMP, 'output2.json');
  const reportFile = join(TMP, 'report2.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -r ${reportFile} -k ${keypairFile}`);
  const capsuleRaw = readFileSync(outputFile, 'utf8');
  const report = JSON.parse(readFileSync(reportFile, 'utf8'));
  assert.ok(!capsuleRaw.includes('lnbc100n'), 'BOLT11 invoice should be redacted');
  assert.ok(!capsuleRaw.includes('sk_live_'), 'API key should be redacted');
  assert.ok(!capsuleRaw.includes('mySecretPassword'), 'Password should be redacted');
  assert.ok(!capsuleRaw.includes('ghp_abcdef'), 'GitHub token should be redacted');
  assert.ok(capsuleRaw.includes('[REDACTED:'), 'Should contain redaction markers');
  assert.ok(report.summary.total_secret_findings >= 3, 'Should report at least 3 secrets');
});

// --- Test 3: PII redaction ---
test('redacts email addresses and phone numbers', () => {
  const input = {
    raw_data: {
      contact: 'admin@example.com',
      phone: '(217) 638-1230',
      ssn: '123-45-6789',
    },
  };
  const inputFile = join(TMP, 'input3.json');
  const outputFile = join(TMP, 'output3.json');
  const reportFile = join(TMP, 'report3.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -r ${reportFile} -k ${keypairFile}`);
  const capsuleRaw = readFileSync(outputFile, 'utf8');
  assert.ok(!capsuleRaw.includes('admin@example.com'), 'Email should be redacted');
  assert.ok(!capsuleRaw.includes('123-45-6789'), 'SSN should be redacted');
  const report = JSON.parse(readFileSync(reportFile, 'utf8'));
  assert.ok(report.summary.total_pii_findings >= 2, 'Should report PII findings');
});

// --- Test 4: Chain-of-thought removal ---
test('removes chain-of-thought markers', () => {
  const input = {
    raw_data: {
      agent_log: 'Let me think about this. First, I need to analyze the error. <thinking>This is reasoning</thinking> The answer is 42.',
    },
  };
  const inputFile = join(TMP, 'input4.json');
  const outputFile = join(TMP, 'output4.json');
  const reportFile = join(TMP, 'report4.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -r ${reportFile} -k ${keypairFile}`);
  const capsuleRaw = readFileSync(outputFile, 'utf8');
  assert.ok(!capsuleRaw.includes('<thinking>'), 'CoT tags should be removed');
  const report = JSON.parse(readFileSync(reportFile, 'utf8'));
  assert.ok(report.summary.chain_of_thought_detected === true || report.summary.total_cot_findings > 0, 'Should detect CoT');
});

// --- Test 5: Signature verification ---
test('signature verification passes for valid capsule', () => {
  const input = {
    raw_data: { message: 'test for verification' },
    owner: { owner_id: 'verify-test', owner_type: 'business', custody_mode: 'owner_retained' },
  };
  const inputFile = join(TMP, 'input5.json');
  const outputFile = join(TMP, 'output5.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -k ${keypairFile}`);
  const verifyResult = execSync(`${NODE} ${COLLECTOR} -v -i ${outputFile} -p ${pubKeyFile}`, {
    encoding: 'utf8',
    cwd: TMP,
    stderr: 'pipe',
  });
  assert.ok(verifyResult.includes('Signature valid: true'), 'Signature should be valid');
});

// --- Test 6: Signature verification fails for tampered capsule ---
test('signature verification fails for tampered capsule', () => {
  const input = {
    raw_data: { message: 'original' },
    owner: { owner_id: 'tamper-test', owner_type: 'business', custody_mode: 'owner_retained' },
  };
  const inputFile = join(TMP, 'input6.json');
  const outputFile = join(TMP, 'output6.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -k ${keypairFile}`);
  // Tamper with the capsule
  const capsule = JSON.parse(readFileSync(outputFile, 'utf8'));
  capsule.owner.owner_id = 'tampered';
  writeFileSync(outputFile, JSON.stringify(capsule, null, 2));
  let exitCode = 0;
  try {
    execSync(`${NODE} ${COLLECTOR} -v -i ${outputFile} -p ${pubKeyFile}`, {
      encoding: 'utf8',
      cwd: TMP,
      stderr: 'pipe',
      stdio: 'pipe',
    });
  } catch (e) {
    exitCode = e.status || 1;
  }
  assert.ok(exitCode !== 0, 'Verification should fail for tampered capsule');
});

// --- Test 7: Private key PEM redaction ---
test('redacts PEM private key blocks', () => {
  const input = {
    raw_data: {
      key: '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEINxQ8jQz1kRk5q9pN5S2vZ7xG6pK3h9K7tG4aBcDeFgHoYIao1m6N2pQ\n-----END EC PRIVATE KEY-----',
    },
  };
  const inputFile = join(TMP, 'input7.json');
  const outputFile = join(TMP, 'output7.json');
  writeFileSync(inputFile, JSON.stringify(input));
  runCollector(`-i ${inputFile} -o ${outputFile} -k ${keypairFile}`);
  const capsuleRaw = readFileSync(outputFile, 'utf8');
  assert.ok(!capsuleRaw.includes('BEGIN EC PRIVATE KEY'), 'PEM private key should be redacted');
});

// --- Test 8: stdin input ---
test('reads input from stdin', () => {
  const input = JSON.stringify({ raw_data: { msg: 'stdin test' } });
  const outputFile = join(TMP, 'output8.json');
  execSync(`echo '${input}' | ${NODE} ${COLLECTOR} -o ${outputFile} -k ${keypairFile}`, {
    encoding: 'utf8',
    cwd: TMP,
  });
  const capsule = JSON.parse(readFileSync(outputFile, 'utf8'));
  assert.ok(capsule.capsule_id.startsWith('AOC-'));
});

// Cleanup
rmSync(TMP, { recursive: true, force: true });

console.log(`\n--- Results ---`);
console.log(`Passed: ${testsPassed}`);
console.log(`Failed: ${testsFailed}`);
process.exit(testsFailed > 0 ? 1 : 0);
