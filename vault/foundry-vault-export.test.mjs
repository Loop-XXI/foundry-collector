#!/usr/bin/env node
/**
 * Conformance tests for the Foundry → LoopXXI Vault Capsule exporter.
 * Zero dependencies. Run: node vault/foundry-vault-export.test.mjs
 */
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  sealAocToVaultCapsule, verifyVaultCapsule, scanCapsuleForLeaks,
  privacyGate, computeQualityReceipt, canonicalJson,
  CONTRACT, CONTRACT_VERSION, APP_ID,
} from './foundry-vault-export.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const AOC = JSON.parse(readFileSync(resolve(here, 'fixtures/synthetic-aoc.json'), 'utf8'));

let pass = 0, fail = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.error(`FAIL  ${name}\n      ${e.message}`); fail++; }
}

console.log('Foundry → Vault Capsule conformance suite\n');

await test('privacy gate passes for a clean AOC', () => {
  const g = privacyGate(AOC);
  assert.strictEqual(g.ok, true, g.problems.join('; '));
});

await test('privacy gate blocks secret_scan=fail', () => {
  const bad = { ...AOC, privacy: { ...AOC.privacy, secret_scan: 'fail' } };
  assert.strictEqual(privacyGate(bad).ok, false);
});

await test('privacy gate blocks personal_data_included=true', () => {
  const bad = { ...AOC, privacy: { ...AOC.privacy, personal_data_included: true } };
  assert.strictEqual(privacyGate(bad).ok, false);
});

let sealed;
await test('seal produces a v1.0.0 capsule with the right contract fields', async () => {
  sealed = await sealAocToVaultCapsule(AOC, { passphrase: 'test-pass' });
  const c = sealed.capsule;
  assert.strictEqual(c.contract, CONTRACT);
  assert.strictEqual(c.contractVersion, CONTRACT_VERSION);
  assert.strictEqual(c.title, 'Encrypted capsule');
  assert.strictEqual(c.attestation.appId, APP_ID);
  assert.ok(c.enc.ciphertext && c.enc.wrappedDek && c.enc.iv && c.enc.wrapIv);
});

await test('§9.6 privacy gate: no plaintext / DEK / private key in the capsule', () => {
  const scan = scanCapsuleForLeaks(sealed.capsule);
  assert.strictEqual(scan.ok, true, scan.problems.join('; '));
});

await test('key material (vault key / signing priv) is out-of-band, never in the capsule', () => {
  const s = JSON.stringify(sealed.capsule);
  assert.ok(!s.includes('PRIVATE KEY'));
  assert.ok(!('vaultKeyB64' in sealed.capsule));
  assert.ok(sealed.keyMaterial.saltB64, 'salt returned out of band');
  assert.ok(sealed.keyMaterial.signingPrivPkcs8B64, 'signing priv returned out of band');
});

await test('genuine capsule verifies: envelope, signature, attestation, decrypt, quality', async () => {
  const r = await verifyVaultCapsule(sealed.capsule, {
    passphrase: 'test-pass', saltB64: sealed.keyMaterial.saltB64,
  });
  assert.strictEqual(r.envelopeHashMatches, true);
  assert.strictEqual(r.userSignatureValid, true);
  assert.strictEqual(r.ciphertextHashMatches, true);
  assert.strictEqual(r.attestationCapsuleHashMatches, true);
  assert.strictEqual(r.attestationSignatureValid, true);
  assert.strictEqual(r.payloadHashMatches, true);
  assert.strictEqual(r.qualityReceiptMatches, true);
});

await test('buyer decrypt recovers the exact signed AOC', async () => {
  const r = await verifyVaultCapsule(sealed.capsule, {
    passphrase: 'test-pass', saltB64: sealed.keyMaterial.saltB64,
  });
  const inner = JSON.parse(r.decryptedPayload);
  const recoveredAoc = JSON.parse(inner.content);
  assert.strictEqual(recoveredAoc.capsule_id, AOC.capsule_id);
  assert.strictEqual(recoveredAoc.provenance.capsule_hash, AOC.provenance.capsule_hash);
});

await test('ciphertext tamper fails decrypt & quality (no crash)', async () => {
  const c = JSON.parse(JSON.stringify(sealed.capsule));
  const b = Buffer.from(c.enc.ciphertext, 'base64'); b[8] ^= 0xff; c.enc.ciphertext = b.toString('base64');
  const r = await verifyVaultCapsule(c, { passphrase: 'test-pass', saltB64: sealed.keyMaterial.saltB64 });
  assert.strictEqual(r.payloadHashMatches, false);
  assert.strictEqual(r.qualityReceiptMatches, false);
});

await test('envelope-field tamper breaks the user signature', async () => {
  const c = JSON.parse(JSON.stringify(sealed.capsule));
  c.appVersion = '9.9.9'; // signed field mutated
  const r = await verifyVaultCapsule(c, {});
  assert.strictEqual(r.envelopeHashMatches, false);
  assert.strictEqual(r.userSignatureValid, false);
});

await test('self-minted "production_server" attestation must NOT verify as production', async () => {
  const c = JSON.parse(JSON.stringify(sealed.capsule));
  c.attestation.mode = 'production_server'; // lie: signed by a local key, not the pinned one
  const r = await verifyVaultCapsule(c, {});
  assert.strictEqual(r.attestationSignatureValid, false);
});

await test('quality receipt is recomputable & deterministic from the sealed payload', async () => {
  const qr = await computeQualityReceipt(sealed.sealedPayload);
  assert.strictEqual(canonicalJson(qr), canonicalJson(sealed.capsule.qualityReceipt));
  assert.strictEqual(qr.content_commitment, sealed.capsule.payloadHash);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
