# LoopXXI Vault Capsule Interoperability Contract

**Contract id:** `loopxxi.vault.capsule`
**Contract version:** `1.0.0`
**Status:** Stable (additive changes only within v1)
**Reuses:** the live Vault envelope, provenance attestation, structural quality receipt, and buyer-key-wrap primitives already running at https://vault.loopxxi.com. This contract does **not** invent a parallel format — it is the portable specification of the format the live Vault already produces and consumes.

---

## 1. Purpose

Every first-party LoopXXI app may optionally emit a **Vault Capsule**: an encrypted, user-controlled copy of data the human or agent created, sealed so that:

- key material is held by the originating client, never by LoopXXI Vault infrastructure;
- the payload is encrypted per-capsule with AES-GCM under a per-capsule Data Encryption Key (DEK), which is itself wrapped under a client-held vault key;
- server-visible rows are **opaque** (ciphertext + hashes + public keys + signatures only);
- provenance is signed (production uses a server-held key; PoC uses a local demo key);
- structural quality evidence is attached that describes *shape*, never *truth, accuracy, ownership, identity, or consent*;
- the capsule can be exported and, on sale, the DEK is re-wrapped to a buyer's public key so the buyer decrypts locally.

## 2. Trust / visibility boundary (honest, do not weaken)

This contract makes an explicit line between two parties and does **not** claim every app is zero-knowledge:

| Party | Sees |
|---|---|
| **Originating app / provider** (e.g. Foundry Collector on the owner's machine, or a server app that must process input) | May see plaintext input, because it must process it to produce data. For Foundry Collector this is the owner's own local machine; nothing is transmitted. For a server-side app the provider necessarily processes user input. |
| **LoopXXI Vault infrastructure** (`vault.loopxxi.com` + its Supabase rows + attest Edge Function) | Sees only the **opaque envelope**: `ciphertext`, `iv`, `wrapped_dek`, `wrap_iv`, integrity hashes, the user's signing public key, the user's signature, and the (non-sensitive) structural quality receipt. Never plaintext, never the DEK, never the vault key, never a private key. |

An app is only allowed to advertise `zero_knowledge: true` in its discovery manifest (see §7) when the originating service does **not** process plaintext server-side (client-only sealing). Foundry Collector qualifies (local-only). A hosted service that must read user input server-side MUST advertise `zero_knowledge: false` and instead advertise `server_sees: "plaintext_input"`.

## 3. Canonical envelope schema (v1)

A conforming capsule is the object below. Field names, casing, and hash inputs are **normative** because they match the live Vault (`src/lib/capsule.ts`, `src/lib/crypto.ts`, `src/lib/types.ts`).

```jsonc
{
  "contract": "loopxxi.vault.capsule",
  "contractVersion": "1.0.0",

  "id": "<uuid v4>",
  "appType": "<string, e.g. notes | chat | agent_outcome>",
  "appVersion": "<producer app version>",
  "createdAt": "<ISO-8601>",
  "updatedAt": "<ISO-8601>",

  // Opaque server title. The real title (if any) lives ONLY inside the encrypted payload.
  "title": "Encrypted capsule",

  // AES-GCM encrypted payload + wrapped DEK (base64). Matches EncryptedPayload.
  "enc": {
    "ciphertext": "<base64>",
    "iv": "<base64, 12 bytes>",
    "wrappedDek": "<base64: DEK wrapped under the client-held vault key>",
    "wrapIv": "<base64, 12 bytes>"
  },

  // Integrity commitments (SHA-256 hex).
  "payloadHash": "<sha256hex of the sealed plaintext payload>",
  "ciphertextHash": "<sha256hex of enc.ciphertext>",

  // User origin + tamper evidence.
  "userPublicKey": "<ECDSA P-256 SPKI, base64>",
  "userSignature": "<ECDSA P-256 signature over canonicalJson(envelope), base64>",
  "envelopeHash": "<sha256hex of canonicalJson(envelope)>",

  // Provenance attestation (see §4). Optional but expected for marketplace listing.
  "attestation": { /* Attestation, §4 */ },

  // Structural quality evidence (see §5). Non-sensitive.
  "qualityReceipt": { /* QualityReceipt, §5 */ }
}
```

### 3.1 Signed-envelope canonicalization

The signed `envelope` (the object whose canonical JSON is hashed to `envelopeHash` and signed to `userSignature`) is exactly:

```
{ id, appType, appVersion, createdAt, title, payloadHash, ciphertextHash, enc, userPublicKey }
```

with `title` set to the opaque literal `"Encrypted capsule"`. Canonicalization is recursive key-sorted JSON (`canonicalJson` in `src/lib/crypto.ts`). This is byte-for-byte compatible with the live Vault `buildEnvelope` + `sealCapsule`.

### 3.2 Sealed payload (v3)

The plaintext that is encrypted is a JSON string:

```json
{ "schemaVersion": 3, "appType": "<appType>", "title": "<real title>", "content": "<payload>", "createdAt": "<ISO>", "updatedAt": "<ISO>" }
```

`payloadHash = sha256hex(sealedPayloadString)`. This lets the buyer recompute the quality receipt after local decrypt.

## 4. Attestation

Matches `Attestation` in the live Vault. Two honest claims, keyed to `mode`:
- `production_server`: *"an authenticated LoopXXI session sealed this capsule at time T"* (the Vault attest Edge Function verified a real Supabase JWT).
- `poc_local`: *"this capsule was sealed locally at time T with a self-generated key"* — **no** authenticated-session claim.

Neither claims content is true.

```jsonc
{
  "capsuleHash": "<= envelopeHash>",
  "userIdHash": "<sha256hex(userPublicKey)>",
  "appId": "<producer app id>",
  "appVersion": "<producer app version>",
  "timestamp": "<ISO>",
  "provenanceLevel": "local_export" | "authenticated_session" | "verified_human",
  "qualityReceipt": { /* §5, echoed and signed */ },
  "serverPublicKey": "<SPKI base64>",
  "serverSignature": "<signature over canonicalJson(unsigned attestation)>",
  "mode": "poc_local" | "production_server"
}
```

**Mode is an explicit allowlist** — `poc_local` and `production_server` only. Any other/misspelled value MUST fail verification (no silent fallback to "treat as local").

**Provenance binding (normative):**
- `poc_local` receipts MUST carry `provenanceLevel: "local_export"`. They MUST NOT claim `authenticated_session` — the receipt was signed by a local key, not a JWT-authenticated server session.
- `authenticated_session` (and the reserved `verified_human`) are legitimate **only** for `production_server`.

`production_server` receipts MUST verify against the **pinned** production key (`PRODUCTION_ATTEST_PUBLIC_SPKI`); a self-minted key must never verify as production. Verification logic is `verifyAttestation` in `src/lib/attest-verify.ts` and, for the exporter, `verifyVaultCapsule` (mode allowlist + pinned-key rule) in `vault/foundry-vault-export.mjs`.

**Production-response verification (normative).** When a producer obtains a `production_server` receipt from the attest Edge Function, it MUST verify — before emitting the capsule — that the returned `capsuleHash` equals the submitted envelope hash, the `serverPublicKey` equals the pinned key, and the signature verifies under the pinned key. A bad or mismatched response fails closed (`verifyProductionAttestation`).

## 5. Structural quality receipt

Matches `QualityReceipt` (`src/lib/quality.ts`). HONEST label: **structural quality evidence only**. Describes shape (counts, rates, byte size, time range, content commitment). Never proof of truth, accuracy, ownership, identity, or consent. Never exposes titles or text.

```jsonc
{
  "version": 1,
  "source_type": "<appType>",
  "record_count": <int>,
  "turn_count": <int>,
  "time_range": { "min": "<ISO>", "max": "<ISO>" },
  "required_field_nonempty_rate": <0..1>,
  "empty_count": <int>,
  "duplicate_rate": <0..1>,
  "content_byte_count": <int>,
  "content_commitment": "<sha256hex of sealed payload>"
}
```

The buyer recomputes this from the decrypted payload and compares field-by-field (`verifyQualityReceipt`). Any payload tamper changes the recomputed receipt; any receipt tamper breaks the server signature.

## 6. Buyer key wrap (sale / handoff)

On sale the seller re-encrypts only the DEK to the buyer's ECDH P-256 public key (`reencryptDekToBuyer`), producing a packed blob `sellerEphemPub(65) || iv(12) || sealed`. The buyer decrypts with `buyerDecrypt`. LoopXXI infra never receives plaintext or the DEK. This is unchanged from the live Vault.

## 7. Machine-readable discovery (agents only — NOT in the human UI)

A LoopXXI product declares Vault-capsule support at a well-known path:

```
GET https://<product-host>/.well-known/loop-vault-capsule.json
```

```jsonc
{
  "contract": "loopxxi.vault.capsule",
  "contractVersion": "1.0.0",
  "supported": true,
  "producer": true,        // emits capsules
  "consumer": false,       // ingests capsules
  "appId": "loopxxi.foundry-collector",
  "appType": "agent_outcome",
  "zero_knowledge": true,  // true ONLY if the producer never processes plaintext server-side
  "server_sees": "nothing_local_only", // or "plaintext_input" for hosted producers
  "envelope_schema_url": "https://loopxxi.com/schemas/vault-capsule-v1.json",
  "attestation": { "modes": ["poc_local", "production_server"] },
  "buyer_key_wrap": "ecdh-p256-aesgcm",
  "vault_ingest_url": "https://vault.loopxxi.com",
  "contact": "business@loopxxi.com"
}
```

For CLI/library producers with no host, the equivalent manifest ships in-repo as `vault/.well-known/loop-vault-capsule.json` and is referenced from the repo's `llms-install.md` / README so agents can discover it.

## 8. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Vault infra reads user plaintext | Only ciphertext + hashes + public keys stored. DEK wrapped under client vault key; vault key never transmitted. |
| Row/ciphertext tampering | `envelopeHash` + `userSignature` (ECDSA P-256). Any change breaks verification. |
| Forged provenance ("this came from LoopXXI") | `production_server` attestation verified against pinned server key; `poc_local` receipts carry `provenanceLevel: local_export` and never the authenticated/production label. |
| Attestation mode confusion / misspelling | Mode is an explicit allowlist (`poc_local`, `production_server`); any other value fails closed with no fallback. |
| Unverified source data sealed as "signed evidence" | The producer verifies the inner AOC's stored hash **and** owner signature (against a supplied public key) before sealing; a signed AOC with no supplied key, a corrupted hash, or a bad signature fails closed. |
| Malicious/mismatched attest server response | `production_server` responses are verified (capsuleHash == submitted envelope hash, pinned key match, signature under pinned key) before the capsule is emitted. |
| Quality inflation / lying about shape | Receipt recomputed by buyer from decrypted payload; signed by server; tamper on either side fails. |
| Private key exfiltration into server metadata | Only public keys, signatures, and wrapped (encrypted) DEK ever leave the client. Enforced by conformance test §9. |
| DEK leak on sale | DEK re-wrapped to buyer ECDH key locally; infra sees only the packed blob. |
| False "zero-knowledge" marketing | §2/§7 forbid `zero_knowledge: true` for any server-side plaintext processor. |

Out of scope for v1: metadata-timing correlation, buyer collusion after legitimate decrypt, and legal sufficiency of any sale (the contract explicitly claims none).

## 9. Conformance

An implementation is conforming if, for the fixtures in `vault/fixtures/`:

1. `enc.ciphertext` decrypts to the sealed v3 payload using the client vault key.
2. `payloadHash == sha256(sealedPayload)` and `ciphertextHash == sha256(enc.ciphertext)`.
3. `envelopeHash == sha256(canonicalJson(signedEnvelope))` and `userSignature` verifies under `userPublicKey`.
4. `attestation.mode` is in the allowlist; `attestation.capsuleHash == envelopeHash`; the attestation signature verifies under its mode's rules; and `provenanceLevel` is consistent with `mode` (`poc_local` ⇒ `local_export`; `authenticated_session` ⇒ `production_server`).
5. The recomputed quality receipt deep-equals `qualityReceipt`.
6. **No plaintext, no DEK, and no private key** appears anywhere in the capsule object (regex + structural scan). This is the privacy gate.
7. **Inner-source integrity (producer-side, pre-seal):** before sealing, the producer recomputes the source AOC body hash, confirms it equals the stored `provenance.capsule_hash`, and verifies the owner signature under a **supplied** public key. Missing key, corrupted hash, or bad signature ⇒ refuse to seal.

## 10. Versioning & migration

- `contractVersion` is semver. **v1.x is additive only**: new optional fields may be added; existing field names, hash inputs, and canonicalization are frozen.
- A consumer MUST reject a capsule whose major `contractVersion` it does not implement.
- Breaking changes require `contractVersion` `2.0.0` and a new `envelope_schema_url`. Producers SHOULD keep emitting the highest v1 their consumers accept until a coordinated cutover.
- `sealed payload schemaVersion` (currently 3) versions the *plaintext* layout independently; consumers fall back per `parseSealedPayload`.
- Attestation `mode` and the pinned production key may rotate via `VITE_LOOP_ATTEST_PUBLIC_SPKI` without a contract bump (key rotation is not a schema change).

---

*Contact for this contract: business@loopxxi.com. No personal identifiers on any public surface.*
