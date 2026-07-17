# Foundry Collector → LoopXXI Vault

This directory adds an **optional Vault mechanism** to Foundry Collector: a human or
agent that produces a signed Agent Outcome Capsule (AOC) can seal it into an
encrypted, user-controlled **Vault capsule** that is byte-compatible with the
live LoopXXI Vault at https://vault.loopxxi.com.

## What's here

| File | Purpose |
|---|---|
| `VAULT-CAPSULE-CONTRACT.md` | The versioned interoperability contract (v1.0.0). Reuses the live Vault envelope, attestation, quality-receipt, and buyer-key-wrap primitives. |
| `vault-capsule-v1.schema.json` | JSON Schema for the capsule envelope. |
| `foundry-vault-export.mjs` | The exporter: signed AOC → `loopxxi.vault.capsule` v1.0.0. Dependency-free. |
| `foundry-vault-export.test.mjs` | 12-case conformance suite (seal, verify, tamper, privacy gate, buyer decrypt). |
| `.well-known/loop-vault-capsule.json` | Machine-readable discovery manifest (agents only; not in the human UI). |
| `COMPATIBILITY-MATRIX.md` | Audit of all first-party apps and Vault-integration priority. |
| `ROLLOUT.md` | Prioritized rollout sequence with explicit kill conditions. |
| `fixtures/` | Synthetic, non-sensitive test fixtures. |

## Quick start

```bash
# 1. Produce a signed AOC from a trace (existing collector)
node foundry-collector.mjs -i trace.json -o aoc.json

# 2. Seal it into a Vault capsule (client-held key; nothing transmitted)
node vault/foundry-vault-export.mjs -i aoc.json -o capsule.json \
  --key-out keys.json --passphrase '<your passphrase>'

# 3. Verify (envelope, signature, attestation, buyer decrypt, leak scan)
node vault/foundry-vault-export.mjs -i capsule.json --verify \
  --passphrase '<your passphrase>' --salt "$(jq -r .saltB64 keys.json)"
```

## Privacy boundary (honest)

Foundry Collector runs entirely on the owner's machine and redacts
secrets/PII/chain-of-thought before output — so this producer is genuinely
**zero-knowledge with respect to LoopXXI Vault infrastructure**: the Vault only
ever sees the opaque envelope (ciphertext + hashes + public keys + signature).
This is **not** a claim that every LoopXXI app is zero-knowledge — hosted
services that must process user input server-side advertise
`server_sees: "plaintext_input"` in their discovery manifest.

The exporter never writes plaintext, the DEK, or any private key into the
capsule; key material is returned out-of-band via `--key-out` only.

Contact: business@loopxxi.com
