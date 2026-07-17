# Fixtures

Synthetic, non-sensitive fixtures for the Vault-capsule conformance suite.

- `synthetic-trace.json` — a fully synthetic agent trace (no secrets, no PII).
- `synthetic-aoc.json` — the signed Agent Outcome Capsule produced from it by `foundry-collector.mjs`.
- `synthetic-redaction.json` — the collector's redaction report (all scans pass).
- `synthetic-vault-capsule.json` — the sealed `loopxxi.vault.capsule` v1.0.0 envelope.

Key material is intentionally NOT committed. The conformance suite
(`../foundry-vault-export.test.mjs`) seals with an ephemeral passphrase at test
time, so no vault key or signing private key is ever stored in the repo.
Regenerate the capsule locally with:

    node ../foundry-vault-export.mjs -i synthetic-aoc.json -o synthetic-vault-capsule.json \
      --key-out /tmp/keys.json --passphrase '<your passphrase>'

(`/tmp/keys.json` stays on your machine; never commit it.)
