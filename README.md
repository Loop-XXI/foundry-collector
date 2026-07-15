# @loop-xxi/foundry-collector

A local, dependency-free Node.js tool that transforms agent execution traces into signed, privacy-reviewed **Agent Outcome Capsules**.

## What it does

The collector takes a JSON trace or API probe result as input and produces:

1. A **signed capsule** conforming to the [Agent Outcome Capsule schema](schemas/agent-outcome-capsule.schema.json).
2. A **redaction report** documenting all secrets, PII, and chain-of-thought content removed.

The capsule captures: a real task, an execution failure, observable evidence, an intervention, a verified before/after outcome, provenance, and a scoped license. It excludes raw secrets, personal data, and chain-of-thought reasoning.

## Key properties

- **No external dependencies.** Runs on Node.js >= 18 using only built-in modules.
- **No data transmitted.** The collector runs entirely locally. It never sends data to Loop XXI or any third party.
- **Automatic redaction.** Scans for API keys, Bearer tokens, BOLT11 invoices, preimages, macaroons, private keys, passwords, connection strings, email addresses, phone numbers, SSNs, credit card numbers, IP addresses, and chain-of-thought markers. Replaces them with `[REDACTED:type]` markers.
- **Cryptographic provenance.** Computes SHA-256 source and capsule hashes. Signs with Ed25519 or P-256 (ECDSA).
- **Verifiable.** Anyone with the public key can verify the capsule signature without contacting Loop XXI.
- **Redaction report.** Every removed item is documented with type, severity, path, and a truncated preview. No actual secret values are included in the report.
- **Optional Sentry integration.** Set `FOUNDRY_SENTRY_DSN` to report collector errors (not capsule data) to Sentry with correlation IDs.

## Installation

```bash
# No npm install needed — it has zero dependencies.
# Just clone and run.
git clone https://github.com/Loop-XXI/foundry-collector.git
cd foundry-collector

# Or copy the single file:
cp foundry-collector.mjs /your/project/
```

## Usage

### Generate a keypair (one-time)

```bash
node foundry-collector.mjs -g keypair.json -a ed25519
```

### Collect a trace into a capsule

```bash
node foundry-collector.mjs \
  -i trace.json \
  -o capsule.json \
  -r redaction-report.json \
  -k keypair.json
```

Or via stdin:

```bash
cat trace.json | node foundry-collector.mjs -o capsule.json -k keypair.json
```

### Verify a capsule signature

```bash
node foundry-collector.mjs -v -i capsule.json -p public-key.pem
```

## Input format

The input is a JSON object with the following fields:

```json
{
  "capsule_id": "AOC-MYINCIDENT",
  "owner": {
    "owner_id": "my-company",
    "owner_type": "business",
    "custody_mode": "owner_retained",
    "public_name": "My Company LLC"
  },
  "environment": {
    "domain": "agent-payment-infrastructure",
    "agent_architecture": "Python HTTP agent",
    "model_family": "claude",
    "tool_classes": ["HTTP", "L402"]
  },
  "task": {
    "task_class": "paid-route-discovery-validation",
    "objective": "Test discovery compatibility of a paid endpoint.",
    "success_criteria": ["GET returns 402", "Token passes validator"]
  },
  "failure": {
    "taxonomy": "payment_challenge",
    "decisive_step": 1,
    "observable_evidence": ["Directory classified service as degraded"],
    "severity": "high"
  },
  "intervention": {
    "intervention_class": "token-format-fix",
    "change_summary": "Switched to base64url encoding.",
    "version_reference": "abc123def"
  },
  "outcome": {
    "before": {"status": "degraded"},
    "after": {"status": "healthy"},
    "success_verified": true,
    "verification_method": "counterfactual_run"
  },
  "raw_data": {
    "probe_request": {"method": "GET", "url": "https://example.com/api"},
    "probe_response": {"status": 402, "body": {"token": "..."}}
  },
  "license": {
    "license_id": "MY-LICENSE-0.1",
    "allowed_uses": ["evaluation", "regression_testing"],
    "prohibited_uses": ["resale", "unlicensed_model_training"],
    "term": "12 months",
    "revocation_applies_to_future_access": true
  }
}
```

The `raw_data` field is scanned and redacted. Its hash is recorded as `source_hash` in the provenance. The redacted version is included in the capsule body for transparency, but with all secrets replaced by `[REDACTED:type]` markers.

## Output

### Capsule

A JSON object conforming to `schemas/agent-outcome-capsule.schema.json` with:

- `capsule_id`: Unique identifier
- `schema_version`: `0.1.0`
- `owner`: Custody and identity info
- `rights`: Ownership attestation and collection basis
- `provenance`: Source hash, capsule hash, transformation log, and cryptographic signature
- `environment`: Domain, architecture, model, tools
- `task`: Objective and success criteria
- `failure`: Taxonomy, evidence, severity
- `intervention`: What was changed and why
- `outcome`: Before/after state and verification method
- `quality`: Completeness, reproducibility, novelty scores
- `privacy`: Scan results and redaction summary
- `license`: Allowed/prohibited uses, term, territory

### Redaction report

A JSON object documenting:

- Total secret/PII/CoT findings
- Per-finding: type, severity, JSON path, truncated preview
- Privacy assessment (pass/review/fail for secrets and PII)

## Redaction patterns

### Secrets (critical/high severity)

`sk_*` API keys, generic API key assignments, Bearer tokens, Authorization headers, L402 tokens, BOLT11 invoices, 64-char hex preimages, macaroons, PEM private keys, hex private keys, seed phrases/mnemonics, Stripe webhook secrets (`whsec_*`), GitHub tokens (`ghp_*`/`ghs_*`/etc.), password assignments, database connection strings.

### PII (low/medium/high severity)

Email addresses, phone numbers, SSNs, credit card numbers, IPv4 addresses, street addresses.

### Chain-of-thought

Markers like "let me think", "step 1:", `<thinking>` tags, and similar LLM reasoning artifacts.

## License

MIT. Copyright (c) 2026 Loop XXI LLC.
