# LoopXXI Vault-Capsule Rollout Sequence

Ship the shared contract + one real integration (Foundry Collector — done in this pass), then roll out the rest in ROI order. Each phase has an explicit **kill condition**: if it trips, stop that phase and do not spend further credits on it.

## Prioritized sequence

### Phase 1 — Foundry Collector (DONE this pass)
Exporter `vault/foundry-vault-export.mjs`, contract v1.0.0, schema, fixtures, 12 conformance tests, discovery manifest. Proven with synthetic data end-to-end.
- **Kill condition:** if no Foundry AOC is ever produced by a real owner within 30 days, deprioritize Foundry vaulting and move evidence-vaulting effort to Settlement Probe.

### Phase 2 — Settlement Probe / Agent Revenue Readiness Audit evidence
Wrap the Ed25519-signed settlement receipts + audit findings into Vault capsules. Highest compounding trust value after Foundry; shares a signing identity already published in `verifier.json`.
- **Why next:** signed settlement/audit evidence is the scarcest, most buyer-relevant artifact LoopXXI produces, and it is the current paid deliverable.
- **Kill condition:** if the first external audit engagement does not want a verifiable evidence capsule (i.e. buyers don't value the vaulted artifact), stop and re-evaluate before building the Audit adapter.

### Phase 3 — loop-subagent delegation attestations
Vault macaroon-delegation *structure* (caveats, budget caps) as provenance capsules — never the macaroon secret.
- **Kill condition:** if delegation records cannot be summarized without leaking the macaroon root or per-agent secrets, do not integrate.

### Phase 4 — loop-mcp call-outcome evidence
Signed "which tool ran, result shape, settled" evidence (tokens/preimages redacted).
- **Kill condition:** if redaction cannot guarantee zero payment-secret leakage in high-volume call logs, stop.

### Deferred / breadth-only (low compounding value)
AgentReady (public-data, easy but low value), LightLink / bolt12-tools / satsledger / satsper (low sensitivity, low value). Do these only if a specific buyer asks.

### Gated out of scope for now
- **loop-microloan** and **SpeedSpend**: financial + custody + multi-tenant sensitivity. **Hard kill** under this initiative's constraints (no custody, no new legal terms, no real financial obligation). Revisit only with an explicit legal review.
- **Loop Gateway prompt content**: never vaultable (server sees plaintext + keys). Only usage/settlement summaries, and only if a buyer wants them.

## Global kill conditions (stop the whole rollout)
- Any capsule is found to contain plaintext, a DEK, or a private key on a public/server surface → halt, fix the leak, re-audit before resuming.
- Any product would need to falsely advertise `zero_knowledge:true` to justify integration → do not integrate it that way.
- A Founder personal identifier appears on any public surface → halt and remediate immediately.
- Cumulative spend approaches the initiative's credit ceiling → stop and report.

## Next three high-ROI implementation tasks
1. **Settlement Probe exporter** (`settlement-probe/vault/probe-vault-export.mjs`): reuse `foundry-vault-export.mjs` primitives verbatim; map a signed receipt into the sealed v3 payload; add its `.well-known/loop-vault-capsule.json` (`producer:true, zero_knowledge:false` because the probe reads a target route). Reuses this pass's contract with zero schema change.
2. **Vault consumer/import path**: add a `consumer` code path in the live Vault so a capsule sealed by any producer (Foundry today) can be imported and listed via existing `lv_capsules`/`lv_listings`, wiring the buyer-key rewrap to the exporter's identical envelope. (No new format — same primitives.)
3. **Publish the two discovery surfaces**: host `vault-capsule-v1.schema.json` at `loopxxi.com/schemas/vault-capsule-v1.json` and add a `vault_capsule` capability entry to public `products.json` so agents can discover, per product, whether it emits/ingests capsules — machine-readable only, not in any human UI.
