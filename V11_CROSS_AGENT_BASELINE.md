# V11 — Cross-Agent Content Baseline

## Summary

Tex now evaluates outbound content against a **tenant-scope** content
baseline, not just a per-agent one. Every PERMITted action contributes
a deterministic 64-band MinHash signature to a per-tenant, per-action-
type ring buffer. On every subsequent evaluation, the behavioral
stream computes the candidate content's similarity to that buffer and
folds two new signals into its result:

- **`tenant_novel_content`** — outbound content is semantically far
  from anything any agent in the tenant has previously released
  authorized on this action_type.
- **`tenant_novel_recipient_domain`** — recipient domain is unseen
  tenant-wide for this action_type.

This is the cross-agent layer the rest of the market is missing.
Zenity and Noma's "stateful threat engine" tracks tool-call sequences
across users and sessions; their behavioral primitives operate on
*how the agent moves*, not *what content it actually emits*. V11 is
the first system to ask "no agent in your tenant has ever emitted
content like this — should this action go through?" at the moment
of release, and to answer that as a peer evidence stream in the
same fusion event that produces the verdict.

## Why this is different from per-agent behavioral baselines

The V10 behavioral evaluator answered: "is this action consistent
with how *this agent* has behaved?" That catches drift, hijack, and
prompt injection that produces tool-use patterns the agent has never
produced before. It does not catch content drift that is *new for
the agent but normal for the tenant*, and it does not catch content
that is *new for the entire tenant even though normal for this agent*
— the second case being the more dangerous one because it is the
shape of fleet-wide compromise.

V11 closes both gaps at once because the tenant baseline is a peer
to the per-agent baseline. The behavioral signal now captures both
lenses in one signal, with no architectural seam.

## What changed

### Domain layer
- **`tex.domain.tenant_baseline`** — new module. Defines the
  deterministic 64-band MinHash signature scheme
  (`compute_content_signature`), the persisted record
  (`ContentSignatureRecord`), and the lookup result
  (`TenantContentBaselineLookup`). The signature is a pure function
  of normalized content, dependency-free, identical across
  processes / machines / Python versions.
- **`tex.domain.agent.AgentIdentity`** — gains `tenant_id: str`
  (default `"default"`). Lowercase-normalized at validation time.
  Backwards compatible: pre-V11 agents and tests continue to work
  by falling into the `"default"` tenant.
- **`tex.domain.agent_signal.BehavioralSignal`** — gains four new
  fields with safe defaults: `tenant_sample_size`, `tenant_cold_start`,
  `tenant_novelty_score`, `tenant_recipient_novel`. Existing
  consumers of the signal (router, fingerprint, decision builder)
  continue to work without modification.
- **`tex.domain.determinism`** — fingerprint is extended with a
  tenant signature line, but only inside the existing
  `agent_present=True` branch. The legacy contract — a request with
  no `agent_id` reproduces the pre-agent-fusion fingerprint exactly —
  continues to hold.

### Engine layer
- **`tex.agent.behavioral_evaluator.AgentBehavioralEvaluator`** —
  accepts an optional `tenant_baseline` reader. When wired, it
  computes the candidate content's signature, looks it up against
  the tenant buffer, and folds tenant-scope signals into the
  existing deviation-component / finding / uncertainty-flag shape.
  When not wired, the evaluator behaves identically to V10.
- **`tex.agent.suite.AgentEvaluationSuite`** — accepts an optional
  `tenant_baseline`, threads it into the behavioral evaluator at
  construction time.

### Stores
- **`tex.stores.tenant_content_baseline`** — new module.
  `InMemoryTenantContentBaseline` is a thread-safe per-(tenant,
  action_type) ring buffer with bounded memory. Tracks recent
  signatures plus per-action-type recipient-domain counts. Exposes
  `append`, `lookup`, `count_for`, `recipient_domains_for`,
  `list_for`, `total_count`.

### Application layer
- **`tex.commands.evaluate_action.EvaluateActionCommand`** — accepts
  optional `agent_registry` and `tenant_baseline` parameters.
  Writes one signature record to the tenant baseline after every
  PERMITted, agent-attached decision. Writes are deliberately gated
  on PERMIT so the baseline represents *normal authorized output*,
  not *every output the agent ever attempted*.

### API layer
- **`tex.api.tenant_routes`** — new module.
  `GET /v1/tenants/{tenant_id}/baseline` returns a summary of
  per-action-type sample counts and recipient-domain counts.
  Buyers and operators use this to see "how much has Tex learned
  about normal output for this tenant" — useful for both demos and
  for deciding when the baseline is mature enough to lean on.
- **`tex.api.agent_routes`** — `RegisterAgentRequest` and `AgentDTO`
  now carry `tenant_id` so the field round-trips through the
  registration and fetch endpoints.

### Runtime
- **`tex.main.TexRuntime`** — composition root now builds and
  exposes `tenant_baseline`, attaches it to FastAPI app state
  alongside `agent_registry` and `action_ledger`, and threads it
  through the agent suite and the evaluate-action command.

## Backwards-compatibility contract

Three properties hold:

1. **No agent: bit-for-bit fingerprint reproduction.** A request
   with `agent_id=None` produces the same `determinism_fingerprint`
   whether or not V11 is wired in, and that fingerprint is identical
   to what pre-V10 Tex produced.
   Verified by `test_no_agent_request_fingerprint_unchanged_by_v11`.

2. **Agent present, baseline empty: identical fingerprints across
   reruns of the same inputs.** With `agent_id` set but no tenant
   data yet, two evaluations of the same request produce the same
   fingerprint. The tenant signature line is stable for cold-start.
   Verified by
   `test_agent_request_with_no_tenant_data_reproduces_v10_fingerprint_for_same_inputs`.

3. **All V10 tests pass unchanged.** 259 pre-V11 tests continue to
   pass with zero modifications.

## Test coverage

- 259 pre-V11 tests: all passing (zero regressions).
- 34 new V11 tests: all passing.
- Total: **293 passing, 0 failing.**

New test categories:

- Content signature math (determinism, similarity, edge cases)
- Tenant baseline store (cold-start, isolation across tenants and
  action_types, ring-buffer cap, recipient-domain tracking,
  normalization)
- Behavioral evaluator integration (neutral when not wired,
  cold-start uncertainty, finding fires on novel content, finding
  does NOT fire on familiar content, recipient novelty, thin
  baseline does not escalate)
- Suite plumbing (optional baseline parameter, tenant fields
  populated correctly)
- Command write-through (PERMIT writes baseline, FORBID/ABSTAIN do
  not, no agent_id does not write)
- PDP integration (end-to-end evaluation with the baseline live)
- Backwards compatibility (no-agent fingerprint identity, repeat
  determinism)
- API (tenant_id round-trip on register/get, baseline endpoint
  empty / after evaluation / cross-tenant isolation)

## Files added

```
src/tex/api/tenant_routes.py
src/tex/domain/tenant_baseline.py
src/tex/stores/tenant_content_baseline.py
tests/test_tenant_content_baseline.py
V11_CROSS_AGENT_BASELINE.md
```

## Files modified

```
src/tex/agent/behavioral_evaluator.py    # tenant baseline lookup + folding
src/tex/agent/suite.py                   # optional tenant_baseline parameter
src/tex/api/agent_routes.py              # tenant_id round-trip on DTOs
src/tex/commands/evaluate_action.py      # write-on-PERMIT to tenant baseline
src/tex/domain/agent.py                  # AgentIdentity.tenant_id field
src/tex/domain/agent_signal.py           # BehavioralSignal tenant fields
src/tex/domain/determinism.py            # fingerprint folds tenant signature
src/tex/main.py                          # composition root wires baseline
```

## Pitch for the change

V10 made Tex the first product to evaluate the agent and its content
in one fused event with no posture-runtime seam. V11 adds the lens
nobody in the market has: **content novelty at tenant scope**.

The runtime decision is now informed by:

- who the agent is (identity)
- what it is authorized to do (capability)
- how it has behaved (per-agent behavioral)
- **how the entire tenant has behaved on this action_type
  (cross-agent content baseline)**
- what is in the policy
- what the deterministic gate flagged
- what the specialist judges scored
- what the semantic analyzer scored

Every decision is one composite question with one fingerprint, one
chain, one verdict. Competitors who do agent posture, capability, or
behavioral monitoring still run their checks upstream as separate
systems and try to reconcile across the seam. Tex has no seam — and
now also has the cross-agent content lens those systems cannot offer
at all because their behavioral primitives never look at content.
