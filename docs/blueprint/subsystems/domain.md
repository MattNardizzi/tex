# Subsystem Dossier: `domain` — Core Types

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/domain/` (23 `.py` files).
> Branch: `feat/proof-carrying-gate`. All claims below are code-verified; any
> claim sourced only from a docstring/markdown is labelled **(claim, unverified)**.

---

## Overview

`tex.domain` is the **shared vocabulary** of the whole system: the frozen,
validated, persistable data types that every other layer speaks. It is the
most-imported package in the codebase. Verified importer counts (this branch):

- **188** `.py` files under `src/tex/` import `tex.domain` (excluding the
  package itself: **175**). Counting tests and tooling repo-wide: **315–318**
  files reference `tex.domain`. The "389 importers" figure in the task brief
  is **(claim, unverified)** — I measure 315–318 referencing files / 175
  non-domain `src` importers; either way it is by a wide margin the most
  imported package. (Verified via `grep -rEl "from tex\.domain|import tex\.domain"`.)

The package is almost entirely **pure data**: Pydantic v2 `BaseModel`s with
`model_config = ConfigDict(frozen=True, extra="forbid")`, strict
field/model validators, timezone-aware datetimes, and small `StrEnum`/`IntEnum`
value objects. There is no HTTP, no DB driver, no model-provider code in the
data models. Three modules are exceptions that import *out* into other layers
(`determinism.py`, `asi_builder.py`, `calibration_proposal.py`); see
[Wiring Out](#wiring-out).

The single most important design decision lives in `evidence.py`: the
`TexEvidence` / `CombinedEvidence` types and the `compose_*` e-value spine.
These encode statistical-honesty *invariants in the type itself* — a producer
cannot declare a Ville-bounded e-value over an object that does not carry the
bound. This is real, executable logic (verified below), not a docstring claim.

The vocabulary partitions cleanly into the four-layer Tex loop:

| Loop stage | Domain types |
|---|---|
| **Decide** (verdict surface) | `Verdict`, `EvaluationRequest`, `EvaluationResponse`, `Decision`, `Finding`, `Severity`, `LatencyBreakdown`, `PolicySnapshot` |
| **Prove** (evidence/receipts) | `EvidenceRecord`, `TexEvidence`, `CombinedEvidence`, `compose_*`, `AbstentionCertificate` |
| **Discover** (agent inventory) | `CandidateAgent`, `DiscoverySource`, `ReconciliationOutcome`, `DiscoveryLedgerEntry`, `SignalTrustTier`, `AgentIdentity`, `CapabilitySurface` |
| **Learn** (calibration/outcomes) | `OutcomeRecord`, `OutcomeTrustLevel`, `CalibrationProposal`, `TenantContentBaselineLookup` |
| **Agent governance signals** | `AgentIdentitySignal`, `CapabilitySignal`, `BehavioralSignal`, `AgentEvaluationBundle`, `BehavioralBaseline`, `ActionLedgerEntry` |
| **Risk taxonomy** | OWASP ASI 2026 mapping (`owasp_asi.py`, `asi_finding.py`, `asi_builder.py`) |

---

## File Inventory

| File | Lines | Role |
|---|---:|---|
| `__init__.py` | 11 | Layer marker only (`__layer_kind__ = 'cross_cutting_domain'`); no re-exports. |
| `verdict.py` | 72 | `Verdict` StrEnum (PERMIT/ABSTAIN/FORBID) — the terminal decision surface; `allows_release`/`requires_human_review`/`blocks_release`/`from_str`. |
| `severity.py` | 84 | `Severity` StrEnum (INFO/WARNING/CRITICAL) + `SeverityScore` IntEnum + `_SEVERITY_RANK`; `max()`, `rank`. |
| `finding.py` | 109 | `Finding` model — one structured detection (source, rule, severity, span); `is_blocking`, `has_span`. |
| `latency.py` | 51 | `LatencyBreakdown` model — per-stage wall-clock ms; `dominant_stage`. |
| `decision.py` | 244 | `Decision` — the durable, immutable decision record (the internal canonical record). |
| `evaluation.py` | 394 | `EvaluationRequest` (public input), `EvaluationResponse` (public output), `AgentRuntimeIdentity`. |
| `policy.py` | 439 | `PolicySnapshot` — immutable versioned policy config; fusion weights, thresholds, criticality maps; `_DEFAULT_FUSION_WEIGHTS`. |
| `agent.py` | 604 | Agent governance models: lifecycle/trust/env enums, `CapabilitySurface`, `AgentAttestation`, `AgentIdentity`, `ActionLedgerEntry`, `BehavioralBaseline`. |
| `agent_signal.py` | 342 | Stream results: `AgentIdentitySignal`, `CapabilitySignal`, `BehavioralSignal`, `AgentEvaluationBundle`. |
| `evidence.py` | 868 | `EvidenceRecord` (audit envelope) + `TexEvidence`/`CombinedEvidence` (e-value snapshots) + `compose_arithmetic_mean`/`compose_product_independence`/`compose_spine`. **The statistical-honesty core.** |
| `retrieval.py` | 367 | `RetrievedPolicyClause`, `RetrievedPrecedent`, `RetrievedEntity`, `RetrievalContext` (grounding context). |
| `outcome.py` | 259 | `OutcomeKind`, `OutcomeLabel`, `OutcomeRecord` (post-decision result for the learning loop); `classify`/`create`. |
| `outcome_trust.py` | 110 | `OutcomeTrustLevel`, `OutcomeSourceType`, `VerificationMethod` — calibration trust hierarchy with per-tier weights. |
| `discovery.py` | 525 | Discovery models: `DiscoverySource`, `DiscoveryFindingKind`, `DiscoveryRiskBand`, `ReconciliationAction`, `DiscoveredCapabilityHints`, `CandidateAgent`, `ReconciliationOutcome`, `DiscoveryLedgerEntry`, `DiscoveryScanRun`. |
| `signal_trust.py` | 136 | `SignalTrustTier` IntEnum (tamper-resistance grade of a discovery signal) + `tier_for_source`. |
| `tenant_baseline.py` | 323 | MinHash content signature functions + `ContentSignatureRecord` + `TenantContentBaselineLookup` (V11 tenant content baseline). |
| `owasp_asi.py` | 260 | OWASP ASI 2026 taxonomy constants + signal→category mapping tables + lookup helpers. |
| `asi_finding.py` | 212 | `ASITrigger`, `ASIFinding`, `ASITriggerSource`, `ASIVerdictInfluence` — structured ASI findings on a response. |
| `asi_builder.py` | 304 | `build_asi_findings(...)` — pure builder turning pipeline artifacts into `ASIFinding`s. **Imports OUT.** |
| `abstention_certificate.py` | 252 | `AbstentionTrigger`, `AbstentionJustification`, `NonWeaponizationWitness`, `AbstentionCertificate` — descriptive ABSTAIN receipt. |
| `calibration_proposal.py` | 185 | `ProposalStatus`, `ProposalDiff`, `CalibrationProposal` — pending threshold change with lifecycle. **Imports OUT.** |
| `determinism.py` | 150 | `compute_determinism_fingerprint(...)` + `fingerprint_components(...)`. **Imports OUT.** |

Total: 23 files, ~6,160 lines.

---

## Internal Architecture

### The verdict surface (Decide)

- **`Verdict`** (`verdict.py:6`) — a 3-member `StrEnum`. Behaviour-by-property:
  `allows_release` (PERMIT), `requires_human_review` (ABSTAIN),
  `blocks_release` (FORBID); `from_str` (`verdict.py:58`) normalizes external
  input case-insensitively. Deliberately minimal ("stays small on purpose").
- **`Severity`** (`severity.py:6`) — INFO/WARNING/CRITICAL with a separate
  `SeverityScore` IntEnum (`severity.py:68`) and `_SEVERITY_RANK` map
  (`severity.py:81`) so the human-readable string enum and the ordering stay
  decoupled. `Finding.is_blocking` (`finding.py:104`) == `severity.is_critical`.
- **`Finding`** (`finding.py:8`) — frozen detection record. Validator
  `validate_index_order` (`finding.py:79`) enforces start/end span integrity
  (both-or-neither, end>start). This is the atom carried up by every layer.
- **`EvaluationRequest`** (`evaluation.py:118`) — canonical input. `request_id`
  is required and first-class ("must enter the system at the edge"); content is
  bounded to 50 000 chars; `action_type`/`channel`/`environment` lower-cased.
  Optional agent context (`agent_id`, `session_id`, `agent_identity`) is the
  backwards-compatible hook for agent fusion. `AgentRuntimeIdentity`
  (`evaluation.py:16`) carries a `fingerprint_hash` property (SHA-256 over a
  stable key, `evaluation.py:113`).
- **`EvaluationResponse`** (`evaluation.py:230`) — public output. Carries
  verdict, confidence, fused score, findings, ASI findings, optional
  `determinism_fingerprint`, optional `abstention_certificate`, optional
  `latency`, and `replay_url`/`evidence_bundle_url`. `model_validator`
  (`evaluation.py:377`) enforces "ABSTAIN ⇒ at least one uncertainty flag".
- **`Decision`** (`decision.py:15`) — the durable internal record (distinct from
  the transport DTO). Stricter: `content_sha256` must be 64-hex
  (`decision.py:148`), scores bounded (`decision.py:166`), and a cross-field
  `validate_verdict_consistency` (`decision.py:214`): ABSTAIN requires an
  uncertainty flag, FORBID requires non-zero risk/findings/reasons. Convenience
  properties `is_permit`/`is_abstain`/`is_forbid`/`blocking_findings`.

### Policy (`policy.py`)

`PolicySnapshot` (`policy.py:44`) is the tunable config snapshot. Two
load-bearing constants:

- `_ALLOWED_FUSION_KEYS` (`policy.py:11`) — the 7 fusion axes
  (deterministic, specialists, semantic, criticality, agent_identity,
  agent_capability, agent_behavioral).
- `_DEFAULT_FUSION_WEIGHTS` (`policy.py:33`) — the default 7-way weights,
  summing to 1.0. `model_validator` (`policy.py:258`) enforces
  `permit_threshold < forbid_threshold` and `|Σ weights − 1.0| ≤ 1e-6`.

Behaviour: `criticality_for(...)` (`policy.py:272`) averages action/channel/
environment criticality (missing → 0.0, no hidden fallback);
`blocks_severity` (`policy.py:306`); `ordered_fusion_weights` (`policy.py:312`)
returns weights in stable sorted-key order for the engine.

> Note: `_DEFAULT_FUSION_WEIGHTS` is imported directly by
> `engine/credal_hold.py:95` — a private symbol crossing the package boundary.

### Agent governance (`agent.py`, `agent_signal.py`)

`agent.py` holds the registry-side records:

- Enums: `AgentLifecycleStatus` (`agent.py:32`, with `forces_abstain`/
  `forces_forbid`/`is_reversible` behaviour — SLEEPING/QUARANTINED force
  ABSTAIN, REVOKED forces FORBID), `AgentTrustTier` (`agent.py:94`, with
  `baseline_risk_contribution`/`baseline_confidence` lookup tables),
  `AgentEnvironment` (`agent.py:130`).
- `CapabilitySurface` (`agent.py:149`) — declared allow-lists with real
  matching logic: `permits_action_type`/`permits_channel`/`permits_environment`/
  `permits_recipient` (`agent.py:202`–`245`). `permits_recipient` parses a
  domain out of an email/URL/bare string and matches suffixes — genuine logic.
- `AgentIdentity` (`agent.py:309`), `AgentAttestation` (`agent.py:253`),
  `ActionLedgerEntry` (`agent.py:422`, one immutable row per agent decision),
  `BehavioralBaseline` (`agent.py:531`, "never stored — computed at eval time").
- Shared helper `_normalize_lowercase_string_tuple` (`agent.py:583`) dedupes/
  casefolds string-tuple fields and rejects plain-string inputs.

`agent_signal.py` holds the three stream *results* and the bundle:
`AgentIdentitySignal` (`agent_signal.py:81`), `CapabilitySignal`
(`agent_signal.py:144`), `BehavioralSignal` (`agent_signal.py:189`, incl. the
V11 tenant-scope fields at `agent_signal.py:225`), and `AgentEvaluationBundle`
(`agent_signal.py:263`). The bundle computes `aggregate_risk_score`
(equal-weighted mean of three streams, capped 1.0, `agent_signal.py:282`) and
`aggregate_confidence` (conservative `min`, `agent_signal.py:301`).

### Evidence and the e-value spine (`evidence.py`) — the crown jewel

Two unrelated concerns share the file:

1. **`EvidenceRecord`** (`evidence.py:25`) — the *audit envelope*: an
   append-only, hash-chained record (decision_id, payload_json,
   payload_sha256, previous_hash, record_hash, policy_version). All hashes
   validated as 64-char lowercase hex (`evidence.py:96`–`126`). Note the
   docstring explicitly says chain *verification* lives in `tex.evidence.chain`,
   not here (`evidence.py:40`) — this model is the envelope only.

2. **`TexEvidence`** (`evidence.py:245`) — one immutable snapshot of a single
   evidence stream's e-value, **in log space** (`log_e_value`,
   `evidence.py:292`). It carries self-describing validity:
   `kind` (`EvidenceKind`, `evidence.py:201`: E_PROCESS / E_VALUE /
   CONFIDENCE_SEQUENCE_BOUND / CALIBRATION_CERTIFICATE), `maturity`
   (`EvidenceMaturity`, `evidence.py:227`), `is_true_e_value`,
   `sequentially_predictable`, `filtration_id`, `null_hypothesis_id`,
   `calibrator`. The **honesty invariant** is a `model_validator`
   (`_honesty_invariants`, `evidence.py:356`) that *refuses* contradictory
   over-claims at construction: a `CALIBRATION_CERTIFICATE` can never be a true
   e-value; a `CONFIDENCE_SEQUENCE_BOUND` needs an explicit `calibrator` to be
   one; an `E_PROCESS` must be `sequentially_predictable`. Derived API:
   `e_value` = `exp(log_e_value)` (`evidence.py:391`), `ville_p_value` =
   `min(1, 1/E)` **only if** `is_true_e_value` else `None`
   (`evidence.py:398`), `is_ville_significant_at(alpha)` (`evidence.py:410`).
   Sealing: `canonical_payload`/`canonical_json` (sorted keys, tight
   separators — same idiom as `provenance/ledger.py`) + `payload_sha256`
   (`evidence.py:425`–`465`).

   The combiners (`evidence.py:743`–`869`):
   - `compose_arithmetic_mean` (`evidence.py:743`) — Vovk–Wang admissible merge
     under arbitrary dependence, via numerically-stable `_log_mean_exp`
     (`evidence.py:538`).
   - `compose_product_independence` (`evidence.py:775`) — sum-of-logs product;
     **requires** a non-empty `justification` string (raises otherwise).
   - `compose_spine` (`evidence.py:820`) — the high-level entry: drops every
     non-e-value into `excluded_ids`, returns an **abstain** `CombinedEvidence`
     (log_e=0, neutral) when zero true e-values survive, else mean (default) or
     product (opt-in with justification).
   - `CombinedEvidence` (`evidence.py:600`) re-checks honesty in its own
     `model_validator` (`evidence.py:663`): `anytime_valid ⇒ is_true_e_value`;
     `abstain ⇏ e-value`; product ⇒ justification present; non-product ⇒ no
     justification. `_is_anytime_valid` (`evidence.py:572`) is True only when
     every input is a sequentially-predictable E_PROCESS on one shared
     filtration (`_shared_filtration`, `evidence.py:563`). `_weakest_maturity`
     (`evidence.py:530`) enforces weakest-link maturity.

   I executed this spine: two real E_PROCESS snapshots compose to an
   `arithmetic_mean` `CombinedEvidence` with `anytime_valid=True`,
   `log_e≈1.6201`, `ville_p≈0.1979`, and a stable `payload_sha256` — **REAL,
   executable math, not a stub.**

### Discovery (`discovery.py`, `signal_trust.py`)

`discovery.py` is the canonical discovery shape. Enums: `DiscoverySource`
(`discovery.py:45`, incl. conduit IdP sources Okta/Google/GCP/Ping and
tamper-resistant planes cloud_audit/network_egress/kernel_ebpf),
`DiscoveryFindingKind`, `DiscoveryRiskBand` (with `suggested_trust_tier`
property — never auto-promotes above STANDARD, `discovery.py:120`),
`ReconciliationAction`. Models: `DiscoveredCapabilityHints` (`discovery.py:163`),
`CandidateAgent` (`discovery.py:237`, with the load-bearing
`reconciliation_key` property = `{source}:{tenant}:{external_id}`,
`discovery.py:370`), `ReconciliationOutcome` (`discovery.py:387`),
`DiscoveryLedgerEntry` (`discovery.py:446`, the EvidenceRecord-pattern
hash-chained row), `DiscoveryScanRun` (`discovery.py:481`).

`signal_trust.py` adds an orthogonal axis: `SignalTrustTier` (`signal_trust.py:51`)
is an `IntEnum` (SELF_DECLARED=1 … KERNEL_ATTESTED=5) so `max(...)` yields the
strongest defensible grade; `is_tamper_resistant` (≥ NETWORK_OBSERVED),
`admissibility` phrasing. `_SOURCE_TIER` (`signal_trust.py:115`) maps
source-strings→tier (deliberately keyed by string to avoid an import cycle with
`discovery.py`); `tier_for_source` (`signal_trust.py:134`) defaults unknown
sources to the conservative CONTROL_PLANE.

### Learning / outcomes (`outcome.py`, `outcome_trust.py`, `calibration_proposal.py`, `tenant_baseline.py`)

- `OutcomeRecord` (`outcome.py:59`) with the static `classify(...)`
  (`outcome.py:177`) deriving an `OutcomeLabel` from (verdict, outcome_kind,
  was_safe), and a `create(...)` convenience constructor (`outcome.py:217`).
- `OutcomeTrustLevel` (`outcome_trust.py:39`) with real per-tier
  `calibration_weight` (VERIFIED=1.0, VALIDATED=0.6, else 0.0) and
  `is_calibration_eligible`; `OutcomeSourceType.baseline_trust`
  (`outcome_trust.py:77`) maps source→starting tier.
- `tenant_baseline.py` contains **real MinHash logic**:
  `compute_content_signature` (`tenant_baseline.py:97`) builds a 64-band MinHash
  over 5-char shingles using 64 fixed prime seeds (`_HASH_SEEDS`,
  `tenant_baseline.py:54`) and SHA-256 digests — fully deterministic across
  runs/processes/interpreters. `signature_jaccard_similarity`
  (`tenant_baseline.py:137`), `signature_distance`, `signature_to_hex`. The
  persistable `ContentSignatureRecord` (`tenant_baseline.py:171`) and the
  evaluator result `TenantContentBaselineLookup` (`tenant_baseline.py:256`).
- `CalibrationProposal` (`calibration_proposal.py:74`) — pending threshold
  change with a full status lifecycle enforced by `_check_lifecycle`
  (`calibration_proposal.py:112`: APPROVED/REJECTED/APPLIED/ROLLED_BACK each
  require their approver+timestamp fields) and a `build(...)` factory
  (`calibration_proposal.py:142`). Uses `arbitrary_types_allowed=True` because
  it embeds non-domain learning objects.

### ASI taxonomy (`owasp_asi.py`, `asi_finding.py`, `asi_builder.py`)

- `owasp_asi.py` — the 10 ASI-2026 category constants (`owasp_asi.py:23`–`32`),
  `ASICategoryMetadata` (`__slots__` descriptor, `owasp_asi.py:35`), the
  `_ASI_METADATA` registry, and three signal→category mapping tables
  (`_SEMANTIC_DIMENSION_TO_ASI`, `_RECOGNIZER_TO_ASI`, `_SPECIALIST_TO_ASI`)
  plus threshold-gated lookup helpers (`asi_tags_for_*`).
- `asi_finding.py` — the structured output types: `ASITrigger`
  (`asi_finding.py:55`), `ASIFinding` (`asi_finding.py:110`, with a regex
  `short_code` pattern `^ASI\d{2}$`), influence/source enums.
- `asi_builder.py` — `build_asi_findings(...)` (`asi_builder.py:63`): a **pure**
  aggregator (one finding per category, max-score severity, confidence with
  source-diversity + trigger-count bonuses, decisive/contributing/informational
  classification, plain-English counterfactual). Determinism is explicit
  (`asi_builder.py:18`) because the output feeds the determinism fingerprint.

### Determinism fingerprint (`determinism.py`)

`compute_determinism_fingerprint(...)` (`determinism.py:27`) hashes a
canonicalized `|`-joined string over content hash + policy version + sorted
deterministic firings + 2-decimal-quantized specialist/semantic scores +
(optional) agent stream signatures. `_quantize` (`determinism.py:116`) rounds
to 2 decimals so float jitter does not change the fingerprint — a deliberate
stability anchor, not a bit-for-bit hash. Agent/discovery/tenant signatures are
folded in *only* when an agent is present, preserving the legacy content-only
fingerprint exactly (`determinism.py:79`).

---

## Public API

There is **no curated re-export surface** — `__init__.py` (`domain/__init__.py`)
exposes only `__layer__`/`__layer_kind__`. Consumers import directly from
submodules (`from tex.domain.verdict import Verdict`). The de-facto public API,
ranked by verified non-domain `src` importer count:

| Symbol(s) | Module | Importers (src, non-domain) |
|---|---|---:|
| `EvaluationRequest`, `EvaluationResponse`, `AgentRuntimeIdentity` | `evaluation` | 49 |
| `Verdict` | `verdict` | 48 |
| discovery types (`CandidateAgent`, `DiscoverySource`, …) | `discovery` | 39 |
| agent types (`AgentIdentity`, `CapabilitySurface`, …) | `agent` | 35 |
| retrieval types (`RetrievalContext`, …) | `retrieval` | 29 |
| `EvidenceRecord`, `TexEvidence`, `CombinedEvidence`, `compose_*` | `evidence` | 26 |
| `PolicySnapshot` | `policy` | 25 |
| `Decision` | `decision` | 20 |
| `OutcomeRecord`, `OutcomeKind`, `OutcomeLabel` | `outcome` | 16 |
| `Finding` | `finding` | 15 |
| `Severity` | `severity` | 14 |
| trust enums | `outcome_trust` | 11 |
| ASI taxonomy | `owasp_asi` | 10 |
| `AgentEvaluationBundle`, stream signals | `agent_signal` | 7 |
| `SignalTrustTier`, `tier_for_source` | `signal_trust` | 5 |
| tenant baseline | `tenant_baseline` | 3 |
| `CalibrationProposal` | `calibration_proposal` | 3 |
| `ASIFinding`, `ASITrigger` | `asi_finding` | 3 |
| `AbstentionCertificate` (+ parts) | `abstention_certificate` | 3 |
| `LatencyBreakdown` | `latency` | 2 |
| `build_asi_findings` | `asi_builder` | 2 |
| `compute_determinism_fingerprint` | `determinism` | 1 |

Explicit `__all__` lists exist in `evidence.py` (`evidence.py:13`),
`abstention_certificate.py` (`abstention_certificate.py:55`),
`calibration_proposal.py` (`calibration_proposal.py:181`),
`outcome_trust.py` (`outcome_trust.py:106`), and `asi_builder.py`
(`asi_builder.py:302`).

---

## Wiring

### Wiring In (who consumes it, and the LIVE call path)

`wired_status = LIVE`. The domain types are on the hot path of every
evaluation. Verified end-to-end call path:

1. `create_app(...)` — `src/tex/main.py:1309`
2. → `build_runtime(...)` — `src/tex/main.py:519` — constructs
   `PolicyDecisionPoint(...)` at `src/tex/main.py:876` and the
   `EvaluateActionCommand`, mounting them on app state
   (`app.state.pdp = runtime.pdp`, `src/tex/main.py:1594`).
3. `POST /evaluate` route — `src/tex/api/routes.py:111` →
   `evaluate_action(...)` (`api/routes.py:117`) resolves the command from app
   state (`_get_evaluate_action_command`, `api/routes.py:581`).
4. → `EvaluateActionCommand.execute(EvaluationRequest)` —
   `src/tex/commands/evaluate_action.py:187` — calls
   `self._pdp.evaluate(...)` (`evaluate_action.py:214`).
5. The PDP (`src/tex/engine/pdp.py`) imports and threads the domain types
   directly: `Decision` (`pdp.py:22`), `EvaluationRequest`/`EvaluationResponse`
   (`pdp.py:24`), `PolicySnapshot` (`pdp.py:27`), `RetrievalContext`
   (`pdp.py:28`), `Verdict` (`pdp.py:29`), `AgentEvaluationBundle` (`pdp.py:20`),
   `AbstentionCertificate` (`pdp.py:19`), `build_asi_findings` (`pdp.py:21`),
   `compute_determinism_fingerprint` (`pdp.py:23`), `LatencyBreakdown`
   (`pdp.py:26`), `Finding` (`pdp.py:25`).
6. The PDP also wires the **evidence spine** in: it imports
   `RiskSpine, apply_risk_spine` (`pdp.py:52`) and calls `apply_risk_spine(...)`
   at `pdp.py:423`. `engine/risk_spine.py:307` calls `compose_spine(...)`. So
   `TexEvidence`/`CombinedEvidence`/`compose_*` are reachable from the live PDP,
   not just tests.

The router (`engine/router.py:8`–`13`), CRC gate (`engine/crc_gate.py:97`),
hold (`engine/hold.py:53`), risk spine (`engine/risk_spine.py:98`), contract
bridge, and dozens of API routes (`agent_routes.py`, `discovery_routes.py`,
`provenance_routes.py`, `learning_routes.py`, etc.) consume domain types. The
provenance verifier (`provenance/bundle.py:62`) re-runs `compose_arithmetic_mean`
/`compose_product_independence` to re-check a sealed composition offline —
confirming the spine is an externally-replayable contract.

`main.py` itself imports `EvaluationRequest` (`main.py:66`), `PolicySnapshot`
(`main.py:67`), retrieval types (`main.py:68`), and lazily
`AgentLifecycleStatus` (`main.py:1090`) and `DiscoverySource` (`main.py:1618`).

### Wiring Out (what domain depends on)

The data models depend only on **`pydantic` v2** and the **Python stdlib**
(`hashlib`, `json`, `math`, `re`, `datetime`, `enum`, `uuid`, `typing`,
`collections.abc`). Internal intra-package edges:
`decision`→`{asi_finding, finding, latency, verdict}`,
`evaluation`→`{abstention_certificate, asi_finding, finding, latency, verdict}`,
`policy`/`finding`→`severity`, `outcome`→`{outcome_trust, verdict}`,
`discovery`→`agent`, `agent_signal`→`finding`, `retrieval`→`verdict`,
`abstention_certificate`→`verdict`.

**Three modules break the "leaf" rule and import OUT into higher layers**
(verified — these create domain→engine/learning/semantic/specialists edges):

- `determinism.py:21,23,24` — imports `tex.deterministic.gate`,
  `tex.semantic.schema`, `tex.specialists.base`, and
  `tex.domain.agent_signal`.
- `asi_builder.py:25,42,43` — imports `tex.deterministic.gate`,
  `tex.semantic.schema`, `tex.specialists.base`.
- `calibration_proposal.py:39,40,41` — imports `tex.learning.calibrator`,
  `tex.learning.health`, `tex.learning.replay`.

These are "domain" by file location but are really **adapters/builders** that
should arguably live in `engine`/`learning` (one even says so:
`abstention_certificate.py:4` notes "the builder lives in
`engine/abstention_certificate.py` because it reads engine artifacts" — yet
`asi_builder.py` and `determinism.py` read the same kind of engine artifacts but
sit in `domain`). See [Notable Findings](#notable-findings).

---

## Implementation Reality

**`implementation_reality = REAL`.** This is genuine, executable code, not a
stub farm. Evidence:

- **No `NotImplementedError`, no `TODO`, no `FIXME`, no placeholder `pass`**
  bodies anywhere in `domain/` (verified by reading all 23 files). Every model
  has real validators; every behaviour property/method has real logic.
- The **e-value spine executes correctly** — I ran `compose_spine` over two real
  E_PROCESS snapshots and got a valid `arithmetic_mean` `CombinedEvidence`
  (`anytime_valid=True`, finite log_e, stable `payload_sha256`). The honesty
  `model_validator`s genuinely refuse contradictory constructions
  (`evidence.py:356`, `evidence.py:663`).
- The **MinHash signature** is real deterministic crypto-hash logic
  (`tenant_baseline.py:97`), not a placeholder — 64 prime seeds, SHA-256
  digests, banded minima.
- The **capability matcher** does real domain parsing/suffix-matching
  (`agent.py:217`).
- **Cross-field invariants are enforced**, not decorative: Decision verdict
  consistency (`decision.py:214`), policy threshold ordering + weight-sum
  (`policy.py:258`), proposal lifecycle (`calibration_proposal.py:112`),
  evidence honesty (`evidence.py:356`/`663`), retrieval rank/ID uniqueness
  (`retrieval.py:219`).

**No crypto/zk/tee primitives are implemented here** — the domain layer only
*describes* sealed objects (hashes, e-values) and provides canonical
serialization (`canonical_json`, `payload_sha256`). The actual ECDSA-P256 seal
and hash-chain live in `provenance/`/`evidence.chain` (the
`abstention_certificate.py:42` claim "the SEAL is real (live ECDSA-P256 + hash
chain)" refers to those layers, **(claim, unverified here)** — out of scope of
`domain/`). The honest split is correct: `EvidenceRecord` is explicitly the
envelope and says verification belongs elsewhere (`evidence.py:40`).

**Honest "uncalibrated" posture is real, not aspirational:**
`AbstentionCertificate.certified` defaults to following the CRC band's real
calibration signal (`abstention_certificate.py:232`); `descriptive_only` is a
`Literal[True]` structurally pinned (`abstention_certificate.py:241`) so the
certificate can never enter a decision path.

---

## Technology / SOTA

- **Pydantic v2** frozen models with `extra="forbid"`, `field_validator`/
  `model_validator`, `mode="before"/"after"` — used uniformly. `StrEnum`/
  `IntEnum` value objects.
- **Anytime-valid sequential statistics (e-values / e-processes).**
  `evidence.py` implements an honest multiplicative e-value spine with two
  merge rules, each backed by a named theorem cited in the module banner:
  - Arithmetic-mean merge of arbitrarily-dependent e-values: **Vovk–Wang,
    Biometrika 2025 / arXiv:2409.19888** (cited `evidence.py:174`).
  - Product (GROW-optimal) merge under independence / sequential structure:
    **Grünwald–de Heide–Koolen "Safe Testing", JRSS-B 2024** (cited
    `evidence.py:170`).
  - Cross-filtration adjuster note: **Choe–Ramdas, JRSS-B 2026 /
    arXiv:2402.09698** (cited `evidence.py:178`).
  - **Ville's inequality** for the sup-over-time bound; `ville_p_value =
    min(1, 1/E)`.
  The *type-level* enforcement of which merge is legal (dispatch on `kind`,
  never on a producer name) is the genuinely novel design pattern here.
- **MinHash / banded Jaccard** near-duplicate detection
  (`tenant_baseline.py`) — 64-band signature, 5-char shingles, ~12.5% mean
  estimator error **(claim from docstring `tenant_baseline.py:43`, plausible,
  not independently re-derived)**.
- **Hash-chain / append-only ledger** pattern (`EvidenceRecord`,
  `DiscoveryLedgerEntry`) — SHA-256 `record_hash` over `payload_sha256 +
  previous_hash`.
- **OWASP Top 10 for Agentic Applications 2026 (ASI)** taxonomy mapping
  (`owasp_asi.py`) — signal→category tables with conservative thresholds.
- Design patterns: immutable value objects, factory classmethods
  (`OutcomeRecord.create`, `RetrievalContext.empty`, `CalibrationProposal.build`),
  weakest-link aggregation (`_weakest_maturity`), conservative aggregation
  (min-confidence in `AgentEvaluationBundle`).

---

## Persistence

The domain layer holds **no persistence of its own** — it is the *shape* of
state, not the store. Every model is frozen and designed to be safe to persist,
hash, compare, and replay. Durability is owned by other layers:

- Decisions: `tex.stores.decision_store.InMemoryDecisionStore` (in-memory by
  default; `commands/evaluate_action.py:31`).
- Evidence: `tex.evidence` / `tex.provenance` ledger (hash chain).
- Discovery: discovery ledger (`DiscoveryLedgerEntry` rows).
- `BehavioralBaseline` is explicitly **never stored** — recomputed at evaluation
  time from the action ledger window (`agent.py:531` docstring; consistent with
  it having no store reference).
- Timestamps everywhere are timezone-aware and normalized to UTC by validators
  (e.g. `decision.py:207`, `agent.py:395`, `evidence.py:84`), which is the
  precondition for stable, replayable persistence.

---

## Notable Findings

1. **Three "domain" modules are not pure data and import UP the stack.**
   `determinism.py` (→ deterministic/semantic/specialists), `asi_builder.py`
   (→ deterministic/semantic/specialists), and `calibration_proposal.py`
   (→ learning) violate the package's own stated rule ("nothing here knows
   about HTTP, persistence backends, or model providers", e.g. `agent.py:14`,
   `discovery.py:13`). They are builders/aggregators mislocated in `domain`.
   Inconsistency: `abstention_certificate.py:4` correctly pushed its builder out
   to `engine/`, but the structurally identical `asi_builder.py`/`determinism.py`
   were not. Not a bug — a layering smell. They are still LIVE (used by PDP).

2. **`__init__.py` docstring overstates the public surface.** It says the package
   provides "Pydantic models for EvaluationRequest, Decision, Policy,
   AgentRecord, etc." (`domain/__init__.py:2`) but exports nothing and there is
   no `AgentRecord` type (the type is `AgentIdentity`/`ActionLedgerEntry`).
   **(claim vs code mismatch.)**

3. **Importer-count claim ("389 importers") not reproduced.** Verified figures:
   175 non-domain `src` importers; 315–318 referencing files repo-wide. Still
   the most-imported package, but the specific number in the brief is unverified.

4. **Private symbol crosses the package boundary.** `engine/credal_hold.py:95`
   imports `_DEFAULT_FUSION_WEIGHTS` (a leading-underscore private)
   from `policy.py`. Works, but couples the engine to a private constant.

5. **Unused helper symbols (dead-ish, but harmless).** Verified not imported
   anywhere outside `domain/` (only defined, and in some cases test-only):
   `fingerprint_components` (`determinism.py:121`) — 0 src importers, 0 test
   files; `dedupe_asi_tags`, `get_asi_metadata`, `signature_to_hex`,
   `signature_distance` — 0 src importers each (1 test file each). These are
   API completeness/debug helpers with no live caller. `ASICategoryMetadata` is
   used internally (12 uses) so it is *not* dead.

6. **`CandidateAgent` silently mutates a frozen field.** `discovery.py:367`
   uses `object.__setattr__` inside a `model_validator` to clamp
   `last_seen_active_at` down to `discovered_at` rather than rejecting an
   out-of-order timestamp. Deliberate (commented), but it is a frozen-model
   bypass worth knowing about for replay determinism.

7. **The e-value honesty machinery is the standout asset and it is REAL.**
   The long banner in `evidence.py:129`–`198` is unusually candid: it names the
   `nanozk` "stats-sounding name the body does not deliver" failure mode as the
   thing this type exists to prevent, and states its own honest limit (the type
   blocks *declaring* a contradictory over-claim but does not verify the
   underlying martingale math). The code backs the prose — the `model_validator`
   invariants and the combiner `_require_true_e_values` guard
   (`evidence.py:584`) genuinely refuse non-e-values into a product. This is the
   opposite of an overstated audit target.

8. **No async, no I/O, fast to import.** The whole package imports cleanly under
   `PYTHONPATH=src` and instantiates/executes without side effects, consistent
   with its role as a leaf vocabulary (modulo finding #1).
