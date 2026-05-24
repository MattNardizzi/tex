# Ecosystem Engine — Operational Reference

> **Architecture overview** lives in [`ECOSYSTEM_GOVERNANCE.md`](../ECOSYSTEM_GOVERNANCE.md).
> This file is the operator's runtime reference: environment flags,
> collaborator wiring, the eight-axis verdict surface, viability index,
> GAAT enforcement tiers, and the RiskGate P3 monotonic restriction.

The `EcosystemEngine` (`tex.ecosystem.engine.EcosystemEngine`) is Tex's
top-level evaluator. It composes eight pipeline steps over a proposed
event and emits a single `EcosystemVerdict` carrying:

  * the admit/reject decision (`kind`),
  * a six-field `EcosystemAxisScores` object,
  * a computed `viability_index` (Aubin / RiskGate scalar),
  * a `graduated_level` enforcement tier (GAAT L0..L4).

## Environment flags

### `TEX_ECOSYSTEM`

Default: `0` (off). Set to `1` to enable the ecosystem engine. When
off, `evaluate()` returns an inert PERMIT with neutral axis scores —
the legacy six-layer pipeline runs untouched.

### `TEX_ECOSYSTEM_SYSTEMIC` (Thread 7 / 7.1)

Default: `0` (off). Controls whether `evaluate()` calls
`SystemicRiskEvaluator.score()` at Step 7.

| Flag value | Engine behavior at Step 7 |
| --- | --- |
| Not set, `0`, or any value other than exactly `1` | Step 7 short-circuits; `systemic_risk_under_event` axis is reported as `0.0`. Telemetry: `step7.systemic_skipped_flag_off`. |
| `1` and `systemic=None` at construction | Step 7 short-circuits; axis `0.0`. Telemetry: `step7.systemic_skipped_flag_off` with `systemic_collaborator_wired=False`. |
| `1` and a `SystemicRiskEvaluator` wired (Thread 7.1 default) | **ProbGuard PCTL bounded-reachability** computed over a 27-state DTMC abstraction (arxiv 2508.00500 v3). Score = `P[F^{≤k} unsafe \| current_state]`. Telemetry: `step7.systemic_scored`. |
| `1` and scorer returns `< 0.0` or `> 1.0` | Defensive clamp to `[0.0, 1.0]`. |
| `1` and scorer raises `NotImplementedError` | Backward-compat path for callers using a custom scorer stub; axis `0.0` + telemetry `step7.systemic_not_implemented`. |
| `1` and scorer raises any other exception | Fail-closed: axis `0.0`, telemetry `step7.systemic_error`. Engine continues. |

Strict equality with `"1"` — values like `"true"`, `"yes"`, `"on"`,
`"01"`, or `"1 "` are treated as off.

## Eight-step pipeline status

| Step | Description | Status (Thread 7.1) | Source-paper anchor |
| --- | --- | --- | --- |
| 1 | Ontology validation | Wired | — |
| 2 | Graph projection | Wired | — |
| 3 | Behavioral contract check | Wired | Bhardwaj ABC, arxiv 2602.22302 |
| 4 | Governance-graph LTS legality | Wired | arxiv 2601.11369 |
| 5 | Pre-emission causal attribution (Shapley) | **Wired with full Shapley** | Halpern-Kleiman-Weiner 2018; Friedenberg-Halpern 2019; arxiv 2605.00248 |
| 6 | Drift detection (BOCPD + anytime-valid + Rath taxonomy) | **Wired with three Rath dimensions** | Adams/MacKay BOCPD; arxiv 2603.08578; arxiv 2601.04170 |
| 7 | Systemic risk (ProbGuard PCTL) | **Live scorer, not flag-gated to NotImplementedError** | arxiv 2508.00500 v3 |
| 8 | Intervention selection | Pending (Thread 8) | AAF §4 |

## RiskGate Viability Index (Thread 7.1)

The `EcosystemAxisScores` model exposes a computed `viability_index`
in `[0, 1]` derived from the six axis scores per RiskGate's
`B̂(x) = U(x) + SB(x) + RG(x)` decomposition:

```
viability_index = 1 - max(U, SB, RG)
```

where

  * **U(x)** unobserved risk     = `drift_delta`
  * **SB(x)** system-boundary    = `max(contract_violation_severity, 1 - governance_graph_legality)`
  * **RG(x)** regulation-graph   = `systemic_risk_under_event`

Higher viability = healthier. `1.0` = full viability, `0.0` = at the
viability boundary.

## GAAT Graduated Enforcement Levels (Thread 7.1)

The `graduated_level` computed property maps `viability_index` to a
discrete tier per GAAT's published Theorem 3 table (Apple, arxiv
2604.05119 §III.A):

| viability_index | enforcement_level | GAAT action |
| --- | --- | --- |
| ≥ 0.90 | `L0_allow` | ALLOW |
| 0.70–0.90 | `L1_alert` | ALERT |
| 0.50–0.70 | `L2_flag` | FLAG |
| 0.25–0.50 | `L3_redirect` | REDIRECT |
| < 0.25 | `L4_quarantine` | QUARANTINE |

Thread 7.1 surfaces these tiers but the engine still PERMITs at every
level — the level is **advisory**. The composition gate that turns
these into FORBID/SANCTION decisions is Thread 8.

## RiskGate P3 Monotonic Restriction (Thread 7.1, opt-in)

Per RiskGate Property P3, once an actor has been observed at a low
viability index, subsequent evaluations cannot relax that floor
without an explicit recovery event. Enable via:

```python
engine = EcosystemEngine(..., monotonic_restriction=True)
```

API:

```python
floor = engine.viability_floor_for("agent_42")    # None or float
engine.record_recovery(actor_entity_id="agent_42")  # clear the floor
```

When the floor is active and the current evaluation reports a higher
viability than the floor, the PERMIT rationale includes
`P3 floor enforced at X.XXX`. Telemetry event:
`ecosystem.engine.monotonic_restriction.floor_enforced`.

Default: `False` for backward compatibility.

## OpenTelemetry Span Schema (GAAT-compatible, Thread 7.1)

Render any `EcosystemVerdict` as an OpenTelemetry span attribute dict:

```python
from tex.observability.governance_span import verdict_to_otel_attributes

attrs = verdict_to_otel_attributes(
    verdict,
    additional={"tenant.id": "acme", "request.id": "req_123"},
)
# Pass attrs into your existing OTel exporter's set_attributes(...)
```

The dict contains:

  * **OpenTelemetry resource** — `service.name`, `service.namespace`
  * **GAAT governance core** — `governance.decision`,
    `governance.enforcement_level`, `governance.viability_index`
  * **Tex six-axis decomposition** — `tex.axis.*`
  * **Envelope correlation** — `tex.proposed_event_id`,
    `tex.state_hash_before`, `tex.state_hash_after`,
    `tex.evidence_record_id`, `tex.issued_at`

Schema version: `tex.governance.schema_version: "1.0"`.

Tex does NOT take a hard dependency on `opentelemetry-api`; downstream
operators wrap the attribute dict into a real span via their existing
OTel pipeline.

## Constructor — full surface

```python
from tex.causal.chief import HierarchicalCausalGraph
from tex.contracts.runtime_enforcement import ContractEnforcer
from tex.drift.signal_registry import (
    DriftSignalRegistry,
    ProbeMapPolicy,
    DEFAULT_PROBE_MAP_POLICY,
)
from tex.ecosystem.engine import EcosystemEngine
from tex.systemic.probguard import DTMCModel
from tex.systemic.risk_evaluator import SystemicRiskEvaluator

engine = EcosystemEngine(
    ontology=..., graph=..., projection=..., events=..., provenance=...,
    governance_graph=..., oracle=...,
    contracts=ContractEnforcer(contracts=(...)),
    causal=HierarchicalCausalGraph(),
    drift=DriftSignalRegistry(seed_defaults=True),
    systemic=SystemicRiskEvaluator(model=DTMCModel(), horizon_k=10),
    monotonic_restriction=True,  # RiskGate P3, opt-in
    enabled=True,
)
```

## Demo

```
scripts/demo_thread_7_eightaxis.sh
```

Produces a verdict showing all four newly-wired axes plus the
viability index, graduated level, and (with P3 on) the floor.
