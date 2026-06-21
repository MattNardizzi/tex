# Habits interface — POSTED for the orchestrator (presence L-wave)

**Branch** `presence/l3-habits` (base `presence/l2-profile` → `presence/s5-memory`).
**Status:** built + green, interface frozen. Interface version `1.0.0`
(`tex.presence.habits.HABITS_INTERFACE_VERSION`).

L3 notices recurring patterns in a tenant's OWN sealed history and OFFERS them as
hypotheses the operator confirms before anything changes. It owns
`src/tex/presence/habits/**` and a thin tex-systems surface; it consumes L2's
`ProfileMemory` and S5's `SealedPresenceMemory`; it does NOT edit `main.py` /
`voice_ask.py`.

Import everything from the package root:

```python
from tex.presence.habits import (
    build_habit_surface, HabitSurface,            # the orchestrator seam
    HabitHypothesis, HypothesisAction,            # the offered shape
    HabitConfirmation, HabitDecline,              # the confirm/decline receipts
    HabitMiner, MinerConfig,                      # tune the gate if needed
    S5MemoryHistorySource, ProfileCorrectionHistorySource,
    IterableHistorySource, CompositeHistorySource,
    OutcomeDimension, ObservedOutcome,            # for a custom source
)
```

## The seam the orchestrator wires (no main.py edit by L3)

```python
# at startup, beside app.state.presence_memory / app.state.presence_profile:
app.state.presence_habits = build_habit_surface(
    memory=app.state.presence_memory,     # S5 — feeds the governance-verdict habit
    profile=app.state.presence_profile,   # L2 — a mining source AND the write target
    # source=<custom HistorySource>,      # optional, e.g. governance Decision resolutions
    # config=MinerConfig(...),            # optional, conservative defaults otherwise
)
```

`build_habit_surface` raises `ValueError` if no source can be assembled (nothing to
mine). It composes whatever of `source` / `memory` / `profile` is provided.

### Surfacing (read-only, inert)

```python
hyps = app.state.presence_habits.surface(tenant=tenant)   # tuple[HabitHypothesis, ...]
```

Each `HabitHypothesis` carries: `hypothesis_id` (content-addressed `"hh-<sha256>"`),
`subject_key`, `dominant_outcome`, `dimension`, `action` (a tightening — never
`SEALED`), `confidence` (a `PatternConfidence`: `n/k`, `point_rate`, `wilson_lower`,
`alpha_effective`, `family_size`, honest `label`), `supporting` (the EXACT sealed
`EvidenceRef`s — the receipts), and `phrasing` (the deterministic "I've noticed…" line).
Surfacing writes nothing and changes no verdict.

**When to surface** is the orchestrator's call (on operator request, or at the end of a
session). L3 does not decide cadence and does not auto-apply anything.

### Confirm / decline (the only writes)

```python
receipt = app.state.presence_habits.confirm(
    hypothesis=h,
    operator=server_side_identity,        # NEVER a request-body value
    decision_id=optional_governance_id,   # passed to the L2 correction; lets L2's
)                                         #   route feed L1 calibration server-side
# receipt: HabitConfirmation(profile_ref=<presence_profile EvidenceRef>, ...)

app.state.presence_habits.decline(hypothesis=h, operator=...)   # writes nothing
```

`confirm` writes exactly ONE `ProfileMemory.apply_correction` capping the subject's
tier at the proposed ceiling (`DERIVED`/`ABSTAIN`). It inherits L2's whole
constitution: sealed, citable, revocable, tightening-only, provenance-gated. It
raises `ValueError` (writing nothing) on an empty operator or a malformed hypothesis,
and propagates L2's refusal of an inflating correction.

## The three invariants the orchestrator must preserve

1. **Surfacing is inert.** Nothing reaches a verdict, a profile, or a future answer
   without an explicit `confirm`. Do not auto-confirm.
2. **Caution only.** A confirmed habit is an L2 *correction* — it can only ever lower a
   future verdict (via L2's `tier_ceiling` fold). Never wire a path that raises a tier
   from a habit signal.
3. **Provenance + tenant.** Pass the server-side operator identity and the resolved
   tenant; the browser never names either (same discipline as `/decisions/{id}/seal`).

## Custom sources (e.g. governance resolutions — the flagship case)

The miner is source-agnostic. To mine a store L3 does not own, map each row to an
`ObservedOutcome` whose `evidence` points at the real sealed record, then inject it:

```python
obs = [
    ObservedOutcome(
        subject_key=norm_subject(decision.subject_claim_id),
        dimension=OutcomeDimension.GOVERNANCE_VERDICT,
        outcome_value=decision.verdict.value.casefold(),   # "forbid"/"permit"/"abstain"
        evidence=decision_evidence_ref,                     # a re-verifiable receipt
        observed_at=decision.created_at,
    )
    for decision in server_looked_up_resolutions_for(tenant)
]
surface = build_habit_surface(profile=app.state.presence_profile,
                              source=IterableHistorySource(obs))
```

Per-tenant correctness of a raw `IterableHistorySource` is the caller's contract
(build one per tenant). The `S5MemoryHistorySource` is strictly tenant-scoped by S5.

## Response shape (coordinated with S6 / tex-systems)

`surface()` → render each hypothesis as a card:

```json
{
  "hypothesis_id": "hh-<sha256>",
  "subject_key": "<normalised claim_id>",
  "dimension": "governance_verdict" | "correction_tier",
  "dominant_outcome": "forbid" | "abstain" | "derived",
  "proposed_tier": "abstain" | "derived",
  "phrasing": "I've noticed …",
  "confidence": { "n": 6, "k": 6, "point_rate": 1.0, "wilson_lower": 0.62,
                  "family_size": 1, "label": "heuristic consistency lower bound …" },
  "supporting": [ { "record_id": "...", "record_hash": "...", "store": "presence_memory" } ]
}
```

`confirm` returns the L2 receipt shape (`record_id`, `anchor_sha256`, `store`,
`subject_key`, `corrected_tier`, `operator`, `created_at`, signature, `tenant`) — see
L2's `PROFILE_INTERFACE.md`.
