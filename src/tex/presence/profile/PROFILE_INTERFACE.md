# ProfileMemory interface — POSTED for L3 (presence L-wave)

**Branch** `presence/l2-profile` (based on `presence/s5-memory`). **Status:**
interface FROZEN and importable; build in progress. **L3 may build against this
now.** Interface version `1.0.0` (`tex.presence.profile.types.PROFILE_INTERFACE_VERSION`).

Import everything from the package root — these symbols are stable:

```python
from tex.presence.profile import (
    ProfileMemory, ProfileFact, ProfileFacts, ProfileFactKind,  # the seam + shapes
    apply_profile_corrections,        # orchestrator's one-line influence wire
    apply_corrections_to_verdicts,    # verdict-level variant (decoupled from the gate)
    cap_verdict,                      # the pure monotone cap
    build_profile_memory,             # factory → SealedProfileMemory
    PROFILE_STORE_NAME,               # == "presence_profile" (EvidenceRef.store)
)
from tex.presence.contract import PresenceTier, EvidenceRef  # frozen, unchanged
```

## The protocol (what L3 codes against)

`tex.presence.profile.types.ProfileMemory` (a `runtime_checkable` `Protocol`):

```python
def recall_profile(self, *, tenant: str, query: str | None = None) -> ProfileFacts
def apply_correction(self, *, tenant: str, claim_id: str,
                     corrected_tier: PresenceTier, operator: str,
                     statement: str = "", original_tier: PresenceTier | None = None,
                     decision_id: str | None = None,
                     believed_value: str | None = None) -> EvidenceRef
def confirm(self, *, tenant: str, claim_id: str, tier: PresenceTier, operator: str,
            statement: str = "", decision_id: str | None = None) -> EvidenceRef
def revoke(self, *, tenant: str, record_id: str) -> bool
```

The concrete `SealedProfileMemory` adds `remember_preference(...)`,
`get(...) -> SealedProfileFact | None`, and `verify(fact) -> bool`.

### `ProfileFacts` (the recall result L3 reads)

```python
@dataclass(frozen=True, slots=True)
class ProfileFacts:
    tenant: str
    facts: tuple[ProfileFact, ...]
    def refs(self) -> tuple[EvidenceRef, ...]        # citable, per fact
    def corrections(self) -> tuple[ProfileFact, ...] # CORRECTION-kind only
    def tier_ceiling(self, claim_id: str) -> PresenceTier | None          # legacy: folds over _norm_subject(claim_id)
    def tier_ceiling_for_subject(self, subject_key: str) -> PresenceTier | None  # folds over an already-resolved STABLE subject
```

### `ProfileFact`

`record_id` (`"pf-<sha256>"`), `tenant`, `kind` (`ProfileFactKind`), `subject_key`
(normalised claim_id), `corrected_tier` (CORRECTION only; never `SEALED`),
`statement`, `operator`, `created_at`, `original_tier`, `decision_id`,
`believed_value`, `content_hash`; `.as_ref() -> EvidenceRef` (store
`"presence_profile"`, `prior_link_witness=None`).

## The three invariants L3 (and the orchestrator) must preserve

1. **Monotone-lowering.** Corrections only ever move a tier toward caution. The
   influence fold uses `tighten`, never `max`. A correction to `SEALED` is REFUSED
   at the write-gate. Do not add any path that raises a tier from a profile signal.
2. **Provenance before write.** `operator` is required (a named human act);
   `apply_correction`/`confirm` validate it before writing. Pass the **server-side**
   identity, never a request-body value (same discipline as `/decisions/{id}/seal`).
3. **No spoken typed values.** `believed_value` is operator-belief metadata; it is
   NEVER spoken. The gate recomputes from rows; corrections only lower a tier.

## How influence reaches a decision (the orchestrator's ONE line)

Between the gate and `compose.build_envelope`:

```python
detailed = gate.evaluate_detailed(request=..., tenant=tenant, draft=draft,
                                  claims=claims, facts=facts)
detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed,
                                     profile=app.state.presence_profile)
envelope = build_envelope(detailed, templated_abstain=...)
```

`apply_profile_corrections` caps each `ClaimEvaluation.verdict` at the subject's
active correction ceiling (fail-open to uncorrected verdicts on any error). A
correction-suppressed claim becomes `ABSTAIN` and is stripped by `build_envelope`
exactly as any ABSTAIN — so corrections influence the spoken answer without L2
editing `run_presence`.

### The STABLE subject key (so a correction caps the SAME thing asked again)

A correction is scoped to a **subject**, and the subject must be stable across
re-asks or the cap is cosmetic. The brain's `claim_id` is NOT stable (LLM string /
`claim-{index}` fallback), and the verdict's evidence `record_id` set is NOT stable
either (an AGGREGATE binds a witness set capped at 64 that grows as rows arrive; a
discovery/event claim binds the moving latest sequence). So
`influence.stable_subject_key(evaluation)` keys on the gate's **routing identity**
(`routed.query.key` + `routed.target`) — a fixed registry entry stable across
re-asks AND as rows change. EXACT match only; no embeddings/similarity.

- **Surface it.** `compose._surface_object` puts `subject_key` on every claim row;
  the confirm/correct UI echoes it to `POST /v1/presence/profile/correct`
  (`CorrectRequest.subject_key`).
- **Store it.** `apply_correction(..., subject_key=...)` scopes the cap to the
  stable subject. **Always pass it** for a correction that must survive a re-ask;
  omitting it falls back to the legacy `claim_id` key (see the trap below).
- **Look it up.** The read side does a monotone **dual-lookup**: the stable subject
  ceiling `tighten`-folded with the ceiling for the **current** verdict's `claim_id`
  subject. Corrections stored with an explicit `subject_key` are robust across
  re-asks; corrections stored under a bare `claim_id` **silently stop applying** the
  moment the brain re-asks with a different generated `claim_id` (the legacy arm
  keys on the *current* claim_id, and nothing persists the original — see
  `test_legacy_claim_id_correction_silently_fails_across_reask_but_stable_key_holds`).
  The legacy arm exists only for **non-regression**, not stability. Matches are only
  ever ADDED and a `tighten`-fold can still only lower a tier, so dual-lookup is
  monotone-safe regardless.

> **The legacy `claim_id` trap (L3 + UI).** A correction without an explicit
> `subject_key` keys on the brain's volatile `claim_id` string. If your writer does
> not surface `subject_key`, the operator's correction will silently stop applying
> across re-asks. Always read `subject_key` from `compose._surface_object` (or call
> `stable_subject_key(evaluation)`) and pass it to `apply_correction(subject_key=...)`.
> **Known gap:** the habit-confirm writer (`habits/confirm.py`) currently writes via
> the legacy `claim_id` arm (it mines pre-gate and has no routing identity), so
> habit-confirmed corrections are NOT yet stable across re-asks — tracked in
> `COORDINATION.md` for the L3 track.

Watch metric: `PresenceTelemetry.over_suppression_rate` — the share of answers a
correction lowered. Over-suppression is the correction loop's only real failure
mode; inflation is structurally impossible (no path raises a tier), so there is no
inflation counter.

## L3 integration notes

- **Recall for grounding.** Call `recall_profile(tenant=...)` to surface a tenant's
  preferences/boundaries to the brain/UI. Each fact is citable via `.as_ref()`.
  Corrections are *not* facts to speak — they are verdict constraints; let the fold
  apply them, don't have the brain assert their text.
- **Calibration is wired in the ROUTE, not the store.** A decision-backed correction
  feeds L1's calibration seam from `tex.api.presence_profile_routes` (server-looked-up
  `Decision`), and `revoke` of such a correction pulls the calibration contribution
  via S5's `PresenceCalibrationFeed.forget_resolution`. If L3 needs a different
  calibration sink, the route accepts an injected `CorrectionCalibrationSink`
  (structural — S5's `PresenceCalibrationFeed` already satisfies it).
- **The confirm/correct route** (`build_presence_profile_router(...)`) returns a
  FastAPI `APIRouter` the orchestrator includes; response shape is coordinated with
  S6 (see the route module docstring).

See `RESEARCH.md` for the 2026 frontier this design answers (mnemonic sovereignty /
TierMem / portable agent memory).
