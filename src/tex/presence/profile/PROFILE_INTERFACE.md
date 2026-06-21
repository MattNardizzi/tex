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
    def tier_ceiling(self, claim_id: str) -> PresenceTier | None  # monotone fold of corrections
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
