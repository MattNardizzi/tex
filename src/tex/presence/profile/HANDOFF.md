# PRESENCE Session L2 — per-tenant PROFILE + confirm/correct loop (handoff)

Branch `presence/l2-profile` (base `presence/s5-memory`). All new code is in
`src/tex/presence/profile/` + one new route module `src/tex/api/presence_profile_routes.py`
+ the tex-systems UI (`~/dev/tex-systems`). **`main.py` / `voice/voice_ask.py` /
`engine/pdp.py` were NOT touched.** The frozen `tex.presence.contract` was NOT
edited. The orchestrator wires this in via the factories below.

## What was built

1. **`SealedProfileMemory`** (`store.py`) — implements the new `ProfileMemory`
   protocol (`types.py`): `recall_profile` / `apply_correction` / `confirm` /
   `revoke` (+ `remember_preference` / `get` / `verify`). Sealed, per-tenant,
   write-gated, FORGETTABLE — built on S5's patterns (content anchor + the
   `tex.evidence.seal` signer + the durable-mirror idiom + forget-soundness).
2. **`apply_profile_corrections`** (`influence.py`) — the post-gate MONOTONE FOLD
   that lets a correction TIGHTEN the next verdict (`tighten`-only — never raises;
   never fabricates a DERIVED floor; clears evidence on ABSTAIN). The orchestrator's
   one-line insertion between the gate and `compose.build_envelope`.
3. **`ProfileDurableMirror`** (`durable.py`) — dedicated `tex_presence_profile`
   table (self-contained DDL), tenant-scoped on every statement, real `DELETE`.
   No-op when `DATABASE_URL` is unset.
4. **The confirm/correct route** (`tex.api.presence_profile_routes`) — `correct` /
   `confirm` / `recall` / `revoke`; tenant from the principal, operator from the
   body; decision-backed correction feeds L1's calibration seam server-side; revoke
   pulls the calibration contribution (cross-substrate). Exposes
   `build_presence_profile_router()`.
5. **Hooks** (`hooks.py`) — `build_profile_memory(durable=..., sign=...)`.
6. **tex-systems UI** — `src/lib/presenceProfile.js` + `components/Dashboard/
   ConfirmCorrect.jsx`(+css) + `PRESENCE_PROFILE_UI.md` (S6 mounts it; no S6 file
   edited).

## Integration contract (orchestrator owner) — see `PROFILE_INTERFACE.md`

```python
from tex.presence.profile import build_profile_memory, apply_profile_corrections
from tex.api.presence_profile_routes import build_presence_profile_router

app.state.presence_profile = build_profile_memory(durable=True)   # no-op w/o DATABASE_URL
app.include_router(build_presence_profile_router())
# (optional) app.state.presence_calibration = build_calibration_feed()  # S5

# In run_presence, ONE line between the gate and build_envelope:
detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed,
                                     profile=app.state.presence_profile)
```

`PROFILE_INTERFACE.md` is the POSTED seam **L3 builds against** (frozen, version
1.0.0). `RESEARCH.md` is the 2026 frontier survey.

## Honest edges (baked into the code; never overclaim)

- **A correction can only TIGHTEN.** The influence fold uses `tighten`, never
  `max`; an upward correction (to SEALED) is refused at the write-gate; a confirm
  is non-inflating by construction (the fold ignores it). Proven exhaustively in
  `test_influence.py::test_cap_never_raises_a_tier_for_any_combination`.
- **A correction is a LABEL, not a retrain.** It is a sealed, content-anchored,
  citable, revocable record. Forgetting is sound BY AVOIDANCE (facts live only in
  this store). `revoke`'s `True` is scoped to THIS store instance.
- **Provenance validated BEFORE write.** A named `operator` is required (closes the
  2026 frontier's named blind spot, `RESEARCH.md` §1). The tenant comes from the
  principal, never a payload; a decision-backed correction feeds calibration from
  the server-looked-up `Decision`, never a request value.
- **A typed `believed_value` is NEVER spoken** — the gate recomputes from rows; a
  correction only lowers a tier. (`test_write_gate.py`.)
- **Per-tenant isolation is application-layer ONLY** (dict outer key + `WHERE
  tenant_id`) — no RLS, no encryption-at-rest. A wrong tenant string crosses
  silently. (Same posture as S5.)
- **DERIVED-ceiling-on-SEALED resolves to ABSTAIN** rather than fabricate a
  correctness floor the gate never computed. (`influence.py`,
  `test_influence.py::test_derived_ceiling_on_sealed_drops_to_abstain...`.)
- **No new crypto** — the content anchor reuses S5's `presence_record_hash`; the
  signature rides `tex.evidence.seal` (ML-DSA only when a backend is present, else
  honestly `ecdsa-p256`). Tamper REJECTION proven, not just acceptance
  (`test_signed_seal.py`).
- **The profile is INERT without real usage.** The V1 claim is "Tex CAN learn your
  preferences, verifiably and revocably," NOT "Tex knows you."

## Self-audit (the strongest claims, falsified)

1. *"Cannot inflate a tier."* — Survives. `tighten`-only fold + write-gate refusal
   of SEALED + confirm ignored by the fold; even a hypothetical SEALED ceiling is a
   no-op (`tighten(t, SEALED) == t`). Exhaustive 9-combo test.
2. *"Influence is real, not a toy."* — Survives, with the honest caveat that the
   LIVE wiring is the orchestrator's one line; influence is proven through the REAL
   `PresenceTruthGate.evaluate_detailed` → fold → `build_envelope` pipeline
   (`test_end_to_end.py`), not yet on the live voice path (same NOT-merged posture
   as S2–S5).
3. *"Revoke truly forgets."* — Survives. Pop-from-authoritative + durable-delete
   that RAISES-and-restores on failure (no false `True`); cross-substrate pull of
   the calibration contribution. Boundary (vendor cache / copied refs) disclosed.
4. *"No new crypto."* — Survives. Reuses S5 anchor + `tex.evidence.seal`; tamper
   rejected.
5. *"Calibration feed doesn't poison the floor."* — Survives **only** because the
   feed is gated on an attached `decision_id` (a deliberate "this decision was
   wrong" act) and the refused-only + real-`final_score` S5 guards; a pure
   credibility correction (no `decision_id`) feeds the profile ONLY. The
   interpretation is disclosed in `presence_profile_routes._maybe_feed_calibration`;
   L1 owns the final mapping and may inject a different sink.

## Tests / evidence

`PYTHONPATH=src python -m pytest tests/presence` → **143 passed** (98 prior + new
profile suite). Verdict-floor + S5 substrate regression
(`test_crc_gate`, `test_structural_floor`, `test_deterministic`, `test_enforcement`,
`test_replay_validator`, `tests/presence/memory`) → **120 passed, 0 new failures**.
New tests: `tests/presence/profile/{test_write_gate, test_influence,
test_recall_revoke, test_tenant_isolation, test_end_to_end, test_signed_seal,
test_route}.py`. Only NEW files were added under `src/tex` (no existing module
edited), so the blast radius on `main` is structurally zero.

## Maturity

- In-memory store + write-gate + influence fold + revoke + route:
  `production`-quality, unit-tested (incl. the durable-revoke rowcount/raise paths,
  signed tamper REJECTION, concurrent-revoke atomicity, and the gate-driven e2e).
- Durable Postgres mirror: SQL tenant-scoping + delete path proven via a fake
  connection; the live-Postgres round-trip is `RUNTIME-DEPENDENT` (no live DB this
  session — same honest posture as S5).
- The profile is `research-solid` as a *capability* (verifiable + revocable
  personalization); it is INERT until the orchestrator wires the one line and real
  operators use it.
