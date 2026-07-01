# Precedent influence — decision write-up for founder sign-off

**Status: BUILT on `track/moat-precedent-verdict`, NOT merged. The repo is PUBLIC; nothing
committed/pushed. This document + the isolated diff are for Matt to approve.**
**Maturity: `research-early`** — the mechanism is real, live, deterministic, and replayable;
the N / freshness / confidence thresholds carry no field-calibrated guarantee yet.

---

## 1. What this is, in one line

> When `policy.precedent_autoresolve` is ON, a tenant's **own** consistent, sealed, prior
> **human** resolutions of an edge-class may auto-resolve a current **discretionary ABSTAIN to
> PERMIT** — citing, and sealed against, the precedents that drove it — so the same hard call
> stops escalating to a person. It can **never** touch the structural floor / a FORBID / any
> non-ABSTAIN verdict, and it is **OFF by default**.

This closes the last step of the moat thesis: precedents were already *retrieved*
(`retrieval/orchestrator.py`) and carried into the PDP, but only ever used as **audit metadata**
(`pdp.py` `precedent_count`, `precedent_decision_ids`). No prior resolution could change a current
verdict. Now — narrowly, consciously, and auditably — one can.

## 2. Exact semantics

- The only mutation is the **categorical verdict**: `ABSTAIN → PERMIT`. `final_score`,
  `confidence`, findings, and the determinism fingerprint are untouched. (This mirrors the existing
  `_merge_soft_contract_signals` / CRC-demotion idiom, which already move the categorical verdict
  without re-scoring — only the *direction* here is novel, which is why it is fenced.)
- It runs **after** the CRC gate (the last scoring touch) and **before** `build_hold`, so a
  resolved ABSTAIN raises **no operator hold** — the operator surface simply sees one fewer ABSTAIN.
- It is **deterministic and explainable**: the verdict is a pure function of
  `(base verdict, uncertainty flags, the retrieved precedents' sealed provenance, policy)`. No
  opaque scoring. Identical inputs → identical verdict and identical citation.
- Single wiring point: one self-contained call in `engine/pdp.py`
  (`apply_precedent_autoresolve(...)`), exactly like `apply_pq_durability_hold` / `apply_risk_spine`.
  All logic lives in `engine/precedent_influence.py`.

## 3. Eligibility gates (ALL required, each deterministic & replayable)

| Gate | Rule |
|---|---|
| **Default OFF** | `policy.precedent_autoresolve` must be `True` (default `False`). |
| **Floor sacrosanct** | Acts **only** when `base.verdict is ABSTAIN`. A FORBID/PERMIT is returned untouched. The floor only ever emits FORBID, so it is structurally unreachable. |
| **Discretionary band only** | Every `uncertainty_flag` on the ABSTAIN must be in a small **fail-closed allowlist** of genuine judgment-call markers (`borderline_fused_score`, `low_confidence_semantic_dimension`, `weak_semantic_evidence`, `confidence_below_policy_minimum`, `cold_start`, `no_behavioral_history`). Any other flag — or none — refuses. |
| **Sealed-or-nothing** | Requires a decision ledger. No ledger ⇒ no influence (no unsealed influenced verdict can exist). |
| **Same tenant** | `request.agent_identity.tenant_id` must equal each precedent's recorded tenant. |
| **Same edge-class** | `(action_type, channel, environment)` must match (case-insensitive). |
| **Human-resolved** | Each precedent must record a sealed **human** resolution (`resolved_by_human=True`). |
| **N consistent + identical** | ≥ `precedent_autoresolve_min_count` survivors (hard floor **3**), **unanimously PERMIT**. A split history, or a unanimous FORBID history, refuses. |
| **Freshness** | Each survivor resolved within `precedent_autoresolve_freshness_days` of `request.requested_at` (and not after it). Measured against the request time so the gate is deterministic/replayable. |
| **Confidence** | Each survivor's recorded resolution confidence ≥ `precedent_autoresolve_min_confidence` (default 0.9). |

## 4. What is explicitly OUT OF BOUNDS

1. **The deterministic / structural floor.** A floor FORBID can never be softened. Proven by
   `test_precedent_cannot_override_forbid_floor` (unit, returns the FORBID object unchanged, seals
   nothing) and `test_pdp_structural_floor_stays_forbid_with_flag_on` (a real PCAS-deny floor
   through the full PDP, flag ON, matching precedents present → still FORBID).
2. **Any non-ABSTAIN verdict.** PERMIT and FORBID are left untouched.
3. **Caution-RAISING.** Only `ABSTAIN → PERMIT`. A unanimous *FORBID* history is deliberately out
   of scope (auto-FORBID would be a separate feature; not built).
4. **Signaled ABSTAINs.** A capability gap (PQ-durability), a statistical alarm (drift e-spine,
   CRC permit-region), or a policy/proof violation (contract / path / structural) each stamps its
   own marker flag, so the fail-closed allowlist refuses them. Precedent can never wave those away.
   A *future* signal's new marker is also refused by default (allowlist, not denylist).
5. **The evidence-chain semantics.** Precedent citations are **payload fields** in a new
   `SealedFact(PRECEDENT)`; no hash computation changed. The PRECEDENT kind is invisible to L1
   (seal-binding) and L3 (verdict-count) by construction — it is never a DECISION fact.

## 5. The governor change (`selfgov/governor.py`) — deliberate, isolated

The census entry at the old line 269 made a blanket claim that is no longer the whole truth:

```
MutationSite("decision/precedent/outcome/entity stores", "*", "EXCLUDED",
  "evidence records — they record what happened, they do not parameterize verdicts")
```

I **split** it: `decision/outcome/entity` keep that reason verbatim (still true); **precedent**
becomes a separate, narrowly-scoped **bounded exception**. The status stays `EXCLUDED` (the census
tripwire `test_census_excluded_entries_carry_reasons` requires `status ∈ {WIRED, COVERED_VIA,
EXCLUDED}`, and the precedent *store write* genuinely is still not a controller mutation — gating an
append would recurse the seal, exactly as with the "ledger appends" entry). What changed is that the
reason now states the truth and **points at where the boundary is enforced in code and proven by a
test** — it is *encoded and enforced*, not merely documented:

> the verdict-touching boundary is a **structural invariant** (the resolver acts only when
> `verdict is ABSTAIN`) enforced in `engine/precedent_influence.py` and proven by
> `tests/test_precedent_influence.py::test_precedent_cannot_override_forbid_floor`.

Verbatim diff:

```diff
     # ── EXCLUDED (one-line reasons, per the census discipline) ──
-    MutationSite("decision/precedent/outcome/entity stores", "*", "EXCLUDED", "evidence records — they record what happened, they do not parameterize verdicts"),
+    MutationSite("decision/outcome/entity stores", "*", "EXCLUDED", "evidence records — they record what happened, they do not parameterize verdicts"),
+    # The ONE audited exception (moat / Thread-C). Precedent records used to be
+    # bundled into the blanket "do not parameterize verdicts" above; that is no
+    # longer the whole truth. A tenant's OWN sealed prior HUMAN resolutions may
+    # now parameterize a verdict — but the exception is fenced to the point of a
+    # near-no-op, so the precedent *store write* is still not a controller
+    # mutation (gating an append would recurse the seal, as with "ledger
+    # appends" below). The verdict-touching boundary is not documented-and-
+    # trusted; it is ENFORCED in code and PROVEN by tests, named in the note.
+    MutationSite("precedent store → discretionary-band auto-resolve", "engine/precedent_influence.py", "EXCLUDED", "BOUNDED EXCEPTION to 'evidence does not parameterize verdicts': a tenant's own consistent (≥N) sealed prior HUMAN resolutions may auto-resolve the DISCRETIONARY band ONLY (ABSTAIN→PERMIT), NEVER the structural floor / FORBID / any non-ABSTAIN verdict; default OFF (policy.precedent_autoresolve); requires a ledger so every influenced verdict is sealed as SealedFactKind.PRECEDENT citing each driving record_hash; fail-closed discretionary-flag allowlist. Floor-untouchability is a structural invariant (acts only when verdict is ABSTAIN) enforced in engine/precedent_influence.py and proven by tests/test_precedent_influence.py::test_precedent_cannot_override_forbid_floor"),
     MutationSite("src/tex/api/auth.py", ":279 activate example", "EXCLUDED", "docstring usage example inside RequireScope, not a route"),
```

## 6. Sealing & replay (auditable, replayable)

- Every influenced verdict appends a `SealedFact(SealedFactKind.PRECEDENT)` to the decision ledger
  **before** the M0 DECISION seal. Its `detail` carries `driving_precedent_record_hashes`,
  `driving_precedent_decision_ids`, the edge-class, tenant, `consistent_count`, and the exact gate
  values used. Its `claim` says in words that it proves authorship + integrity and binds the
  precedents by `record_hash` — **not** that the verdict is correct (correctness rests on the cited
  human judgments). Chain integrity is verifiable offline (`verify_chain`).
- The **calibration replay validator** (`learning/replay.py`) now honours precedent influence the
  same way the live PDP applies it: a precedent-influenced decision's verdict is pinned to its
  sealed resolution **only when the raw threshold re-derivation is itself ABSTAIN**. If a proposed
  recalibration pushes the score into the FORBID region, **the FORBID wins even in replay** —
  precedent never overrides a forbid, anywhere. (Without this, a precedent PERMIT — which sits in
  the ABSTAIN band by construction — would be mis-counted as a threshold-driven flip that never
  happened.) Backward-compatible: decisions without the marker behave exactly as before.

## 7. Honest note on determinism (read this)

`compute_determinism_fingerprint` covers the **scoring** inputs (content, policy version,
deterministic/specialist/semantic/agent signals) — it does **not** include the routing result, the
retrieved precedents, or `request.metadata`. So a precedent-influenced PERMIT and a flag-OFF ABSTAIN
on the same inputs share a fingerprint but differ in verdict. **This is not new**: the categorical
verdict was *already* not a pure function of the fingerprint — `_merge_soft_contract_signals`, the
CRC demotion, and the PQ hold all move it based on inputs outside the fingerprint (CRC calibration,
`request.metadata`). Precedent influence is consistent with that architecture. The influence half of
determinism is captured by the **sealed PRECEDENT fact** (it records the exact precedents + gates),
so the decision remains fully reconstructible; replay uses both halves.

## 8. Frontier framing & the risk we are taking on

This is the inverse of **learning-to-defer / selective prediction** (Mozannar et al., 2023; "L2D to
a population", Tailor et al., 2024) — *learning to **un-defer*** from an accumulated population of
consistent human resolutions. The **automation-bias** literature (CSET, *AI Safety and Automation
Bias*, 2024; EDPS TechDispatch 2/2025, *Human Oversight of Automated Decision-Making*) names the
exact hazard: auto-resolving human-review cases erodes the human-oversight guardrail. Our
mitigations map directly onto its recommendations (defined thresholds; halt when ill-equipped):
hard floor, N-consistency, freshness, confidence, default-OFF, and a sealed/replayable citation that
makes every un-deferral auditable after the fact.

*(Citations retrieved this session, 2026-06-17, via web search; not re-derived from the papers'
internals — treat the framing as directional, not as a proof.)*

## 9. Production-wiring gap (honest, and why default-OFF is safe regardless)

The production precedent store is a **NoOp today** (`retrieval/orchestrator.py`
`NoOpPrecedentStore`), and `RetrievedPrecedent` carries the resolution provenance in its existing
`metadata` dict (I deliberately did **not** widen the shared domain contract). For the feature to
fire in production, a precedent store must populate, per precedent:

```python
metadata["precedent_resolution"] = {
    "tenant_id": str,
    "resolution_verdict": "PERMIT" | "ABSTAIN" | "FORBID",   # the HUMAN's resolution
    "resolved_by_human": bool,
    "resolved_at": "<ISO-8601 tz-aware>",
    "resolution_confidence": float,   # 0..1
    "record_hash": str,               # the sealed record hash of the resolution (the citation)
}
```

Until then — and whenever the flag is OFF, or no ledger is wired (the default PDP) — this is a
zero-cost no-op that reproduces today's behaviour **bit-for-bit**. Teaching the store to emit this
provenance is the one remaining production step; it is localized and does not touch the engine.

## 10. Evidence (run from this worktree)

`tests/test_precedent_influence.py` — 29 tests, all green — proves (a) N consistent precedents
resolve a discretionary ABSTAIN→PERMIT (unit + full PDP); (b) precedent cannot override a FORBID
floor (unit + real structural floor); (c) the influenced verdict is sealed citing the
`record_hash`(es) + chain verifies; (d) the replay validator pins it in-band and lets a
recalibration into FORBID win; (e) flag OFF / no ledger ⇒ no influence, no seal; plus the
fail-closed allowlist, the consistency requirement, and every eligibility gate. The shared CI gate
(`test_crc_gate`, `test_structural_floor`, `test_deterministic`, `test_enforcement`,
`test_replay_validator`, `test_pdp_crc_path_integration`) and the census/governor/conservation
guardrails (`test_decision_fact_contract`, `test_reflexive_gov`, `test_two_sided_hold`,
`test_attempt_seal`) stay green. Exact commands + output are in the summary that accompanies this
document.

## 11. Self-critique — what an adversary attacks first, and what survived

- *"You broke the monotone-lowering invariant (CLAUDE.md rule 2)."* — **Conceded and deliberate.**
  Rule 2 governs *probabilistic signals*; precedent influence is a *deterministic* adoption of a
  human's repeated sealed judgment, fenced to the discretionary band, caution-reducing only,
  default-OFF, sealed. This is the consciously-resolved governance invariant the task asked for.
- *"Precedent can be used to launder a FORBID into a PERMIT."* — **Refuted.** The resolver acts only
  on `verdict is ABSTAIN`; a FORBID is a FORBID. Proven structurally (unit) and end-to-end (real
  PCAS floor), and even under replay (recalibration-into-FORBID test).
- *"It will auto-resolve PQ/drift/contract ABSTAINs it shouldn't."* — **Refuted.** Those each stamp a
  non-allowlisted marker flag; the fail-closed subset rule refuses them (and any future signal).
- *"A single fluke approval auto-permits the next case."* — **Refuted.** Hard floor of N≥3, unanimous,
  human, fresh, confident, same-tenant, same-edge-class.
- *"The influence is invisible / unreplayable."* — **Refuted.** Sealed `PRECEDENT` fact cites every
  driving `record_hash`; the verdict carries the marker flag + a human-readable citation; replay
  honours it.
- **Residual, honestly flagged:** (i) the verdict is no longer a pure function of the determinism
  fingerprint (§7 — but neither were the existing soft signals); (ii) the N/freshness/confidence
  thresholds are uncalibrated (`research-early`); (iii) production firing depends on the precedent
  store emitting the provenance (§9). None of these can produce an *unsafe* verdict (the floor and
  fail-closed gates hold regardless); they bound *when the feature fires*, not *whether it is safe*.

---

## NEEDS FOUNDER SIGN-OFF

This change **intentionally alters a deliberate governance invariant** (`selfgov/governor.py`
census + the monotone-lowering doctrine). It is built, tested, and isolated, but it is **not merged
and must not be** without Matt's explicit approval. The two decisions to sign off on:

1. **That precedent may parameterize the discretionary band at all** — the conscious exception to
   "evidence records do not parameterize verdicts."
2. **That the fence is the right fence** — discretionary band only, caution-reducing only, floor
   sacrosanct, N≥3 unanimous human, default-OFF, sealed-or-nothing.
