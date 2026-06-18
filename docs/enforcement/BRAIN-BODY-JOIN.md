# Proof-Carrying Action Gate — joining the brain to the body

> **Vision.** Tex is the first voice of AI. Today it can *decide* (the brain) and it
> can *prove* (the receipt spine), but the decision isn't yet wired to *act*. This is
> the plan to join them — and to do it in a way **no one has shipped**, so Tex sets the
> standard instead of copying it.

**Branch:** `feat/proof-carrying-gate` (off `main` in `~/dev/tex`)
**Status:** plan only — no code written yet. This doc is the seed for a fresh build thread.
**Date:** 2026-06-18

---

## 1. The bet (in one sentence)

Build an **un-bypassable, in-path gate** that, for **every** agent action, **synchronously
asks Tex's decision brain**, **blocks the forbidden ones before they execute**, and emits a
**per-decision, offline-verifiable, externally-anchored receipt bound to a cryptographically
attested agent identity.**

That specific fusion — **enforce AND prove, verifiably, per-decision, identity-bound** — is
**unowned as of mid-June 2026** (verified below). It is the thing Tex is uniquely positioned
to own, because it already holds the hardest leg.

---

## 2. The verified landscape (why this is the white space)

From a fact-checked deep-research pass (mid-June 2026; sources are real but several are
*individual* IETF drafts / self-sourced repos — do **not** cite them as adopted standards):

The field splits into three camps, and **no single shipped system spans all four criteria**:

| Player | Blocks in-path? | Verifiable proof? | Externally anchored? | Attested identity? |
|---|:--:|:--:|:--:|:--:|
| **Pipelock** (shipping AI-agent firewall, the closest) | ✅ | ✅ Ed25519, hash-chained | ❌ self-asserted clock | ❌ self-declared string |
| **Sello / AIVS / akmon / ACTA / Asqav** (proof-only) | ❌ | ✅ | ✅ (some: RFC-3161 / Merkle) | ✅ (some) |
| **AgentROA / PCAA** (spec/paper only, not built) | spec | spec | ❌ local clock | ❌ id is a field |

**The decisive insight:** the two legs the closest *shipping* competitor (Pipelock) is
missing are **external anchoring** and **attested identity** — and **external anchoring is
the leg Tex already built and proved** (the RFC-3161 / freetsa / Ed25519 + Merkle receipt
spine; see the offline verifier `scripts/verify_conduit_receipt.py --selftest`). So Tex is
not behind the frontier on the differentiator — it **already holds the rarest piece** and is
missing the parts that are comparatively well-trodden (in-path enforcement, identity binding).

**Caveat / threat:** Pipelock's enterprise tier reportedly uses SPIFFE/mTLS per-agent
identity, so it could close the gap. The window is **narrowing, not open-ended** — speed
matters.

> **Full verified findings, players, votes, caveats, and open questions:**
> `docs/enforcement/RESEARCH-FINDINGS.md` (the durable in-repo copy of the deep-research pass).

Key sources (verify before quoting): Pipelock `github.com/luckyPipewrench/pipelock` +
`pipelab.org/learn/action-receipt-spec`; AgentROA `draft-nivalto-agentroa-route-authorization`;
PCAA `arXiv 2606.04104`; Sello `arXiv 2606.04193`; AIVS `draft-stone-aivs-00`; ACTA
`draft-farley-acta-signed-receipts-01`; Asqav `draft-marques-asqav-compliance-receipts-02`.

---

## 3. The architecture: the Proof-Carrying Action Gate

Synchronous, in-line, fail-closed. One pass per agent action:

```
agent action ─▶ [GATE] ──ask──▶ BRAIN (StandingGovernance.decide_for_request)
                  │                │
                  │           DecisionOutcome(verdict, released)
                  │                │
                  ├─ released? ────┤
                  │   PERMIT  ─▶ run the action, then seal an ALLOW receipt
                  │   FORBID  ─▶ DO NOT run (raise), seal a DENY receipt
                  │   ABSTAIN ─▶ DO NOT run, hold-to-voice, seal a HELD receipt
                  ▼
            SEAL (per decision): leaf ▶ EnforcementProvenanceChain
              → offline-verifiable receipt (payload hash + Merkle + Ed25519 note)
              → externally anchored (RFC-3161) so time/order can't be faked
              → bound to an ATTESTED agent identity (SPIFFE SVID / mTLS), not a string
```

Every allow **and** every deny produces a receipt a third party can verify **without
trusting Tex**. That is "proof-carrying enforcement": the action and its authorization travel
together, and the authorization is independently checkable.

---

## 4. What we reuse vs. build (grounded in the real code)

**Reuse (already built, verified working):**
- **Body** — `TexGate` / `tex_gated` (`src/tex/enforcement/gate.py`): on FORBID it raises and
  the wrapped callable never runs (fail-closed); **every gated execution emits exactly one
  `GateEvent`** to a configurable observer → that observer is the seam where we seal.
- **Brain** — `StandingGovernance.decide_for_request(request)` (`src/tex/governance/standing.py:333`),
  explicitly documented as *"the in-process PEP bridge."* Returns
  `DecisionOutcome(verdict, released, decision_id, evidence_hash, …)`.
- **Proof** — `ConduitReceipt` + `ConduitProvenanceChain` (`src/tex/discovery/conduit/seal.py`),
  the gix Ed25519 signed-note + RFC-3161 external anchor stack (`src/tex/interchange/gix.py`,
  `external_anchor.py`), and the offline verifier pattern (`scripts/verify_conduit_receipt.py`).

**Build (the genuinely new parts):**
- A `TexEvaluationTransport` adapter whose `.evaluate(request)` calls
  `standing.decide_for_request(request)` and maps `DecisionOutcome` → PERMIT-pass / non-release-block.
  **(This single adapter IS the brain↔body join.)**
- An enforcement-decision sealer: a `GateEventObserver` that appends a leaf per decision and
  produces a `ConduitReceipt`-shaped receipt. Add an `ENFORCEMENT_DECISION` event kind.
- External anchoring of the enforcement chain (Phase 1), attested identity (Phase 2),
  un-bypassable chokepoint (Phase 3), verifiable decision (Phase 4).

---

## 5. Phased build plan (smallest proof first)

> Founder-scale. Each phase ships and is provable on its own. Do **not** build ahead.

**Phase 0 — The join + the per-decision receipt (the smallest thing that proves it).**
- Wire `TexGate` → `decide_for_request` via the transport adapter.
- Seal one offline-verifiable receipt per allow/deny via a gate observer + new event kind.
- **Proof it ran:** a FORBID blocks the callable AND emits a receipt that verifies offline;
  flip one byte in the sealed payload → the verifier rejects it. Mirror
  `scripts/verify_conduit_receipt.py --selftest` with a `--selftest` for enforcement receipts.
- **All local. No network, no new infra.** Days, not weeks. *This is the first slice.*

**Phase 1 — External anchor.** Attach an RFC-3161 anchor to the enforcement chain checkpoint
(reuse `external_anchor.py` + the daily-anchor job pattern). Now receipts are un-backfillable.
*This is the leg Pipelock lacks.*

**Phase 2 — Attested identity.** Bind the receipt's actor to a SPIFFE SVID / mTLS client cert
— a real cryptographic credential, not a self-declared name. *The other leg Pipelock lacks.*

**Phase 3 — Un-bypassable, in-path.** Promote from the in-process gate to a network chokepoint
(the existing `src/tex/pep/proxy.py` deployed as an MCP/egress proxy via the operator sidecar,
`src/tex/operator/webhook.py`), so agents that don't call Tex voluntarily are still gated.
This is where "stop the action" becomes true for arbitrary agents, not just opted-in code.

**Phase 4 — The leap (the next paradigm).** zkML / verifiable-computation proof that the
**decision itself** was computed correctly per policy — third-party verifiable **without
trusting the gate operator.** PCAA names this as an unowned "future verification lane." This
is what makes Tex *set* the standard rather than match it. Research-grade; treat as aspirational.

---

## 6. Honest risks (do not overclaim)

- **Proof ≠ prevention until Phase 3.** Phases 0–2 enforce only for callables/agents that
  route *through* the gate (opt-in). The receipt proves a decision was made and (for the
  in-process gate) that the wrapped callable was not invoked — it does **not** prove an
  out-of-band side channel didn't act. True un-bypassability requires the network chokepoint
  (Phase 3) and depends on deployment-level isolation (forced egress).
- **Attestation is only as strong as its root.** A SPIFFE/mTLS identity is real; a string is
  theater. Don't claim "attested" before Phase 2.
- **External-anchor wiring is a known small gap, not new crypto.** The live conduit grant-seal
  currently passes `anchor=None`; the anchoring machinery is built and proven (freetsa) but not
  yet attached per-decision. Phase 1 attaches it.
- **In-memory chain = single-worker.** Like the conduit chain, the enforcement chain holds
  leaves in process. Single-worker first; shared store before scaling.
- **zkML (Phase 4) is immature/expensive.** Start with simpler verifiable computation if needed;
  label the strongest claim aspirational until shipped.

---

## 7. The standard we're setting

If this lands, the receipt becomes the unit of trust: **every agent action carries a
proof of its own authorization that anyone can check without trusting the operator, the
vendor, or Tex.** That is the "proof-carrying / attestation-bound agent action" — the future
standard the field is circling but no one has shipped. Tex gets there first by fusing the one
leg it already owns (externally-anchored, offline-verifiable receipts) with the in-path body.

---

## 8. Working style (the founder, Matt)

Plain language. One small step at a time — **show it ran, then propose the next.** Lead with
the vision; the proof is the receipt. **Never fake it** (no rigged demos, no planted results).
Confirm before hard-to-reverse / outward-facing actions (deploys, pushes). Pre-launch and
stretched — be a steady anchor, don't pile on complexity. Build Phase 0 and *prove it* before
touching Phase 1.
