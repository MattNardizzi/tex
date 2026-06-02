# Layer 4 (Execution Governance) — Where It Stands

> Plain-language status of the permit/forbid layer after the CRC + structural-floor +
> path-policy + adaptive-harness work. Honest scorecard: what is solid, what is still
> open. Drop this in `docs/layers/` and keep it current.

## One-line summary

The decision layer is **structurally robust and now carries a statistical guarantee** —
a fundable, defensible Layer 4 — but it is **not "finished" or "unbeatable,"** and there
are three open items disclosed below. Claiming perfection is the one move that loses a
sophisticated room; this layer's strength is that it tells the truth about itself.

## What the layer does

For every proposed agent action it fuses its risk signals and returns one of three
verdicts — **PERMIT / ABSTAIN / FORBID** — with a confidence, a deterministic
fingerprint (so the same input always reproduces the same decision), and an evidence
record. It is the engine the rest of Tex feeds or consumes.

## Decision vs. enforcement — a FORBID actually stops the action

The PDP above is a *decision point*: it rules and seals, it does not itself reach into
the world. Enforcement is a separate, wired layer — the *policy enforcement point* (PEP)
— and it is real: a FORBID (or any non-release: ABSTAIN, unknown/unsealed agent, or the
deep PDP being unreachable) blocks the action, fail-closed. This is **one enforcement
layer with three deployment shapes, sharing one decision authority and one transport
protocol**, not three competing things:

1. **Network PEP** — `tex.pep`: a transparent, MCP-aware enforcement proxy plus an eBPF
   kernel-floor, auto-injected as a sidecar by `tex.operator` (ambient/ztunnel style).
   On a non-release it returns 403 and never forwards upstream; on an MCP `tools/list`
   it strips the response to the agent's sealed capability surface so the agent never
   learns a forbidden tool exists. *Verified by execution: a FORBID returns 403 and the
   request never reaches the upstream.*

2. **In-process gate** — `enforcement/` via `build_standing_gate(governor)`: wraps any
   callable an agent invokes so it cannot execute unless the full two-tier standing PDP
   permits — no HTTP hop. Routes through `StandingGovernanceTransport`, so it makes the
   *identical* ruling the network PEP makes, fail-closed floor included. Now wired into
   the composition root as `app.state.standing_gate`. *Verified by execution: a FORBID
   raises and the wrapped callable never runs.*

3. **Developer SDK** — `sdks/python/tex_guardrail`: the `@gate` decorator and `TexClient`
   over HTTP for teams adding a guardrail call to their own agent. Ships first-party
   framework integrations under `tex_guardrail.integrations` (LangChain `TexCallbackHandler`
   + `guard_tool`; CrewAI/MCP adapters available in-process).

All three honor the same contract: **FORBID always blocks (no override), PERMIT passes
through, ABSTAIN is configurable (`AbstainPolicy`: BLOCK default / ALLOW / REVIEW→human),
transport failure fails closed.** The single boolean every PEP obeys is `released`, and
only the deep PDP's PERMIT sets it true.

**Consolidation (this pass):** removed the older redundant ASGI proxy that used to live in
`enforcement/proxy.py` (superseded by the MCP-aware `tex.pep` proxy); exposed
`build_standing_gate` in the composition root; gave the SDK its promised
`tex_guardrail.integrations.langchain` module (previously referenced but missing); unified
the in-process shapes on the `TexEvaluationTransport` protocol (`DirectCommandTransport`
in-process, `HttpClientTransport` over the wire, `StandingGovernanceTransport` for the full
two-tier PDP).

## What is solid (shipped + tested)

1. **Certified false-permit bound (CRC gate).** The final verdict is no longer decided by
   hand-tuned thresholds alone. When calibrated on labelled outcomes, the gate provides a
   finite-sample, distribution-free bound: "a PERMIT leaks a genuinely unsafe action at
   most α of the time, at confidence 1−δ." It is **monotone-safe** — it can only make a
   verdict more conservative (PERMIT→ABSTAIN), never relax one, so wiring it in cannot
   create a new false-permit. Every decision carries an auditable certificate.
   *(RCPS / Hoeffding–Bentkus; Bates et al., JACM 2021.)*

2. **Structural FORBID floor.** The four deterministic structural defenses — PCAS
   (Datalog deny), CaMeL (capability denial), IFC (typed flow violation), ARGUS
   (counterfactual injection proof) — now FORBID on their own instead of being averaged
   into a weighted vote. Fixes the tier inversion where a *proven* deny on clean content
   used to land at ABSTAIN. Fires only on a genuine deterministic deny signature, never on
   a merely-high probabilistic score.

3. **Sequence-aware path governance (path policies).** The PDP can now judge an action by
   the *order it occurs in* — "refund only after identity check," "deploy only after
   tests then approval" — not just the action in isolation. Block → FORBID, warn →
   ABSTAIN, audit → finding. *(Kaptein et al., arXiv:2603.16586.)*

4. **An adversarial harness that tells the truth.** Static fixtures are replaced by an
   adaptive "attacker-moves-second" search that tries to bypass the live decision layer,
   runnable as a CI gate. It reports real attack-success rates by defense class.
   *(Reproduces the Nasr et al. arXiv:2510.09023 evaluation methodology.)*

**Evidence it holds:** in the adaptive campaign, the **structural defense class held at
0% attack-success rate** across the full query budget — content obfuscation cannot move a
decision computed over the action graph. That is the load-bearing result.

## What is still open (disclosed, on the roadmap — not hidden)

1. **Lexical pre-filter is obfuscation-bypassable.** The adaptive harness found the
   regex/lexical layer is ~100% bypassable by simple tricks (e.g. leetspeak:
   `drop table` → `dr0p t@bl3`). This is the cheap pre-filter, not the load-bearing
   structural layer, but it is a real defect. **Fix:** input canonicalization
   (unicode-fold, leet-decode, homoglyph collapse, zero-width strip) ahead of the lexical
   recognizers. Scoped, scheduled as "Fix #5," not yet built.

2. **The CRC gate ships inert until fed real data.** The bound is only as honest as the
   labelled calibration set behind it. Until Layer 6 outcome validation supplies real
   labels, the gate is pass-through. The *capability* is wired; the *live guarantee* needs
   your data.

3. **CRC assumes exchangeable data.** Plain conformal risk control is finite-sample valid
   under exchangeability. Under an adaptive, online-updated stream the stronger object is
   an anytime-valid (e-process) version — a future upgrade, not a current need.

4. **PEP data-plane coverage needs a real-cluster smoke test.** The userspace enforcement
   proxy and the in-process gate are verified to block by execution (403/no-forward; raise/
   no-run). What is *not* yet verified end-to-end in CI is the eBPF kernel-floor + operator
   auto-injection that make coverage automatic and total in a live cluster — the eBPF
   program lives outside the Python package and needs a real kernel. **Before staking the
   "you can sleep" promise in a room, run a cluster smoke test that shows a forbidden
   destination dropped by the eBPF redirect with no sidecar explicitly configured.** The
   enforcement *mechanism* is proven; the *automatic total coverage* rides on that layer.

## The honest sentence for diligence

> "Our decision layer is structurally robust and carries a certified false-permit bound;
> here's the adaptive red-team that proves the structural defenses hold at zero and the
> two gaps we're hardening." — **not** "it's good now, it doesn't make mistakes."

## Test footprint

- `tests/test_crc_gate.py`, `tests/test_pdp_crc_path_integration.py`
- `tests/test_path_policy_bridge.py`
- `tests/test_structural_floor.py`
- `tests/adversarial/test_adaptive.py`
- `tests/test_enforcement.py` — the in-process gate, transports, framework adapters
- `tests/test_enforcement_consolidation.py` — in-process FORBID blocks the callable;
  standing transport satisfies `TexEvaluationTransport`; the redundant ASGI proxy is gone
- Full suite: no new regressions introduced by this work.
