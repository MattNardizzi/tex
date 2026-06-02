# Two-Sided Hold — Integration Notes

What shipped in this drop, across both repos. The architecture and the research
behind it live in `TEX_ABSTAIN_DOCTRINE.md`; this is the wiring record.

## The one sentence

ABSTAIN — the only verdict the operator ever sees — now stands on the same
caliber of object as a PERMIT certificate or a FORBID proof: a **two-sided
certified hold band**, a **typed** abstention (epistemic vs aleatoric), and the
**single pivotal question** that would resolve it — produced by the real engine,
carried end-to-end to the voice surface, and pushed live over SSE.

---

## Backend (`tex/`)

**`src/tex/engine/crc_gate.py` — the two-sided gate.**
The CRC gate now bounds *both* sides. Alongside the existing false-permit cutoff
`lambda_hat` it calibrates a false-forbid cutoff `lambda_forbid` (RCPS /
Hoeffding–Bentkus, the same machinery), so the certified **hold band**
`[lambda_hat, lambda_forbid]` is the region where neither a PERMIT nor a FORBID
can be certified at its budget. The `CRCCertificate` gained the forbid-side and
hold-band fields (all defaulted → older certificates/tests stay valid).
**Monotone-safe is preserved**: the verdict transform is still demotion-only and
**never relaxes a FORBID** — the second bound makes the hold *auditable*, it does
not unblock anything. New optional ctor arg `alpha_forbid` (defaults to `alpha`).

**`src/tex/engine/hold.py` — the first-class Hold (new).**
`build_hold(...)` turns an ABSTAIN into a typed, self-resolving object: an
epistemic/aleatoric *score* (not a brittle label — margin-based, degrades to
MIXED), a `resolution_mode` (SELF_HEAL / HUMAN_FACT / HUMAN_JUDGMENT), and the
`resolving_question` — the one pivotal fact, derived deterministically from the
uncertainty flags the pipeline already raised (the EPIG-style VOI *seam*; honest
that a full predictive-info-gain ranking is a Layer-6 dependency). Pure and
deterministic, so the PDP determinism fingerprint is preserved.

**`src/tex/engine/pdp.py` — wiring.**
After the CRC step, on (and only on) a final ABSTAIN, the PDP builds the Hold and
surfaces it at `decision.metadata["pdp"]["hold"]`.

**`src/tex/governance/standing.py` — the live path.**
The standing PDP's ABSTAIN branch now pulls `metadata["pdp"]["hold"]` and queues
it on the held-decision sink (with the decision id + sealed anchor), so the real
typed Hold reaches the voice. Falls back to the flat note if no hold is present.

**`src/tex/provenance/feed.py` — `HeldDecision` carries the hold.**
Three additive optional fields (`hold`, `decision_id`, `anchor_sha256`).

**`src/tex/vigil/held_provider.py` — the vigil seam (new).**
`HeldDecisionVigilProvider` adapts the held-decision sink into the `/v1/vigil`
`human_decision` channel, tenant-scoped, read-only, never blocks the cycle.

**`src/tex/api/vigil_routes.py` — contract + SSE.**
`human_decision` is now a `HumanDecisionDTO` carrying a `HoldDTO`
(`hold_type, resolution_mode, resolving_question, epistemic/aleatoric_score,
band_certified, band_lower/upper`). New endpoint **`GET /v1/vigil/stream`**
(`text/event-stream`): the live voice as SSE — `event: vigil` frames, monotonic
`id:` for resume, heartbeat comments, `X-Accel-Buffering: no`. Same auth as the
poll (`decision:read`).

**`src/tex/main.py`** wires `app.state.held_decision_provider`.

**Tests:** `tests/test_two_sided_hold.py` (11, all green) — two-sided band
structure, monotone-safety (FORBID never relaxed), certificate carries both
bounds, typed/self-resolving holds, determinism, honest uncertified posture.
Regression: `test_crc_gate.py` (13) + `test_pdp_crc_path_integration.py` (9)
green. One unrelated pre-existing discovery-reconciliation failure in
`test_governance_endpoint.py` is unchanged by this work (verified against a clean
tree).

### Going live (the honest posture)
The hold band is *capability-wired, guarantee-inert* until calibration arrives —
exactly like the existing CRC gate. With no labelled calibration set the gate is
pass-through and `band_certified` is `false` (the surface shows no watermark; Tex
never displays a guarantee it can't stand behind). Feed the gate a two-sided
calibration set (past decisions tagged actually-unsafe / actually-safe, from
Layer-6 outcome validation) and the live band + watermark turn on.

---

## Frontend (`tex-systems/`)

**`src/lib/texApi.js`** — documents the real `human_decision` + `hold` contract;
adds `vigilStreamUrl(tenantId)` (the SSE URL; rides the existing same-origin
proxy untouched — the proxy already pipes `text/event-stream` through).

**`src/hooks/useVigil.js`** — upgraded to the 2026 SOTA push: subscribes to
`/v1/vigil/stream` via **EventSource** (native auto-reconnect + `Last-Event-ID`
resume), renders each frame on arrival, and **falls back to the 30s poll** if
EventSource is unavailable or the browser stops retrying. State updates only on
change (no React churn, rotation stays steady). Silence remains the failure mode.

**`src/components/Dashboard/Vigil.jsx`** — the held card renders the real hold:
the **typed line** (whether a fact could resolve it), the **resolving question**
(set apart, italic — the pivotal fact, never the case file), and the
**certified-band watermark** (monospace, shown only when `band_certified`). The
preview `DEMO_ABSTAIN` was upgraded to the exact wire shape, so what you see in
preview is precisely what the backend delivers.

**`src/components/Dashboard/Vigil.css`** — `.tex-held-hold`, `.tex-held-type`,
`.tex-held-question`, `.tex-held-cert`, in the locked tokens (Source Serif 4 /
Inter / SF Mono).

`npm run build` is green (Vite, 42 modules). The WebSocket stays only where it's
genuinely bidirectional (the recognizer); the one-way voice is SSE.

---

## What's next (doctrine build sequence)
This is build **#1 (the certified band)** + the surface that renders it. Builds
2–5 attach to the certificate object: deterministic self-heal (fetch the pivotal
fact, clear without a human), the anytime-valid e-process for the live stream,
and calibrated joint-outcome deferral once Layer-6 reviewer labels exist.
