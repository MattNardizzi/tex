# Layer 4 — Activating CRC + Path Policies

Both features shipped **wired but inert**. The PDP behaves bit-for-bit as before
until you turn them on. Here is how.

## Conformal Risk Control (CRC) verdict gate

What it does: puts a finite-sample, distribution-free bound on the **false-permit
rate**. After calibration on labelled outcomes, any PERMIT whose fused score lies
outside the certified region is demoted to ABSTAIN, and every decision carries a
certificate stating the certified false-permit rate.

It is **monotone-safe**: it can only ever make a verdict more conservative
(PERMIT → ABSTAIN). It never relaxes a FORBID/ABSTAIN and never creates a PERMIT,
so wiring it in cannot introduce a new false-permit — only remove one.

### Turning it on

```python
from tex.engine.crc_gate import CalibrationRecord, ConformalRiskGate
from tex.engine.pdp import PolicyDecisionPoint

# Labelled history: (fused final_score Tex produced, was-it-actually-unsafe).
# Source these from Layer 6 outcome validation, human review, or a red-team set.
calibration = [
    CalibrationRecord(final_score=0.04, unsafe=False),
    CalibrationRecord(final_score=0.91, unsafe=True),
    # ... a few hundred points; more points => tighter bound.
]

gate = ConformalRiskGate(
    calibration=calibration,
    alpha=0.02,   # target false-permit rate <= 2%
    delta=0.05,   # at 95% confidence
)
pdp = PolicyDecisionPoint(crc_gate=gate)
```

The certificate lands on every decision at
`decision.metadata["pdp"]["crc"]` — `certified_false_permit_rate` is the number
to put in front of a buyer or auditor.

Math: split-conformal RCPS (Bates et al., JACM 2021) with the tighter of the
Hoeffding and Bentkus upper bounds. `lambda_hat` is computed once at construction
and frozen, so evaluation stays fully deterministic and replay-safe. With no
calibration the gate is inert (pass-through, `certified=False`).

## Path policies (LTLf over the execution path)

What it does: judges an action by the **sequence** it occurs in, not in isolation
— "issue_refund only after confirm_identity", "never export after reading
untrusted input", "deploy_to_prod only after run_tests then approve". Closes the
PDP's per-action blind spot where sequence-shaped attacks live.

It is **opt-in per request** via metadata; absent metadata is a zero-cost no-op.

### Turning it on

Attach policies + the prior trace to the request:

```python
request.metadata["path_policy"] = {
    "policies": [
        {
            "policy_id": "refund_after_idcheck",
            "description": "refund only after identity verified",
            "ltl_formula": "F tool=confirm_identity",
            "severity": "block",   # block | warn | audit
        },
    ],
    "trace": [   # prior COMPLETED steps in this session (oldest first)
        {"state": {}, "action": {"tool": "confirm_identity"}, "observation": {"verified": True}},
    ],
    "candidate_action": {"tool": "issue_refund"},  # optional; defaults to action_type
}
```

Severity mapping (Kaptein et al., arXiv:2603.16586 §4.4):
- `block` → hard violation → PDP short-circuits to **FORBID** (joins the
  deterministic / structural FORBID floor).
- `warn`  → soft violation → promotes a router PERMIT to **ABSTAIN**.
- `audit` → finding only; verdict untouched.

LTLf grammar (atoms `tool=<name>`, `action.<k>=<v>`, `state.<k>>=<n>`, …;
operators `& | ! ->` and `G F X U`) is documented in
`src/tex/governance/path_policy/ltlf.py`.

The path-policy audit trail lands at `decision.metadata["pdp"]["path_policy"]`.

## Tests

```bash
pytest tests/test_crc_gate.py \
       tests/test_path_policy_bridge.py \
       tests/test_pdp_crc_path_integration.py
```

## Structural FORBID floor (automatic — no activation needed)

`specialists/structural_floor.py` runs on every evaluation. When PCAS, CaMeL,
IFC, or ARGUS emits its **deterministic-deny signature**, the PDP short-circuits
to FORBID instead of letting the proof dilute through the router's weighted sum.
It is always on and only ever raises severity (it cannot relax a verdict), so
there is nothing to configure. The deny signatures it recognises:

- **PCAS**  — `risk_score == 1.0` (Datalog FORBID verdict).
- **CaMeL** — `risk_score == 1.0` (capability denial / fail-closed interpreter error).
- **IFC**   — any `ifc.*` violation code in `matched_policy_clause_ids`
  (flow_integrity, min_trust_floor, causality_laundering, ci_norm_violation,
  neurotaint_cross_session, rule_of_two_trifecta).
- **ARGUS** — `ARGUS_DECISION_OBSERVATION_DRIVEN` (counterfactual injection proof).

A merely high probabilistic score never triggers the floor — only a proof.
Audit trail: `decision.metadata["pdp"]["structural_floor"]`.

## Adaptive red-team harness (the attacker moves second)

Replaces static-fixture evaluation with an adaptive search that tries to bypass
the live PDP.

```bash
# Run a campaign and fail (exit 1) if adaptive ASR exceeds the threshold.
python -m tex.adversarial --budget 80 --max-asr 0.34
```

```python
from tex.adversarial.adaptive import run_adaptive_campaign
from tex.adversarial.adaptive_seeds import build_runtime_scorer, default_seeds
from tex.main import build_runtime

report = run_adaptive_campaign(default_seeds(), build_runtime_scorer(build_runtime()))
print(report.static_asr, report.adaptive_asr, report.asr_for_class("structural"))
```

Threat model: the attacker controls the **content channel** (indirect injection),
not the action graph / capabilities / policy. That is why structural defenses
show ~0 adaptive ASR while content-lexical defenses do not.

**Known finding (first run):** lexical/deterministic recognizers are ~100%
adaptively bypassable via simple obfuscation (e.g. leetspeak); the structural
class holds at 0%. Input canonicalization in front of the deterministic + lexical
layers is the indicated next hardening step (a separate piece of work).
