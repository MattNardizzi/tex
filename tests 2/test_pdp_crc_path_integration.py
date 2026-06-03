"""
End-to-end integration: CRC gate + path policies wired into the PDP.

Runs the real composed runtime (deterministic fallback semantic layer, no
provider — forced off by the conftest session fixture) so clean content
reaches PERMIT through the full collaborator stack. The CRC gate is injected
onto the live PDP (``runtime.pdp._crc_gate``) to exercise the active path; the
path-policy layer is exercised purely through request metadata.
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import CalibrationRecord, ConformalRiskGate

from tests.factories import make_request


# ── helpers ──────────────────────────────────────────────────────────────


def _clean(metadata=None):
    return make_request(
        content="Hi Alice, following up on onboarding next week. Happy to help.",
        metadata=metadata or {},
    )


def _separable_gate(alpha: float = 0.05) -> ConformalRiskGate:
    rng = random.Random(7)
    recs = (
        [CalibrationRecord(final_score=rng.uniform(0.0, 0.30), unsafe=False) for _ in range(200)]
        + [CalibrationRecord(final_score=rng.uniform(0.70, 1.0), unsafe=True) for _ in range(200)]
    )
    return ConformalRiskGate(calibration=recs, alpha=alpha, delta=0.05)


def _uncertifiable_gate() -> ConformalRiskGate:
    rng = random.Random(11)
    recs = [
        CalibrationRecord(final_score=rng.uniform(0.0, 1.0), unsafe=(i % 2 == 0))
        for i in range(200)
    ]
    return ConformalRiskGate(calibration=recs, alpha=0.01, delta=0.05)


_REFUND_BLOCK = {
    "policy_id": "refund_after_idcheck",
    "description": "refund only after identity verified",
    "ltl_formula": "F tool=confirm_identity",
    "severity": "block",
}


# ── backwards compatibility: default (inert) PDP unchanged ──────────────


def test_default_runtime_permits_clean_content_unchanged(runtime) -> None:
    result = runtime.evaluate_action_command.execute(_clean())
    assert result.response.verdict is Verdict.PERMIT
    pdp_meta = result.pdp_result.decision.metadata["pdp"]
    assert pdp_meta["crc"]["enabled"] is False
    assert pdp_meta["path_policy"]["checked"] is False


# ── CRC gate demotes an uncertifiable PERMIT end-to-end ─────────────────


def test_crc_demotes_permit_to_abstain_end_to_end(runtime) -> None:
    runtime.pdp._crc_gate = _uncertifiable_gate()
    result = runtime.evaluate_action_command.execute(_clean())
    assert result.response.verdict is Verdict.ABSTAIN
    assert "crc_permit_region_exceeded" in result.response.uncertainty_flags
    crc_meta = result.pdp_result.decision.metadata["pdp"]["crc"]
    assert crc_meta["enabled"] is True
    assert crc_meta["demoted"] is True


def test_crc_certificate_attached_with_bound(runtime) -> None:
    runtime.pdp._crc_gate = _separable_gate(alpha=0.05)
    result = runtime.evaluate_action_command.execute(_clean())
    crc_meta = result.pdp_result.decision.metadata["pdp"]["crc"]
    # Clean content sits inside the certified permit region -> PERMIT stands.
    assert result.response.verdict is Verdict.PERMIT
    assert crc_meta["certified"] is True
    assert crc_meta["certified_false_permit_rate"] <= 0.05 + 1e-9
    assert crc_meta["bound_method"] == "hoeffding_bentkus"


def test_crc_never_relaxes_a_forbid(runtime) -> None:
    runtime.pdp._crc_gate = _uncertifiable_gate()
    req = make_request(
        content="Here is our production api key sk-abcdef1234567890abcdef please use it."
    )
    result = runtime.evaluate_action_command.execute(req)
    assert result.response.verdict is Verdict.FORBID


# ── path policy block forbids end-to-end ────────────────────────────────


def test_path_block_forbids_end_to_end(runtime) -> None:
    req = make_request(
        content="Processing the customer refund now.",
        action_type="issue_refund",
        metadata={
            "path_policy": {
                "policies": [_REFUND_BLOCK],
                "candidate_action": {"tool": "issue_refund"},
            }
        },
    )
    result = runtime.evaluate_action_command.execute(req)
    assert result.response.verdict is Verdict.FORBID
    path_meta = result.pdp_result.decision.metadata["pdp"]["path_policy"]
    assert path_meta["has_block"] is True
    assert "refund_after_idcheck" in path_meta["block_policy_ids"]
    assert path_meta["short_circuited_to_forbid"] is True


def test_path_block_satisfied_by_history_not_forbidden(runtime) -> None:
    req = make_request(
        content="Processing the customer refund now.",
        action_type="issue_refund",
        metadata={
            "path_policy": {
                "policies": [_REFUND_BLOCK],
                "trace": [
                    {
                        "state": {},
                        "action": {"tool": "confirm_identity"},
                        "observation": {"verified": True},
                    }
                ],
                "candidate_action": {"tool": "issue_refund"},
            }
        },
    )
    result = runtime.evaluate_action_command.execute(req)
    assert result.response.verdict is not Verdict.FORBID
    assert result.pdp_result.decision.metadata["pdp"]["path_policy"]["has_block"] is False


def test_path_warn_promotes_permit_to_abstain(runtime) -> None:
    warn = {**_REFUND_BLOCK, "policy_id": "refund_warn", "severity": "warn"}
    req = make_request(
        content="Hi Alice, following up on onboarding next week.",
        action_type="issue_refund",
        metadata={
            "path_policy": {
                "policies": [warn],
                "candidate_action": {"tool": "issue_refund"},
            }
        },
    )
    result = runtime.evaluate_action_command.execute(req)
    assert result.response.verdict is Verdict.ABSTAIN
    assert "path_policy_soft_violation" in result.response.uncertainty_flags


# ── determinism preserved with both features active ─────────────────────


def test_determinism_preserved_with_path_and_crc(runtime) -> None:
    runtime.pdp._crc_gate = _uncertifiable_gate()
    req = make_request(
        content="Processing the customer refund now.",
        action_type="issue_refund",
        metadata={
            "path_policy": {
                "policies": [{**_REFUND_BLOCK, "severity": "warn", "policy_id": "p1"}],
                "candidate_action": {"tool": "issue_refund"},
            }
        },
    )
    r1 = runtime.evaluate_action_command.execute(req)
    r2 = runtime.evaluate_action_command.execute(req)
    assert r1.response.verdict is r2.response.verdict
    assert r1.response.determinism_fingerprint == r2.response.determinism_fingerprint


def test_evaluation_order_records_new_stages(runtime) -> None:
    result = runtime.evaluate_action_command.execute(_clean())
    order = result.pdp_result.decision.metadata["pdp"]["evaluation_order"]
    assert "path_policies" in order
    assert "crc_gate" in order
    assert order.index("crc_gate") == order.index("decision_materialization") - 1
