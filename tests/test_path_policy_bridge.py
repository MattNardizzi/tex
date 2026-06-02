"""
Tests for the path-policy bridge (engine/path_policy_bridge.py).

Verifies: inert when no metadata; block -> hard violation; warn -> soft
violation with promotion flag; audit -> findings only; trace replay matters
(same candidate, different history -> different outcome).
"""

from __future__ import annotations

from tex.engine.path_policy_bridge import (
    NEUTRAL_PATH_OUTCOME,
    evaluate_path_policies_for_request,
)

from tests.factories import make_request


_REFUND_BLOCK = {
    "policy_id": "refund_after_idcheck",
    "description": "refund only after identity verified",
    "ltl_formula": "F tool=confirm_identity",
    "severity": "block",
}
_REFUND_WARN = {**_REFUND_BLOCK, "policy_id": "refund_warn", "severity": "warn"}
_REFUND_AUDIT = {**_REFUND_BLOCK, "policy_id": "refund_audit", "severity": "audit"}


def _req(metadata):
    return make_request(content="please issue the refund", metadata=metadata)


def test_no_metadata_is_inert() -> None:
    out = evaluate_path_policies_for_request(request=make_request())
    assert out is NEUTRAL_PATH_OUTCOME
    assert out.checked is False
    assert out.has_block is False


def test_empty_policies_is_inert() -> None:
    out = evaluate_path_policies_for_request(
        request=_req({"path_policy": {"policies": []}})
    )
    assert out.checked is False


def test_block_violation_no_history() -> None:
    out = evaluate_path_policies_for_request(
        request=_req(
            {
                "path_policy": {
                    "policies": [_REFUND_BLOCK],
                    "candidate_action": {"tool": "issue_refund"},
                }
            }
        )
    )
    assert out.checked is True
    assert out.has_block is True
    assert "refund_after_idcheck" in out.block_policy_ids
    assert out.forbid_reason is not None
    assert any(f.rule_name == "refund_after_idcheck" for f in out.findings)


def test_block_satisfied_by_history() -> None:
    out = evaluate_path_policies_for_request(
        request=_req(
            {
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
            }
        )
    )
    assert out.checked is True
    assert out.has_block is False
    assert out.history_length == 1


def test_warn_is_soft_not_block() -> None:
    out = evaluate_path_policies_for_request(
        request=_req(
            {
                "path_policy": {
                    "policies": [_REFUND_WARN],
                    "candidate_action": {"tool": "issue_refund"},
                }
            }
        )
    )
    assert out.has_block is False
    assert out.has_warn is True
    assert "path_policy_soft_violation" in out.soft_uncertainty_flags


def test_audit_only_emits_finding() -> None:
    out = evaluate_path_policies_for_request(
        request=_req(
            {
                "path_policy": {
                    "policies": [_REFUND_AUDIT],
                    "candidate_action": {"tool": "issue_refund"},
                }
            }
        )
    )
    assert out.has_block is False
    assert out.has_warn is False
    assert "refund_audit" in out.audit_policy_ids
    assert len(out.findings) == 1


def test_candidate_action_defaults_to_request_action_type() -> None:
    # No explicit candidate_action: bridge derives one from action_type.
    out = evaluate_path_policies_for_request(
        request=make_request(
            action_type="issue_refund",
            content="refund please",
            metadata={"path_policy": {"policies": [_REFUND_BLOCK]}},
        )
    )
    assert out.checked is True
    # No confirm_identity in history -> block fires.
    assert out.has_block is True
