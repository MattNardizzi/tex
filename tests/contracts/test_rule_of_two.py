"""
Rule-of-Two structural contract (tex.contracts.rule_of_two).

Meta "Agents Rule of Two" (2025-10-31): untrusted-input ∧ sensitive-access ∧
state-change, with no human oversight → not safe to operate autonomously →
FORBID. The contract fires only when all three are PROVEN present (a structural
FORBID is a proof, not a guess).
"""

from __future__ import annotations

from tex.contracts.rule_of_two import (
    classify_rule_of_two,
    evaluate_rule_of_two,
)

from tests.factories import make_request


# ── explicit-bucket form ────────────────────────────────────────────────


def test_all_three_buckets_fire() -> None:
    out = classify_rule_of_two(
        {"untrusted_input": True, "sensitive_access": True, "state_change": True}
    )
    assert out.fired is True
    assert set(out.present_buckets) == {
        "untrusted_input",
        "sensitive_access",
        "state_change",
    }


def test_only_two_buckets_does_not_fire() -> None:
    # Any one of the three missing breaks the trifecta — no fabricated FORBID.
    for missing in ("untrusted_input", "sensitive_access", "state_change"):
        block = {
            "untrusted_input": True,
            "sensitive_access": True,
            "state_change": True,
        }
        block[missing] = False
        assert classify_rule_of_two(block).fired is False, missing


def test_human_oversight_disarms_the_trifecta() -> None:
    out = classify_rule_of_two(
        {
            "untrusted_input": True,
            "sensitive_access": True,
            "state_change": True,
            "human_oversight": True,
        }
    )
    assert out.fired is False  # supervised → not autonomous → not forbidden
    # but the trifecta is still recognised in the buckets
    assert len(out.present_buckets) == 3


def test_absent_bucket_is_not_proven_not_assumed_present() -> None:
    # A bucket with no evidence is treated as NOT present (FORBID needs proof).
    out = classify_rule_of_two(
        {"untrusted_input": True, "sensitive_access": True}  # state_change absent
    )
    assert out.fired is False
    assert out.state_change is False


# ── FIDES-label-derived form ────────────────────────────────────────────


def test_derive_buckets_from_fides_capabilities_and_action() -> None:
    out = classify_rule_of_two(
        {
            "capabilities": [
                {"level": "UNTRUSTED", "confidentiality": "PUBLIC", "source": "web"},
                {"level": "TRUSTED", "confidentiality": "RESTRICTED", "source": "crm"},
            ],
            "action": {"external": True},
        }
    )
    assert out.fired is True
    assert out.untrusted_input is True
    assert out.sensitive_access is True
    assert out.state_change is True
    assert out.evidence.get("untrusted_sources") == ["web"]
    assert out.evidence.get("sensitive_sources") == ["crm"]


def test_derive_no_sensitive_source_does_not_fire() -> None:
    out = classify_rule_of_two(
        {
            "capabilities": [
                {"level": "UNTRUSTED", "confidentiality": "INTERNAL", "source": "web"},
            ],
            "action": {"external": True},
        }
    )
    # INTERNAL is below the is_sensitive threshold → bucket B not proven.
    assert out.fired is False
    assert out.sensitive_access is False


def test_unknown_level_string_is_ignored_not_dangerous() -> None:
    out = classify_rule_of_two(
        {
            "capabilities": [
                {"level": "BOGUS", "confidentiality": "ALSO_BOGUS", "source": "x"},
            ],
            "action": {"state_change": True},
        }
    )
    assert out.untrusted_input is False
    assert out.sensitive_access is False
    assert out.fired is False


# ── request wrapper ─────────────────────────────────────────────────────


def test_evaluate_no_metadata_is_neutral() -> None:
    assert evaluate_rule_of_two(make_request()).fired is False


def test_evaluate_reads_request_metadata() -> None:
    req = make_request(
        metadata={
            "rule_of_two": {
                "untrusted_input": True,
                "sensitive_access": True,
                "state_change": True,
            }
        }
    )
    assert evaluate_rule_of_two(req).fired is True
