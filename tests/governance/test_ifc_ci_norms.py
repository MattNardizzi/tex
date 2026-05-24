"""Tests for the CA-CI norm model (Thread 11)."""

from __future__ import annotations

import pytest

from tex.governance.private_data_exec.ifc.ci_norms import (
    CiNorm,
    CiNormRegistry,
    TransmissionPrinciple,
)


def _norm(
    *,
    sender: str = "agent",
    receiver: str = "vendor@example.com",
    subject: str = "alice",
    information_type: str = "contact",
    transmission_principle: TransmissionPrinciple = TransmissionPrinciple.CONSENT,
    purpose: str = "lead_followup",
) -> CiNorm:
    return CiNorm(
        sender=sender,
        receiver=receiver,
        subject=subject,
        information_type=information_type,
        transmission_principle=transmission_principle,
        purpose=purpose,
    )


def test_norms_normalize_case() -> None:
    n = _norm(sender="Agent")
    assert n.sender == "agent"


def test_norms_equality_via_matches() -> None:
    a = _norm()
    b = _norm()
    assert a.matches(b) is True


def test_norms_mismatch_on_any_field() -> None:
    base = _norm()
    assert base.matches(_norm(receiver="other@example.com")) is False
    assert base.matches(_norm(subject="bob")) is False
    assert base.matches(_norm(information_type="medical")) is False
    assert base.matches(
        _norm(transmission_principle=TransmissionPrinciple.COMMERCIAL)
    ) is False


def test_purpose_change_distinguishes_norms() -> None:
    """CA-CI scope-creep detection: same flow, different purpose, is
    a distinct norm."""
    base = _norm()
    drift = base.with_purpose("marketing_blast")
    assert base.matches(drift) is False


def test_blank_field_rejected() -> None:
    with pytest.raises(ValueError):
        _norm(purpose="   ")


def test_registry_permits_when_norm_present() -> None:
    target = _norm()
    registry = CiNormRegistry(norms=(target,))
    assert registry.is_permitted(target) is True


def test_registry_denies_when_norm_absent() -> None:
    registry = CiNormRegistry(norms=(_norm(purpose="x"),))
    assert registry.is_permitted(_norm(purpose="y")) is False


def test_registry_empty_denies_all() -> None:
    """Default-empty registry corresponds to fail-closed CI."""
    registry = CiNormRegistry()
    assert registry.is_permitted(_norm()) is False
