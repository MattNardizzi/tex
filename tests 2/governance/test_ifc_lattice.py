"""Tests for the IFC lattice primitives (Thread 11)."""

from __future__ import annotations

import pytest

from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)


# ── IntegrityLevel ────────────────────────────────────────────────────


def test_integrity_lattice_total_order() -> None:
    levels = [
        IntegrityLevel.TOOL_DESC,
        IntegrityLevel.TOOL_UNTRUSTED,
        IntegrityLevel.TOOL_TRUSTED,
        IntegrityLevel.USER_INPUT,
        IntegrityLevel.SYS_INSTR,
    ]
    assert sorted(levels) == levels


def test_integrity_join_returns_minimum() -> None:
    assert IntegrityLevel.join(
        [IntegrityLevel.SYS_INSTR, IntegrityLevel.TOOL_UNTRUSTED]
    ) is IntegrityLevel.TOOL_UNTRUSTED
    assert IntegrityLevel.join(
        [IntegrityLevel.USER_INPUT, IntegrityLevel.TOOL_DESC]
    ) is IntegrityLevel.TOOL_DESC


def test_integrity_join_empty_defaults_to_sysinstr() -> None:
    assert IntegrityLevel.join([]) is IntegrityLevel.SYS_INSTR


def test_is_untrusted_threshold() -> None:
    assert IntegrityLevel.TOOL_UNTRUSTED.is_untrusted is True
    assert IntegrityLevel.TOOL_DESC.is_untrusted is True
    assert IntegrityLevel.TOOL_TRUSTED.is_untrusted is False
    assert IntegrityLevel.USER_INPUT.is_untrusted is False


# ── ConfidentialityLevel ──────────────────────────────────────────────


def test_confidentiality_join_returns_maximum() -> None:
    assert ConfidentialityLevel.join(
        [ConfidentialityLevel.PUBLIC, ConfidentialityLevel.RESTRICTED]
    ) is ConfidentialityLevel.RESTRICTED


def test_confidentiality_join_empty_defaults_to_public() -> None:
    assert ConfidentialityLevel.join([]) is ConfidentialityLevel.PUBLIC


def test_is_sensitive_threshold() -> None:
    assert ConfidentialityLevel.CONFIDENTIAL.is_sensitive is True
    assert ConfidentialityLevel.RESTRICTED.is_sensitive is True
    assert ConfidentialityLevel.INTERNAL.is_sensitive is False
    assert ConfidentialityLevel.PUBLIC.is_sensitive is False


# ── CapacityType (FIDES) ──────────────────────────────────────────────


def test_capacity_declassification_rule() -> None:
    assert CapacityType.BOOL.declassifies is True
    assert CapacityType.ENUM.declassifies is True
    assert CapacityType.NUMBER.declassifies is False
    assert CapacityType.TEXT.declassifies is False


# ── IfcLabel composite ────────────────────────────────────────────────


def test_label_join_integrity_floors_confidentiality_climbs() -> None:
    a = IfcLabel(
        integrity=IntegrityLevel.SYS_INSTR,
        confidentiality=ConfidentialityLevel.PUBLIC,
        capacity=CapacityType.BOOL,
    )
    b = IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
        capacity=CapacityType.TEXT,
    )
    joined = a.join(b)
    assert joined.integrity is IntegrityLevel.TOOL_UNTRUSTED
    assert joined.confidentiality is ConfidentialityLevel.RESTRICTED
    assert joined.capacity is CapacityType.TEXT


def test_flow_violation_predicate() -> None:
    untrusted_sensitive = IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
        capacity=CapacityType.TEXT,
    )
    assert untrusted_sensitive.is_flow_violation is True

    trusted_sensitive = IfcLabel(
        integrity=IntegrityLevel.SYS_INSTR,
        confidentiality=ConfidentialityLevel.RESTRICTED,
        capacity=CapacityType.TEXT,
    )
    assert trusted_sensitive.is_flow_violation is False

    untrusted_public = IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        capacity=CapacityType.TEXT,
    )
    assert untrusted_public.is_flow_violation is False


def test_may_declassify_flag() -> None:
    bool_label = IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
        capacity=CapacityType.BOOL,
    )
    assert bool_label.may_declassify is True

    text_label = IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
        capacity=CapacityType.TEXT,
    )
    assert text_label.may_declassify is False


def test_label_is_frozen() -> None:
    label = IfcLabel.trusted()
    with pytest.raises((TypeError, AttributeError, ValueError)):
        label.integrity = IntegrityLevel.TOOL_DESC  # type: ignore[misc]


def test_label_factories() -> None:
    assert IfcLabel.trusted().integrity is IntegrityLevel.SYS_INSTR
    assert IfcLabel.untrusted_public().integrity is IntegrityLevel.TOOL_UNTRUSTED
    assert (
        IfcLabel.sensitive_trusted().confidentiality
        is ConfidentialityLevel.RESTRICTED
    )
