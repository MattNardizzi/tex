"""
FIDES dual-axis (integrity × confidentiality) lattice in camel/capability.py.

Reference: FIDES, "Securing AI Agents with Information-Flow Control"
(arXiv:2505.23643). The load-bearing predicate is the product-lattice flow
violation: untrusted-integrity meeting sensitive-confidentiality.

These tests also pin the *isomorphism* with the codebase's other FIDES lattice
(``ifc.lattice``) so the two confidentiality vocabularies cannot drift apart.
"""

from __future__ import annotations

from tex.camel.capability import (
    Capability,
    CapabilityLevel,
    CapabilitySet,
    ConfidentialityLevel,
    FidesLabel,
)


# ── confidentiality axis ────────────────────────────────────────────────


def test_confidentiality_total_order_and_join() -> None:
    assert ConfidentialityLevel.PUBLIC < ConfidentialityLevel.INTERNAL
    assert ConfidentialityLevel.INTERNAL < ConfidentialityLevel.CONFIDENTIAL
    assert ConfidentialityLevel.CONFIDENTIAL < ConfidentialityLevel.RESTRICTED
    # join climbs to the most sensitive (dual of integrity's taint floor).
    j = ConfidentialityLevel.INTERNAL.join(ConfidentialityLevel.RESTRICTED)
    assert j is ConfidentialityLevel.RESTRICTED


def test_is_sensitive_threshold_is_confidential() -> None:
    assert not ConfidentialityLevel.PUBLIC.is_sensitive
    assert not ConfidentialityLevel.INTERNAL.is_sensitive
    assert ConfidentialityLevel.CONFIDENTIAL.is_sensitive
    assert ConfidentialityLevel.RESTRICTED.is_sensitive


# ── back-compat: the integrity axis is untouched ────────────────────────


def test_integrity_axis_unchanged_default_public() -> None:
    # Pre-FIDES construction sites keep their exact meaning: confidentiality
    # defaults to PUBLIC, integrity behaves as before.
    c = Capability.untrusted("email_body")
    assert c.level is CapabilityLevel.UNTRUSTED
    assert c.confidentiality is ConfidentialityLevel.PUBLIC
    s = CapabilitySet.of(Capability.trusted(), Capability.untrusted("doc"))
    assert s.level is CapabilityLevel.UNTRUSTED
    assert s.is_untrusted
    assert not s.is_sensitive  # no sensitive member


# ── the FIDES flow-violation predicate ──────────────────────────────────


def test_flow_violation_requires_both_axes() -> None:
    # untrusted but public → not a flow violation
    assert not FidesLabel(
        integrity=CapabilityLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
    ).is_flow_violation
    # trusted but sensitive → not a flow violation
    assert not FidesLabel(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
    ).is_flow_violation
    # untrusted AND sensitive → the canonical FIDES violation
    assert FidesLabel(
        integrity=CapabilityLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.CONFIDENTIAL,
    ).is_flow_violation


def test_capabilityset_fides_label_joins_both_axes() -> None:
    # An untrusted-but-public source joined with a trusted-but-sensitive source
    # yields the dangerous corner: untrusted ∧ sensitive.
    untrusted_public = Capability.untrusted("web_scrape")
    trusted_sensitive = Capability.sensitive("crm_record")
    s = CapabilitySet.of(untrusted_public, trusted_sensitive)
    label = s.fides_label
    assert label.integrity is CapabilityLevel.UNTRUSTED
    assert label.confidentiality is ConfidentialityLevel.CONFIDENTIAL
    assert label.is_flow_violation
    assert s.is_flow_violation


def test_label_join_is_high_water_mark_on_both_axes() -> None:
    a = FidesLabel(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
    )
    b = FidesLabel(
        integrity=CapabilityLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
    )
    j = a.join(b)
    assert j.integrity is CapabilityLevel.UNTRUSTED  # taint spreads
    assert j.confidentiality is ConfidentialityLevel.RESTRICTED  # sensitivity spreads
    assert j.is_flow_violation


def test_empty_set_is_trusted_public() -> None:
    s = CapabilitySet.empty()
    assert s.confidentiality is ConfidentialityLevel.PUBLIC
    assert not s.is_sensitive
    assert not s.is_flow_violation
    assert s.fides_label.integrity is CapabilityLevel.TRUSTED


# ── isomorphism with the canonical IFC FIDES lattice ─────────────────────


def test_confidentiality_isomorphic_to_ifc_lattice() -> None:
    """camel's confidentiality axis must agree name-for-name with ifc.lattice.

    A divergent second FIDES lattice would be a real correctness/credibility
    hazard; this pins them together.
    """
    from tex.governance.private_data_exec.ifc.lattice import (
        ConfidentialityLevel as IfcConfidentiality,
    )

    camel_names = {m.name for m in ConfidentialityLevel}
    ifc_names = {m.name for m in IfcConfidentiality}
    assert camel_names == ifc_names
    for name in camel_names:
        # same ordinal and same is_sensitive threshold on both lattices
        assert int(ConfidentialityLevel[name]) == int(IfcConfidentiality[name])
        assert (
            ConfidentialityLevel[name].is_sensitive
            == IfcConfidentiality[name].is_sensitive
        )
