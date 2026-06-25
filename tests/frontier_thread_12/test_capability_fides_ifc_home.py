"""
Isomorphism witness for the IFC home of the FIDES capability lattice.

``tex.governance.private_data_exec.ifc.capability_compat`` is the IFC package's
stable home for the CaMeL product lattice (decommission of ``tex.camel``). This
test PINS three-way agreement so the copied-verbatim symbols can never drift:

  1. The IFC home agrees, symbol-for-symbol, with the original
     ``tex.camel.capability`` (same enum names, ordinals, thresholds, and
     identical FIDES flow-violation behaviour).
  2. The IFC home's confidentiality axis is isomorphic to
     ``ifc.lattice.ConfidentialityLevel`` (the engine's own dual-axis ladder).
  3. The IFC home's integrity axis corresponds to ``ifc.lattice.IntegrityLevel``
     under the documented inverse encoding (camel.TRUSTED ↔ ifc.SYS_INSTR,
     camel.UNTRUSTED ↔ ifc.TOOL_UNTRUSTED), agreeing on the low-integrity
     ("untrusted") predicate.

Mirrors the witness in ``test_capability_fides.py`` but anchored on the IFC
home instead of ``tex.camel``.
"""

from __future__ import annotations

from tex.governance.private_data_exec.ifc.capability_compat import (
    Capability,
    CapabilityLevel,
    CapabilitySet,
    ConfidentialityLevel,
    FidesLabel,
)


# ── the IFC home reproduces camel.capability exactly ─────────────────────


def test_ifc_home_enums_match_camel_names_and_ordinals() -> None:
    from tex.camel.capability import (
        CapabilityLevel as CamelCapabilityLevel,
        ConfidentialityLevel as CamelConfidentiality,
    )

    assert {m.name: int(m) for m in CapabilityLevel} == {
        m.name: int(m) for m in CamelCapabilityLevel
    }
    assert {m.name: int(m) for m in ConfidentialityLevel} == {
        m.name: int(m) for m in CamelConfidentiality
    }
    for name in (m.name for m in ConfidentialityLevel):
        assert (
            ConfidentialityLevel[name].is_sensitive
            == CamelConfidentiality[name].is_sensitive
        )
    for name in (m.name for m in CapabilityLevel):
        assert (
            CapabilityLevel[name].is_untrusted_level
            == CamelCapabilityLevel[name].is_untrusted_level
        )


# ── confidentiality axis ─────────────────────────────────────────────────


def test_confidentiality_total_order_and_join() -> None:
    assert ConfidentialityLevel.PUBLIC < ConfidentialityLevel.INTERNAL
    assert ConfidentialityLevel.INTERNAL < ConfidentialityLevel.CONFIDENTIAL
    assert ConfidentialityLevel.CONFIDENTIAL < ConfidentialityLevel.RESTRICTED
    j = ConfidentialityLevel.INTERNAL.join(ConfidentialityLevel.RESTRICTED)
    assert j is ConfidentialityLevel.RESTRICTED


def test_is_sensitive_threshold_is_confidential() -> None:
    assert not ConfidentialityLevel.PUBLIC.is_sensitive
    assert not ConfidentialityLevel.INTERNAL.is_sensitive
    assert ConfidentialityLevel.CONFIDENTIAL.is_sensitive
    assert ConfidentialityLevel.RESTRICTED.is_sensitive


# ── back-compat: the integrity axis is untouched ─────────────────────────


def test_integrity_axis_unchanged_default_public() -> None:
    c = Capability.untrusted("email_body")
    assert c.level is CapabilityLevel.UNTRUSTED
    assert c.confidentiality is ConfidentialityLevel.PUBLIC
    s = CapabilitySet.of(Capability.trusted(), Capability.untrusted("doc"))
    assert s.level is CapabilityLevel.UNTRUSTED
    assert s.is_untrusted
    assert not s.is_sensitive


# ── the FIDES flow-violation predicate ───────────────────────────────────


def test_flow_violation_requires_both_axes() -> None:
    assert not FidesLabel(
        integrity=CapabilityLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
    ).is_flow_violation
    assert not FidesLabel(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.RESTRICTED,
    ).is_flow_violation
    assert FidesLabel(
        integrity=CapabilityLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.CONFIDENTIAL,
    ).is_flow_violation


def test_capabilityset_fides_label_joins_both_axes() -> None:
    untrusted_public = Capability.untrusted("web_scrape")
    trusted_sensitive = Capability.sensitive("crm_record")
    s = CapabilitySet.of(untrusted_public, trusted_sensitive)
    label = s.fides_label
    assert label.integrity is CapabilityLevel.UNTRUSTED
    assert label.confidentiality is ConfidentialityLevel.CONFIDENTIAL
    assert label.is_flow_violation
    assert s.is_flow_violation


# ── isomorphism with the canonical IFC lattice (ifc.lattice) ─────────────


def test_confidentiality_isomorphic_to_ifc_lattice() -> None:
    """The IFC home's confidentiality axis must agree name-for-name with the
    engine's own ``ifc.lattice.ConfidentialityLevel``."""
    from tex.governance.private_data_exec.ifc.lattice import (
        ConfidentialityLevel as IfcConfidentiality,
    )

    home_names = {m.name for m in ConfidentialityLevel}
    ifc_names = {m.name for m in IfcConfidentiality}
    assert home_names == ifc_names
    for name in home_names:
        assert int(ConfidentialityLevel[name]) == int(IfcConfidentiality[name])
        assert (
            ConfidentialityLevel[name].is_sensitive
            == IfcConfidentiality[name].is_sensitive
        )


def test_integrity_axis_corresponds_to_ifc_integrity_lattice() -> None:
    """camel integrity ↔ ifc.lattice integrity under the inverse encoding.

    camel.TRUSTED ↔ ifc.SYS_INSTR (most trusted), camel.UNTRUSTED ↔
    ifc.TOOL_UNTRUSTED (low integrity). The two encodings join in opposite
    numeric directions (max vs min) but agree on the low-integrity predicate.
    """
    from tex.governance.private_data_exec.ifc.lattice import (
        IntegrityLevel as IfcIntegrity,
    )

    # The "untrusted" tier maps across both lattices.
    assert CapabilityLevel.UNTRUSTED.is_untrusted_level
    assert IfcIntegrity.TOOL_UNTRUSTED.is_untrusted
    # The "trusted" root is not low-integrity on either side.
    assert not CapabilityLevel.TRUSTED.is_untrusted_level
    assert not IfcIntegrity.SYS_INSTR.is_untrusted


# ── the package re-exports the IFC home under non-colliding aliases ──────


def test_package_reexports_camel_lattice_under_aliases() -> None:
    import tex.governance.private_data_exec.ifc as ifc_pkg

    # CaMeL enums are exposed under Camel* aliases so they do not clobber the
    # package's own (isomorphic) ConfidentialityLevel from ifc.lattice.
    assert ifc_pkg.CamelCapabilityLevel is CapabilityLevel
    assert ifc_pkg.CamelConfidentialityLevel is ConfidentialityLevel
    assert ifc_pkg.Capability is Capability
    assert ifc_pkg.CapabilitySet is CapabilitySet
    assert ifc_pkg.FidesLabel is FidesLabel
    # The package-level ConfidentialityLevel remains the ifc.lattice one.
    from tex.governance.private_data_exec.ifc.lattice import (
        ConfidentialityLevel as IfcConfidentiality,
    )

    assert ifc_pkg.ConfidentialityLevel is IfcConfidentiality
