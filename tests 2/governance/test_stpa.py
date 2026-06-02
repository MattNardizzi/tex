"""
Tests for tex.governance.stpa_specs.

Covers:
  - Manifest YAML round-trip (Path/bytes/inline str/file path str)
  - All artifact types load
  - Cross-validation errors (every chain): hazard->loss, sc->hazard,
    uca->hazard, loss_scenario->uca, requirement->hazard, spec->requirement
  - Duplicate-id detection across all 8 types, errors collected at once
  - Coverage matrix two-path computation (direct + transitive)
  - Uncovered UCAs detected
  - Reverse module_to_ucas index
  - Missing pyyaml gives clear error
  - Enforcement tier validation rejects invalid tier
  - UCA guide_word default "provided"
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tex.governance.stpa_specs import (
    Hazard,
    Loss,
    LossScenario,
    MCPLabel,
    Requirement,
    SafetyConstraint,
    Specification,
    Stakeholder,
    StpaCoverageMatrix,
    StpaManifest,
    StpaManifestValidationError,
    UnsafeControlAction,
    build_coverage_matrix,
    load_manifest,
)


def _full_manifest_yaml() -> str:
    return """
stakeholders:
  - {stakeholder_id: SH-1, name: User, is_direct: true, values: [privacy, autonomy]}
  - {stakeholder_id: SH-2, name: Regulator, is_direct: false}

losses:
  - {loss_id: L-1, description: 'Regulatory fine'}
  - {loss_id: L-2, description: 'PII leak'}

hazards:
  - {hazard_id: H-1, description: 'Agent emits PII to external service', leads_to_losses: [L-1, L-2]}
  - {hazard_id: H-2, description: 'Agent overwrites critical record', leads_to_losses: [L-1]}

safety_constraints:
  - {constraint_id: SC-1, description: 'PII never crosses public boundary', inverts_hazards: [H-1]}

unsafe_control_actions:
  - {uca_id: UCA-1, control_action: external_send, context: 'after PII read', why_unsafe: 'leaks PII', related_hazards: [H-1], guide_word: provided}
  - {uca_id: UCA-2, control_action: log_full_payload, context: 'on every call', why_unsafe: 'records secrets', related_hazards: [H-1]}
  - {uca_id: UCA-3, control_action: overwrite_record, context: 'no backup', why_unsafe: 'data loss', related_hazards: [H-2]}

loss_scenarios:
  - {scenario_id: LS-1, causal_chain: [read_pii, external_send], related_uca: UCA-1, mitigation_modules: [path_policy, kernel_mcp]}

requirements:
  - {requirement_id: REQ-1, description: 'PII never sent without approval', addresses_hazards: [H-1]}
  - {requirement_id: REQ-2, description: 'No record overwrite without backup', addresses_hazards: [H-2]}

specifications:
  - {spec_id: SPEC-1, description: 'Block external_send when PII tainted', refines_requirement: REQ-1, enforcement_tier: blocklist, enforcement_modules: [private_data_exec]}
  - {spec_id: SPEC-2, description: 'Confirm before overwrite', refines_requirement: REQ-2, enforcement_tier: confirmation, enforcement_modules: [path_policy]}

mcp_labels:
  - {tool_name: web_fetch, capabilities: [external_read], confidentiality: public, trust: untrusted}
  - {tool_name: send_email, capabilities: [external_write], confidentiality: private, trust: trusted, extra: {region: 'us-east-1'}}
"""


# ===========================================================================
# Manifest loading (sources)
# ===========================================================================


class TestManifestSources:
    def test_load_from_inline_str(self):
        m = load_manifest(_full_manifest_yaml())
        assert isinstance(m, StpaManifest)
        assert len(m.losses) == 2

    def test_load_from_bytes(self):
        m = load_manifest(_full_manifest_yaml().encode("utf-8"))
        assert len(m.hazards) == 2

    def test_load_from_path(self, tmp_path):
        f = tmp_path / "manifest.yaml"
        f.write_text(_full_manifest_yaml())
        m = load_manifest(f)
        assert len(m.unsafe_control_actions) == 3

    def test_load_from_path_str(self, tmp_path):
        f = tmp_path / "manifest.yaml"
        f.write_text(_full_manifest_yaml())
        m = load_manifest(str(f))
        assert len(m.specifications) == 2

    def test_invalid_source_type_raises(self):
        with pytest.raises(StpaManifestValidationError):
            load_manifest(12345)  # type: ignore[arg-type]

    def test_root_must_be_mapping(self):
        with pytest.raises(StpaManifestValidationError):
            load_manifest("- just\n- a\n- list\n")


# ===========================================================================
# Loaded artifact integrity
# ===========================================================================


class TestLoadedArtifacts:
    @pytest.fixture
    def manifest(self):
        return load_manifest(_full_manifest_yaml())

    def test_stakeholders(self, manifest):
        assert len(manifest.stakeholders) == 2
        sh = next(s for s in manifest.stakeholders if s.stakeholder_id == "SH-1")
        assert sh.values == ("privacy", "autonomy")
        assert sh.is_direct is True

    def test_losses(self, manifest):
        assert all(isinstance(l, Loss) for l in manifest.losses)

    def test_hazards(self, manifest):
        h1 = next(h for h in manifest.hazards if h.hazard_id == "H-1")
        assert h1.leads_to_losses == ("L-1", "L-2")

    def test_safety_constraints(self, manifest):
        assert len(manifest.safety_constraints) == 1
        assert isinstance(manifest.safety_constraints[0], SafetyConstraint)

    def test_ucas(self, manifest):
        u1 = next(u for u in manifest.unsafe_control_actions if u.uca_id == "UCA-1")
        assert u1.guide_word == "provided"

    def test_uca_guide_word_default(self):
        # UCA-2 in the fixture has no guide_word — should default to "provided".
        m = load_manifest(_full_manifest_yaml())
        u2 = next(u for u in m.unsafe_control_actions if u.uca_id == "UCA-2")
        assert u2.guide_word == "provided"

    def test_loss_scenarios(self, manifest):
        ls = manifest.loss_scenarios[0]
        assert isinstance(ls, LossScenario)
        assert ls.mitigation_modules == ("path_policy", "kernel_mcp")

    def test_requirements(self, manifest):
        r = next(r for r in manifest.requirements if r.requirement_id == "REQ-1")
        assert isinstance(r, Requirement)
        assert r.addresses_hazards == ("H-1",)

    def test_specifications(self, manifest):
        s = next(s for s in manifest.specifications if s.spec_id == "SPEC-1")
        assert isinstance(s, Specification)
        assert s.enforcement_tier == "blocklist"
        assert s.enforcement_modules == ("private_data_exec",)

    def test_mcp_labels(self, manifest):
        labels = {l.tool_name: l for l in manifest.mcp_labels}
        assert isinstance(labels["web_fetch"], MCPLabel)
        assert labels["send_email"].extra == {"region": "us-east-1"}


# ===========================================================================
# Cross-validation
# ===========================================================================


class TestCrossValidation:
    def test_hazard_unknown_loss(self):
        yaml = """
losses: []
hazards: [{hazard_id: H-1, description: x, leads_to_losses: [L-MISSING]}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown loss 'L-MISSING'" in str(e.value)

    def test_safety_constraint_unknown_hazard(self):
        yaml = """
losses: []
hazards: []
safety_constraints: [{constraint_id: SC-1, description: x, inverts_hazards: [H-MISSING]}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown hazard 'H-MISSING'" in str(e.value)

    def test_uca_unknown_hazard(self):
        yaml = """
losses: []
hazards: []
unsafe_control_actions: [{uca_id: U-1, control_action: x, context: y, why_unsafe: z, related_hazards: [H-MISSING]}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown hazard 'H-MISSING'" in str(e.value)

    def test_loss_scenario_unknown_uca(self):
        yaml = """
losses: []
hazards: []
loss_scenarios: [{scenario_id: LS-1, related_uca: UCA-MISSING}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown uca 'UCA-MISSING'" in str(e.value)

    def test_requirement_unknown_hazard(self):
        yaml = """
losses: []
hazards: []
requirements: [{requirement_id: R-1, description: x, addresses_hazards: [H-MISSING]}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown hazard 'H-MISSING'" in str(e.value)

    def test_specification_unknown_requirement(self):
        yaml = """
losses: []
specifications: [{spec_id: SPEC-1, description: x, refines_requirement: REQ-MISSING, enforcement_tier: blocklist}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "unknown requirement 'REQ-MISSING'" in str(e.value)

    def test_invalid_enforcement_tier(self):
        yaml = """
losses: []
requirements: [{requirement_id: R-1, description: x, addresses_hazards: []}]
specifications: [{spec_id: SPEC-1, description: x, refines_requirement: R-1, enforcement_tier: bogus}]
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "enforcement_tier" in str(e.value)

    def test_duplicate_id_detection(self):
        yaml = """
losses:
  - {loss_id: L-1, description: a}
  - {loss_id: L-1, description: b}
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        assert "duplicate loss id: 'L-1'" in str(e.value)

    def test_all_errors_collected_at_once(self):
        """A bad manifest with multiple violations surfaces every one in a single raise."""
        yaml = """
losses:
  - {loss_id: L-1, description: a}
  - {loss_id: L-1, description: dup}
hazards:
  - {hazard_id: H-1, description: x, leads_to_losses: [L-MISSING]}
unsafe_control_actions:
  - {uca_id: UCA-1, control_action: a, context: b, why_unsafe: c, related_hazards: [H-MISSING]}
loss_scenarios:
  - {scenario_id: LS-1, related_uca: UCA-MISSING}
"""
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest(yaml)
        msg = str(e.value)
        # All four violations present.
        assert "duplicate loss id" in msg
        assert "unknown loss 'L-MISSING'" in msg
        assert "unknown hazard 'H-MISSING'" in msg
        assert "unknown uca 'UCA-MISSING'" in msg


# ===========================================================================
# Coverage matrix
# ===========================================================================


class TestCoverageMatrix:
    @pytest.fixture
    def manifest(self):
        return load_manifest(_full_manifest_yaml())

    def test_returns_matrix(self, manifest):
        matrix = build_coverage_matrix(manifest)
        assert isinstance(matrix, StpaCoverageMatrix)

    def test_uca1_gets_union_of_direct_and_transitive(self, manifest):
        # UCA-1 has both:
        #   direct: LossScenario LS-1 -> [path_policy, kernel_mcp]
        #   transitive: H-1 -> REQ-1 -> SPEC-1 -> [private_data_exec]
        # Union = {kernel_mcp, path_policy, private_data_exec}
        matrix = build_coverage_matrix(manifest)
        assert set(matrix.uca_to_modules["UCA-1"]) == {
            "kernel_mcp",
            "path_policy",
            "private_data_exec",
        }

    def test_uca2_inherits_only_from_specification(self, manifest):
        # UCA-2 has no LossScenario; only the H-1 -> REQ-1 -> SPEC-1
        # transitive chain. It should only show private_data_exec.
        matrix = build_coverage_matrix(manifest)
        assert matrix.uca_to_modules["UCA-2"] == ("private_data_exec",)

    def test_uca3_uses_h2_chain(self, manifest):
        # UCA-3 -> H-2 -> REQ-2 -> SPEC-2 -> path_policy
        matrix = build_coverage_matrix(manifest)
        assert matrix.uca_to_modules["UCA-3"] == ("path_policy",)

    def test_uncovered_ucas(self):
        """A UCA with no matching scenario AND no requirement chain is uncovered."""
        yaml = """
losses: []
hazards:
  - {hazard_id: H-1, description: x, leads_to_losses: []}
unsafe_control_actions:
  - {uca_id: UCA-LONELY, control_action: a, context: b, why_unsafe: c, related_hazards: [H-1]}
"""
        m = load_manifest(yaml)
        matrix = build_coverage_matrix(m)
        assert matrix.uncovered_ucas == ("UCA-LONELY",)
        assert matrix.uca_to_modules["UCA-LONELY"] == ()

    def test_module_to_uca_reverse(self, manifest):
        matrix = build_coverage_matrix(manifest)
        assert "UCA-1" in matrix.module_to_ucas["path_policy"]
        assert "UCA-3" in matrix.module_to_ucas["path_policy"]
        assert "UCA-2" in matrix.module_to_ucas["private_data_exec"]


# ===========================================================================
# Missing pyyaml
# ===========================================================================


class TestMissingPyyaml:
    def test_actionable_error(self):
        # Force the lazy import inside _read_yaml to fail.
        original_modules = sys.modules.copy()
        sys.modules["yaml"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(StpaManifestValidationError) as e:
                load_manifest("losses: []")
            assert "PyYAML" in str(e.value)
        finally:
            sys.modules.clear()
            sys.modules.update(original_modules)


# ===========================================================================
# Field validation
# ===========================================================================


class TestFieldValidation:
    def test_missing_required_field(self):
        # loss without description
        with pytest.raises(StpaManifestValidationError) as e:
            load_manifest("losses: [{loss_id: L-1}]")
        assert "missing required field" in str(e.value)

    def test_list_field_must_be_list(self):
        with pytest.raises(StpaManifestValidationError):
            load_manifest("losses: 'not a list'")

    def test_nested_string_in_list_must_be_string(self):
        # values: [42] would inject an int into a tuple-of-string
        with pytest.raises(StpaManifestValidationError):
            load_manifest(
                "stakeholders: [{stakeholder_id: SH-1, name: User, values: [42]}]"
            )


# ===========================================================================
# Manifest immutability
# ===========================================================================


class TestManifestImmutability:
    def test_frozen_pydantic_model(self):
        m = load_manifest(_full_manifest_yaml())
        with pytest.raises(Exception):
            m.losses = ()  # type: ignore[misc]
