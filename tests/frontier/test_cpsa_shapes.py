"""
Thread 6 tests — CPSA formal verification of the cosign protocol (gap 3).

Loads the vendored CPSA shapes JSON for ``cpsa_models/tex_cosign_v2.scm``
and asserts:

  * Every expected protocol shape is present (G1–G5).
  * No unexpected shapes are present (CPSA found no attacks).
  * Each declared security goal (G1, G2, G3, G4, G5) is covered by
    at least one skeleton.
  * The ``tex.formal_verification`` C2PA assertion payload is
    well-formed and bound to the .scm source.

CPSA itself is not invoked at test time (it's a Haskell tool, not in
the Python runtime). The vendored shapes JSON is the build artifact
checked in CI; regenerate via the workflow documented in
``src/tex/c2pa/cpsa_shapes.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tex.c2pa import (
    ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
    TEX_FORMAL_VERIFICATION_SCHEMA_V1,
    CpsaShapesBundle,
    CpsaSkeleton,
    load_cpsa_shapes,
    model_provenance_assertion_data,
)


# ---------------------------------------------------------------------------
# Vendored bundle smoke tests
# ---------------------------------------------------------------------------


class TestCpsaShapesBundleLoad:
    def test_load_default_bundle(self):
        bundle = load_cpsa_shapes()
        assert isinstance(bundle, CpsaShapesBundle)
        assert bundle.model.endswith("tex_cosign_v2.scm")
        assert bundle.cpsa_version.startswith("4.")
        assert len(bundle.skeletons) >= 2

    def test_load_missing_file_raises(self, tmp_path):
        ghost = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_cpsa_shapes(ghost)

    def test_load_malformed_file_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text('"not an object"', encoding="utf-8")
        with pytest.raises(ValueError, match="object"):
            load_cpsa_shapes(bad)


# ---------------------------------------------------------------------------
# Skeleton-level checks
# ---------------------------------------------------------------------------


class TestCpsaSkeletons:
    def test_verifier_pov_skeleton_present(self):
        bundle = load_cpsa_shapes()
        sk = bundle.skeleton("verifier-pov")
        assert isinstance(sk, CpsaSkeleton)
        assert set(sk.goals) >= {"G1", "G2", "G3", "G4"}
        assert sk.is_satisfied

    def test_no_signature_reflection_skeleton_present(self):
        bundle = load_cpsa_shapes()
        sk = bundle.skeleton("no-signature-reflection")
        assert "G5" in sk.goals
        assert sk.is_satisfied
        # The G5 skeleton must find no attack shape.
        assert sk.unexpected_shapes == 0

    def test_unknown_skeleton_raises(self):
        bundle = load_cpsa_shapes()
        with pytest.raises(KeyError):
            bundle.skeleton("nonexistent-skeleton")

    def test_every_skeleton_is_satisfied(self):
        bundle = load_cpsa_shapes()
        unsatisfied = [s.name for s in bundle.skeletons if not s.is_satisfied]
        assert not unsatisfied, f"Unsatisfied CPSA skeletons: {unsatisfied}"


# ---------------------------------------------------------------------------
# Goal coverage
# ---------------------------------------------------------------------------


class TestGoalCoverage:
    def test_all_five_goals_covered(self):
        bundle = load_cpsa_shapes()
        goals = set(bundle.all_goals)
        assert goals >= {"G1", "G2", "G3", "G4", "G5"}, goals

    def test_all_satisfied_aggregate(self):
        bundle = load_cpsa_shapes()
        assert bundle.all_satisfied is True


# ---------------------------------------------------------------------------
# tex.formal_verification assertion data
# ---------------------------------------------------------------------------


class TestFormalVerificationAssertion:
    def test_assertion_payload_well_formed(self):
        bundle = load_cpsa_shapes()
        data = model_provenance_assertion_data(bundle)
        assert data["$schema"] == TEX_FORMAL_VERIFICATION_SCHEMA_V1
        assert data["tool"] == "cpsa"
        assert data["tool_version"].startswith("4.")
        assert data["all_satisfied"] is True
        assert set(data["all_goals"]) >= {"G1", "G2", "G3", "G4", "G5"}
        # Per-skeleton breakdown is included.
        assert len(data["skeletons"]) == len(bundle.skeletons)
        for sk in data["skeletons"]:
            assert sk["actual_count"] == sk["expected_count"]
            assert sk["unexpected_shapes"] == 0
            assert sk["is_satisfied"] is True

    def test_assertion_includes_scm_hash_when_path_provided(self, tmp_path):
        # Synthesize a temporary .scm-like file to hash.
        bundle = load_cpsa_shapes()
        scm_file = tmp_path / "model.scm"
        scm_file.write_text("(defprotocol test basic)", encoding="utf-8")
        data = model_provenance_assertion_data(bundle, scm_path=scm_file)
        assert "scm_sha256" in data
        assert len(data["scm_sha256"]) == 64

    def test_paper_reference_cites_2604_24890(self):
        bundle = load_cpsa_shapes()
        data = model_provenance_assertion_data(bundle)
        assert "2604.24890" in data["paper_reference"]

    def test_assertion_label_constant(self):
        # The label string is the C2PA assertion label clients look up.
        assert ASSERTION_LABEL_TEX_FORMAL_VERIFICATION == "tex.formal_verification"


# ---------------------------------------------------------------------------
# Source-file consistency
# ---------------------------------------------------------------------------


class TestSourceConsistency:
    def test_scm_source_file_exists(self):
        repo_root = Path(__file__).resolve().parents[2]
        scm = repo_root / "cpsa_models" / "tex_cosign_v2.scm"
        assert scm.exists(), f"CPSA source missing at {scm}"
        body = scm.read_text(encoding="utf-8")
        # The .scm file must declare the protocol name + at least one role.
        assert "(defprotocol tex-cosign-v2" in body
        assert "(defrole outer-signer" in body
        assert "(defrole cosign-signer" in body
        assert "(defrole verifier" in body
        # Both defskeletons must be present (one for G1-G4, one for G5).
        assert body.count("(defskeleton tex-cosign-v2") == 2
