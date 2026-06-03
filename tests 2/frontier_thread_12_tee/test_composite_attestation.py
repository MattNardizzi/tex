"""
Unit tests for Thread 12 — composite CPU+GPU TEE attestation.

Coverage targets
----------------
* Domain models (composite envelope, EAT-AI claims, trustworthiness vector)
* Decision-bound nonce (CrossGuard pattern, arxiv 2604.23280)
* Composer in dev-mode (deterministic stub JWT)
* Verifier — happy path, every fail-closed failure mode
* EAT-AI claim verification end-to-end
* Trustworthiness vector population per draft-ietf-rats-ear-03
* Compound attestation link semantics (arxiv 2605.03213)
"""

from __future__ import annotations

import os

import pytest

from tex.tee import (
    CompositeAttestationEnvelope,
    CompositeVerificationResult,
    CompoundAttestationLink,
    CpuTeeType,
    EatAiClaims,
    EatAiDigest,
    ExpectedMeasurements,
    GpuTeeType,
    TrustworthinessVector,
    build_test_mode_composite_jwt,
    compose_attestation,
    decision_bound_nonce,
    verify_attestation,
)
from tex.tee.h100_attestation import collect_gpu_evidence
from tex.tee.tdx_attestation import collect_tdx_evidence, fresh_user_data


@pytest.fixture(autouse=True)
def _force_test_mode(monkeypatch):
    """Every test in this module runs with TEX_TEE_ATTESTATION_MODE=test."""
    monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "test")
    yield


# --------------------------------------------------------------------------- #
# Decision-bound nonce (CrossGuard)                                           #
# --------------------------------------------------------------------------- #


class TestDecisionBoundNonce:
    def test_deterministic_for_same_inputs(self):
        a = decision_bound_nonce("decision-1", "request-1")
        b = decision_bound_nonce("decision-1", "request-1")
        assert a == b

    def test_different_decisions_produce_different_nonces(self):
        a = decision_bound_nonce("decision-1", "request-1")
        b = decision_bound_nonce("decision-2", "request-1")
        assert a != b

    def test_request_id_affects_nonce(self):
        a = decision_bound_nonce("decision-1", "request-1")
        b = decision_bound_nonce("decision-1", "request-2")
        assert a != b

    def test_nonce_is_32_hex_chars(self):
        n = decision_bound_nonce("decision-1", "request-1")
        assert len(n) == 32
        assert all(c in "0123456789abcdef" for c in n)

    def test_empty_decision_id_rejected(self):
        with pytest.raises(ValueError):
            decision_bound_nonce("")


# --------------------------------------------------------------------------- #
# Dev-mode evidence collectors                                                #
# --------------------------------------------------------------------------- #


class TestDevModeCollectors:
    def test_tdx_collector_returns_marked_stub(self):
        ev = collect_tdx_evidence(user_data=b"hello")
        assert ev.is_dev_mode is True
        assert ev.platform == "dev-stub"
        assert len(ev.quote) == 512
        assert ev.user_data == b"hello"

    def test_tdx_collector_deterministic(self):
        a = collect_tdx_evidence(user_data=b"x")
        b = collect_tdx_evidence(user_data=b"x")
        assert a.quote == b.quote

    def test_tdx_collector_different_user_data_different_quote(self):
        a = collect_tdx_evidence(user_data=b"x")
        b = collect_tdx_evidence(user_data=b"y")
        assert a.quote != b.quote

    def test_gpu_collector_returns_marked_stub(self):
        ev = collect_gpu_evidence(nonce=b"nonce-bytes")
        assert ev.is_dev_mode is True
        assert ev.hwmodel == "DEV-STUB"
        assert len(ev.evidence_blob) == 1024

    def test_gpu_collector_requires_nonce(self):
        with pytest.raises(ValueError):
            collect_gpu_evidence(nonce=b"")

    def test_fresh_user_data_is_64_bytes(self):
        ud = fresh_user_data("seed")
        assert len(ud) == 64
        # Per ITA convention, lower 32 must be SHA-256 of upper 32.
        import hashlib

        assert hashlib.sha256(ud[:32]).digest() == ud[32:]


# --------------------------------------------------------------------------- #
# Composer                                                                    #
# --------------------------------------------------------------------------- #


class TestComposer:
    def test_compose_returns_envelope_with_test_mode_flag(self):
        env = compose_attestation(decision_id="d-1")
        assert env.test_mode is True
        assert env.ita_attest_type == "tdx+nvgpu"
        assert env.cpu_tee_type == CpuTeeType.TDX
        assert env.gpu_tee_type == GpuTeeType.NVIDIA_HOPPER

    def test_compose_jwt_is_parseable(self):
        env = compose_attestation(decision_id="d-1")
        assert env.ita_jwt is not None
        assert env.ita_jwt.count(".") == 2

    def test_compose_nonce_is_decision_bound(self):
        env = compose_attestation(decision_id="d-1", request_id="r-1")
        assert env.nonce == decision_bound_nonce("d-1", "r-1")

    def test_compose_includes_eat_ai_claims_when_provided(self):
        claims = EatAiClaims(
            ai_model_id="urn:dev:texaegis.com:model-v1",
            ai_model_hash=EatAiDigest(alg="SHA-384", hash_b64="dGVzdA=="),
            dp_epsilon=0.5,
        )
        env = compose_attestation(decision_id="d-1", eat_ai_claims=claims)
        assert env.eat_ai is not None
        assert env.eat_ai.ai_model_id == "urn:dev:texaegis.com:model-v1"
        assert env.eat_ai.dp_epsilon == 0.5

    def test_compose_in_production_with_dev_evidence_raises(self, monkeypatch):
        """Production mode + dev-stub evidence must fail loudly."""
        monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "production")
        with pytest.raises(RuntimeError, match="dev-stub evidence"):
            compose_attestation(decision_id="d-1")

    def test_jwt_sha256_matches_jwt_bytes(self):
        import hashlib

        env = compose_attestation(decision_id="d-1")
        assert env.ita_jwt_sha256 == hashlib.sha256(env.ita_jwt.encode()).hexdigest()

    def test_blackwell_envelope_type(self):
        env = compose_attestation(
            decision_id="d-1", gpu_tee_type=GpuTeeType.NVIDIA_BLACKWELL
        )
        assert env.gpu_tee_type == GpuTeeType.NVIDIA_BLACKWELL


# --------------------------------------------------------------------------- #
# Verifier — happy path                                                       #
# --------------------------------------------------------------------------- #


class TestVerifierHappyPath:
    def test_verify_dev_mode_ok(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.ok is True
        assert result.reason == "ok_test_mode"
        assert result.test_mode is True

    def test_verify_returns_trustworthiness_vector(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.trustworthiness.configuration.value == "affirming"
        assert result.trustworthiness.hardware.value == "affirming"
        assert result.trustworthiness.executables.value == "affirming"
        assert result.trustworthiness.runtime_opaque.value == "affirming"

    def test_verify_extracts_cpu_and_gpu_types(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.cpu_tee_type == CpuTeeType.TDX
        assert result.gpu_tee_type == GpuTeeType.NVIDIA_HOPPER

    def test_verify_extracts_tdx_mrtd(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.tdx_mrtd is not None
        # MRTD is 48 bytes / 96 hex chars
        assert len(result.tdx_mrtd) == 96

    def test_verify_extracts_issuer(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.issuer == "https://portal.trustauthority.intel.com/"


# --------------------------------------------------------------------------- #
# Verifier — fail-closed paths                                                #
# --------------------------------------------------------------------------- #


class TestVerifierFailClosed:
    def test_malformed_jwt_rejected(self):
        result = verify_attestation("not.a.jwt.really", expected_nonce="x")
        assert result.ok is False
        assert result.reason == "parse_error"

    def test_two_parts_rejected(self):
        result = verify_attestation("aaa.bbb", expected_nonce="x")
        assert result.ok is False
        assert result.reason == "parse_error"

    def test_wrong_nonce_rejected(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(env.ita_jwt, expected_nonce="WRONG")
        assert result.ok is False
        assert result.reason == "nonce_mismatch"

    def test_wrong_issuer_rejected(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(
            env.ita_jwt,
            expected_nonce=env.nonce,
            expected_issuer="https://wrong.example.com/",
        )
        assert result.ok is False
        assert result.reason == "issuer_mismatch"

    def test_test_mode_jwt_in_production_rejected(self, monkeypatch):
        env = compose_attestation(decision_id="d-1")
        monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "production")
        result = verify_attestation(env.ita_jwt, expected_nonce=env.nonce)
        assert result.ok is False
        assert result.reason == "test_mode_in_prod"

    def test_pinned_tdx_mrtd_mismatch_rejected(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(
            env.ita_jwt,
            expected_nonce=env.nonce,
            expected=ExpectedMeasurements(tdx_mrtd="0" * 96),
        )
        assert result.ok is False
        assert result.reason == "tdx_mrtd_mismatch"

    def test_pinned_eat_ai_model_id_mismatch_rejected(self):
        env = compose_attestation(
            decision_id="d-1",
            eat_ai_claims=EatAiClaims(ai_model_id="urn:dev:correct-model"),
        )
        result = verify_attestation(
            env.ita_jwt,
            expected_nonce=env.nonce,
            expected=ExpectedMeasurements(eat_ai_model_id="urn:dev:wrong-model"),
        )
        assert result.ok is False
        assert result.reason == "eat_ai_model_id_mismatch"

    def test_pinned_gpu_hwmodel_mismatch_rejected(self):
        env = compose_attestation(decision_id="d-1")
        result = verify_attestation(
            env.ita_jwt,
            expected_nonce=env.nonce,
            expected=ExpectedMeasurements(gpu_hwmodel="GB200"),
        )
        # Dev-stub reports GH100, so requiring GB200 must fail
        assert result.ok is False
        assert result.reason == "gpu_hwmodel_mismatch"

    def test_verify_failure_contraindicates_hardware_axis(self):
        result = verify_attestation("bad.jwt.invalid", expected_nonce="x")
        assert result.trustworthiness.hardware.value == "contraindicated"


# --------------------------------------------------------------------------- #
# EAT-AI claim model (draft-messous-eat-ai-01)                                #
# --------------------------------------------------------------------------- #


class TestEatAiClaims:
    def test_minimal_claim_set_valid(self):
        claims = EatAiClaims(ai_model_id="urn:dev:test")
        assert claims.ai_model_id == "urn:dev:test"
        assert claims.dp_epsilon is None
        assert claims.capabilities == ()

    def test_frozen_model_cannot_be_mutated(self):
        claims = EatAiClaims(ai_model_id="urn:dev:test")
        with pytest.raises(Exception):
            claims.ai_model_id = "different"  # type: ignore[misc]

    def test_extra_field_rejected(self):
        with pytest.raises(Exception):
            EatAiClaims(ai_model_id="urn:dev:test", unknown_field="x")

    def test_to_cwt_int_map_uses_correct_keys(self):
        claims = EatAiClaims(
            ai_model_id="urn:dev:test",
            ai_model_hash=EatAiDigest(alg="SHA-384", hash_b64="abc"),
            dp_epsilon=0.5,
            capabilities=("a", "b"),
        )
        out = claims.to_cwt_int_map()
        # Per draft-messous-eat-ai-01 §7.2
        assert out[-75000] == "urn:dev:test"
        assert out[-75001] == ["SHA-384", "abc"]
        assert out[-75005] == 0.5
        assert out[-75010] == ["a", "b"]

    def test_to_cwt_int_map_omits_unset_claims(self):
        claims = EatAiClaims(ai_model_id="urn:dev:test")
        out = claims.to_cwt_int_map()
        assert -75000 in out
        assert -75001 not in out
        assert -75005 not in out

    def test_digest_integer_alg_normalized_to_string(self):
        d = EatAiDigest(alg=-44, hash_b64="abc")  # type: ignore[arg-type]
        assert d.alg == "SHA-384"


# --------------------------------------------------------------------------- #
# Compound attestation link (arxiv 2605.03213)                                #
# --------------------------------------------------------------------------- #


class TestCompoundLink:
    def test_link_validates_hop_index(self):
        with pytest.raises(Exception):
            CompoundAttestationLink(
                hop_index=-1,
                agent_id="agent",
                jwt_sha256="a" * 64,
            )

    def test_origin_link_has_no_previous(self):
        link = CompoundAttestationLink(
            hop_index=0,
            agent_id="agent-origin",
            jwt_sha256="a" * 64,
        )
        assert link.previous_jwt_sha256 is None

    def test_downstream_link_chains_to_previous(self):
        link = CompoundAttestationLink(
            hop_index=1,
            agent_id="agent-downstream",
            jwt_sha256="b" * 64,
            previous_jwt_sha256="a" * 64,
        )
        assert link.previous_jwt_sha256 == "a" * 64

    def test_compose_carries_compound_link(self):
        link = CompoundAttestationLink(
            hop_index=1,
            agent_id="downstream",
            jwt_sha256="b" * 64,
            previous_jwt_sha256="a" * 64,
        )
        env = compose_attestation(decision_id="d-1", compound_link=link)
        assert env.compound_link is not None
        assert env.compound_link.hop_index == 1


# --------------------------------------------------------------------------- #
# Envelope discipline                                                         #
# --------------------------------------------------------------------------- #


class TestEnvelopeDiscipline:
    def test_envelope_is_frozen(self):
        env = compose_attestation(decision_id="d-1")
        with pytest.raises(Exception):
            env.nonce = "x"  # type: ignore[misc]

    def test_envelope_serializes_to_json_safe_dict(self):
        env = compose_attestation(decision_id="d-1")
        dumped = env.model_dump(mode="json")
        # No bytes, no non-JSON types
        import json

        assert json.dumps(dumped)  # raises on non-JSON type

    def test_envelope_test_mode_propagates_into_serialized(self):
        env = compose_attestation(decision_id="d-1")
        dumped = env.model_dump(mode="json")
        assert dumped["test_mode"] is True

    def test_envelope_with_eliding_jwt(self):
        env = compose_attestation(decision_id="d-1", include_full_jwt=False)
        assert env.ita_jwt is None
        assert env.ita_jwt_sha256  # still set
