"""Tests for tex.vet.agent_identity_document."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.vet.agent_identity_document import (
    AID_VERSION,
    AidIssuanceRequest,
    AidPresentationRequest,
    AidStatus,
    issue,
    present,
    to_vc_2_0,
    verify,
    verify_presentation_envelope,
)


def _make_request(**overrides) -> AidIssuanceRequest:
    defaults = dict(
        agent_id="agent-007",
        issuer_did="did:tex:issuer:tenant-1",
        model_measurement="sha256:gpt-4o-2025-08-15",
        software_stack_measurement="sha256:tex-runtime-1.0",
        supported_proof_systems=("tee-tdx", "zktls-reclaim"),
        compliance_assertions=("SOC2", "HIPAA"),
        algorithm=SignatureAlgorithm.ED25519,
    )
    defaults.update(overrides)
    return AidIssuanceRequest(**defaults)


class TestIssuance:
    def test_basic_aid_issues_and_verifies(self) -> None:
        aid = issue(request=_make_request())
        assert aid.agent_id == "agent-007"
        assert aid.aid_version == AID_VERSION
        assert aid.status is AidStatus.ACTIVE
        result = verify(aid)
        assert result.valid is True

    def test_aid_with_aivs_micro(self) -> None:
        aid = issue(request=_make_request(include_aivs_micro=True))
        assert aid.aivs_micro is not None
        # AIVS-Micro is a self-verifying record
        from tex.vet.aivs_micro import verify_aivs_micro

        assert verify_aivs_micro(aid.aivs_micro).valid is True

    def test_aid_with_ptv_attestation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Force the Ed25519-bridge method so sandbox without liboqs runs.
        from tex.vet import ptv_attestation as ptv_mod
        from tex.vet.ptv_attestation import PtvAttestationMethod

        original = ptv_mod.generate_ptv_attestation

        def _fixed(**kwargs):
            kwargs["method"] = PtvAttestationMethod.SCHNORR_ED25519_BRIDGE
            return original(**kwargs)

        monkeypatch.setattr(ptv_mod, "generate_ptv_attestation", _fixed)

        aid = issue(request=_make_request(include_ptv_attestation=True))
        assert aid.ptv_attestation_jwt is not None
        result = ptv_mod.verify_ptv_attestation(
            aid.ptv_attestation_jwt, expected_agent_id="agent-007"
        )
        assert result.valid is True

    def test_aid_expires(self) -> None:
        aid = issue(request=_make_request(expires_in_seconds=1))
        # Re-create with a forced expiry in the past
        expired = aid.model_copy(
            update={"expires_at": datetime.now(UTC) - timedelta(seconds=10)}
        )
        result = verify(expired)
        assert result.valid is False
        assert "expired" in result.reason

    def test_revoked_aid_rejected(self) -> None:
        aid = issue(request=_make_request()).model_copy(
            update={"status": AidStatus.REVOKED}
        )
        result = verify(aid)
        assert result.valid is False
        assert "revoked" in result.reason


class TestVcEnvelope:
    def test_vc_2_0_envelope_has_canonical_shape(self) -> None:
        aid = issue(request=_make_request())
        vc = to_vc_2_0(aid)
        assert "VerifiableCredential" in vc["type"]
        assert "AgentIdentityCredential" in vc["type"]
        assert vc["issuer"] == "did:tex:issuer:tenant-1"
        assert vc["credentialSubject"]["id"] == "did:tex:agent:agent-007"
        assert vc["proof"]["type"] == "DataIntegrityProof"
        assert vc["proof"]["cryptosuite"].startswith("bbs-2023-shape-")


class TestSelectivePresentation:
    def test_reveal_only_compliance_hides_model(self) -> None:
        aid = issue(request=_make_request())
        pres = present(
            aid,
            AidPresentationRequest(
                reveal=("compliance_assertions",),
                audience="https://verifier.example.com",
                nonce="nonce-1",
            ),
        )
        result = verify_presentation_envelope(
            pres,
            expected_audience="https://verifier.example.com",
            expected_nonce="nonce-1",
            expected_agent_id="agent-007",
        )
        assert result.valid is True
        assert "compliance_assertions" in result.revealed_claims
        assert "model_measurement" not in result.revealed_claims
        assert "software_stack_measurement" not in result.revealed_claims

    def test_replay_against_wrong_audience_fails(self) -> None:
        aid = issue(request=_make_request())
        pres = present(
            aid,
            AidPresentationRequest(
                reveal=("compliance_assertions",),
                audience="https://verifier.example.com",
            ),
        )
        result = verify_presentation_envelope(
            pres,
            expected_audience="https://evil.example.com",
        )
        assert result.valid is False
        assert "audience" in result.reason

    def test_expired_presentation_rejected(self) -> None:
        aid = issue(request=_make_request())
        pres = present(
            aid,
            AidPresentationRequest(
                reveal=("compliance_assertions",),
                audience="https://verifier.example.com",
                expires_in_seconds=1,
            ),
        )
        # Backdate the expiry
        expired = pres.model_copy(
            update={"expires_at": datetime.now(UTC) - timedelta(seconds=5)}
        )
        result = verify_presentation_envelope(
            expired, expected_audience="https://verifier.example.com"
        )
        assert result.valid is False
        assert "expired" in result.reason

    def test_agent_id_pinning_works(self) -> None:
        aid = issue(request=_make_request())
        pres = present(
            aid,
            AidPresentationRequest(
                reveal=("compliance_assertions",),
                audience="https://verifier.example.com",
            ),
        )
        # Wrong expected agent ID
        result = verify_presentation_envelope(
            pres,
            expected_audience="https://verifier.example.com",
            expected_agent_id="other-agent",
        )
        assert result.valid is False
        assert "agent_id" in result.reason

    def test_mandatory_claims_always_revealed(self) -> None:
        aid = issue(request=_make_request())
        # Don't request anything explicitly
        pres = present(
            aid,
            AidPresentationRequest(
                reveal=(),
                audience="https://verifier.example.com",
            ),
        )
        result = verify_presentation_envelope(
            pres, expected_audience="https://verifier.example.com"
        )
        assert result.valid is True
        # agent_id, issuer_did always disclosed
        assert "agent_id" in result.revealed_claims
        assert "issuer_did" in result.revealed_claims
        # Sensitive fields hidden by default
        assert "model_measurement" not in result.revealed_claims
