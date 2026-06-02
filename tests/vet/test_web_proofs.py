"""Tests for tex.vet.web_proofs."""

from __future__ import annotations

import pytest

from tex.vet.web_proofs import (
    MultiAttestorCommittee,
    TlsNotarySubprocessClient,
    WebProofMode,
    ZkTlsAttestorClient,
    notarize_session,
    verify_web_proof,
)


SAMPLE_SESSION = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
    b'{"choices":[{"text":"hello"}]}'
)


class TestNotarizeSolo:
    """Single-attestor notarization across the three solo modes."""

    @pytest.mark.parametrize(
        "mode",
        [
            WebProofMode.ZKTLS_RECLAIM,
            WebProofMode.ZKTLS_PLUTO,
            WebProofMode.TLSNOTARY_MPC,
        ],
    )
    def test_emits_stub_mode_when_no_live_backend(
        self, mode: WebProofMode
    ) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION, mode=mode,
            response_body=b'{"hi":1}',
        )
        # In sandbox, no live binary/URL is present so the proof is STUB.
        assert proof.mode is WebProofMode.STUB
        assert proof.threshold_k == 1
        assert len(proof.attestations) == 1

    def test_stub_rejected_by_default_verifier(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            mode=WebProofMode.ZKTLS_RECLAIM, response_body=b'{"x":1}',
        )
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
        )
        assert ok is False  # allow_stub=False by default

    def test_stub_accepted_when_allow_stub_true(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            mode=WebProofMode.ZKTLS_RECLAIM, response_body=b'{"x":1}',
        )
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True

    def test_host_mismatch_fails(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}',
        )
        assert not verify_web_proof(
            proof,
            expected_target_host="api.anthropic.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )

    def test_response_mismatch_fails(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}',
        )
        assert not verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash="0" * 64,
            allow_stub=True,
        )

    def test_host_normalized_strips_scheme_and_path(self) -> None:
        proof = notarize_session(
            target_host="https://api.openai.com/v1/chat",
            session_log=SAMPLE_SESSION, response_body=b'{"x":1}',
        )
        assert proof.target_host == "api.openai.com"


class TestMultiAttestorCommittee:
    """k-of-n threshold notarization."""

    def test_2_of_3_committee_verifies(self) -> None:
        committee = MultiAttestorCommittee(
            [
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM),
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_PLUTO),
                TlsNotarySubprocessClient(),
            ],
            threshold_k=2,
        )
        proof = notarize_session(
            target_host="api.anthropic.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}', committee=committee,
        )
        assert proof.mode is WebProofMode.MULTI_ATTESTOR
        assert proof.threshold_k == 2
        assert len(proof.attestations) == 3
        ok = verify_web_proof(
            proof,
            expected_target_host="api.anthropic.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True

    def test_committee_rejects_invalid_threshold(self) -> None:
        clients = [ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM)]
        with pytest.raises(ValueError):
            MultiAttestorCommittee(clients, threshold_k=2)
        with pytest.raises(ValueError):
            MultiAttestorCommittee(clients, threshold_k=0)
        with pytest.raises(ValueError):
            MultiAttestorCommittee([], threshold_k=1)

    def test_pinned_attestor_pubkeys_filter_attestations(self) -> None:
        committee = MultiAttestorCommittee(
            [
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM),
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_PLUTO),
            ],
            threshold_k=1,
        )
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}', committee=committee,
        )
        # Whitelist only the first attestor's pubkey
        trusted = {proof.attestations[0].public_key}
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            trusted_attestor_pubkeys=trusted,
            allow_stub=True,
        )
        assert ok is True  # Still passes because one verifies and k=1

    def test_pinned_with_no_matching_pubkeys_fails(self) -> None:
        committee = MultiAttestorCommittee(
            [ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM)], threshold_k=1
        )
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}', committee=committee,
        )
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            trusted_attestor_pubkeys={"nonexistent-pubkey"},
            allow_stub=True,
        )
        assert ok is False
