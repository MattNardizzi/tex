"""Tests for TLSNotary Proxy mode (alpha.15, May 10, 2026)."""

from __future__ import annotations

import pytest

from tex.vet.web_proofs import (
    MultiAttestorCommittee,
    TlsNotaryProxyClient,
    TlsNotarySubprocessClient,
    WebProofMode,
    ZkTlsAttestorClient,
    notarize_session,
    verify_web_proof,
)


SESSION = b"HTTP/1.1 200 OK\r\n\r\nhello"


class TestTlsNotaryProxyClient:
    """Standalone Proxy-mode client."""

    def test_emits_stub_when_no_live_url(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SESSION,
            mode=WebProofMode.TLSNOTARY_PROXY, response_body=b"hello",
        )
        # No TEX_TLSNOTARY_PROXY_URL set → STUB
        assert proof.mode is WebProofMode.STUB
        assert proof.attestations[0].attestor_id == "stub-tlsn-proxy"

    def test_stub_verifies_with_allow_stub_true(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SESSION,
            mode=WebProofMode.TLSNOTARY_PROXY, response_body=b"hello",
        )
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True

    def test_proxy_client_reports_correct_mode(self) -> None:
        client = TlsNotaryProxyClient()
        assert client.mode is WebProofMode.TLSNOTARY_PROXY

    def test_proxy_client_is_live_when_url_set(self) -> None:
        client = TlsNotaryProxyClient(proxy_url="https://proxy.notary.example.com")
        assert client.is_live() is True
        # And not when URL is None
        client_no_url = TlsNotaryProxyClient(proxy_url=None)
        assert client_no_url.is_live() is False


class TestMixedModeCommittee:
    """k-of-n committees that mix MPC + Proxy + Reclaim attestors."""

    def test_three_mode_committee_2_of_3(self) -> None:
        committee = MultiAttestorCommittee(
            [
                TlsNotarySubprocessClient(),                 # MPC mode
                TlsNotaryProxyClient(),                       # Proxy mode (NEW)
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM),
            ],
            threshold_k=2,
        )
        proof = notarize_session(
            target_host="api.anthropic.com",
            session_log=SESSION,
            response_body=b"hello",
            committee=committee,
        )
        assert proof.mode is WebProofMode.MULTI_ATTESTOR
        assert proof.threshold_k == 2
        assert len(proof.attestations) == 3
        attestor_ids = {a.attestor_id for a in proof.attestations}
        assert "stub-tlsn-proxy" in attestor_ids
        assert "stub-tlsnotary" in attestor_ids

        ok = verify_web_proof(
            proof,
            expected_target_host="api.anthropic.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True

    def test_four_mode_committee_3_of_4(self) -> None:
        """A maximum-diversity committee that includes Proxy + MPC +
        Reclaim + Pluto. Three-of-four threshold simulates a real
        Tex deployment that wants Byzantine-tolerance across
        trust models."""
        committee = MultiAttestorCommittee(
            [
                TlsNotarySubprocessClient(),
                TlsNotaryProxyClient(),
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_RECLAIM),
                ZkTlsAttestorClient(mode=WebProofMode.ZKTLS_PLUTO),
            ],
            threshold_k=3,
        )
        proof = notarize_session(
            target_host="api.openai.com",
            session_log=SESSION,
            response_body=b"hello",
            committee=committee,
        )
        assert proof.threshold_k == 3
        assert len(proof.attestations) == 4
        ok = verify_web_proof(
            proof,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True
