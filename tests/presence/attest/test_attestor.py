"""Attestor: the 1:1 signer→Attestation mapping, algorithm honesty, the
TEX_SEAL_DECISIONS gate, ABSTAIN handling, and the apply-attestation seam."""

from __future__ import annotations

import dataclasses

import pytest

from tex.presence.attest import (
    apply_attestation,
    build_attestation_subject,
    build_presence_attestor,
    subject_digest_hex,
    verify_attestation,
)
from tex.presence.attest.attestor import PresenceBindingAttestor
from tex.presence.contract import AnswerEnvelope, Attestation, PresenceTier


# ───────────────────────────── the TEX_SEAL_DECISIONS gate ──────────────────
def test_disabled_attestor_returns_none(claim, sealed_verdict):
    attestor = build_presence_attestor(enabled=False)
    assert attestor.enabled is False
    assert attestor.attest(claim=claim, verdict=sealed_verdict) is None


def test_factory_off_by_default_when_env_unset(monkeypatch, claim, sealed_verdict):
    monkeypatch.delenv("TEX_SEAL_DECISIONS", raising=False)
    attestor = build_presence_attestor()
    assert attestor.enabled is False
    assert attestor.attest(claim=claim, verdict=sealed_verdict) is None


def test_factory_env_gates_on_real_signer(monkeypatch, tmp_path, claim, sealed_verdict):
    """End-to-end through the real build_evidence_chain_signer factory (disk +
    governor), proving the env gate wires a working signer."""
    monkeypatch.setenv("TEX_SEAL_DECISIONS", "1")
    attestor = build_presence_attestor(key_dir=str(tmp_path / "keys"))
    assert attestor.enabled is True
    att = attestor.attest(claim=claim, verdict=sealed_verdict)
    assert att is not None
    # Whatever the local backend, the label must match the real signature.
    assert att.is_post_quantum == ("ml-dsa" in att.algorithm)
    res = verify_attestation(
        attestation=att, claim=claim, verdict=sealed_verdict,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is True


@pytest.mark.parametrize("value", ["0", "false", "no", "", "off"])
def test_factory_falsey_env_stays_disabled(monkeypatch, value):
    monkeypatch.setenv("TEX_SEAL_DECISIONS", value)
    assert build_presence_attestor().enabled is False


# ───────────────────────────── 1:1 mapping + algorithm honesty ──────────────
def test_attestation_maps_signer_block_one_to_one(attestor, ecdsa_signer, claim, sealed_verdict):
    att = attestor.attest(claim=claim, verdict=sealed_verdict)
    assert isinstance(att, Attestation)
    # Rebuild the block the signer would emit and compare the mapped fields.
    subject = build_attestation_subject(claim, sealed_verdict)
    block = ecdsa_signer.sign_payload(subject)
    assert att.algorithm == block["algorithm"]
    assert att.key_id == block["key_id"]
    assert att.public_key_b64 == block["public_key_b64"]
    # Digest is deterministic over the subject (signed_at/signature differ each call).
    assert att.signed_digest_sha256 == block["signed_digest_sha256"]
    assert att.signed_digest_sha256 == subject_digest_hex(subject)


def test_ecdsa_signer_is_honestly_classical(attestor, claim, sealed_verdict):
    att = attestor.attest(claim=claim, verdict=sealed_verdict)
    assert att.algorithm == "ecdsa-p256"
    assert att.is_post_quantum is False


def test_pq_signer_is_honestly_post_quantum(pq_signer, claim, sealed_verdict):
    attestor = build_presence_attestor(enabled=True, signer=pq_signer)
    att = attestor.attest(claim=claim, verdict=sealed_verdict)
    assert att.algorithm == "composite-ml-dsa-65-ed25519"
    assert att.is_post_quantum is True


def test_is_post_quantum_never_assumed(attestor, pq_signer, claim, sealed_verdict):
    """The label always tracks the algorithm that actually signed — both ways."""
    classical = attestor.attest(claim=claim, verdict=sealed_verdict)
    assert classical.is_post_quantum is ("ml-dsa" in classical.algorithm)
    pq = build_presence_attestor(enabled=True, signer=pq_signer).attest(
        claim=claim, verdict=sealed_verdict
    )
    assert pq.is_post_quantum is ("ml-dsa" in pq.algorithm)


# ───────────────────────────── ABSTAIN + coherence ──────────────────────────
def test_abstain_verdict_is_never_attested(attestor, claim, abstain_verdict):
    assert attestor.attest(claim=claim, verdict=abstain_verdict) is None


def test_attest_refuses_mismatched_claim_verdict(attestor, claim, sealed_verdict):
    wrong = dataclasses.replace(sealed_verdict, claim_id="some_other_claim")
    with pytest.raises(ValueError, match="mismatch"):
        attestor.attest(claim=claim, verdict=wrong)


# ───────────────────────────── apply_attestation ────────────────────────────
def test_apply_to_envelope_sets_attestation_on_each_verdict(attestor, envelope):
    out = apply_attestation(envelope, attestor)
    assert isinstance(out, AnswerEnvelope)
    assert len(out.verdicts) == len(envelope.verdicts)
    for v in out.verdicts:
        assert v.attestation is not None
        assert v.attestation.signature_b64
    # Claims and spoken text are untouched.
    assert out.claims == envelope.claims
    assert out.spoken_text == envelope.spoken_text
    # And each attached attestation verifies against its own claim+verdict.
    claims_by_id = {c.claim_id: c for c in out.claims}
    for v in out.verdicts:
        res = verify_attestation(
            attestation=v.attestation, claim=claims_by_id[v.claim_id], verdict=v,
            expected_public_key_b64=v.attestation.public_key_b64,
        )
        assert res.ok is True


def test_apply_to_single_verdict_requires_claim(attestor, claim, sealed_verdict):
    out = apply_attestation(sealed_verdict, attestor, claim=claim)
    assert out.attestation is not None
    with pytest.raises(ValueError, match="requires claim"):
        apply_attestation(sealed_verdict, attestor)


def test_apply_is_noop_when_disabled(envelope):
    disabled = build_presence_attestor(enabled=False)
    out = apply_attestation(envelope, disabled)
    assert all(v.attestation is None for v in out.verdicts)


def test_apply_is_noop_when_attestor_none(envelope):
    out = apply_attestation(envelope, None)
    assert out is envelope


def test_apply_swallows_attest_errors_failing_closed(attestor, sealed_verdict):
    """A claim/verdict mismatch on the hot path must not raise — it leaves the
    verdict unattested rather than breaking the voice."""
    from tex.presence.contract import ClaimKind, PresenceClaim

    mismatched = PresenceClaim(claim_id="not_the_same", text_span="x", kind=ClaimKind.AGGREGATE)
    out = apply_attestation(sealed_verdict, attestor, claim=mismatched)
    assert out.attestation is None


def test_apply_rejects_unknown_target_type(attestor):
    with pytest.raises(TypeError):
        apply_attestation("not a verdict", attestor)  # type: ignore[arg-type]


def test_disabled_attestor_reports_no_algorithm():
    disabled = PresenceBindingAttestor(signer=None)
    assert disabled.algorithm is None
    assert disabled.is_post_quantum is False
