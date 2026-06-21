"""Offline verifier: the happy path, key-pinning for origin, and the fail-closed
tamper / forgery cases (flipped tier, swapped evidence, tampered span, wrong key,
mismatched evidence anchors)."""

from __future__ import annotations

import dataclasses

import pytest

from tex.presence.attest import (
    build_attestation_subject,
    build_presence_attestor,
    recompute_row_hash,
    subject_digest_hex,
    verify_attestation,
)
from tex.presence.contract import EvidenceRef, PresenceTier
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider


@pytest.fixture()
def attested(attestor, claim, sealed_verdict):
    """(attestation, claim, verdict) for a freshly signed binding."""
    att = attestor.attest(claim=claim, verdict=sealed_verdict)
    return att, claim, sealed_verdict


# ───────────────────────────── happy path + origin ──────────────────────────
def test_verify_ok_with_pinned_key(attested):
    att, claim, verdict = attested
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is True
    assert res.digest_ok is True
    assert res.signature_ok is True
    assert res.key_pinned is True
    assert res.key_trusted is True
    assert res.reason.startswith("OK:")


def test_verify_with_pinned_key_id_too(attested):
    att, claim, verdict = attested
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, expected_key_id=att.key_id,
    )
    assert res.ok is True


def test_no_pin_is_integrity_only_not_origin(attested):
    """Without a pin the binding is self-consistent but origin is UNVERIFIED —
    the result says so honestly rather than implying Tex signed it."""
    att, claim, verdict = attested
    res = verify_attestation(attestation=att, claim=claim, verdict=verdict)
    assert res.digest_ok is True
    assert res.signature_ok is True
    assert res.key_pinned is False
    assert res.key_trusted is None
    assert res.ok is True  # integrity holds
    assert "ORIGIN IS UNVERIFIED" in res.reason


def test_digest_matches_independent_recompute(attested):
    att, claim, verdict = attested
    subject = build_attestation_subject(claim, verdict)
    assert subject_digest_hex(subject) == att.signed_digest_sha256


# ───────────────────────────── tamper: the binding is bound ─────────────────
def test_flipped_tier_fails(attested):
    att, claim, verdict = attested
    tampered = dataclasses.replace(verdict, tier=PresenceTier.DERIVED)
    res = verify_attestation(
        attestation=att, claim=claim, verdict=tampered,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is False
    assert res.digest_ok is False
    assert "digest mismatch" in res.reason


def test_swapped_evidence_fails(attested):
    att, claim, verdict = attested
    swapped = dataclasses.replace(
        verdict,
        evidence=(EvidenceRef(record_id="evil", record_hash="c" * 64, store="decision_store"),),
    )
    res = verify_attestation(
        attestation=att, claim=claim, verdict=swapped,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is False
    assert res.digest_ok is False


def test_changed_recomputed_value_fails(attested):
    att, claim, verdict = attested
    tampered = dataclasses.replace(verdict, recomputed_value=9999)
    res = verify_attestation(
        attestation=att, claim=claim, verdict=tampered,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is False
    assert res.digest_ok is False


def test_tampered_spoken_span_fails(attested):
    """The exact spoken phrasing is bound — rewording the span breaks the seal."""
    att, _claim, verdict = attested
    lying_claim = dataclasses.replace(_claim, text_span="There are 999 forbids on record.")
    res = verify_attestation(
        attestation=att, claim=lying_claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is False
    assert res.digest_ok is False


# ───────────────────────────── forgery: wrong key ───────────────────────────
def test_wrong_key_forgery_fails_against_pin(attestor, claim, sealed_verdict):
    """An attacker re-signs a DOCTORED binding with their own key and embeds their
    own public key. digest_ok and signature_ok both pass (internally consistent),
    but pinning Tex's key exposes it: key_trusted is False, so ok is False."""
    tex_att = attestor.attest(claim=claim, verdict=sealed_verdict)

    attacker_key = get_signature_provider(SignatureAlgorithm.ECDSA_P256).generate_keypair("attacker")
    from tex.evidence.seal import EvidenceChainSigner

    attacker = build_presence_attestor(enabled=True, signer=EvidenceChainSigner(key=attacker_key))
    doctored = dataclasses.replace(sealed_verdict, recomputed_value=0)
    forged = attacker.attest(claim=claim, verdict=doctored)

    res = verify_attestation(
        attestation=forged, claim=claim, verdict=doctored,
        expected_public_key_b64=tex_att.public_key_b64,  # pin the REAL Tex key
    )
    assert res.digest_ok is True       # the forger built a consistent binding
    assert res.signature_ok is True    # ...validly signed under their own key
    assert res.key_trusted is False    # ...but it is NOT Tex's key
    assert res.ok is False
    assert "NOT signed by Tex" in res.reason


def test_verifier_derives_pq_from_algorithm_not_the_flag(attested):
    """A hand-forged is_post_quantum=True over an ecdsa-p256 signature must not be
    parroted: the verifier derives PQ from the (authenticated) algorithm."""
    att, claim, verdict = attested
    assert att.algorithm == "ecdsa-p256"
    lying = dataclasses.replace(att, is_post_quantum=True)  # the lie
    res = verify_attestation(
        attestation=lying, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.is_post_quantum is False  # reported from the real algorithm
    assert res.ok is True  # the signature itself is still valid ECDSA


def test_wrong_key_id_pin_fails(attested):
    att, claim, verdict = attested
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, expected_key_id="some-other-key",
    )
    assert res.ok is False
    assert res.key_trusted is False


def test_missing_public_key_fails_closed(attested):
    att, claim, verdict = attested
    no_pub = dataclasses.replace(att, public_key_b64=None)
    res = verify_attestation(
        attestation=no_pub, claim=claim, verdict=verdict,
        expected_public_key_b64="anything",
    )
    assert res.ok is False
    assert res.signature_ok is False


def test_corrupted_signature_fails(attested):
    att, claim, verdict = attested
    import base64

    raw = bytearray(base64.b64decode(att.signature_b64))
    raw[0] ^= 0xFF
    bad = dataclasses.replace(att, signature_b64=base64.b64encode(bytes(raw)).decode("ascii"))
    res = verify_attestation(
        attestation=bad, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64,
    )
    assert res.ok is False
    assert res.signature_ok is False


# ───────────────────────────── evidence anchoring ───────────────────────────
def test_evidence_anchoring_match(attested):
    att, claim, verdict = attested
    resolved = {r.record_id: r.record_hash for r in verdict.evidence}
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, resolved_record_hashes=resolved,
    )
    assert res.ok is True
    assert res.evidence_ok is True
    assert "evidence anchored" in res.reason


def test_evidence_anchoring_mismatch_fails(attested):
    att, claim, verdict = attested
    resolved = {r.record_id: "f" * 64 for r in verdict.evidence}  # substituted record
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, resolved_record_hashes=resolved,
    )
    assert res.ok is False
    assert res.evidence_ok is False
    assert "record_hash mismatch" in res.reason


def test_evidence_anchoring_missing_record_fails(attested):
    att, claim, verdict = attested
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, resolved_record_hashes={},
    )
    assert res.ok is False
    assert res.evidence_ok is False


def test_require_evidence_without_records_fails(attested):
    att, claim, verdict = attested
    res = verify_attestation(
        attestation=att, claim=claim, verdict=verdict,
        expected_public_key_b64=att.public_key_b64, require_evidence=True,
    )
    assert res.ok is False
    assert res.evidence_ok is None


def test_recompute_row_hash_matches_gate(attested):
    """recompute_row_hash is the gate's own canonical anchor, so a verifier can
    rebuild resolved hashes for digest-less rows exactly as the gate sealed them."""
    from tex.presence.gate.evidence import canonical_row_hash

    class _Row:
        def __init__(self) -> None:
            self.status = "active"
            self.name = "agent-7"

    row = _Row()
    assert recompute_row_hash(row) == canonical_row_hash(row)


def test_verify_never_raises_on_garbage():
    """Fail-closed on a structurally broken attestation rather than raising."""
    from tex.presence.contract import (
        Attestation,
        ClaimKind,
        PresenceClaim,
        PresenceVerdict,
    )

    junk = Attestation(
        algorithm="ecdsa-p256", signed_digest_sha256="zz", signature_b64="!!!notb64!!!",
        is_post_quantum=False, public_key_b64="!!!notb64!!!",
    )
    c = PresenceClaim(claim_id="x", text_span="x", kind=ClaimKind.AGGREGATE)
    v = PresenceVerdict(claim_id="x", tier=PresenceTier.SEALED, evidence=(), recomputed_value=1)
    res = verify_attestation(attestation=junk, claim=c, verdict=v, expected_public_key_b64="x")
    assert res.ok is False
