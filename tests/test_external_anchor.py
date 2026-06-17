"""
External-anchor tests (moat / provable-age).

These tests prove the load-bearing property end-to-end against a **real,
self-issued** RFC 3161 Time-Stamp Authority (``interchange/_local_tsa.py``): a
CA + TSA leaf cert minted with ``cryptography`` and a real CMS ``SignedData``
token signed by the TSA key — NOT a mock of the unit under test. The verifier
must:

  * accept a genuine token and recover the TSA's ``genTime``;
  * reject an altered tree-head (messageImprint no longer matches);
  * reject a token signed by anyone other than the pinned authority — pinning is
    load-bearing exactly as in ``test_sealed_fact_bundle`` (a forgery re-signed
    with an attacker key, while embedding the real TSA cert, must fail);
  * reject a TSA cert without the id-kp-timeStamping EKU;
  * reject a not-granted response and a genTime outside the cert validity.

No network: the TSA is exercised through a pure in-process function and an
injected ``poster``. Interop against the *real* freetsa.org TSA is exercised
out-of-band by ``scripts/anchor_checkpoint.py`` / CI, not here.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules import rfc3161

from tex.domain.evidence import EvidenceRecord
from tex.evidence.chain import verify_evidence_chain
from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa
from tex.interchange.external_anchor import (
    AnchorFailureCode,
    CheckpointAnchorRecord,
    anchor_subject_digest,
    build_timestamp_request,
    submit_anchor,
    verify_anchor_receipt,
)
from tex.interchange.gix import Checkpoint, CheckpointPublisher, merkle_root

_CP = Checkpoint(
    origin="tex.local/gix-decision-log",
    tree_size=10,
    root_hash=hashlib.sha256(b"tree-head-root").digest(),
)


def _digest(cp: Checkpoint = _CP) -> bytes:
    return anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)


def _record_for(resp_der: bytes, *, checkpoint=_CP, authority="local-tsa", nonce=None):
    return CheckpointAnchorRecord.from_response(
        checkpoint=checkpoint,
        signed_note=None,
        authority=authority,
        response_der=resp_der,
        request_nonce=nonce,
    )


# --------------------------------------------------------------------------- #
# the happy path — submit (mocked TSA), persist, verify offline
# --------------------------------------------------------------------------- #
def test_submit_persist_and_verify_offline(tmp_path):
    """The end-to-end flow the brief asks for: submit a checkpoint to a mocked
    RFC-3161 TSA, persist the receipt, verify it offline against the pin."""
    tsa = mint_local_tsa()
    digest = _digest()

    # The mocked TSA: a pure poster returning a real signed token. It asserts the
    # request really carries our imprint (proves the request builder binds it).
    def poster(url: str, request_der: bytes) -> bytes:
        req, _ = der_decoder.decode(request_der, asn1Spec=rfc3161.TimeStampReq())
        assert bytes(req["messageImprint"]["hashedMessage"]) == digest
        return issue_timestamp_response(digest, tsa, nonce=int(req["nonce"]))

    resp_der = submit_anchor(digest, tsa_url="https://tsa.invalid", nonce=999, poster=poster)
    record = _record_for(resp_der, nonce=999)

    # Persist as JSONL and reload — the verifier needs only the artifact + the pin.
    store = tmp_path / "checkpoint_anchors.jsonl"
    store.write_text(record.model_dump_json() + "\n", encoding="utf-8")
    reloaded = CheckpointAnchorRecord.model_validate_json(store.read_text().strip())

    result = verify_anchor_receipt(reloaded, pinned_tsa_cert_der=tsa.ca_pin_der, expected_nonce=999)
    assert result.ok is True, result.detail
    assert result.gen_time == datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)
    assert result.tsa_cert_fingerprint_sha256 == tsa.tsa_cert.fingerprint(hashes.SHA256()).hex()
    assert result.subject_digest_hex == digest.hex()
    assert "independent of Tex's key" in result.summary()


def test_exact_leaf_pin_also_verifies():
    """Pinning the TSA leaf cert directly (exact fingerprint) is accepted, not
    only pinning the issuing CA."""
    tsa = mint_local_tsa()
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa)
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.leaf_pin_der)
    assert result.ok is True, result.detail


def test_build_timestamp_request_binds_the_imprint():
    digest = _digest()
    der = build_timestamp_request(digest, nonce=7)
    req, _ = der_decoder.decode(der, asn1Spec=rfc3161.TimeStampReq())
    assert bytes(req["messageImprint"]["hashedMessage"]) == digest
    assert int(req["nonce"]) == 7
    assert bool(req["certReq"]) is True


def test_build_timestamp_request_rejects_non_sha256_digest():
    with pytest.raises(ValueError):
        build_timestamp_request(b"too-short", nonce=1)


# --------------------------------------------------------------------------- #
# tamper / forgery — every one must fail closed
# --------------------------------------------------------------------------- #
def test_altered_root_fails_message_imprint():
    tsa = mint_local_tsa()
    digest = _digest()
    record = _record_for(issue_timestamp_response(digest, tsa))
    # Flip the root the receipt claims; the token still imprints the OLD root.
    forged = record.model_copy(update={"root_hash_hex": hashlib.sha256(b"a-different-tree").hexdigest()})
    result = verify_anchor_receipt(forged, pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.SUBJECT_MISMATCH


def test_caller_supplied_expected_digest_mismatch_fails():
    tsa = mint_local_tsa()
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa)
    result = verify_anchor_receipt(
        _record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der, expected_subject_digest=hashlib.sha256(b"x").digest()
    )
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.SUBJECT_MISMATCH


def test_wrong_pin_fails_untrusted():
    tsa = mint_local_tsa()
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa)
    other = mint_local_tsa()
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=other.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.TSA_UNTRUSTED


def test_forged_signature_with_real_cert_embedded_fails():
    """The load-bearing case: an attacker mints a token with a back-dated
    genTime, embeds the *real* TSA cert, but cannot sign with the TSA's key.
    Verifying the CMS signature against the embedded cert catches it."""
    tsa = mint_local_tsa()
    digest = _digest()
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resp = issue_timestamp_response(digest, tsa, sign_key=attacker_key, gen_time="20200101000000Z")
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.SIGNATURE_INVALID


def test_tampered_token_byte_fails():
    """Flipping a byte in the cert/signature region breaks verification — never a
    silent pass."""
    tsa = mint_local_tsa()
    digest = _digest()
    resp = bytearray(issue_timestamp_response(digest, tsa))
    resp[len(resp) * 2 // 3] ^= 0x01
    result = verify_anchor_receipt(_record_for(bytes(resp)), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False


def test_missing_timestamping_eku_fails():
    tsa = mint_local_tsa(eku=False)
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa)
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.MISSING_EKU


def test_non_sole_timestamping_eku_fails():
    """RFC 3161 §2.3: a cert authorized for timestamping *and other uses* (e.g. a
    multi-purpose cert from the same CA) must not be trusted to timestamp."""
    from cryptography.x509.oid import ExtendedKeyUsageOID

    tsa = mint_local_tsa(extra_ekus=(ExtendedKeyUsageOID.CLIENT_AUTH,))
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa)
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.MISSING_EKU


def test_not_granted_status_fails():
    tsa = mint_local_tsa()
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa, status=2)
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.NOT_GRANTED


def test_gentime_outside_cert_validity_fails():
    # TSA cert valid only through 2026-03; a token claiming 2026-06 is rejected.
    tsa = mint_local_tsa(not_after=datetime(2026, 3, 1, tzinfo=timezone.utc))
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa, gen_time="20260601120000Z")
    result = verify_anchor_receipt(_record_for(resp), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.OUTSIDE_VALIDITY


def test_nonce_mismatch_fails():
    tsa = mint_local_tsa()
    digest = _digest()
    resp = issue_timestamp_response(digest, tsa, nonce=111)
    result = verify_anchor_receipt(
        _record_for(resp, nonce=111), pinned_tsa_cert_der=tsa.ca_pin_der, expected_nonce=222
    )
    assert result.ok is False
    assert result.failure_code is AnchorFailureCode.NONCE_MISMATCH


def test_garbage_response_fails_closed():
    tsa = mint_local_tsa()
    result = verify_anchor_receipt(_record_for(b"\x30\x03\x02\x01\x00"), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is False
    assert result.failure_code in (
        AnchorFailureCode.MALFORMED,
        AnchorFailureCode.NOT_GRANTED,
        AnchorFailureCode.NO_TST_TOKEN,
    )


# --------------------------------------------------------------------------- #
# the record is self-describing and JSON-portable
# --------------------------------------------------------------------------- #
def test_verification_recomputes_digest_and_never_trusts_stored_hex():
    tsa = mint_local_tsa()
    digest = _digest()
    record = _record_for(issue_timestamp_response(digest, tsa))
    # Poison the stored subject digest; verification recomputes from origin/size/
    # root, so the poisoned field is ignored and the true imprint still matches.
    poisoned = record.model_copy(update={"subject_digest_hex": "00" * 32})
    result = verify_anchor_receipt(poisoned, pinned_tsa_cert_der=tsa.ca_pin_der)
    assert result.ok is True
    assert result.subject_digest_hex == digest.hex()


# --------------------------------------------------------------------------- #
# guardrail: anchoring is ADDITIVE — it never mutates the chain or the root
# --------------------------------------------------------------------------- #
def _evidence_record(seq: int, previous_hash: str | None) -> EvidenceRecord:
    import json
    from uuid import uuid4

    payload = json.dumps({"seq": seq}, sort_keys=True, separators=(",", ":"))
    payload_sha = hashlib.sha256(payload.encode()).hexdigest()
    chain_input = json.dumps(
        {"payload_sha256": payload_sha, "previous_hash": previous_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    record_hash = hashlib.sha256(chain_input.encode()).hexdigest()
    return EvidenceRecord(
        decision_id=uuid4(),
        request_id=uuid4(),
        record_type="decision",
        payload_json=payload,
        payload_sha256=payload_sha,
        previous_hash=previous_hash,
        record_hash=record_hash,
        policy_version="v1",
    )


def test_anchoring_does_not_mutate_chain_or_root():
    # An independent evidence chain — verifies valid before AND after anchoring.
    r0 = _evidence_record(0, None)
    r1 = _evidence_record(1, r0.record_hash)
    assert verify_evidence_chain([r0, r1]).is_valid is True

    # A gix checkpoint over those record hashes; capture its root.
    hashes_hex = (r0.record_hash, r1.record_hash)
    root_before = merkle_root(hashes_hex)
    publisher = CheckpointPublisher(origin="tex.local/gix-decision-log", read_record_hashes=lambda: hashes_hex)
    snapshot = publisher.current_signed_checkpoint()

    # Produce + serialize an anchor record for this checkpoint.
    tsa = mint_local_tsa()
    digest = anchor_subject_digest(
        snapshot.checkpoint.origin, snapshot.checkpoint.tree_size, snapshot.checkpoint.root_hash
    )
    record = CheckpointAnchorRecord.from_response(
        checkpoint=snapshot.checkpoint,
        signed_note=snapshot.signed_note,
        authority="local-tsa",
        response_der=issue_timestamp_response(digest, tsa),
    )
    _ = record.model_dump_json()  # persistence round-trips, no exception

    # Nothing the anchor touched changed the chain or the root.
    assert verify_evidence_chain([r0, r1]).is_valid is True
    assert merkle_root(hashes_hex) == root_before
    assert snapshot.checkpoint.root_hash_hex == root_before
    assert record.root_hash_hex == root_before  # binds to exactly this root, additively
