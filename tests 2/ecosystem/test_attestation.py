"""
Tests for tex.ecosystem._attestation — SCITT-shaped Signed Statement builder.

The envelope is the on-the-wire artifact an insurer/regulator verifies. These
tests pin its shape, prove its signature is verifiable with the public key
alone (no Tex-specific tooling), and lock the canonical-JSON determinism so
two attestations with the same inputs produce the same bytes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from tex.ecosystem._attestation import (
    ATTESTATION_ENVELOPE_TYPE,
    ATTESTATION_ISSUER,
    ATTESTATION_PAYLOAD_TYPE,
    ATTESTATION_SCHEMA_VERSION,
    ATTESTATION_SUBJECT,
    build_attestation_payload,
    build_envelope,
    parse_envelope,
    sign_envelope,
)
from tex.events._canonical import canonical_json, sha256_hex
from tex.events._ecdsa_provider import default_signature_provider


@pytest.fixture
def signing_provider():
    return default_signature_provider()


@pytest.fixture
def keypair(signing_provider):
    return signing_provider.generate_keypair("attestation-test")


@pytest.fixture
def sample_payload():
    return build_attestation_payload(
        state_hash_at_end="a" * 64,
        window_merkle_root="b" * 64,
        ledger_head_sequence=42,
        ledger_head_record_hash="c" * 64,
        event_count_in_window=7,
        first_sequence_in_window=36,
        last_sequence_in_window=42,
    )


@pytest.fixture
def sample_envelope(sample_payload):
    return build_envelope(
        issued_at=datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC),
        period_start=datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC),
        period_end=datetime(2026, 5, 7, 0, 0, 0, tzinfo=UTC),
        payload=sample_payload,
    )


# --------------------------------------------------------- payload shape


def test_payload_has_all_required_fields(sample_payload) -> None:
    expected = {
        "schema_version",
        "envelope_type",
        "state_hash_at_end",
        "window_merkle_root",
        "ledger_head_sequence",
        "ledger_head_record_hash",
        "event_count_in_window",
        "first_sequence_in_window",
        "last_sequence_in_window",
    }
    assert set(sample_payload.keys()) == expected


def test_payload_is_canonical_json_compatible(sample_payload) -> None:
    """No floats; canonical_json must accept it."""
    canonical = canonical_json(sample_payload)
    assert isinstance(canonical, str)
    # Round-trip parse-able.
    json.loads(canonical)


def test_payload_handles_empty_window_with_none_seqs() -> None:
    payload = build_attestation_payload(
        state_hash_at_end="0" * 64,
        window_merkle_root="0" * 64,
        ledger_head_sequence=0,
        ledger_head_record_hash="0" * 64,
        event_count_in_window=0,
        first_sequence_in_window=None,
        last_sequence_in_window=None,
    )
    assert payload["first_sequence_in_window"] is None
    # Canonical JSON must accept None.
    canonical_json(payload)


# --------------------------------------------------------- envelope shape


def test_envelope_carries_scitt_compatible_cwt_claims(sample_envelope) -> None:
    cwt = sample_envelope["cwt_claims"]
    assert cwt["iss"] == ATTESTATION_ISSUER
    assert cwt["sub"] == ATTESTATION_SUBJECT
    assert cwt["nbf"].startswith("2026-05-01")
    assert cwt["exp"].startswith("2026-05-07")
    assert cwt["iat"].startswith("2026-05-07")


def test_envelope_pins_schema_version(sample_envelope) -> None:
    assert sample_envelope["schema_version"] == ATTESTATION_SCHEMA_VERSION
    assert ATTESTATION_SCHEMA_VERSION == "1"  # bump deliberately


def test_envelope_pins_envelope_type_and_payload_type(sample_envelope) -> None:
    assert sample_envelope["envelope_type"] == ATTESTATION_ENVELOPE_TYPE
    assert sample_envelope["envelope_type"] == "tex.ecosystem.state_attestation"
    assert sample_envelope["payload_type"] == ATTESTATION_PAYLOAD_TYPE


def test_envelope_canonical_json_is_deterministic(sample_envelope) -> None:
    """Two canonicalizations of the same envelope yield identical bytes."""
    a = canonical_json(sample_envelope)
    b = canonical_json(sample_envelope)
    assert a == b


# --------------------------------------------------------- sign + parse


def test_sign_envelope_returns_bytes_with_trailer(
    sample_envelope, keypair, signing_provider
) -> None:
    packet = sign_envelope(
        envelope=sample_envelope,
        signing_key=keypair,
        provider=signing_provider,
    )
    assert isinstance(packet, bytes)
    text = packet.decode("utf-8")
    assert "\nsignature: " in text
    assert "\nkey_id: " in text
    assert "\nalgorithm: " in text


def test_parse_envelope_round_trip(
    sample_envelope, keypair, signing_provider
) -> None:
    packet = sign_envelope(
        envelope=sample_envelope,
        signing_key=keypair,
        provider=signing_provider,
    )
    parsed_env, signature, key_id, algorithm = parse_envelope(packet)
    assert parsed_env == sample_envelope
    assert key_id == keypair.key_id
    assert algorithm == keypair.algorithm.value
    assert isinstance(signature, bytes)
    assert len(signature) > 0


def test_signature_verifies_with_public_key_alone(
    sample_envelope, keypair, signing_provider
) -> None:
    """The whole point: an external verifier needs only the public key."""
    packet = sign_envelope(
        envelope=sample_envelope,
        signing_key=keypair,
        provider=signing_provider,
    )
    parsed_env, signature, _, _ = parse_envelope(packet)
    envelope_sha256 = sha256_hex(canonical_json(parsed_env))
    assert signing_provider.verify(
        envelope_sha256.encode("utf-8"),
        signature,
        keypair.public_key,
    )


def test_signature_does_not_verify_with_wrong_key(
    sample_envelope, keypair, signing_provider
) -> None:
    packet = sign_envelope(
        envelope=sample_envelope,
        signing_key=keypair,
        provider=signing_provider,
    )
    parsed_env, signature, _, _ = parse_envelope(packet)
    envelope_sha256 = sha256_hex(canonical_json(parsed_env))
    other = signing_provider.generate_keypair("other")
    assert not signing_provider.verify(
        envelope_sha256.encode("utf-8"),
        signature,
        other.public_key,
    )


def test_signature_does_not_verify_after_envelope_mutation(
    sample_envelope, keypair, signing_provider
) -> None:
    packet = sign_envelope(
        envelope=sample_envelope,
        signing_key=keypair,
        provider=signing_provider,
    )
    parsed_env, signature, _, _ = parse_envelope(packet)
    parsed_env["payload"]["event_count_in_window"] = 9999
    tampered_sha = sha256_hex(canonical_json(parsed_env))
    assert not signing_provider.verify(
        tampered_sha.encode("utf-8"),
        signature,
        keypair.public_key,
    )


# --------------------------------------------------------- parse robustness


def test_parse_envelope_rejects_missing_signature() -> None:
    with pytest.raises(ValueError, match="signature: ' trailer"):
        parse_envelope(b'{"a": 1}\n')


def test_parse_envelope_rejects_malformed_trailer_line() -> None:
    bogus = b'{"a": 1}\nsignature: zzzz\nbroken-no-colon\nkey_id: x\nalgorithm: y\n'
    with pytest.raises(ValueError, match="malformed trailer line"):
        parse_envelope(bogus)


def test_parse_envelope_rejects_missing_required_trailer_field() -> None:
    no_algo = b'{"a": 1}\nsignature: AAAA\nkey_id: kid\n'
    with pytest.raises(ValueError, match="missing required field: 'algorithm'"):
        parse_envelope(no_algo)


def test_parse_envelope_rejects_invalid_base64_signature() -> None:
    bad_b64 = b'{"a": 1}\nsignature: !!!!\nkey_id: kid\nalgorithm: ecdsa-p256\n'
    with pytest.raises(ValueError, match="not valid base64"):
        parse_envelope(bad_b64)


def test_parse_envelope_rejects_invalid_json_envelope() -> None:
    bad_json = b'{not json,\nsignature: AAAA\nkey_id: kid\nalgorithm: ecdsa-p256\n'
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_envelope(bad_json)


# --------------------------------------------------------- determinism end-to-end


def test_two_signs_of_same_envelope_produce_same_canonical_bytes(
    sample_envelope, keypair, signing_provider
) -> None:
    """
    The envelope canonicalization is deterministic; the signature itself
    may vary (ECDSA includes randomness). Test the canonical body, not the
    full packet.
    """
    p1 = sign_envelope(
        envelope=sample_envelope, signing_key=keypair, provider=signing_provider
    )
    p2 = sign_envelope(
        envelope=sample_envelope, signing_key=keypair, provider=signing_provider
    )
    body1 = p1.split(b"\nsignature: ", 1)[0]
    body2 = p2.split(b"\nsignature: ", 1)[0]
    assert body1 == body2
