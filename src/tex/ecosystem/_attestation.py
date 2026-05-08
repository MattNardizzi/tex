"""
Ecosystem-state attestation envelope.

Produces a SCITT-shaped Signed Statement that an external verifier (insurer,
NAIC examiner, FTC auditor) can validate offline using only:
    - the public key (PEM bytes)
    - a SHA-256 implementation
    - a JSON parser
    - the canonical-JSON rules from ``tex.events._canonical``

No Tex-specific verifier required.

Wire format
-----------
The on-the-wire bytes are::

    <canonical_json_envelope>
    \\n
    signature: <base64(signature_over_envelope_sha256)>
    \\n
    key_id: <key_id>
    \\n
    algorithm: <signature_algorithm_value>
    \\n

Rationale for a JSON-with-trailer rather than COSE_Sign1 CBOR today:

* No CBOR dependency in the requirements.txt freeze.
* The envelope's *fields* mirror SCITT's Signed Statement (CWT_Claims, payload
  type, payload). Migrating to COSE_Sign1 is a serializer swap; the call
  site does not change.
* Tests can ``in`` / ``startswith`` against the bytes for cheap assertions.

Reference
---------
- IETF SCITT architecture draft -22 (April 2026): Signed Statement /
  Receipt structure, CWT claims, hash-detached payload.
- IETF SCRAPI -09 (April 2026): Transparency Service registration API.
- AAF (arxiv 2512.18561) §4.2: ecosystem-state evidence packet.

Priority: P0.

TODO(P0->P1): swap wire format to ``application/scitt-statement+cose`` once
  cbor2 is approved as a dependency.
TODO(P1): add a ``time_anchor`` field populated from a VDF beacon
  (eprint 2026/737) so ``nbf``/``exp`` are un-backdatable.
TODO(P2): include a ``zk_proof_id`` field for zkAgent (eprint 2026/199)
  proofs of agent execution covering the window.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from tex.events._canonical import canonical_json, sha256_hex
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureKeyPair,
    SignatureProvider,
)


# Bumped only when the canonical envelope structure changes shape. Pinned by
# tests so byte-for-byte compatibility is enforced.
ATTESTATION_SCHEMA_VERSION: str = "1"

# Mirrors SCITT's ``application/scitt-statement+cose`` content type while we
# emit JSON. Swap to the COSE media type when CBOR is approved.
ATTESTATION_PAYLOAD_TYPE: str = (
    "application/vnd.tex.ecosystem-state-attestation+json"
)

# Envelope-type discriminator carried inside the payload itself so a verifier
# can route to the right validator before parsing internals.
ATTESTATION_ENVELOPE_TYPE: str = "tex.ecosystem.state_attestation"

# CWT claim issuer. Future per-tenant deployments would parameterize this; for
# P0 a fixed string keeps the verification surface constant.
ATTESTATION_ISSUER: str = "tex"
ATTESTATION_SUBJECT: str = "ecosystem"


def build_attestation_payload(
    *,
    state_hash_at_end: str,
    window_merkle_root: str,
    ledger_head_sequence: int,
    ledger_head_record_hash: str,
    event_count_in_window: int,
    first_sequence_in_window: int | None,
    last_sequence_in_window: int | None,
) -> dict[str, Any]:
    """
    Build the canonical ``payload`` block of a Tex ecosystem state attestation.

    All fields are int/str/None so the result canonicalizes through
    ``tex.events._canonical.canonical_json`` without rejection.

    Parameters mirror the SCITT Statement payload shape:
    a self-contained dict whose canonical SHA-256 is what gets signed.

    Reference: IETF SCITT architecture draft -22, §6 (Signed Statements).
    """
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "envelope_type": ATTESTATION_ENVELOPE_TYPE,
        "state_hash_at_end": state_hash_at_end,
        "window_merkle_root": window_merkle_root,
        "ledger_head_sequence": ledger_head_sequence,
        "ledger_head_record_hash": ledger_head_record_hash,
        "event_count_in_window": event_count_in_window,
        "first_sequence_in_window": first_sequence_in_window,
        "last_sequence_in_window": last_sequence_in_window,
    }


def build_envelope(
    *,
    issued_at: datetime,
    period_start: datetime,
    period_end: datetime,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Wrap a payload in a SCITT-shaped envelope with CWT claims.

    The envelope's ``cwt_claims`` block uses the same field semantics as
    RFC 8392 (CBOR Web Tokens) and IETF SCITT — ``iss`` (issuer),
    ``sub`` (subject), ``iat`` (issued at), ``nbf`` (not before),
    ``exp`` (expires / period end). Datetimes are serialized as RFC 3339
    strings; integer-seconds-since-epoch is the COSE-CBOR convention but
    JSON callers historically read ISO strings, and the canonical hash
    pins both representations.

    Reference: RFC 8392 (CWT), IETF SCITT architecture draft -22 §6.
    """
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "envelope_type": ATTESTATION_ENVELOPE_TYPE,
        "cwt_claims": {
            "iss": ATTESTATION_ISSUER,
            "sub": ATTESTATION_SUBJECT,
            "iat": issued_at.isoformat(),
            "nbf": period_start.isoformat(),
            "exp": period_end.isoformat(),
        },
        "payload_type": ATTESTATION_PAYLOAD_TYPE,
        "payload": payload,
    }


def sign_envelope(
    *,
    envelope: dict[str, Any],
    signing_key: SignatureKeyPair,
    provider: SignatureProvider,
) -> bytes:
    """
    Sign an attestation envelope and produce wire-format bytes.

    Steps
    -----
    1. Canonicalize the envelope via ``canonical_json`` (RFC 8785 subset
       inherited from Thread 2). Float-rejecting; all envelope fields are
       int/str/None/dict by construction.
    2. SHA-256 the canonical bytes.
    3. Sign the SHA-256 hex (UTF-8 bytes) via the injected provider.
       Signing the *hex of the hash* — not the raw digest bytes — matches
       how Thread 2 signs ``record_hash`` in ``CryptoProvenance.attach``,
       so verifiers reuse the same byte-prep convention.
    4. Emit a four-line trailer (signature, key_id, algorithm) so the
       packet is greppable and field-extractable without CBOR.

    Reference: SCITT architecture draft -22 §6, RFC 9052 (COSE) for the
    field meanings (we serialize as JSON for now; migration path is in
    the module docstring).

    Returns
    -------
    bytes
        Wire-format attestation packet.
    """
    canonical_envelope_str = canonical_json(envelope)
    envelope_bytes = canonical_envelope_str.encode("utf-8")
    envelope_sha256 = sha256_hex(canonical_envelope_str)

    signature = provider.sign(
        envelope_sha256.encode("utf-8"),
        signing_key,
    )
    signature_b64 = base64.b64encode(signature).decode("ascii")

    trailer = (
        f"\nsignature: {signature_b64}\n"
        f"key_id: {signing_key.key_id}\n"
        f"algorithm: {signing_key.algorithm.value}\n"
    )

    emit_event(
        "ecosystem.attestation.signed",
        envelope_sha256=envelope_sha256,
        algorithm=signing_key.algorithm.value,
        key_id=signing_key.key_id,
    )
    return envelope_bytes + trailer.encode("ascii")


def parse_envelope(packet: bytes) -> tuple[dict[str, Any], bytes, str, str]:
    """
    Parse a wire-format attestation packet back into its components.

    Test-friendly inverse of ``sign_envelope``. Production verifiers should
    use this same parser since it's the reference implementation of the
    wire format.

    Returns
    -------
    (envelope_dict, signature_bytes, key_id, algorithm)

    Raises
    ------
    ValueError
        If the trailer is malformed or required fields are missing.
    """
    text = packet.decode("utf-8")
    # The envelope is a single canonical JSON object on a logical first
    # "section" terminated by the trailer's leading newline+keyword. The
    # trailer is small (four lines, ASCII), so a right-split is robust.
    sentinel = "\nsignature: "
    cut = text.rfind(sentinel)
    if cut == -1:
        raise ValueError("attestation packet missing 'signature: ' trailer")
    envelope_str = text[:cut]
    trailer_str = text[cut + 1 :]  # drop the leading \n

    # Parse trailer: three "key: value\n" lines.
    fields: dict[str, str] = {}
    for line in trailer_str.strip().splitlines():
        if ": " not in line:
            raise ValueError(f"malformed trailer line: {line!r}")
        key, _, value = line.partition(": ")
        fields[key] = value
    for required in ("signature", "key_id", "algorithm"):
        if required not in fields:
            raise ValueError(f"trailer missing required field: {required!r}")

    try:
        signature_bytes = base64.b64decode(
            fields["signature"].encode("ascii"), validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"signature is not valid base64: {exc}") from exc

    import json

    try:
        envelope_dict = json.loads(envelope_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"envelope is not valid JSON: {exc}") from exc

    return envelope_dict, signature_bytes, fields["key_id"], fields["algorithm"]
