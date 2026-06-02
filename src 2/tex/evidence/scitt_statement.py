"""
SCITT-shaped Signed Statement builder for Tex evidence.

This module mints COSE_Sign1_Tagged envelopes over arbitrary CBOR claim
sets, intended for use as SCITT Signed Statements. It is a sibling of
``tex.c2pa.signer`` but is **not** C2PA-specific — the payload is an
opaque CBOR-encoded claim set chosen by the caller.

What we emit
------------
A ``COSE_Sign1_Tagged`` (CBOR tag 18) envelope per RFC 9052 §4.2,
matching the SCITT architecture's mandate that "Signed Statements
produced by Issuers must be COSE_Sign1 messages" (draft-ietf-scitt-
architecture-22 §6).

The protected header carries:
  * ``alg`` (label 1) — COSE algorithm integer from
    ``tex.evidence.scitt_cose_alg.cose_alg_for``
  * ``content-type`` (label 3) — set to ``"application/cbor"`` by
    default, per draft-kamimura-scitt-refusal-events-02 §5.1
  * Optional ``x5chain`` (label 33) — array of DER-encoded X.509
    certificates per RFC 9360. Omitted when caller passes no chain.

Unprotected header is the empty map ``{}``.

Payload mode: **attached**. Unlike the C2PA signer, which uses
detached payload (``payload`` = nil) and ships the claim CBOR
out-of-band in the manifest, SCITT Signed Statements ship the claim
set in the envelope itself. This matches the refusal-events spec
example C.2 (DENY JSON example shown serialized in line).

Algorithm agility
-----------------
The actual signing operation routes through
``tex.pqcrypto.algorithm_agility.get_signature_provider``, which is
the single chokepoint for crypto primitives in Tex. The COSE alg
integer is resolved via ``tex.evidence.scitt_cose_alg.cose_alg_for``
— a SCITT-permissive map (full Tex enum) distinct from the C2PA-
restricted whitelist.

Claim set construction
----------------------
The caller supplies the claim set as a Python mapping. Common claims
defined by draft-kamimura-scitt-refusal-events-02 §3.1 are:

  * ``event-type``     — "ATTEMPT" | "DENY" | "GENERATE" | "ERROR"
                        plus deployment-specific extensions (we use
                        ``"ATTRIBUTE"`` for Tex attribution statements,
                        permitted by the spec's ``* tstr => any``
                        extension point in §4)
  * ``event-id``       — UUIDv7 string (per RFC 9562, recommended in
                        §3.1)
  * ``timestamp``      — RFC 3339 string or epoch integer
  * ``issuer``         — issuer URI

We do **not** validate the claim set semantically. Callers are
responsible for assembling a claim set that conforms to whatever
profile (refusal events, VAP, VCP, or a Tex-private extension) they
target. The builder is encoding-only.

Verification
------------
``verify_signed_statement`` performs a deterministic COSE_Sign1
verification using the algorithm-agility provider for the encoded
alg integer. Returns ``True`` iff the signature validates over the
canonical ``Sig_structure`` per RFC 9052 §4.4.

References
----------
- RFC 9052 (COSE Structures), STD 96
- draft-ietf-scitt-architecture-22
- draft-kamimura-scitt-refusal-events-02
- draft-kamimura-vap-framework-00 (terminology)

Hard constraints satisfied
--------------------------
- Pydantic v2 strict (where models are exposed)
- All crypto routed through algorithm_agility
- Fail-closed: every error path raises rather than returning a default
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from tex.c2pa import _cbor
from tex.evidence.scitt_cose_alg import cose_alg_for
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureKeyPair,
    get_signature_provider,
)


# COSE header parameter labels per IANA COSE Header Parameters registry.
_COSE_HDR_ALG: int = 1
_COSE_HDR_CONTENT_TYPE: int = 3
_COSE_HDR_X5CHAIN: int = 33

# Content type recommended by draft-kamimura-scitt-refusal-events-02 §5.1.
_DEFAULT_CONTENT_TYPE: str = "application/cbor"

# Sig_structure context string per RFC 9052 §4.4 for COSE_Sign1.
_SIG1_CONTEXT: str = "Signature1"


@dataclass(frozen=True, slots=True)
class SignedStatement:
    """A SCITT-shaped Signed Statement.

    ``envelope_cbor`` is the canonical CBOR encoding of the
    COSE_Sign1_Tagged envelope. ``payload_cbor`` is the inner claim
    set CBOR (handy for ledger entries that want to hash the payload
    separately from the envelope).
    """

    envelope_cbor: bytes
    payload_cbor: bytes
    protected_serialized: bytes
    cose_alg: int
    signature: bytes


def _build_protected_header(
    *,
    alg: int,
    content_type: str,
    x5chain_der: tuple[bytes, ...],
) -> bytes:
    """Serialize the COSE_Sign1 protected header to bytes."""
    header: dict[int, object] = {
        _COSE_HDR_ALG: alg,
        _COSE_HDR_CONTENT_TYPE: content_type,
    }
    if x5chain_der:
        header[_COSE_HDR_X5CHAIN] = list(x5chain_der)
    return _cbor.encode(header)


def _build_sig_structure(
    *,
    protected_serialized: bytes,
    payload: bytes,
) -> bytes:
    """Build the COSE_Sign1 Sig_structure per RFC 9052 §4.4.

        Sig_structure = [
            "Signature1",        ; context for COSE_Sign1
            body_protected,      ; bstr (serialized protected header)
            external_aad,        ; bstr (zero-length here)
            payload              ; bstr (claim set CBOR)
        ]
    """
    return _cbor.encode([_SIG1_CONTEXT, protected_serialized, b"", payload])


def _build_cose_sign1_tagged_attached(
    *,
    protected_serialized: bytes,
    payload: bytes,
    signature: bytes,
) -> bytes:
    """Wrap the attached-payload COSE_Sign1 in tag 18.

    Unlike the C2PA signer (detached payload, nil), SCITT signed
    statements ship the claim set **in** the envelope.
    """
    cose_sign1 = [protected_serialized, {}, payload, signature]
    return _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, cose_sign1)


def mint_signed_statement(
    *,
    claim_set: Mapping[str, Any],
    signing_key: SignatureKeyPair,
    x5chain_der: tuple[bytes, ...] = (),
    content_type: str = _DEFAULT_CONTENT_TYPE,
) -> SignedStatement:
    """Mint a SCITT-shaped COSE_Sign1 Signed Statement.

    Parameters
    ----------
    claim_set
        The claim set as a plain mapping. Will be CBOR-encoded
        deterministically per the rules in ``tex.c2pa._cbor`` (RFC
        8949 §4.2.1). Caller is responsible for the semantic shape
        of the claim set (refusal-events ATTRIBUTE, VAP, etc.).
    signing_key
        Tex algorithm-agile key pair. The COSE alg label is resolved
        from ``signing_key.algorithm`` via
        ``tex.evidence.scitt_cose_alg.cose_alg_for``.
    x5chain_der
        Optional tuple of DER-encoded X.509 certificates for the
        ``x5chain`` protected header. End-entity first per RFC 9360.
        Empty tuple omits the header entirely.
    content_type
        Value for the COSE ``content-type`` (label 3) protected
        header. Defaults to ``"application/cbor"`` per refusal-events
        §5.1.

    Returns
    -------
    SignedStatement
        Carries the full envelope CBOR plus useful intermediates.

    Raises
    ------
    NotImplementedError
        If the signing key's algorithm has no COSE alg mapping.
    ValueError
        If the claim set is empty (defensive — empty claim sets are
        almost certainly a programmer error).
    """
    if not claim_set:
        raise ValueError("claim_set must not be empty")

    cose_alg = cose_alg_for(signing_key.algorithm)
    provider = get_signature_provider(signing_key.algorithm)

    payload = _cbor.encode(dict(claim_set))
    protected_serialized = _build_protected_header(
        alg=cose_alg,
        content_type=content_type,
        x5chain_der=x5chain_der,
    )
    sig_input = _build_sig_structure(
        protected_serialized=protected_serialized,
        payload=payload,
    )
    signature = provider.sign(sig_input, signing_key)
    envelope = _build_cose_sign1_tagged_attached(
        protected_serialized=protected_serialized,
        payload=payload,
        signature=signature,
    )

    emit_event(
        "evidence.scitt.statement.minted",
        algorithm=signing_key.algorithm.value,
        cose_alg=cose_alg,
        key_id=signing_key.key_id,
        payload_bytes=len(payload),
        envelope_bytes=len(envelope),
        signature_bytes=len(signature),
        chain_length=len(x5chain_der),
        content_type=content_type,
    )

    return SignedStatement(
        envelope_cbor=envelope,
        payload_cbor=payload,
        protected_serialized=protected_serialized,
        cose_alg=cose_alg,
        signature=signature,
    )


# --- Verification ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ParsedEnvelope:
    protected_serialized: bytes
    protected_header: dict[int, object]
    unprotected_header: dict[Any, Any]
    payload: bytes
    signature: bytes


def parse_envelope(envelope_cbor: bytes) -> _ParsedEnvelope:
    """Parse a COSE_Sign1_Tagged envelope into its four fields.

    Fail-closed: rejects any envelope that doesn't decode cleanly into
    the expected 4-element COSE_Sign1 array.
    """
    untagged = _cbor.unwrap_tag(_cbor.decode(envelope_cbor), _cbor.COSE_SIGN1_TAG)
    if not isinstance(untagged, list) or len(untagged) != 4:
        raise ValueError(
            "envelope is not a 4-element COSE_Sign1 array"
        )
    protected_serialized, unprotected, payload, signature = untagged
    if not isinstance(protected_serialized, (bytes, bytearray)):
        raise ValueError("COSE_Sign1 body_protected must be a byte string")
    if not isinstance(unprotected, dict):
        raise ValueError("COSE_Sign1 unprotected header must be a map")
    if payload is None:
        # Detached payload is permitted by RFC 9052 but not by the
        # SCITT statements we mint. Reject for now.
        raise ValueError(
            "detached payload (nil) is not supported by Tex SCITT "
            "verifier; minted statements always carry attached payload"
        )
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("COSE_Sign1 payload must be a byte string")
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("COSE_Sign1 signature must be a byte string")

    if protected_serialized:
        protected_header = _cbor.decode(bytes(protected_serialized))
        if not isinstance(protected_header, dict):
            raise ValueError("COSE_Sign1 protected header must decode to a map")
    else:
        protected_header = {}

    return _ParsedEnvelope(
        protected_serialized=bytes(protected_serialized),
        protected_header=protected_header,
        unprotected_header=unprotected,
        payload=bytes(payload),
        signature=bytes(signature),
    )


def verify_signed_statement(
    *,
    envelope_cbor: bytes,
    public_key: bytes,
    expected_algorithm: object,
) -> bool:
    """Verify a SCITT-shaped Signed Statement.

    Returns ``True`` iff the signature validates over the canonical
    Sig_structure per RFC 9052 §4.4. Caller supplies the public key
    and the expected algorithm (a ``SignatureAlgorithm`` enum value).

    The protected header's ``alg`` field must match the expected
    algorithm — fail-closed against alg substitution.
    """
    # Defensive import to keep module load free of circular risk.
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

    if not isinstance(expected_algorithm, SignatureAlgorithm):
        raise TypeError(
            "expected_algorithm must be a SignatureAlgorithm enum"
        )

    parsed = parse_envelope(envelope_cbor)
    expected_cose_alg = cose_alg_for(expected_algorithm)
    actual_alg = parsed.protected_header.get(_COSE_HDR_ALG)
    if actual_alg != expected_cose_alg:
        return False

    sig_input = _build_sig_structure(
        protected_serialized=parsed.protected_serialized,
        payload=parsed.payload,
    )
    provider = get_signature_provider(expected_algorithm)
    return provider.verify(sig_input, parsed.signature, public_key)


def decode_payload(envelope_cbor: bytes) -> dict[str, Any]:
    """Decode the claim set carried as the envelope payload.

    Convenience for verifiers / auditors that want to inspect claim
    contents without recomputing the signature.
    """
    parsed = parse_envelope(envelope_cbor)
    decoded = _cbor.decode(parsed.payload)
    if not isinstance(decoded, dict):
        raise ValueError("payload did not decode to a CBOR map")
    # Re-shape int-keyed COSE-style maps would be unusual here; we
    # expect str keys (refusal-events §4 CDDL definition uses tstr).
    return {str(k): v for k, v in decoded.items()}


__all__ = [
    "SignedStatement",
    "mint_signed_statement",
    "verify_signed_statement",
    "parse_envelope",
    "decode_payload",
]
