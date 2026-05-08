"""
C2PA manifest signer.

Produces a ``COSE_Sign1_Tagged`` envelope (RFC 8152 §4.2 / RFC 9052)
over the canonicalized claim per C2PA 2.2 §13.2. Detached payload
mode: the ``payload`` field of the wire-format ``COSE_Sign1`` is
``nil`` (CBOR null), but the in-memory ``Sig_structure`` is populated
with the claim CBOR so the digital signature actually covers the claim.

Header layout (C2PA 2.2 §13.2, §14.5)
-------------------------------------
Protected header (CBOR map, byte-string-wrapped per RFC 9052 §3):

    1  (alg)     : COSE alg int — see ``tex.c2pa._cose_alg``
    33 (x5chain) : array of DER-encoded X.509 certs, end-entity first

Unprotected header: empty map (``{}``).

x5chain placement: the spec says claim generators **shall always place
the x5chain header in the protected header bucket**. We follow that
strictly.

Algorithm agility
-----------------
The active signer is taken from the algorithm-agile dispatcher
``tex.pqcrypto.algorithm_agility.get_signature_provider``. C2PA 2.2
§13.2 only allows ES256/ES384/ES512/PS256/PS384/PS512/EdDSA, so the
dispatcher's ML-DSA / SLH-DSA / hybrid options are rejected by
``_cose_alg.cose_alg_for`` with a clear pointer at §13.2.

Default today: ECDSA-P256 (rule 6 in the thread brief — default ECDSA
today, switch to ML-DSA-65 when liboqs lands AND C2PA's allowed list
expands to include it).

Keystore
--------
``sign_manifest``'s ``signing_key_id`` argument is an opaque keystore
identifier (matches the field name on ``SignatureKeyPair``). The
process-local ``register_signing_key`` / ``get_signing_key`` /
``clear_signing_keys`` helpers below are the in-process keystore. A
real deployment plugs a different keystore in via
``set_keystore(callable)`` — see the protocol below.

Trust List note (May 2026)
--------------------------
The ITL (Interoperable Trust List) was frozen on 2026-01-01 — no new
entries, no refreshes. The official C2PA Trust List, curated by the
Linux Foundation under the Conformance Program, supersedes it for new
manifests; the TSA Trust List is a separate list for time-stamp
authorities. DigiCert sells C2PA certificates at ~$289/year. There is
no Let's Encrypt equivalent yet. Tex must operate its own intermediate
CA and cross-sign through DigiCert (or wait for the open trust list to
expand). Manifests signed with ITL-derived certs remain valid against
the legacy trust model; new manifests should anchor to the official
C2PA TL.

Priority: P0.
"""

from __future__ import annotations

import base64
import threading
from typing import Callable, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tex.c2pa import _cbor
from tex.c2pa._canonical_claim import canonical_claim_cbor
from tex.c2pa._cose_alg import cose_alg_for, cose_alg_label
from tex.c2pa.manifest import C2paManifest
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureKeyPair,
    get_signature_provider,
)


# COSE header parameter labels (per IANA COSE Header Parameters registry).
_COSE_HDR_ALG: int = 1
_COSE_HDR_X5CHAIN: int = 33


# ---- Keystore plumbing ------------------------------------------------------

KeystoreLookup = Callable[[str], SignatureKeyPair]


_KEY_LOCK = threading.RLock()
_LOCAL_KEYSTORE: dict[str, SignatureKeyPair] = {}
_KEYSTORE_LOOKUP: KeystoreLookup | None = None


def register_signing_key(key: SignatureKeyPair) -> None:
    """Register ``key`` in the process-local in-memory keystore.

    Convenience for tests and for the headless ``tex.api`` path. A
    production deployment should call ``set_keystore`` with an HSM or
    KMS-backed lookup instead.
    """
    with _KEY_LOCK:
        _LOCAL_KEYSTORE[key.key_id] = key


def clear_signing_keys() -> None:
    """Drop all keys from the process-local keystore (test hygiene)."""
    with _KEY_LOCK:
        _LOCAL_KEYSTORE.clear()


def set_keystore(lookup: KeystoreLookup | None) -> None:
    """Install a custom keystore lookup; ``None`` reverts to the
    in-memory store."""
    global _KEYSTORE_LOOKUP
    _KEYSTORE_LOOKUP = lookup


def _resolve_signing_key(signing_key_id: str) -> SignatureKeyPair:
    if _KEYSTORE_LOOKUP is not None:
        return _KEYSTORE_LOOKUP(signing_key_id)
    with _KEY_LOCK:
        try:
            return _LOCAL_KEYSTORE[signing_key_id]
        except KeyError as exc:
            raise KeyError(
                f"No signing key registered for key_id={signing_key_id!r}. "
                "Call tex.c2pa.signer.register_signing_key(...) first, or "
                "install a custom keystore via set_keystore(...)."
            ) from exc


# ---- COSE_Sign1 construction ------------------------------------------------


def _split_pem_chain(certificate_chain_pem: str) -> list[bytes]:
    """Split a PEM bundle into a list of DER-encoded certificate bytes.

    Order is preserved — C2PA 2.2 §14.5 expects the end-entity
    certificate first, then any intermediates. Roots may or may not
    be present; verifiers fetch them from the trust list.
    """
    certs = x509.load_pem_x509_certificates(certificate_chain_pem.encode("utf-8"))
    if not certs:
        raise ValueError("certificate_chain_pem contained no certificates")
    return [c.public_bytes(serialization.Encoding.DER) for c in certs]


def _build_protected_header(
    *, alg: int, x5chain_der: list[bytes]
) -> tuple[dict[int, object], bytes]:
    """Construct the protected header map and its serialized bytes.

    Per RFC 9052 §3, the protected header is a CBOR map encoded into a
    byte string that travels as ``protected`` in the COSE_Sign1 array.
    """
    header: dict[int, object] = {_COSE_HDR_ALG: alg}
    if x5chain_der:
        # RFC 9360: x5chain is an array of byte strings (or a single
        # byte string for a one-cert chain). We always emit an array
        # — round-trips cleanly and matches what c2patool emits.
        header[_COSE_HDR_X5CHAIN] = list(x5chain_der)
    serialized = _cbor.encode(header) if header else b""
    return header, serialized


def _build_sig_structure(
    *, protected_serialized: bytes, payload: bytes
) -> bytes:
    """Build the ``Sig_structure`` per RFC 9052 §4.4 / C2PA 2.2 §13.2.

        Sig_structure = [
            "Signature1",        ; context
            body_protected,      ; bstr (serialized protected header)
            external_aad,        ; bstr (zero-length per C2PA §13.2)
            payload              ; bstr (canonical claim CBOR)
        ]
    """
    return _cbor.encode(["Signature1", protected_serialized, b"", payload])


def _build_cose_sign1_tagged(
    *,
    protected_serialized: bytes,
    signature: bytes,
) -> bytes:
    """Wrap the COSE_Sign1 array in tag 18 (COSE_Sign1_Tagged).

    Per C2PA 2.2 §13.2, payload is nil (None) in detached content mode.
    Unprotected header is the empty map.
    """
    cose_sign1 = [protected_serialized, {}, None, signature]
    return _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, cose_sign1)


def sign_manifest(
    manifest: C2paManifest,
    *,
    signing_key_id: str,
    certificate_chain_pem: str,
) -> C2paManifest:
    """
    Sign the manifest in place, returning a new manifest with `signature_b64`
    and `certificate_chain_pem` populated.

    ``signing_key_id`` is an opaque identifier — see the keystore
    plumbing at the top of this module. The corresponding
    ``SignatureKeyPair`` is fetched, its algorithm tag is mapped to a
    COSE alg integer per ``_cose_alg.cose_alg_for``, and the active
    signature provider is dispatched via
    ``tex.pqcrypto.algorithm_agility.get_signature_provider``.

    The output is a base64-encoded ``COSE_Sign1_Tagged`` envelope (CBOR
    tag 18) per C2PA 2.2 §13.2. Stored as ``signature_b64`` on the
    returned manifest.

    TODO(P0): canonicalize claim bytes per C2PA 2.2 section 13
    TODO(P0): produce COSE_Sign1 envelope per C2PA 2.2 section 14
    TODO(P0): use HybridMlDsaEd25519Provider for transition-period dual signing
    TODO(P0): embed signing time + revocation OCSP staple
    TODO(P1): add timestamp-authority signature per C2PA 2.2 §14 once
        Tex has a TSA trust-list relationship.
    """
    signing_key = _resolve_signing_key(signing_key_id)
    cose_alg = cose_alg_for(signing_key.algorithm)
    provider = get_signature_provider(signing_key.algorithm)

    chain_der = _split_pem_chain(certificate_chain_pem)
    _, protected_serialized = _build_protected_header(
        alg=cose_alg, x5chain_der=chain_der
    )
    payload = canonical_claim_cbor(manifest.claim)
    sig_input = _build_sig_structure(
        protected_serialized=protected_serialized, payload=payload
    )
    signature = provider.sign(sig_input, signing_key)
    cose_sign1_tagged = _build_cose_sign1_tagged(
        protected_serialized=protected_serialized, signature=signature
    )
    encoded = base64.b64encode(cose_sign1_tagged).decode("ascii")

    emit_event(
        "c2pa.manifest.signed",
        algorithm=signing_key.algorithm.value,
        cose_alg=cose_alg,
        cose_alg_label=cose_alg_label(signing_key.algorithm),
        key_id=signing_key_id,
        chain_length=len(chain_der),
        payload_bytes=len(payload),
        signature_bytes=len(signature),
        envelope_bytes=len(cose_sign1_tagged),
    )
    return manifest.model_copy(
        update={
            "signature_b64": encoded,
            "certificate_chain_pem": certificate_chain_pem,
        }
    )


def algorithms_supported() -> Iterable:
    """List the algorithms this signer can emit (C2PA 2.2 §13.2 subset)."""
    from tex.c2pa._cose_alg import _TEX_TO_COSE

    return tuple(_TEX_TO_COSE.keys())
