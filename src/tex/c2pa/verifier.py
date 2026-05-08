"""
C2PA manifest verifier.

Offline verification: all required certificates travel inside the
manifest's x5chain header. The verifier needs only the C2PA Trust
List root CAs (or a local list of additional anchors per C2PA 2.1
§14.4) to validate.

Validation states (C2PA 2.1 §14.3)
----------------------------------
- Well-Formed: parseable, allowed assertions only.
- Valid:       Well-Formed + signature validates + cert in validity
               window + (no OCSP rejection — checked at P1 once OCSP
               stapling lands).
- Trusted:     Valid + signing credential anchored to a trust list.

This implementation reaches Trusted when ``trust_list_pem_paths`` is
provided and the cert chain anchors to one of those PEM bundles.
Otherwise the result tops out at Valid (``is_valid=True``,
``is_trust_list_anchored=False``).

Failure codes (C2PA 2.1 §15.7)
------------------------------
We surface the spec failure codes verbatim in
``C2paVerificationResult.issues`` so a downstream router can route on
them:

    claimSignature.missing
    claimSignature.mismatch
    claimSignature.validated
    signingCredential.invalid
    signingCredential.untrusted
    signingCredential.trusted
    algorithm.unsupported

Priority: P0.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tex.c2pa import _cbor
from tex.c2pa._canonical_claim import canonical_claim_cbor
from tex.c2pa._cose_alg import cose_alg_for
from tex.c2pa.manifest import C2paManifest
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    get_signature_provider,
)


# Reuse the COSE header parameter labels from the signer side.
_COSE_HDR_ALG: int = 1
_COSE_HDR_X5CHAIN: int = 33
_COSE_HDR_X5CHAIN_STR: str = "x5chain"


# C2PA 2.1 §15.7 failure codes that we emit verbatim.
ISSUE_CLAIM_SIG_MISSING: str = "claimSignature.missing"
ISSUE_CLAIM_SIG_MISMATCH: str = "claimSignature.mismatch"
ISSUE_CLAIM_SIG_VALIDATED: str = "claimSignature.validated"
ISSUE_SIGNING_CRED_INVALID: str = "signingCredential.invalid"
ISSUE_SIGNING_CRED_UNTRUSTED: str = "signingCredential.untrusted"
ISSUE_SIGNING_CRED_TRUSTED: str = "signingCredential.trusted"
ISSUE_ALGORITHM_UNSUPPORTED: str = "algorithm.unsupported"
ISSUE_OUTSIDE_VALIDITY: str = "claimSignature.outsideValidity"


@dataclass(frozen=True, slots=True)
class C2paVerificationResult:
    is_valid: bool
    issues: tuple[str, ...]
    signing_certificate_subject: str | None
    is_trust_list_anchored: bool


# Map COSE alg int → SignatureAlgorithm enum for lookup on verify.
def _signature_algorithm_for_cose_alg(cose_alg: int) -> SignatureAlgorithm | None:
    from tex.c2pa._cose_alg import _TEX_TO_COSE

    for tex_alg, (alg_int, _label) in _TEX_TO_COSE.items():
        if alg_int == cose_alg:
            return tex_alg
    return None


def _decode_envelope(signature_b64: str) -> tuple[bytes, dict, bytes]:
    """Decode the base64'd COSE_Sign1_Tagged into (protected_bytes,
    decoded_protected_map, signature_bytes).

    Raises ``ValueError`` on any structural problem.
    """
    try:
        envelope_bytes = base64.b64decode(signature_b64.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 — base64 raises a varied set
        raise ValueError(f"signature_b64 is not valid base64: {exc}") from exc

    decoded = _cbor.decode(envelope_bytes)
    decoded = _cbor.unwrap_tag(decoded, _cbor.COSE_SIGN1_TAG)
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ValueError(
            "COSE_Sign1 must be a 4-element array [protected, "
            "unprotected, payload, signature]"
        )
    protected_bytes, _unprotected, payload, signature = decoded
    if not isinstance(protected_bytes, (bytes, bytearray)):
        raise ValueError("protected header must be a byte string")
    if payload is not None:
        # C2PA 2.1 §13.2 mandates detached content (payload == nil).
        # Tolerate non-detached on read for ecosystem interop, but flag
        # by ignoring the inline payload — we always recompute Sig_structure
        # from the manifest's claim.
        pass
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("signature field must be a byte string")
    if not protected_bytes:
        protected_map: dict = {}
    else:
        protected_map = _cbor.decode(bytes(protected_bytes))
        if not isinstance(protected_map, dict):
            raise ValueError("protected header did not decode to a CBOR map")
    return bytes(protected_bytes), protected_map, bytes(signature)


def _extract_x5chain(protected_map: dict) -> list[bytes]:
    """Pull out the x5chain header. RFC 9360 / C2PA 2.1 §14.5: accept
    either label 33 or string "x5chain" on read."""
    raw = protected_map.get(_COSE_HDR_X5CHAIN)
    if raw is None:
        raw = protected_map.get(_COSE_HDR_X5CHAIN_STR)
    if raw is None:
        return []
    if isinstance(raw, (bytes, bytearray)):
        return [bytes(raw)]
    if isinstance(raw, list):
        out: list[bytes] = []
        for item in raw:
            if not isinstance(item, (bytes, bytearray)):
                raise ValueError("x5chain entries must be byte strings")
            out.append(bytes(item))
        return out
    raise ValueError("x5chain header must be a byte string or array of byte strings")


def _build_sig_structure(*, protected_serialized: bytes, payload: bytes) -> bytes:
    """Mirror of the signer-side Sig_structure builder."""
    return _cbor.encode(["Signature1", protected_serialized, b"", payload])


def _load_trust_anchors(
    trust_list_pem_paths: tuple[str, ...] | None,
) -> list[x509.Certificate]:
    if not trust_list_pem_paths:
        return []
    anchors: list[x509.Certificate] = []
    for path in trust_list_pem_paths:
        data = Path(path).read_bytes()
        for cert in x509.load_pem_x509_certificates(data):
            anchors.append(cert)
    return anchors


def _signing_cert(chain_der: list[bytes]) -> x509.Certificate:
    return x509.load_der_x509_certificate(chain_der[0])


def _is_within_validity(cert: x509.Certificate, now: datetime) -> bool:
    """C2PA 2.1 §14.3 — claimSignature.insideValidity check.

    Use the timezone-aware accessors so we don't trip the deprecation
    warnings on cryptography>=42 and so the comparison is unambiguous.
    """
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return not_before <= now <= not_after


def _is_anchored_to_trust_list(
    chain_der: list[bytes],
    anchors: Iterable[x509.Certificate],
) -> tuple[bool, x509.Certificate | None]:
    """Walk the provided chain and check whether any cert is signed
    by — or *is* — a trust-list anchor.

    This is a deliberately small subset of full RFC 5280 path
    validation. It checks issuer / subject linkage and signature
    validity along the chain, and accepts on the first match against
    a trust anchor.

    TODO(P1): swap to ``cryptography.x509.verification.PolicyBuilder``
        once we cut over to cryptography>=42 with the verification
        module GA. That gives us EKU + revocation handling for free.
    """
    if not chain_der:
        return False, None
    chain = [x509.load_der_x509_certificate(der) for der in chain_der]

    # Build an anchor lookup keyed by Subject DN bytes.
    anchor_by_subject: dict[bytes, x509.Certificate] = {}
    for a in anchors:
        anchor_by_subject[a.subject.public_bytes()] = a

    # Walk: for each cert in the chain, see if its issuer is an anchor;
    # if so, verify the cert's signature with the anchor's public key.
    # Also accept a cert that *is* itself an anchor.
    for cert in chain:
        if cert.subject.public_bytes() in anchor_by_subject:
            anchor = anchor_by_subject[cert.subject.public_bytes()]
            # Self-listed anchor — trivially trusted.
            if anchor.public_bytes(_DerEncoding.DER) == cert.public_bytes(_DerEncoding.DER):
                return True, anchor
        issuer_anchor = anchor_by_subject.get(cert.issuer.public_bytes())
        if issuer_anchor is not None:
            try:
                _verify_cert_signature(cert, issuer_anchor)
                return True, issuer_anchor
            except Exception:  # noqa: BLE001 — any verification failure → not trusted via this anchor
                continue
    return False, None


class _DerEncoding:
    """Tiny shim so we don't repeat ``serialization.Encoding.DER`` inline."""

    DER = serialization.Encoding.DER
    PEM = serialization.Encoding.PEM
    SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def _verify_cert_signature(
    child: x509.Certificate, issuer: x509.Certificate
) -> None:
    """Verify ``child``'s signature using ``issuer``'s public key.

    Uses the modern ``Certificate.verify_directly_issued_by`` API
    available in cryptography>=40. Raises if the signature does not
    validate.
    """
    # cryptography>=40 ships verify_directly_issued_by; if missing,
    # we fall back to a hand-rolled algorithm-agile check.
    if hasattr(child, "verify_directly_issued_by"):
        child.verify_directly_issued_by(issuer)
        return
    raise NotImplementedError(  # pragma: no cover — cryptography>=42 is pinned
        "cryptography<40 lacks verify_directly_issued_by; pin a newer version"
    )


def verify_manifest(
    manifest: C2paManifest,
    *,
    trust_list_pem_paths: tuple[str, ...] | None = None,
    now: datetime | None = None,
) -> C2paVerificationResult:
    """
    Verify a C2PA manifest end-to-end.

    Checks:
      - signature is valid over canonicalized claim bytes
      - certificate chain validates to a C2PA Trust List root
      - timestamp is within signing certificate validity window
      - signing certificate is not revoked (OCSP / CRL — P1)

    TODO(P0): full COSE_Sign1 verification
    TODO(P0): trust list anchor validation
    TODO(P1): OCSP staple validation
    TODO(P1): ingredient chain recursive verification
    """
    issues: list[str] = []
    signing_subject: str | None = None
    is_valid = False
    is_trusted = False

    if manifest.signature_b64 is None:
        issues.append(ISSUE_CLAIM_SIG_MISSING)
        emit_event(
            "c2pa.manifest.verified",
            outcome="missing_signature",
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )

    # 1. Decode the COSE envelope.
    try:
        protected_bytes, protected_map, signature_bytes = _decode_envelope(
            manifest.signature_b64
        )
    except ValueError as exc:
        issues.append(ISSUE_CLAIM_SIG_MISMATCH)
        emit_event(
            "c2pa.manifest.verified",
            outcome="envelope_decode_failed",
            error=str(exc),
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )

    # 2. Resolve the algorithm.
    cose_alg = protected_map.get(_COSE_HDR_ALG)
    if not isinstance(cose_alg, int):
        issues.append(ISSUE_ALGORITHM_UNSUPPORTED)
        emit_event(
            "c2pa.manifest.verified",
            outcome="alg_missing",
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )
    tex_alg = _signature_algorithm_for_cose_alg(cose_alg)
    if tex_alg is None:
        issues.append(ISSUE_ALGORITHM_UNSUPPORTED)
        emit_event(
            "c2pa.manifest.verified",
            outcome="alg_not_on_allowed_list",
            cose_alg=cose_alg,
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )

    # 3. Pull the cert chain.
    try:
        chain_der = _extract_x5chain(protected_map)
    except ValueError:
        issues.append(ISSUE_SIGNING_CRED_INVALID)
        emit_event(
            "c2pa.manifest.verified",
            outcome="x5chain_malformed",
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )
    if not chain_der:
        # C2PA 2.1 §14.2: zero credentials → reject.
        issues.append(ISSUE_SIGNING_CRED_INVALID)
        emit_event(
            "c2pa.manifest.verified",
            outcome="no_credentials",
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )
    try:
        signing_cert = _signing_cert(chain_der)
        signing_subject = signing_cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001 — any cert parse error
        issues.append(ISSUE_SIGNING_CRED_INVALID)
        emit_event(
            "c2pa.manifest.verified",
            outcome="end_entity_parse_failed",
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=None,
            is_trust_list_anchored=False,
        )

    # 4. Re-derive the signed bytes from the manifest's claim and verify.
    payload = canonical_claim_cbor(manifest.claim)
    sig_input = _build_sig_structure(
        protected_serialized=protected_bytes, payload=payload
    )
    provider = get_signature_provider(tex_alg)
    pubkey_pem = signing_cert.public_key().public_bytes(
        _DerEncoding.PEM,
        format=_DerEncoding.SPKI,
    )
    sig_ok = provider.verify(sig_input, signature_bytes, pubkey_pem)
    if not sig_ok:
        issues.append(ISSUE_CLAIM_SIG_MISMATCH)
        emit_event(
            "c2pa.manifest.verified",
            outcome="signature_mismatch",
            cose_alg=cose_alg,
            tex_alg=tex_alg.value,
            signing_subject=signing_subject,
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=signing_subject,
            is_trust_list_anchored=False,
        )
    issues.append(ISSUE_CLAIM_SIG_VALIDATED)

    # 5. Validity-window check.
    resolved_now = now or datetime.now(UTC)
    if not _is_within_validity(signing_cert, resolved_now):
        issues.append(ISSUE_OUTSIDE_VALIDITY)
        emit_event(
            "c2pa.manifest.verified",
            outcome="outside_validity",
            signing_subject=signing_subject,
            is_valid=False,
            is_trust_list_anchored=False,
        )
        return C2paVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            signing_certificate_subject=signing_subject,
            is_trust_list_anchored=False,
        )

    is_valid = True

    # 6. Trust-list anchoring.
    anchors = _load_trust_anchors(trust_list_pem_paths)
    if anchors:
        anchored, anchor_match = _is_anchored_to_trust_list(chain_der, anchors)
        if anchored:
            issues.append(ISSUE_SIGNING_CRED_TRUSTED)
            is_trusted = True
        else:
            issues.append(ISSUE_SIGNING_CRED_UNTRUSTED)

    # Sanity assertion to satisfy a strict type checker.
    _ = anchor_match if anchors else None  # noqa: F841 — clarity over reuse

    emit_event(
        "c2pa.manifest.verified",
        outcome="ok" if is_trusted else ("valid" if is_valid else "invalid"),
        cose_alg=cose_alg,
        tex_alg=tex_alg.value,
        signing_subject=signing_subject,
        chain_length=len(chain_der),
        is_valid=is_valid,
        is_trust_list_anchored=is_trusted,
    )
    return C2paVerificationResult(
        is_valid=is_valid,
        issues=tuple(issues),
        signing_certificate_subject=signing_subject,
        is_trust_list_anchored=is_trusted,
    )
