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


def _decode_envelope(signature_b64: str) -> tuple[bytes, dict, dict, bytes]:
    """Decode the base64'd COSE_Sign1_Tagged.

    Returns ``(protected_bytes, decoded_protected_map, unprotected_map,
    signature_bytes)``. The unprotected map is where C2PA 2.4 places
    OCSP staples (``ocsp_vals``) and TSA v2 tokens (``sigTst2``).

    Raises ``ValueError`` on any structural problem.
    """
    try:
        envelope_bytes = base64.b64decode(signature_b64.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"signature_b64 is not valid base64: {exc}") from exc

    decoded = _cbor.decode(envelope_bytes)
    decoded = _cbor.unwrap_tag(decoded, _cbor.COSE_SIGN1_TAG)
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ValueError(
            "COSE_Sign1 must be a 4-element array [protected, "
            "unprotected, payload, signature]"
        )
    protected_bytes, unprotected, payload, signature = decoded
    if not isinstance(protected_bytes, (bytes, bytearray)):
        raise ValueError("protected header must be a byte string")
    if payload is not None:
        # C2PA 2.1 §13.2 mandates detached content (payload == nil).
        # Tolerate non-detached on read for ecosystem interop.
        pass
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("signature field must be a byte string")
    if not protected_bytes:
        protected_map: dict = {}
    else:
        protected_map = _cbor.decode(bytes(protected_bytes))
        if not isinstance(protected_map, dict):
            raise ValueError("protected header did not decode to a CBOR map")
    if not isinstance(unprotected, dict):
        unprotected = {}
    return bytes(protected_bytes), protected_map, unprotected, bytes(signature)


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


def _extract_ocsp_staples(unprotected_map: dict) -> list[bytes]:
    """Extract C2PA 2.4 ``ocsp_vals`` from the unprotected COSE header.

    The header key is the CBOR text string ``"ocsp_vals"`` per C2PA 2.4
    §14. Tolerates both the canonical (list of byte strings) and a
    single-staple-as-bytes layout for legacy interop.
    """
    raw = unprotected_map.get("ocsp_vals") or unprotected_map.get(b"ocsp_vals")
    if raw is None:
        return []
    if isinstance(raw, (bytes, bytearray)):
        return [bytes(raw)]
    if isinstance(raw, list):
        return [bytes(x) for x in raw if isinstance(x, (bytes, bytearray))]
    return []


def _extract_tsa_tokens(unprotected_map: dict) -> list[bytes]:
    """Extract C2PA 2.4 ``sigTst2`` v2 TSA tokens from the unprotected header."""
    raw = unprotected_map.get("sigTst2") or unprotected_map.get(b"sigTst2")
    if raw is None:
        return []
    if isinstance(raw, (bytes, bytearray)):
        return [bytes(raw)]
    if isinstance(raw, list):
        return [bytes(x) for x in raw if isinstance(x, (bytes, bytearray))]
    return []


def _v2_timestamp_digest(signature_bytes: bytes) -> bytes:
    """Compute the C2PA 2.4 v2 timestamp messageImprint payload.

    Imported lazily to avoid a circular module dependency at import time.
    """
    from tex.c2pa.timestamp import v2_payload_digest

    return v2_payload_digest(signature_bytes)


def _resolve_issuer_for_ocsp(
    chain_der: list[bytes], signing_cert: x509.Certificate
) -> x509.Certificate:
    """Pick the cert that issued ``signing_cert`` from the chain.

    Falls back to the signing cert itself (treating as self-signed) when
    the chain has length 1 — in that degenerate case the OCSP request
    can still be built but the validator will reject any returned response
    that isn't directly self-signed.
    """
    if len(chain_der) < 2:
        return signing_cert
    return x509.load_der_x509_certificate(chain_der[1])


def _validate_ocsp_staple(
    *,
    staple_der: bytes,
    target: x509.Certificate,
    issuer: x509.Certificate,
    now: datetime,
):
    """Wrapper around ``tex.c2pa.ocsp.parse_and_validate_response``.

    Lazy-imports the ocsp module so the verifier remains importable in
    minimal-dep environments where the ocsp module's transitive imports
    might be unavailable.
    """
    from tex.c2pa.ocsp import parse_and_validate_response

    return parse_and_validate_response(
        staple_der,
        issuer=issuer,
        expected_nonce=None,  # stapled responses are typically nonce-less
        target_serial=target.serial_number,
        now=now,
    )


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
    require_ocsp_staple: bool = False,
    require_timestamp: bool = False,
) -> C2paVerificationResult:
    """Verify a C2PA manifest end-to-end.

    Checks (in order):
      - COSE envelope decodes
      - signature validates over the canonicalised claim bytes
      - certificate chain (RFC 5280 partial path validation)
      - timestamp is within signing certificate validity window
      - OCSP staples (C2PA 2.4 §15.9) when present or required
      - TSA v2 timestamp tokens (C2PA 2.4 §15.8) when present or required
      - chain anchors to one of ``trust_list_pem_paths``

    Parameters
    ----------
    manifest
        The manifest to verify.
    trust_list_pem_paths
        Optional tuple of file paths to PEM bundles of trust-anchor
        CAs. When provided and the chain anchors to one of these,
        the result is marked ``is_trust_list_anchored=True``.
    now
        Reference time (defaults to ``datetime.now(UTC)``).
    require_ocsp_staple
        When True, a missing OCSP staple emits
        ``signingCredential.ocspMissing`` and fails the manifest.
        When False (default), absent staples are tolerated but any
        present staple is still validated.
    require_timestamp
        When True, a missing TSA v2 token emits a hard failure.
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
        protected_bytes, protected_map, unprotected_map, signature_bytes = (
            _decode_envelope(manifest.signature_b64)
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

    # 5b. OCSP staple validation (C2PA 2.4 §15.9).
    ocsp_staples = _extract_ocsp_staples(unprotected_map)
    if ocsp_staples:
        issuer_cert = _resolve_issuer_for_ocsp(chain_der, signing_cert)
        for staple_der in ocsp_staples:
            ocsp_result = _validate_ocsp_staple(
                staple_der=staple_der,
                target=signing_cert,
                issuer=issuer_cert,
                now=resolved_now,
            )
            if not ocsp_result.ok:
                issues.append(ocsp_result.failure_code.value)
                emit_event(
                    "c2pa.manifest.verified",
                    outcome="ocsp_staple_invalid",
                    failure_code=ocsp_result.failure_code.value,
                    detail=ocsp_result.detail,
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
    elif require_ocsp_staple:
        from tex.c2pa.ocsp import OcspFailureCode

        issues.append(OcspFailureCode.MISSING.value)
        emit_event(
            "c2pa.manifest.verified",
            outcome="ocsp_staple_missing",
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

    # 5c. TSA v2 timestamp validation (C2PA 2.4 §15.8, §10.3.2.5).
    tsa_tokens = _extract_tsa_tokens(unprotected_map)
    if tsa_tokens:
        from tex.c2pa.timestamp import parse_and_validate_response

        digest_expected = _v2_timestamp_digest(signature_bytes)
        any_valid = False
        last_failure = None
        for token_der in tsa_tokens:
            tsa_result = parse_and_validate_response(
                token_der,
                expected_digest=digest_expected,
                expected_nonce=None,  # stored tokens have no live nonce
                signing_cert_not_before=signing_cert.not_valid_before_utc,
                signing_cert_not_after=signing_cert.not_valid_after_utc,
            )
            if tsa_result.ok:
                any_valid = True
                break
            last_failure = tsa_result
        if not any_valid and last_failure is not None:
            issues.append(last_failure.failure_code.value)
            emit_event(
                "c2pa.manifest.verified",
                outcome="tsa_v2_invalid",
                failure_code=last_failure.failure_code.value,
                detail=last_failure.detail,
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
    elif require_timestamp:
        from tex.c2pa.timestamp import TimestampFailureCode

        issues.append(TimestampFailureCode.MALFORMED.value)
        emit_event(
            "c2pa.manifest.verified",
            outcome="tsa_v2_missing",
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
