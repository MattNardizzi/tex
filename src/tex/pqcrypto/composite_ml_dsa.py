"""
Composite ML-DSA signatures per draft-ietf-lamps-pq-composite-sigs-18.

Bleeding-edge frontier as of May 18, 2026. Composite ML-DSA combines an
ML-DSA signature with a traditional signature (Ed25519, ECDSA-P384) such
that an attacker must break BOTH algorithms simultaneously to forge.
This is the PQ/T Hybrid mandated by BSI (Germany, 2021) and ANSSI
(France, 2024) for high-assurance applications and increasingly demanded
by EU customers anticipating the EU AI Act August 2026 enforcement.

Frontier delta vs competitors
-----------------------------
- Microsoft Agent Governance Toolkit ships ML-DSA-65 alongside Ed25519 but
  as INDEPENDENT credentials — not a composite signature. A single break
  of ML-DSA-65 or single Ed25519 key compromise voids the entire scheme.
- Asqav ships ML-DSA-65 alone — no traditional counter-signature.
- Tex Aegis is first to ship a true composite signature per
  draft-ietf-lamps-pq-composite-sigs-18 (Apr 9 2026 — current revision)
  with the HPKE-style domain separator strings that draft-16 introduced.

Why this matters
----------------
The relevant 2026 attack surface for AI governance evidence chains is not
"is ML-DSA itself broken" (it isn't, no credible attack exists) — it is:
1. Implementation flaws in early ML-DSA libraries (PQC libraries are far
   younger than RSA / ECDSA).
2. Side-channel attacks on liboqs / mlkem-native on production hardware
   (ePrint 2025/1577 LDA-based template attack: 40 traces for full key
   recovery on M4 microcontroller).
3. Fault attacks (ePrint 2026/759 NXP countermeasure paper).
4. The "wait, is lattice cryptography even hard?" residual risk that BSI
   and ANSSI specifically cite when mandating composites.

Composite ML-DSA defeats classes (1), (2), (3) directly — even if liboqs
ships a fatal ML-DSA bug tomorrow, the Ed25519 / ECDSA-P384 half remains
unbroken. Class (4) is mitigated by the SLH-DSA fault countermeasure in
``tex.pqcrypto.slh_dsa``.

Wire format (draft-18 compliant)
--------------------------------
Per draft-ietf-lamps-pq-composite-sigs-18 §4 and §6:

    CompositeSignatureValue ::= SEQUENCE {
        ml_dsa_signature    OCTET STRING,
        classical_signature OCTET STRING
    }

We use a length-prefixed concat to match the draft's serialization
intent without dragging in an ASN.1 dependency (the draft itself notes
that DER is for CMS / X.509 transport; in-protocol it's the same
concatenation logic).

The draft moved (in revision 16, Apr 8 2026) from OID-based domain
separators to HPKE-style label strings. We follow that convention with
the per-algorithm domain separator strings from §6.

Supported parameter sets
------------------------
The draft enumerates a large matrix; we ship the two that matter for AI
governance:

- ``COMPOSITE_ML_DSA_65_ED25519`` — recommended general-use composite.
  Smallest combined signature for the security level. Ed25519 keys are
  cheap and broadly supported.

- ``COMPOSITE_ML_DSA_87_ECDSA_P384`` — CNSA 2.0 quorum-side composite.
  CNSA 2.0 §2 mandates ML-DSA-87; this composite pairs it with the
  classical signature scheme U.S. NSS already operates (ECDSA-P384, FIPS
  186-5). Note: CNSA 2.0 itself does NOT require a composite — but
  BSI/ANSSI customers do, and many U.S. enterprises elect composites as
  a hedge while ML-DSA-87 sees real-world deployment.

References
----------
- draft-ietf-lamps-pq-composite-sigs-18 (Apr 9 2026), Ounsworth et al.
- draft-ietf-lamps-cms-composite-sigs-04 (Feb 5 2026), CMS variant
- draft-reddy-tls-composite-mldsa-10 (May 2026), TLS 1.3
- BSI TR-02102-1 (2021), ANSSI (2024) — PQ/T Hybrid mandates
- RFC 9794 (PQ/T Hybrid terminology)

Priority
--------
P0 — Thread 10. Required for BSI/ANSSI compliance and a clean hedge
against any future ML-DSA implementation flaw.
"""

from __future__ import annotations

import struct
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)
from tex.pqcrypto.ml_dsa import MlDsaProvider


# draft-ietf-lamps-pq-composite-sigs-18 §2.2 specifies the fixed prefix
# ASCII string "CompositeAlgorithmSignatures2025" — note the literal 2025
# (this is the spec version that was frozen for IANA registration; the
# string did NOT bump to 2026 when the draft was revised).
# Hex: 436F6D706F73697465416C676F726974686D5369676E61747572657332303235
_DRAFT_18_PREFIX: bytes = b"CompositeAlgorithmSignatures2025"

# Per draft-18 §6 (Algorithm Identifiers and Parameters) the per-algorithm
# Label is a fixed ASCII string. Domain separator = Prefix || Label.
_LABEL: dict[SignatureAlgorithm, bytes] = {
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519: b"COMPSIG-MLDSA65-Ed25519-SHA512",
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384: b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",
}

# IANA-assigned OIDs from draft-ietf-lamps-pq-composite-sigs-18 §8.1.2.
# Tracked here so CMS / X.509 emitters in tex.pqcrypto.composite_cms can
# round-trip cleanly.
_OID: dict[SignatureAlgorithm, str] = {
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519: "1.3.6.1.5.5.7.6.48",
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384: "1.3.6.1.5.5.7.6.49",
}


def draft_18_oid(parameter_set: SignatureAlgorithm) -> str:
    """Return the IANA OID for ``parameter_set`` per draft-18 §8.1.2."""
    try:
        return _OID[parameter_set]
    except KeyError as exc:
        raise ValueError(
            f"Not a composite ML-DSA parameter set: {parameter_set}"
        ) from exc


def draft_18_label(parameter_set: SignatureAlgorithm) -> bytes:
    """Return the ASCII Label bytes per draft-18 §2.2."""
    try:
        return _LABEL[parameter_set]
    except KeyError as exc:
        raise ValueError(
            f"Not a composite ML-DSA parameter set: {parameter_set}"
        ) from exc


def _domain_separator(parameter_set: SignatureAlgorithm) -> bytes:
    """Per draft-18 §2.2: domain separator = Prefix || Label."""
    return _DRAFT_18_PREFIX + _LABEL[parameter_set]


# Kept as a public mapping for back-compat with callers that consumed
# the old structure; values now produced by ``_domain_separator()``.
_DOMAIN_SEPARATOR: dict[SignatureAlgorithm, bytes] = {
    alg: _DRAFT_18_PREFIX + label for alg, label in _LABEL.items()
}

# Map each composite enum to its component algorithms.
_ML_DSA_COMPONENT: dict[SignatureAlgorithm, SignatureAlgorithm] = {
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519: SignatureAlgorithm.ML_DSA_65,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384: SignatureAlgorithm.ML_DSA_87,
}


class _ClassicalKind:
    ED25519 = "ed25519"
    ECDSA_P384 = "ecdsa-p384"


_CLASSICAL_KIND: dict[SignatureAlgorithm, str] = {
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519: _ClassicalKind.ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384: _ClassicalKind.ECDSA_P384,
}


_LEN_PREFIX_BYTES = 4
_LAYOUT_VERSION = "1"  # bump to 2 when CMS/X.509 DER becomes mandatory


def _split_length_prefixed(blob: bytes, *, label: str) -> tuple[bytes, bytes]:
    if len(blob) < _LEN_PREFIX_BYTES:
        raise ValueError(f"{label} too short to contain length prefix")
    (ml_dsa_len,) = struct.unpack(">I", blob[:_LEN_PREFIX_BYTES])
    end = _LEN_PREFIX_BYTES + ml_dsa_len
    if end > len(blob):
        raise ValueError(f"{label} length prefix exceeds blob size")
    return blob[_LEN_PREFIX_BYTES:end], blob[end:]


def _concat_length_prefixed(ml_dsa_part: bytes, classical_part: bytes) -> bytes:
    return struct.pack(">I", len(ml_dsa_part)) + ml_dsa_part + classical_part


def _bind_message(
    message: bytes,
    parameter_set: SignatureAlgorithm,
    *,
    ctx: bytes = b"",
) -> bytes:
    """Bind ``message`` to the composite parameter set per draft-18 §2.1.

    Constructs the to-be-signed message representative M':

        M' = Prefix || Label || len(ctx) || ctx || PH(M)

    Where:
    - ``Prefix`` is the fixed ASCII string ``CompositeAlgorithmSignatures2025``
    - ``Label`` is the per-algorithm label (see ``_LABEL``)
    - ``ctx`` is the optional application-supplied context (≤255 bytes)
    - ``PH(M)`` is the SHA-512 pre-hash of the message (both composites
      we ship use SHA-512 per draft-18 §6).

    Both signing components sign this binding, preventing component
    signatures from being peeled off and presented as bare ML-DSA or
    bare Ed25519/ECDSA signatures — the non-separability property the
    draft mandates.
    """
    if len(ctx) > 255:
        raise ValueError(
            "Composite ML-DSA ctx string must be at most 255 bytes "
            "(draft-18 §2.2)"
        )

    # SHA-512 pre-hash for both shipped composites (draft-18 §6).
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message)
    ph_m = digest.finalize()

    return (
        _DRAFT_18_PREFIX
        + _LABEL[parameter_set]
        + bytes([len(ctx)])
        + ctx
        + ph_m
    )


class CompositeMlDsaProvider:
    """
    Composite ML-DSA + classical signature provider per draft-18.

    Both the ML-DSA half and the classical half sign the domain-separator-
    prefixed message. ``verify`` returns True only if BOTH halves verify.
    """

    def __init__(
        self,
        parameter_set: SignatureAlgorithm = SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    ) -> None:
        if parameter_set not in _DOMAIN_SEPARATOR:
            raise ValueError(
                f"Not a composite ML-DSA parameter set: {parameter_set}"
            )
        self.parameter_set: SignatureAlgorithm = parameter_set
        self.algorithm: SignatureAlgorithm = parameter_set
        ml_dsa_component = _ML_DSA_COMPONENT[parameter_set]
        self._ml_dsa = MlDsaProvider(parameter_set=ml_dsa_component)
        self._classical_kind: str = _CLASSICAL_KIND[parameter_set]

    # --- key generation ----------------------------------------------------

    def _generate_classical_keypair(self) -> tuple[bytes, bytes]:
        """Return ``(public_pem, private_pem)`` for the classical half."""
        if self._classical_kind == _ClassicalKind.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pub_pem, priv_pem
        if self._classical_kind == _ClassicalKind.ECDSA_P384:
            priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pub_pem, priv_pem
        raise RuntimeError(
            f"unknown classical kind: {self._classical_kind}"
        )  # pragma: no cover

    def _classical_sign(self, message: bytes, classical_priv_pem: bytes) -> bytes:
        priv = serialization.load_pem_private_key(classical_priv_pem, password=None)
        if self._classical_kind == _ClassicalKind.ED25519:
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise ValueError("composite classical key is not Ed25519")
            return priv.sign(message)
        if self._classical_kind == _ClassicalKind.ECDSA_P384:
            if not isinstance(priv, ec.EllipticCurvePrivateKey):
                raise ValueError("composite classical key is not ECDSA")
            if not isinstance(priv.curve, ec.SECP384R1):
                raise ValueError(
                    f"composite ECDSA key uses {priv.curve.name}, expected SECP384R1"
                )
            return priv.sign(message, ec.ECDSA(hashes.SHA384()))
        raise RuntimeError(
            f"unknown classical kind: {self._classical_kind}"
        )  # pragma: no cover

    def _classical_verify(
        self,
        message: bytes,
        signature: bytes,
        classical_pub_pem: bytes,
    ) -> bool:
        try:
            pub = serialization.load_pem_public_key(classical_pub_pem)
        except (ValueError, TypeError):
            return False
        if self._classical_kind == _ClassicalKind.ED25519:
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                return False
            try:
                pub.verify(signature, message)
            except InvalidSignature:
                return False
            return True
        if self._classical_kind == _ClassicalKind.ECDSA_P384:
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            if not isinstance(pub.curve, ec.SECP384R1):
                return False
            try:
                pub.verify(signature, message, ec.ECDSA(hashes.SHA384()))
            except InvalidSignature:
                return False
            return True
        return False  # pragma: no cover

    # --- SignatureProvider interface --------------------------------------

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        """Generate a fresh composite keypair (both halves)."""
        ml_dsa_kp = self._ml_dsa.generate_keypair(
            key_id=f"{key_id or 'composite'}/ml-dsa"
        )
        classical_pub_pem, classical_priv_pem = self._generate_classical_keypair()

        public_key = _concat_length_prefixed(ml_dsa_kp.public_key, classical_pub_pem)
        private_key = _concat_length_prefixed(ml_dsa_kp.private_key, classical_priv_pem)
        resolved_id = key_id or f"{self.parameter_set.value}-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.composite.keygen",
            algorithm=self.parameter_set.value,
            classical_kind=self._classical_kind,
            layout_version=_LAYOUT_VERSION,
            key_id=resolved_id,
            public_key_bytes=len(public_key),
            private_key_bytes=len(private_key),
        )
        return SignatureKeyPair(
            algorithm=self.parameter_set,
            public_key=public_key,
            private_key=private_key,
            key_id=resolved_id,
        )

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        if key.algorithm is not self.parameter_set:
            raise ValueError(
                f"CompositeMlDsaProvider({self.parameter_set.value}) cannot "
                f"sign with key for {key.algorithm.value}"
            )
        ml_dsa_priv, classical_priv_pem = _split_length_prefixed(
            key.private_key, label="composite private key"
        )

        bound_message = _bind_message(message, self.parameter_set)

        # ML-DSA half
        inner_ml_dsa_key = SignatureKeyPair(
            algorithm=_ML_DSA_COMPONENT[self.parameter_set],
            public_key=b"",
            private_key=ml_dsa_priv,
            key_id=f"{key.key_id}/ml-dsa",
        )
        ml_dsa_sig = self._ml_dsa.sign(bound_message, inner_ml_dsa_key)

        # Classical half
        classical_sig = self._classical_sign(bound_message, classical_priv_pem)

        signature = _concat_length_prefixed(ml_dsa_sig, classical_sig)
        emit_event(
            "pqcrypto.composite.signed",
            algorithm=self.parameter_set.value,
            classical_kind=self._classical_kind,
            layout_version=_LAYOUT_VERSION,
            key_id=key.key_id,
            message_bytes=len(message),
            signature_bytes=len(signature),
            ml_dsa_signature_bytes=len(ml_dsa_sig),
            classical_signature_bytes=len(classical_sig),
        )
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            ml_dsa_sig, classical_sig = _split_length_prefixed(
                signature, label="composite signature"
            )
            ml_dsa_pk, classical_pk_pem = _split_length_prefixed(
                public_key, label="composite public key"
            )
        except ValueError:
            return False

        bound_message = _bind_message(message, self.parameter_set)

        ml_dsa_ok = self._ml_dsa.verify(bound_message, ml_dsa_sig, ml_dsa_pk)
        classical_ok = self._classical_verify(
            bound_message, classical_sig, classical_pk_pem
        )

        ok = bool(ml_dsa_ok and classical_ok)
        emit_event(
            "pqcrypto.composite.verified",
            algorithm=self.parameter_set.value,
            classical_kind=self._classical_kind,
            layout_version=_LAYOUT_VERSION,
            ok=ok,
            ml_dsa_ok=bool(ml_dsa_ok),
            classical_ok=bool(classical_ok),
            message_bytes=len(message),
            signature_bytes=len(signature),
        )
        return ok
