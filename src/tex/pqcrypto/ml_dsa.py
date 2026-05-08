"""
ML-DSA (NIST FIPS 204) signature provider.

Implementation note
-------------------
The reference implementation will use liboqs (Open Quantum Safe) Python bindings.
For environments without liboqs, fall back to pyOpenSSL + a vendored ML-DSA
reference implementation.

The ``oqs`` package is imported lazily inside ``sign``/``verify``/
``generate_keypair`` so that the module is importable on machines where
liboqs is not installed (Render free tier, contributor laptops). Calls
into the cryptographic methods raise ``RuntimeError`` with a clear
remediation message.

Performance characteristics (FIPS 204)
--------------------------------------
- Public key size: ~1.3 KB (ML-DSA-44) to ~2.6 KB (ML-DSA-87)
- Signature size: ~2.4 KB (ML-DSA-65, recommended default)
- Sign latency: ~1-3 ms on modern CPU
- Verify latency: ~0.3-1 ms

Wire-format choices (paper-silent)
----------------------------------
Uses "pure" ML-DSA (no pre-hash). FIPS 204 §5.1 specifies HashML-DSA as
optional; we sign the canonicalized message bytes directly. This matches
the algorithm-agility contract used by ECDSA-P256 (which also signs
``message`` directly with an internal SHA-256).

Reference
---------
- NIST FIPS 204 (ML-DSA, finalized August 2024)
- NSA CNSA 2.0 (ML-DSA-87 mandated for NSS by 2030-2035)

Priority
--------
P0 — ship in days 1-14.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)

if TYPE_CHECKING:
    import oqs  # pragma: no cover


# Map our algorithm enum to the liboqs algorithm name string.
_OQS_NAME: dict[SignatureAlgorithm, str] = {
    SignatureAlgorithm.ML_DSA_44: "ML-DSA-44",
    SignatureAlgorithm.ML_DSA_65: "ML-DSA-65",
    SignatureAlgorithm.ML_DSA_87: "ML-DSA-87",
}

_LIBOQS_MISSING_MSG = (
    "liboqs is not available in this environment. "
    "Install via `pip install oqs` and ensure the liboqs C shared library "
    "is on the dynamic loader path. See "
    "https://github.com/open-quantum-safe/liboqs-python for build details."
)


def _import_oqs() -> "oqs":
    """
    Lazy-import ``oqs`` so this module is importable without liboqs.

    Raises ``RuntimeError`` (not ``ImportError``) so callers see a
    consistent exception type across the algorithm-agility surface
    regardless of whether liboqs is missing or fails to load its C
    shared library.
    """
    try:
        import oqs as _oqs  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - exercised in CI without liboqs
        raise RuntimeError(_LIBOQS_MISSING_MSG) from exc
    return _oqs


class MlDsaProvider:
    """
    ML-DSA signature provider per NIST FIPS 204.

    Satisfies the structural ``SignatureProvider`` Protocol from
    ``tex.pqcrypto.algorithm_agility``. Stateless: each call to
    ``sign``/``verify``/``generate_keypair`` opens a fresh
    ``oqs.Signature`` instance, so the provider is safe to share
    across threads.

    Attributes
    ----------
    parameter_set
        The ML-DSA parameter set this provider operates on.
    algorithm
        Mirror of ``parameter_set`` exposed under the same attribute name
        as ``EcdsaP256Provider`` so ``signature_algorithm_for()`` works
        uniformly.
    """

    def __init__(
        self,
        parameter_set: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    ) -> None:
        if parameter_set not in _OQS_NAME:
            raise ValueError(f"Not an ML-DSA parameter set: {parameter_set}")
        self.parameter_set: SignatureAlgorithm = parameter_set
        self.algorithm: SignatureAlgorithm = parameter_set

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        """
        Sign ``message`` (raw bytes) with the ML-DSA private key in ``key``.

        TODO(P0): bind to liboqs.Signature(name).sign(message, key.private_key)
        """
        if key.algorithm is not self.parameter_set:
            raise ValueError(
                f"MlDsaProvider({self.parameter_set.value}) cannot sign with "
                f"key for {key.algorithm.value}"
            )
        oqs = _import_oqs()
        with oqs.Signature(_OQS_NAME[self.parameter_set], key.private_key) as signer:
            signature = bytes(signer.sign(message))
        emit_event(
            "pqcrypto.ml_dsa.signed",
            algorithm=self.parameter_set.value,
            key_id=key.key_id,
            message_bytes=len(message),
            signature_bytes=len(signature),
        )
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify an ML-DSA signature. Returns ``False`` on any verification
        failure — invalid signature, malformed key, wrong message — and
        never raises for cryptographic failure modes.

        TODO(P0): bind to liboqs.Signature(name).verify(message, signature, public_key)
        """
        oqs = _import_oqs()
        try:
            with oqs.Signature(_OQS_NAME[self.parameter_set]) as verifier:
                ok = bool(verifier.verify(message, signature, public_key))
        except Exception:
            # liboqs raises on malformed inputs; treat as failed verify.
            return False
        emit_event(
            "pqcrypto.ml_dsa.verified",
            algorithm=self.parameter_set.value,
            ok=ok,
            message_bytes=len(message),
            signature_bytes=len(signature),
        )
        return ok

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        """
        Generate a fresh ML-DSA keypair for ``self.parameter_set``.

        TODO(P0): bind to liboqs.Signature(name).generate_keypair()
        TODO(P1): add HSM/KMS-backed keygen path for production deployments.
        """
        oqs = _import_oqs()
        with oqs.Signature(_OQS_NAME[self.parameter_set]) as kg:
            public_key = bytes(kg.generate_keypair())
            private_key = bytes(kg.export_secret_key())
        resolved_id = key_id or f"{self.parameter_set.value}-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.ml_dsa.keygen",
            algorithm=self.parameter_set.value,
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
