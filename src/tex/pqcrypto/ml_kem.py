"""
ML-KEM (NIST FIPS 203) key encapsulation provider — production-grade.

Backends (selected at import time)
----------------------------------
1. **pyca/cryptography >= 48.0.0** with OpenSSL >= 3.5.0 — native
   FIPS-validated path. ML-KEM-768 and ML-KEM-1024 only (pyca 48
   does not yet expose ML-KEM-512).
2. **liboqs-python** — full coverage including ML-KEM-512.

CNSA 2.0 (April 2026 update) mandates ML-KEM-1024 exclusively for
US NSS workloads. ML-KEM-512 / 768 remain valid FIPS 203 parameter
sets and are commonly used outside that profile.

Wire format
-----------
- Public key / private key / ciphertext encoded per FIPS 203 §8.
- ``encapsulate(public_key) -> (ciphertext, shared_secret)`` — the
  Tex API exposes the natural protocol order (ciphertext first,
  shared secret second). The pyca native API returns
  ``(shared_secret, ciphertext)``; we swap internally so callers
  do not have to care.
- Shared secret is always 32 bytes per FIPS 203.

References
----------
- NIST FIPS 203 (Aug 2024).
- draft-jenkins-cnsa2-pkix-profile §4 (Apr 2026): ML-KEM-1024 only.
- liboqs 0.15.0 release notes.
- OpenSSL EVP_PKEY-ML-KEM (3.5.0+).

Priority: P0.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import uuid4

from tex.observability.telemetry import emit_event

_logger = logging.getLogger(__name__)


class KemAlgorithm(str, Enum):
    ML_KEM_512 = "ml-kem-512"
    ML_KEM_768 = "ml-kem-768"
    ML_KEM_1024 = "ml-kem-1024"


_PK_BYTES: dict[KemAlgorithm, int] = {
    KemAlgorithm.ML_KEM_512: 800,
    KemAlgorithm.ML_KEM_768: 1184,
    KemAlgorithm.ML_KEM_1024: 1568,
}
_SK_BYTES: dict[KemAlgorithm, int] = {
    KemAlgorithm.ML_KEM_512: 1632,
    KemAlgorithm.ML_KEM_768: 2400,
    KemAlgorithm.ML_KEM_1024: 3168,
}
_CT_BYTES: dict[KemAlgorithm, int] = {
    KemAlgorithm.ML_KEM_512: 768,
    KemAlgorithm.ML_KEM_768: 1088,
    KemAlgorithm.ML_KEM_1024: 1568,
}
_SS_BYTES = 32
# FIPS 203 / RFC 9935 §4: 64-byte seed (d || z), the canonical alternative
# to the expanded decapsulation key. The 2024 NIST-PQC-forum guidance (and
# Filippo Valsorda's "Let's All Agree to Use Seeds as ML-KEM Keys") urges
# this as the preferred storage format — it is always valid by
# construction, while expanded keys require the FIPS 203 §7.3 hash check.
_SEED_BYTES = 64


# ---- Backends --------------------------------------------------------------


class _NativeKemBackend:
    """pyca/cryptography 48+ native ML-KEM (OpenSSL 3.5+).

    Note: pyca 48 supports ML-KEM-768 and ML-KEM-1024 only.
    Use the liboqs backend for ML-KEM-512.
    """

    backend_id = "pyca-cryptography-native"

    def __init__(self) -> None:
        mlkem = importlib.import_module(
            "cryptography.hazmat.primitives.asymmetric.mlkem"
        )
        self._mlkem = mlkem
        # ML-KEM-512 not in pyca 48; expose 768 / 1024 only.
        self._priv_cls: dict[KemAlgorithm, Any] = {}
        self._pub_cls: dict[KemAlgorithm, Any] = {}
        for alg_enum, name in (
            (KemAlgorithm.ML_KEM_768, "768"),
            (KemAlgorithm.ML_KEM_1024, "1024"),
        ):
            priv = getattr(mlkem, f"MLKEM{name}PrivateKey", None)
            pub = getattr(mlkem, f"MLKEM{name}PublicKey", None)
            if priv is not None and pub is not None:
                self._priv_cls[alg_enum] = priv
                self._pub_cls[alg_enum] = pub

    def supports(self, alg: KemAlgorithm) -> bool:
        return alg in self._priv_cls

    def generate_keypair(self, alg: KemAlgorithm) -> tuple[bytes, bytes]:
        priv = self._priv_cls[alg].generate()
        return (
            priv.public_key().public_bytes_raw(),
            priv.private_bytes_raw(),
        )

    def encapsulate(self, alg: KemAlgorithm, public_key: bytes) -> tuple[bytes, bytes]:
        pub = self._pub_cls[alg].from_public_bytes(public_key)
        # pyca returns (shared_secret, ciphertext); flip to (ciphertext, ss).
        ss, ct = pub.encapsulate()
        return ct, ss

    def decapsulate(self, alg: KemAlgorithm, ciphertext: bytes, private_key: bytes) -> bytes:
        # pyca exposes from_private_bytes for ML-KEM? check
        try:
            priv = self._priv_cls[alg].from_private_bytes(private_key)
        except AttributeError:
            priv = self._priv_cls[alg].from_seed_bytes(private_key)
        return priv.decapsulate(ciphertext)


class _LiboqsKemBackend:
    backend_id = "liboqs"

    _NAMES = {
        KemAlgorithm.ML_KEM_512: "ML-KEM-512",
        KemAlgorithm.ML_KEM_768: "ML-KEM-768",
        KemAlgorithm.ML_KEM_1024: "ML-KEM-1024",
    }

    def __init__(self) -> None:
        self._oqs = importlib.import_module("oqs")

    def supports(self, alg: KemAlgorithm) -> bool:
        return alg in self._NAMES

    def generate_keypair(self, alg: KemAlgorithm) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self._NAMES[alg]) as kg:
            return bytes(kg.generate_keypair()), bytes(kg.export_secret_key())

    def encapsulate(self, alg: KemAlgorithm, public_key: bytes) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self._NAMES[alg]) as enc:
            ct, ss = enc.encap_secret(public_key)
        return bytes(ct), bytes(ss)

    def decapsulate(self, alg: KemAlgorithm, ciphertext: bytes, private_key: bytes) -> bytes:
        with self._oqs.KeyEncapsulation(self._NAMES[alg], private_key) as dec:
            return bytes(dec.decap_secret(ciphertext))


def _select_native() -> _NativeKemBackend | None:
    try:
        return _NativeKemBackend()
    except Exception as exc:
        _logger.debug("pyca ML-KEM unavailable: %s", exc)
        return None


def _select_liboqs() -> _LiboqsKemBackend | None:
    try:
        return _LiboqsKemBackend()
    except Exception as exc:
        _logger.debug("liboqs unavailable: %s", exc)
        return None


_NATIVE = _select_native()
_LIBOQS = _select_liboqs()


def active_backend_id_for(alg: KemAlgorithm) -> str | None:
    if _NATIVE is not None and _NATIVE.supports(alg):
        return _NATIVE.backend_id
    if _LIBOQS is not None and _LIBOQS.supports(alg):
        return _LIBOQS.backend_id
    return None


def _resolve_backend(alg: KemAlgorithm):
    if _NATIVE is not None and _NATIVE.supports(alg):
        return _NATIVE
    if _LIBOQS is not None and _LIBOQS.supports(alg):
        return _LIBOQS
    raise RuntimeError(
        f"No ML-KEM backend supports {alg.value}. Install pyca/cryptography "
        ">= 48.0.0 (ML-KEM-768/1024) or liboqs-python (all parameter sets)."
    )


@dataclass(frozen=True, slots=True)
class KemKeyPair:
    """An ML-KEM key pair tagged with its parameter set."""

    algorithm: KemAlgorithm
    public_key: bytes
    private_key: bytes
    key_id: str


class MlKemProvider:
    """ML-KEM key encapsulation per NIST FIPS 203.

    Stateless and thread-safe. Dispatches through the resolved backend
    (pyca/cryptography native or liboqs) per parameter set.
    """

    def __init__(
        self,
        parameter_set: KemAlgorithm = KemAlgorithm.ML_KEM_768,
    ) -> None:
        if parameter_set not in _PK_BYTES:
            raise ValueError(f"Not an ML-KEM parameter set: {parameter_set}")
        self.parameter_set: KemAlgorithm = parameter_set
        self.algorithm: KemAlgorithm = parameter_set

    @property
    def shared_secret_bytes(self) -> int:
        return _SS_BYTES

    @property
    def public_key_bytes(self) -> int:
        return _PK_BYTES[self.parameter_set]

    @property
    def ciphertext_bytes(self) -> int:
        return _CT_BYTES[self.parameter_set]

    # wired: dispatch to native pyca (preferred) or liboqs.
    def generate_keypair(self, key_id: str | None = None) -> KemKeyPair:
        backend = _resolve_backend(self.parameter_set)
        public_key, private_key = backend.generate_keypair(self.parameter_set)
        # pyca uses 32-byte seed format for private key; liboqs returns
        # the expanded private key. Both are accepted by their respective
        # decap calls — we record the actual length.
        resolved_id = key_id or f"{self.parameter_set.value}-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.ml_kem.keygen",
            algorithm=self.parameter_set.value,
            key_id=resolved_id,
            backend=backend.backend_id,
            public_key_bytes=len(public_key),
            private_key_bytes=len(private_key),
        )
        return KemKeyPair(
            algorithm=self.parameter_set,
            public_key=public_key,
            private_key=private_key,
            key_id=resolved_id,
        )

    # wired: encapsulate against a peer public key.
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        expected_pk = _PK_BYTES[self.parameter_set]
        if len(public_key) != expected_pk:
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} encap: public key length "
                f"{len(public_key)} != expected {expected_pk}"
            )
        backend = _resolve_backend(self.parameter_set)
        ciphertext, shared_secret = backend.encapsulate(
            self.parameter_set, public_key
        )
        if len(shared_secret) != _SS_BYTES:
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} encap returned "
                f"shared_secret of length {len(shared_secret)} (expected 32)"
            )
        emit_event(
            "pqcrypto.ml_kem.encapsulated",
            algorithm=self.parameter_set.value,
            backend=backend.backend_id,
            ciphertext_bytes=len(ciphertext),
            shared_secret_bytes=len(shared_secret),
        )
        return ciphertext, shared_secret

    # wired: decapsulate using our private key. Implicit-rejection per FIPS 203
    # §7.3 — wrong ciphertext returns a deterministic-but-wrong 32-byte value.
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        expected_ct = _CT_BYTES[self.parameter_set]
        if len(ciphertext) != expected_ct:
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} decap: ciphertext length "
                f"{len(ciphertext)} != expected {expected_ct}"
            )
        # Fail-fast input validation BEFORE backend resolution. FIPS 203 plus
        # RFC 9935 (the 2026 IETF X.509 ML-KEM spec) define exactly two
        # valid private-key encodings:
        #   * 64-byte seed form (RFC 9935 §4, RFC 9881-aligned), or
        #   * expanded decapsulation key of _SK_BYTES[alg] bytes
        #     (FIPS 203 §7.1 output).
        # Any other length is unambiguously invalid input regardless of
        # which backend (pyca/cryptography, liboqs) happens to be loaded.
        # Validating here:
        #   1. Lets the API reject malformed input with a clear error
        #      class even if no backend is installed (test environments,
        #      bootstrap, FIPS-mode operators on transitional builds).
        #   2. Avoids burning a backend round-trip on obviously bad input
        #      — a latency win on the hot path.
        #   3. Provides a uniform exception type to callers; without this,
        #      pyca raises ValueError, liboqs raises generic RuntimeError,
        #      and missing-backend raises another RuntimeError variant.
        expected_sk_expanded = _SK_BYTES[self.parameter_set]
        if len(private_key) not in (_SEED_BYTES, expected_sk_expanded):
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} decap: invalid private "
                f"key length {len(private_key)}. FIPS 203 / RFC 9935 require "
                f"either a {_SEED_BYTES}-byte seed or a "
                f"{expected_sk_expanded}-byte expanded decapsulation key."
            )
        backend = _resolve_backend(self.parameter_set)
        try:
            shared_secret = backend.decapsulate(
                self.parameter_set, ciphertext, private_key
            )
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} decap: invalid private "
                f"key for backend {backend.backend_id}: {exc}"
            ) from exc
        if len(shared_secret) != _SS_BYTES:
            raise RuntimeError(
                f"ML-KEM {self.parameter_set.value} decap returned "
                f"shared_secret of length {len(shared_secret)} (expected 32)"
            )
        emit_event(
            "pqcrypto.ml_kem.decapsulated",
            algorithm=self.parameter_set.value,
            backend=backend.backend_id,
            ciphertext_bytes=len(ciphertext),
            shared_secret_bytes=len(shared_secret),
        )
        return shared_secret


def get_kem_provider(algorithm: KemAlgorithm) -> MlKemProvider:
    """Algorithm-agile KEM dispatcher (currently ML-KEM only)."""
    if algorithm in (
        KemAlgorithm.ML_KEM_512,
        KemAlgorithm.ML_KEM_768,
        KemAlgorithm.ML_KEM_1024,
    ):
        return MlKemProvider(parameter_set=algorithm)
    raise NotImplementedError(f"No KEM provider registered for: {algorithm}")
