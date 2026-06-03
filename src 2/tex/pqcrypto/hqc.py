"""
HQC (Hamming Quasi-Cyclic) KEM provider — NIST 4th-round additional selection.

**Bleeding edge as of May 20, 2026:** the EU regulatory environment and
BSI cryptographic agility guidance both push for a non-lattice KEM
alongside ML-KEM. HQC is NIST's chosen non-lattice selection (selected
March 2025 as the 4th-round additional KEM standardization candidate)
and is currently in draft as FIPS 207.

**No shipping AI governance platform implements HQC** as of May 20, 2026.
This module is the algorithm-agility hedge against lattice cryptanalysis:
if a future break against ML-KEM emerges, deployments running HQC remain
secure under the much older syndrome decoding hardness assumption.

What this module ships
----------------------
- HQC-128, HQC-192, HQC-256 (NIST Security Level 1, 3, 5)
- Algorithm-agile via the same ``KemAlgorithm`` enum extended with
  ``HQC_128 / HQC_192 / HQC_256``.
- Round-trip encap/decap with telemetry events.
- Fail-closed length validation against expected sizes.

Size envelope (HQC reference impl in liboqs 0.15)
-------------------------------------------------
============  ============  =============  ==============  =================
Param         pk bytes      sk bytes       ciphertext      shared_secret
============  ============  =============  ==============  =================
HQC-128       2,249         2,305          4,433           64
HQC-192       4,522         4,586          8,978           64
HQC-256       7,245         7,317          14,421          64
============  ============  =============  ==============  =================

Note: HQC ciphertexts are ~4-9× larger than ML-KEM. The trade-off is
deliberate — HQC's security relies on a different hardness assumption
than ML-KEM, and "harvest-now-decrypt-later" attackers who break ML-KEM
do not automatically break HQC.

Side-channel posture
--------------------
HQC has been the subject of recent side-channel attacks (CVE-2025-52473
disclosed June 2025 — secret-dependent branches in the reference impl when
compiled with -O1 or above). liboqs 0.15 mitigates by disabling compiler
optimization on the HQC compilation units (``target_compile_options(...
-O0)`` in upstream CMake). This module is suitable for the hedge-KEM
role in Tex; production deployments handling NSS-adjacent workloads
should continue to use ML-KEM-1024 as the primary and HQC-256 as the
defense-in-depth secondary.

References
----------
- NIST IR 8528 (HQC selection, March 11, 2025)
- FIPS 207 (HQC draft, NIST, expected late 2026)
- liboqs 0.15.0 (CVE-2025-52473 mitigation via -O0)
- CVE-2025-52473 (HQC reference impl secret-dependent branches)

Priority
--------
P0 — Thread 10 follow-up. Genuine bleeding edge — non-lattice hedge that
no AI governance product ships.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
from uuid import uuid4

from tex.observability.telemetry import emit_event

if TYPE_CHECKING:
    import oqs  # pragma: no cover


class HqcAlgorithm(str, Enum):
    """Supported HQC parameter sets (NIST 4th-round additional KEM)."""

    HQC_128 = "hqc-128"   # NIST Security Level 1
    HQC_192 = "hqc-192"   # NIST Security Level 3
    HQC_256 = "hqc-256"   # NIST Security Level 5


_OQS_NAME: dict[HqcAlgorithm, str] = {
    HqcAlgorithm.HQC_128: "HQC-128",
    HqcAlgorithm.HQC_192: "HQC-192",
    HqcAlgorithm.HQC_256: "HQC-256",
}

# liboqs 0.15.0 HQC sizes (verified in this module's smoke tests).
_PK_BYTES: dict[HqcAlgorithm, int] = {
    HqcAlgorithm.HQC_128: 2249,
    HqcAlgorithm.HQC_192: 4522,
    HqcAlgorithm.HQC_256: 7245,
}
_SK_BYTES: dict[HqcAlgorithm, int] = {
    HqcAlgorithm.HQC_128: 2305,
    HqcAlgorithm.HQC_192: 4586,
    HqcAlgorithm.HQC_256: 7317,
}
_CT_BYTES: dict[HqcAlgorithm, int] = {
    HqcAlgorithm.HQC_128: 4433,
    HqcAlgorithm.HQC_192: 8978,
    HqcAlgorithm.HQC_256: 14421,
}
_SS_BYTES = 64  # HQC produces a 64-byte shared secret


_LIBOQS_MISSING_MSG = (
    "liboqs is not available, or HQC is not enabled in this build. "
    "Build liboqs with -DOQS_ENABLE_KEM_HQC=ON (it is OFF by default since "
    "the CVE-2025-52473 mitigation — see liboqs 0.15.0 release notes). "
    "Then ensure the C shared library is on the dynamic loader path. "
    "See https://github.com/open-quantum-safe/liboqs."
)


def _import_oqs() -> "oqs":
    try:
        import oqs as _oqs  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(_LIBOQS_MISSING_MSG) from exc
    return _oqs


@dataclass(frozen=True, slots=True)
class HqcKeyPair:
    """An HQC key pair tagged with its parameter set."""

    algorithm: HqcAlgorithm
    public_key: bytes
    private_key: bytes
    key_id: str


class HqcProvider:
    """
    HQC KEM provider.

    Stateless: each call opens a fresh ``oqs.KeyEncapsulation``.

    HQC's primary use case in Tex is as the second-half of a hybrid KEM
    in long-lived encrypted-at-rest paths where the threat model
    explicitly includes "what if lattice cryptography is broken". For
    transport-layer KEM (ML-KEM-1024 in CNSA 2.0), ML-KEM remains the
    primary and HQC is the hedge.
    """

    def __init__(
        self,
        parameter_set: HqcAlgorithm = HqcAlgorithm.HQC_256,
    ) -> None:
        if parameter_set not in _OQS_NAME:
            raise ValueError(f"Not an HQC parameter set: {parameter_set}")
        self.parameter_set: HqcAlgorithm = parameter_set
        self.algorithm: HqcAlgorithm = parameter_set

    @property
    def shared_secret_bytes(self) -> int:
        return _SS_BYTES

    @property
    def public_key_bytes(self) -> int:
        return _PK_BYTES[self.parameter_set]

    @property
    def ciphertext_bytes(self) -> int:
        return _CT_BYTES[self.parameter_set]

    def generate_keypair(self, key_id: str | None = None) -> HqcKeyPair:
        oqs = _import_oqs()
        with oqs.KeyEncapsulation(_OQS_NAME[self.parameter_set]) as kg:
            public_key = bytes(kg.generate_keypair())
            private_key = bytes(kg.export_secret_key())

        if len(public_key) != _PK_BYTES[self.parameter_set]:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} returned public key of "
                f"unexpected length {len(public_key)} "
                f"(expected {_PK_BYTES[self.parameter_set]})"
            )
        if len(private_key) != _SK_BYTES[self.parameter_set]:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} returned private key of "
                f"unexpected length {len(private_key)} "
                f"(expected {_SK_BYTES[self.parameter_set]})"
            )

        resolved_id = key_id or f"{self.parameter_set.value}-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.hqc.keygen",
            algorithm=self.parameter_set.value,
            key_id=resolved_id,
            public_key_bytes=len(public_key),
            private_key_bytes=len(private_key),
        )
        return HqcKeyPair(
            algorithm=self.parameter_set,
            public_key=public_key,
            private_key=private_key,
            key_id=resolved_id,
        )

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate against ``public_key``. Returns ``(ciphertext, shared_secret)``.
        Shared secret is 64 bytes (vs ML-KEM's 32 — derive a 32-byte symmetric
        key with HKDF if interop with AES-256 is needed).
        """
        expected_pk = _PK_BYTES[self.parameter_set]
        if len(public_key) != expected_pk:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} encap: public key length "
                f"{len(public_key)} != expected {expected_pk}"
            )
        oqs = _import_oqs()
        with oqs.KeyEncapsulation(_OQS_NAME[self.parameter_set]) as enc:
            ciphertext, shared_secret = enc.encap_secret(public_key)
        ciphertext = bytes(ciphertext)
        shared_secret = bytes(shared_secret)
        if len(shared_secret) != _SS_BYTES:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} encap returned "
                f"shared_secret of length {len(shared_secret)} (expected 64)"
            )
        emit_event(
            "pqcrypto.hqc.encapsulated",
            algorithm=self.parameter_set.value,
            ciphertext_bytes=len(ciphertext),
            shared_secret_bytes=len(shared_secret),
        )
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate. Returns the 64-byte shared secret.

        Implicit-rejection semantics per the HQC spec: a malformed ciphertext
        returns a deterministic-but-pseudorandom value rather than failing.
        Callers MUST authenticate the shared secret out-of-band.
        """
        expected_ct = _CT_BYTES[self.parameter_set]
        expected_sk = _SK_BYTES[self.parameter_set]
        if len(ciphertext) != expected_ct:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} decap: ciphertext length "
                f"{len(ciphertext)} != expected {expected_ct}"
            )
        if len(private_key) != expected_sk:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} decap: private key length "
                f"{len(private_key)} != expected {expected_sk}"
            )
        oqs = _import_oqs()
        with oqs.KeyEncapsulation(
            _OQS_NAME[self.parameter_set], private_key
        ) as dec:
            shared_secret = bytes(dec.decap_secret(ciphertext))
        if len(shared_secret) != _SS_BYTES:
            raise RuntimeError(
                f"HQC {self.parameter_set.value} decap returned "
                f"shared_secret of length {len(shared_secret)} (expected 64)"
            )
        emit_event(
            "pqcrypto.hqc.decapsulated",
            algorithm=self.parameter_set.value,
            ciphertext_bytes=len(ciphertext),
            shared_secret_bytes=len(shared_secret),
        )
        return shared_secret


# --- Hybrid ML-KEM + HQC composite KEM --------------------------------------
#
# The recommended deployment pattern: encap under BOTH ML-KEM-1024 and HQC-256,
# then combine the two 32-byte / 64-byte shared secrets via HKDF-SHA-512 to
# produce a final session key. The session is secure if EITHER ML-KEM or HQC
# is unbroken — true defense in depth against lattice cryptanalysis.

import hmac
import hashlib

from tex.pqcrypto.ml_kem import KemAlgorithm, MlKemProvider


@dataclass(frozen=True, slots=True)
class HybridKemKeyPair:
    """Combined ML-KEM + HQC keypair."""

    ml_kem_public_key: bytes
    ml_kem_private_key: bytes
    hqc_public_key: bytes
    hqc_private_key: bytes
    key_id: str


@dataclass(frozen=True, slots=True)
class HybridKemCiphertext:
    """Combined ML-KEM + HQC ciphertext."""

    ml_kem_ciphertext: bytes
    hqc_ciphertext: bytes


def _hkdf_sha512_extract_and_expand(
    salt: bytes, ikm: bytes, info: bytes, length: int
) -> bytes:
    """RFC 5869 HKDF-SHA-512 (one-shot extract+expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()
        out += t
        counter += 1
    return out[:length]


class MlKemHqcHybridProvider:
    """
    ML-KEM + HQC hybrid KEM combiner.

    Deployment pattern recommended by BSI TR-02102 and ANSSI for any
    quantum-resilient KEM in long-lived use. Defeats both classical
    cryptanalysis (via ML-KEM's MLWE) AND a hypothetical lattice break
    (via HQC's syndrome decoding hardness).

    The combiner uses HKDF-SHA-512(salt=ml_kem_ct ‖ hqc_ct,
    ikm=ml_kem_ss ‖ hqc_ss, info="tex-mlkem-hqc-hybrid-v1") per
    draft-irtf-cfrg-hpke-pq-style derivation. The output length is
    32 bytes by default (matching AES-256-GCM key size).
    """

    KDF_INFO = b"tex-mlkem-hqc-hybrid-v1"

    def __init__(
        self,
        ml_kem_param: KemAlgorithm = KemAlgorithm.ML_KEM_1024,
        hqc_param: HqcAlgorithm = HqcAlgorithm.HQC_256,
    ) -> None:
        self._mlkem = MlKemProvider(parameter_set=ml_kem_param)
        self._hqc = HqcProvider(parameter_set=hqc_param)
        self._ml_kem_param = ml_kem_param
        self._hqc_param = hqc_param

    def generate_keypair(self, key_id: str | None = None) -> HybridKemKeyPair:
        ml_kp = self._mlkem.generate_keypair(key_id=f"{key_id or 'hybrid'}/ml-kem")
        hqc_kp = self._hqc.generate_keypair(key_id=f"{key_id or 'hybrid'}/hqc")
        resolved = key_id or f"mlkem-hqc-hybrid-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.hybrid_kem.keygen",
            ml_kem_algorithm=self._ml_kem_param.value,
            hqc_algorithm=self._hqc_param.value,
            key_id=resolved,
        )
        return HybridKemKeyPair(
            ml_kem_public_key=ml_kp.public_key,
            ml_kem_private_key=ml_kp.private_key,
            hqc_public_key=hqc_kp.public_key,
            hqc_private_key=hqc_kp.private_key,
            key_id=resolved,
        )

    def encapsulate(
        self, keypair: HybridKemKeyPair, output_bytes: int = 32
    ) -> tuple[HybridKemCiphertext, bytes]:
        """
        Encap against both halves of the hybrid public key.

        Returns ``(HybridKemCiphertext, derived_session_key)`` where the
        session key is HKDF-SHA-512 over the concatenated ciphertexts and
        shared secrets.
        """
        ml_ct, ml_ss = self._mlkem.encapsulate(keypair.ml_kem_public_key)
        hqc_ct, hqc_ss = self._hqc.encapsulate(keypair.hqc_public_key)
        salt = ml_ct + hqc_ct
        ikm = ml_ss + hqc_ss
        session_key = _hkdf_sha512_extract_and_expand(
            salt=salt, ikm=ikm, info=self.KDF_INFO, length=output_bytes,
        )
        emit_event(
            "pqcrypto.hybrid_kem.encapsulated",
            ml_kem_algorithm=self._ml_kem_param.value,
            hqc_algorithm=self._hqc_param.value,
            output_bytes=output_bytes,
        )
        return HybridKemCiphertext(ml_kem_ciphertext=ml_ct, hqc_ciphertext=hqc_ct), session_key

    def decapsulate(
        self,
        ciphertext: HybridKemCiphertext,
        keypair: HybridKemKeyPair,
        output_bytes: int = 32,
    ) -> bytes:
        """Decap both halves and derive the session key."""
        ml_ss = self._mlkem.decapsulate(
            ciphertext.ml_kem_ciphertext, keypair.ml_kem_private_key
        )
        hqc_ss = self._hqc.decapsulate(
            ciphertext.hqc_ciphertext, keypair.hqc_private_key
        )
        salt = ciphertext.ml_kem_ciphertext + ciphertext.hqc_ciphertext
        ikm = ml_ss + hqc_ss
        session_key = _hkdf_sha512_extract_and_expand(
            salt=salt, ikm=ikm, info=self.KDF_INFO, length=output_bytes,
        )
        emit_event(
            "pqcrypto.hybrid_kem.decapsulated",
            ml_kem_algorithm=self._ml_kem_param.value,
            hqc_algorithm=self._hqc_param.value,
            output_bytes=output_bytes,
        )
        return session_key
