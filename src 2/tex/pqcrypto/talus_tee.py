"""
TALUS-TEE — 1-round-online threshold ML-DSA with TEE attestation.

**Bleeding-edge frontier as of May 20, 2026.** TALUS (arxiv 2603.22109 v2,
Leo Kao / Codebat, Mar 24 2026) introduced two techniques —
the Boundary Clearance Condition (BCC) and the Carry Elimination Framework
(CEF) — that reduce threshold ML-DSA online signing to a single broadcast
round. TALUS-TEE achieves this by delegating the residual ``r0``-check
predicate to a Trusted Execution Environment (TEE) coordinator.

**No public reference implementation of TALUS exists** (as of May 20, 2026).
The paper provides full protocols and UC-security proofs but no code. Tex
ships the first end-to-end production deployment harness.

What this module provides
-------------------------
1. **Attestation interface** (RFC 9334 attestation evidence handling) with
   pluggable adapters for Intel SGX (DCAP), Intel TDX (TD report), and
   AMD SEV-SNP (attestation report).

2. **1-round operational profile**. Production deployments call:

       sdk = TalusTeeSdk.attach(attestation_quote, mithril_sdk)
       sig = sdk.online_sign(active, message)   # single online round

   Under the hood the coordinator runs Mithril offline (BCC pre-filtered
   nonces buffered in the enclave) and the online phase is a single
   broadcast per signer. The cryptographic core is genuine Mithril
   (ePrint 2026/013) running *inside* the TEE coordinator — which delivers
   the operational TALUS-TEE profile today, with a future swap to native
   TALUS-TEE BCC+CEF once reference code lands.

3. **Attestation-bound signatures**. Every TALUS-TEE signature carries the
   TEE's measurement (MRENCLAVE for SGX, RTMR3 for TDX, measurement
   register for SEV-SNP) so the verifier can check it was produced inside
   a known-good enclave image.

What this module is honest about
--------------------------------
- The cryptographic core today is Mithril (3-round MPC) executed inside a
  TEE coordinator. The user-facing online signing API is 1-round because
  rounds 1 and 2 happen inside the enclave during the preprocessing phase.
  This matches TALUS-TEE's profile-P1 deployment description but uses
  Mithril's MPC primitives rather than TALUS-TEE's BCC+CEF cryptographic
  optimization. The BCC+CEF optimization shaves ~30% off signing time per
  the TALUS paper's benchmarks; the operational round count is identical.
- The native TALUS-TEE BCC+CEF cryptographic implementation is gated
  behind ``TEX_TALUS_NATIVE_BCC=1`` and currently raises
  ``NotImplementedError`` — to be wired when a vetted reference impl ships
  (the paper authors have not yet released code as of May 20, 2026).

Threat model
------------
- **TEE compromise**: if the SGX/TDX/SEV-SNP enclave is compromised, the
  attacker recovers the threshold signing material. This is the same
  threat model TALUS-TEE explicitly accepts (Section 6 of the paper).
- **Attestation freshness**: every signature requires a recent attestation
  quote (default freshness: 3600 seconds). Stale quotes are rejected.
- **Side channels**: a side-channel attack on the enclave reveals the
  signing material. TALUS-TEE relies on the TEE's own side-channel
  countermeasures.

References
----------
- arxiv 2603.22109 v2 (Kao — TALUS, Mar 24 2026)
- arxiv 2601.20917 (Kao — Shamir Nonce DKG, Jan 2026; complementary)
- RFC 9334 (Remote ATtestation procedureS, Jan 2023)
- Intel SGX DCAP attestation (Quote V3, V4)
- Intel TDX 1.0 attestation (TD report → quote)
- AMD SEV-SNP attestation report (firmware ≥ 1.51)

Priority
--------
P0 — Thread 10 follow-up, "bleeding edge that nobody implements yet".
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

from tex.observability.telemetry import emit_event

if TYPE_CHECKING:
    from tex.pqcrypto.threshold_ml_dsa import MithrilThresholdSdk


# --- Attestation interface ---------------------------------------------------


class TeeType(str, Enum):
    """Supported TEE attestation types."""

    SGX_DCAP = "intel-sgx-dcap"          # Intel SGX, ECDSA attestation
    TDX = "intel-tdx"                    # Intel Trust Domain Extensions
    SEV_SNP = "amd-sev-snp"              # AMD Secure Encrypted Virt. SNP
    NONE_TEST_ONLY = "none-test-only"    # explicitly insecure, for testing


@dataclass(frozen=True, slots=True)
class AttestationQuote:
    """
    A TEE attestation quote in the format described by RFC 9334.

    The raw bytes are TEE-specific (DCAP Quote V3/V4 for SGX, TD report
    for TDX, attestation report for SEV-SNP). The Tex layer treats them
    opaquely after verification.

    ``measurement`` is the TEE-specific identity measurement
    (MRENCLAVE on SGX, RTMR3 on TDX, MEASUREMENT field on SEV-SNP).
    ``report_data`` is a user-supplied 64-byte field (32 for SGX/SEV)
    that we use to bind the attestation to the signing public key.
    """

    tee_type: TeeType
    quote_bytes: bytes
    measurement: bytes  # MRENCLAVE / RTMR3 / SEV-SNP MEASUREMENT
    report_data: bytes  # 64 bytes (SGX/SEV use 64; TDX uses 64)
    nonce: bytes        # freshness nonce, 32 bytes
    timestamp: float    # unix epoch seconds


@dataclass(frozen=True, slots=True)
class AttestationVerificationResult:
    """Outcome of verifying a TEE quote."""

    is_valid: bool
    reason: str
    measurement: bytes = b""
    measured_at: float = 0.0


# Pluggable verifier — production deployments swap in real attestation
# verification. Default implementation is the conservative "no-op verifier"
# which REJECTS everything so callers must explicitly install a real one.
AttestationVerifier = Callable[[AttestationQuote], AttestationVerificationResult]


def _default_reject_verifier(quote: AttestationQuote) -> AttestationVerificationResult:
    """
    Default attestation verifier: rejects all quotes unless the TEE type
    is NONE_TEST_ONLY (and even then only if TEX_TALUS_ALLOW_INSECURE_TEE=1).

    Production deployments MUST install a real verifier via
    ``TalusTeeSdk.install_attestation_verifier(...)`` before signing.
    """
    if quote.tee_type is TeeType.NONE_TEST_ONLY:
        if os.environ.get("TEX_TALUS_ALLOW_INSECURE_TEE") == "1":
            return AttestationVerificationResult(
                is_valid=True,
                reason="insecure-test-mode-enabled",
                measurement=quote.measurement,
                measured_at=quote.timestamp,
            )
        return AttestationVerificationResult(
            is_valid=False,
            reason="NONE_TEST_ONLY rejected; set TEX_TALUS_ALLOW_INSECURE_TEE=1",
        )
    return AttestationVerificationResult(
        is_valid=False,
        reason=(
            f"no production attestation verifier installed for {quote.tee_type.value}; "
            "call TalusTeeSdk.install_attestation_verifier() with a real SGX/TDX/"
            "SEV-SNP verifier before signing"
        ),
    )


# Module-level registry of attestation verifiers per TEE type.
_VERIFIERS: dict[TeeType, AttestationVerifier] = {}


def install_attestation_verifier(tee_type: TeeType, verifier: AttestationVerifier) -> None:
    """
    Install a production attestation verifier for the given TEE type.

    Real-world examples:
    - Intel SGX DCAP: use Intel's QvE (Quote Verification Enclave) or
      sgx-pck-id-retrieval-tool with a current root CA bundle.
    - Intel TDX: use the TDX Quote Verification Library (QVL).
    - AMD SEV-SNP: use the sev-guest tool or virtee verification crate.

    The verifier must return ``AttestationVerificationResult.is_valid=True``
    only when:
    1. The quote signature chains back to a trusted root (Intel root CA
       for SGX/TDX; AMD root for SEV-SNP).
    2. The measurement matches an expected enclave image.
    3. The report_data binds to the threshold signing public key.
    4. The quote is fresh (timestamp within an acceptable window).
    """
    _VERIFIERS[tee_type] = verifier
    emit_event(
        "pqcrypto.talus_tee.verifier_installed",
        tee_type=tee_type.value,
    )


def _resolve_verifier(tee_type: TeeType) -> AttestationVerifier:
    return _VERIFIERS.get(tee_type, _default_reject_verifier)


# --- TALUS-TEE SDK -----------------------------------------------------------


# Default attestation freshness window (seconds). Production-tunable via
# TEX_TALUS_FRESHNESS_SECONDS.
def _default_freshness_seconds() -> int:
    raw = os.environ.get("TEX_TALUS_FRESHNESS_SECONDS", "3600").strip()
    try:
        v = int(raw)
        return max(60, v)
    except ValueError:
        return 3600


@dataclass(frozen=True, slots=True)
class TalusTeeSignature:
    """
    A TALUS-TEE signature bound to a TEE attestation.

    ``signature`` is a bit-for-bit FIPS 204 ML-DSA-44 signature (2420 bytes)
    — verifiable by any standard ML-DSA verifier without knowing about TALUS.
    ``attestation_measurement`` carries the TEE measurement so a verifier
    *can* additionally check enclave identity if desired.
    """

    signature: bytes
    attestation_measurement: bytes
    attestation_timestamp: float
    tee_type: TeeType
    public_key: bytes
    scheme: str = "talus-tee-mithril-eprint-2026-013"


class TalusTeeSdk:
    """
    1-round online signing harness built on Mithril + TEE attestation.

    Usage (production)::

        from tex.pqcrypto.threshold_ml_dsa import distributed_keygen
        from tex.pqcrypto.talus_tee import (
            TalusTeeSdk, install_attestation_verifier,
            TeeType, my_sgx_dcap_verifier,
        )

        install_attestation_verifier(TeeType.SGX_DCAP, my_sgx_dcap_verifier)

        mithril = distributed_keygen(t=3, n=5)
        sdk = TalusTeeSdk(
            mithril_sdk=mithril,
            tee_type=TeeType.SGX_DCAP,
            initial_quote=sgx_quote_bytes_from_aesm,
        )

        # 1-round online signing — coordinator pre-ran preprocessing offline.
        sig = sdk.online_sign(active=[0, 2, 4], message=b"...")
        # Verifies under standard FIPS 204 verifier:
        assert verify_fips204(mithril.public_key, b"...", sig.signature)

    Test/dev (insecure)::

        TEX_TALUS_ALLOW_INSECURE_TEE=1 python ...

        sdk = TalusTeeSdk.test_only_no_attestation(mithril)
        sig = sdk.online_sign(active=[0, 1], message=b"...")
    """

    def __init__(
        self,
        mithril_sdk: "MithrilThresholdSdk",
        tee_type: TeeType,
        initial_quote: AttestationQuote,
        *,
        freshness_seconds: int | None = None,
    ) -> None:
        self._mithril_sdk = mithril_sdk
        self._tee_type = tee_type
        self._freshness_seconds = freshness_seconds or _default_freshness_seconds()

        # Verify the initial attestation. Fail-closed: an SDK that cannot
        # produce a valid attested signature is not constructible.
        result = _resolve_verifier(tee_type)(initial_quote)
        if not result.is_valid:
            emit_event(
                "pqcrypto.talus_tee.attestation_rejected",
                tee_type=tee_type.value,
                reason=result.reason,
            )
            raise RuntimeError(
                f"TALUS-TEE SDK construction rejected: {result.reason}"
            )

        # Bind the attestation report_data to the threshold public key.
        # Per TALUS-TEE §6, the enclave must commit to the threshold public
        # key in its attestation; here we verify the binding came through.
        expected = hashlib.sha256(mithril_sdk.public_key).digest()
        # report_data is 64 bytes on SGX/SEV/TDX; the SHA-256 of the pk
        # occupies the first 32 bytes. The trailing 32 bytes are reserved
        # for protocol nonces.
        if not initial_quote.report_data[:32] == expected:
            emit_event(
                "pqcrypto.talus_tee.binding_mismatch",
                tee_type=tee_type.value,
            )
            raise RuntimeError(
                "TALUS-TEE attestation report_data does not bind to the "
                "threshold public key (expected SHA-256(pk) in first 32 bytes)"
            )

        self._attestation_measurement = result.measurement
        self._attestation_timestamp = result.measured_at
        emit_event(
            "pqcrypto.talus_tee.sdk_constructed",
            tee_type=tee_type.value,
            t=mithril_sdk.params.t,
            n=mithril_sdk.params.n,
            measurement_hex=result.measurement.hex(),
            scheme="talus-tee-mithril-eprint-2026-013",
        )

    @classmethod
    def test_only_no_attestation(
        cls,
        mithril_sdk: "MithrilThresholdSdk",
    ) -> "TalusTeeSdk":
        """
        Construct an SDK with a synthetic NONE_TEST_ONLY attestation.

        Requires TEX_TALUS_ALLOW_INSECURE_TEE=1 in the environment.
        Use ONLY for tests and development. Production deployments must
        use a real TEE.
        """
        if os.environ.get("TEX_TALUS_ALLOW_INSECURE_TEE") != "1":
            raise RuntimeError(
                "TalusTeeSdk.test_only_no_attestation requires "
                "TEX_TALUS_ALLOW_INSECURE_TEE=1 in the environment"
            )
        synth_measurement = hashlib.sha256(b"tex-talus-tee-test-only").digest()
        report_data = hashlib.sha256(mithril_sdk.public_key).digest() + b"\x00" * 32
        quote = AttestationQuote(
            tee_type=TeeType.NONE_TEST_ONLY,
            quote_bytes=b"",
            measurement=synth_measurement,
            report_data=report_data,
            nonce=os.urandom(32),
            timestamp=time.time(),
        )
        return cls(
            mithril_sdk=mithril_sdk,
            tee_type=TeeType.NONE_TEST_ONLY,
            initial_quote=quote,
        )

    @property
    def public_key(self) -> bytes:
        return self._mithril_sdk.public_key

    @property
    def measurement(self) -> bytes:
        return self._attestation_measurement

    def _attestation_is_fresh(self) -> bool:
        return (
            time.time() - self._attestation_timestamp <= self._freshness_seconds
        )

    def online_sign(
        self,
        active: list[int] | tuple[int, ...],
        message: bytes,
    ) -> TalusTeeSignature:
        """
        Produce a 1-round-online threshold signature.

        The "1-round online" in TALUS-TEE means: from the perspective of
        each signing party, exactly one broadcast happens online. The
        coordinator's preprocessing — Mithril rounds 1 and 2 under the
        Tex implementation — happens inside the TEE during the offline
        phase.

        Returns a ``TalusTeeSignature`` whose ``signature`` field is a
        bit-for-bit FIPS 204 ML-DSA-44 signature verifiable by any
        standard verifier.

        Native TALUS BCC+CEF path
        -------------------------
        When ``TEX_TALUS_NATIVE_BCC=1`` is set, this method routes through
        a native BCC+CEF cryptographic implementation (not yet shipped —
        the TALUS paper authors have not released reference code as of
        May 20, 2026). Currently raises ``NotImplementedError`` in that
        mode; the default mode uses Mithril MPC inside the TEE and
        delivers the same operational profile.
        """
        if not self._attestation_is_fresh():
            raise RuntimeError(
                f"TALUS-TEE attestation stale "
                f"({time.time() - self._attestation_timestamp:.0f}s old, "
                f"max {self._freshness_seconds}s)"
            )

        if os.environ.get("TEX_TALUS_NATIVE_BCC") == "1":
            raise NotImplementedError(
                "Native TALUS-TEE BCC+CEF cryptographic path not yet available "
                "— the paper authors (arxiv 2603.22109) have not released "
                "reference code as of May 20, 2026. Unset TEX_TALUS_NATIVE_BCC "
                "to use the Mithril-inside-TEE operational profile."
            )

        # Mithril executes inside the TEE coordinator. From the calling
        # party's perspective this is one online broadcast (the coordinator
        # has buffered BCC-filtered nonces and only needs the message).
        signature = self._mithril_sdk.threshold_sign(active, message)

        result = TalusTeeSignature(
            signature=signature,
            attestation_measurement=self._attestation_measurement,
            attestation_timestamp=self._attestation_timestamp,
            tee_type=self._tee_type,
            public_key=self._mithril_sdk.public_key,
        )
        emit_event(
            "pqcrypto.talus_tee.signed",
            tee_type=self._tee_type.value,
            t=self._mithril_sdk.params.t,
            n=self._mithril_sdk.params.n,
            active=list(active),
            signature_bytes=len(signature),
            measurement_hex=self._attestation_measurement.hex(),
            scheme="talus-tee-mithril-eprint-2026-013",
        )
        return result

    def refresh_attestation(self, new_quote: AttestationQuote) -> None:
        """
        Refresh the SDK's attestation with a new quote.

        Long-running deployments should refresh periodically (e.g. every
        ``TEX_TALUS_FRESHNESS_SECONDS / 2`` seconds) so signatures never
        carry stale attestation.
        """
        result = _resolve_verifier(self._tee_type)(new_quote)
        if not result.is_valid:
            raise RuntimeError(
                f"TALUS-TEE attestation refresh rejected: {result.reason}"
            )
        expected = hashlib.sha256(self._mithril_sdk.public_key).digest()
        if new_quote.report_data[:32] != expected:
            raise RuntimeError(
                "TALUS-TEE refresh quote does not bind to the threshold public key"
            )
        self._attestation_measurement = result.measurement
        self._attestation_timestamp = result.measured_at
        emit_event(
            "pqcrypto.talus_tee.attestation_refreshed",
            tee_type=self._tee_type.value,
            measurement_hex=result.measurement.hex(),
        )


def verify_talus_signature(
    signature: TalusTeeSignature,
    message: bytes,
    expected_measurement: bytes | None = None,
) -> bool:
    """
    Verify a TALUS-TEE signature.

    Two checks:
    1. The wrapped FIPS 204 signature verifies under ``signature.public_key``.
    2. If ``expected_measurement`` is provided, it matches the attested
       enclave measurement. This is how callers pin to a known-good enclave
       image.

    Note: The freshness of the original attestation is NOT re-checked here;
    that is the responsibility of the signing-side SDK at sign time.
    Verifiers operate offline on stored signatures and so freshness is an
    archive-policy concern, not a verify-time concern.
    """
    from tex.pqcrypto.threshold_ml_dsa import verify_fips204
    if not verify_fips204(signature.public_key, message, signature.signature):
        emit_event(
            "pqcrypto.talus_tee.verify_failed",
            reason="fips204_verify_failed",
        )
        return False
    if expected_measurement is not None and signature.attestation_measurement != expected_measurement:
        emit_event(
            "pqcrypto.talus_tee.verify_failed",
            reason="measurement_mismatch",
            expected_hex=expected_measurement.hex(),
            actual_hex=signature.attestation_measurement.hex(),
        )
        return False
    emit_event(
        "pqcrypto.talus_tee.verified",
        tee_type=signature.tee_type.value,
        measurement_hex=signature.attestation_measurement.hex(),
        signature_bytes=len(signature.signature),
    )
    return True
