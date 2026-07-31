"""
Genuine threshold ML-DSA via the Mithril scheme (ePrint 2026/013).

**This is the real thing.** n parties hold replicated shares of one
ML-DSA secret, run a 3-round MPC protocol, and produce a *single*
FIPS 204 signature that any unmodified ML-DSA-44 verifier accepts.
Bit-for-bit standards-compliant.

Bleeding-edge frontier as of May 20, 2026
-----------------------------------------
**No shipping AI governance platform implements genuine threshold ML-DSA.**

- Microsoft Agent Governance Toolkit (Apr 2 2026): ML-DSA-65 single-key.
  Quote: "Ed25519 + ML-DSA-65 agent credentials." Single-key.
- Asqav (Apr 2026): ML-DSA-65 single-key with hash chain.
- IBM Quorus (MPTS 2026): 2 online rounds, honest majority — paper only,
  no public implementation.
- PQShield Mithril (ePrint 2026/013): the Rust crate ``threshold-ml-dsa``
  v0.3 (crates.io, Apr 14 2026, MIT). **This is what Tex binds to.**
- TALUS (arxiv 2603.22109 v2, Codebat, Mar 24 2026): 1 online round
  with TEE. See ``tex.pqcrypto.talus_tee`` for the Tex implementation.

How this module works
---------------------
This module is a thin Python wrapper around the Rust ``threshold-ml-dsa``
crate via PyO3. The native extension (``tex_mithril.so``) is shipped in
``vendor/mithril/`` for x86_64 Linux. On other platforms, build from the
vendored source in ``vendor/mithril/binding_src/`` with::

    cd vendor/mithril/binding_src
    cargo build --release
    cp target/release/libtex_mithril.so ../tex_mithril.so

The Rust crate implements the Mithril protocol exactly per ePrint
2026/013, Figure 8: Replicated Secret Sharing (RSS), K-parallel
commitments with SHAKE-256-bound transcripts, hyperball-based rejection
sampling via Box-Muller for Rényi-divergence safety, Algorithm 6 balanced
partition, and the 3-round commit/reveal/respond protocol.

Supported (T, N) parameter sets (Mithril Figure 8)
--------------------------------------------------
(2,2), (2,3), (3,3), (2,4), (3,4), (4,4), (2,5), (3,5), (4,5), (5,5),
(2,6), (3,6), (4,6), (5,6), (6,6).

Currently only ML-DSA-44 is supported by the upstream Rust crate (v0.3).
ML-DSA-65 and ML-DSA-87 support will land in upstream v0.4; until then,
the L3/L5 quorum-signing path is served by ``tex.pqcrypto.quorum_ml_dsa``
which produces a quorum certificate over independent ML-DSA-65/87 keys.

Security properties
-------------------
- **Forgery resistance** ≥ ML-DSA-44 EUF-CMA under MLWE assumption.
- **t-1 corruption resistance**: any subset of t-1 parties learns nothing
  about the signing key (proven in ROM, reduces to MLWE).
- **Fail-closed signing**: every aggregated signature is verified by the
  standard FIPS 204 verifier in the Rust crate before being returned.
- **Sybil resistance via strict ordering**: ``active`` must be sorted
  strictly ascending; the Rust crate rejects ambiguous sets.
- **Single-use nonce state**: Rust ownership prevents replay of the same
  nonce randomness with different coordinator challenges.
- **Zeroize-on-drop**: secret material in the Rust crate is wiped on drop.

References
----------
- ePrint 2026/013 (Celi/del Pino/Espitau/Niot/Prest — Mithril,
  USENIX Security '26)
- ``threshold-ml-dsa`` v0.3.6 (crates.io, lattice-safe org, MIT licensed)
- FIPS 204 ML-DSA (Aug 2024)
- ``tex.pqcrypto.quorum_ml_dsa`` — the no-coordination quorum certificate
- ``tex.pqcrypto.talus_tee`` — TALUS-TEE 1-round MPC with attestation

Priority
--------
P0 — Thread 10 follow-up. Genuine MPC threshold signing. The actual
bleeding edge.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tex.observability.telemetry import emit_event


# --- Load the vendored PyO3 extension ----------------------------------------

_VENDOR_DIR = Path(__file__).resolve().parent.parent.parent.parent / "vendor" / "mithril"
_TEX_MITHRIL_SO_NAME = "tex_mithril.so"

_NATIVE_NOT_AVAILABLE_MSG = (
    "tex_mithril native extension not found. The Mithril threshold ML-DSA path "
    "requires the Rust-backed PyO3 binding shipped in vendor/mithril/. On x86_64 "
    "Linux the prebuilt .so should work as-is; on other platforms rebuild with "
    "`cd vendor/mithril/binding_src && cargo build --release && "
    "cp target/release/libtex_mithril.so ../tex_mithril.so`. "
    "Fall back to tex.pqcrypto.quorum_ml_dsa for the no-coordination quorum "
    "certificate path, which does not require the native extension."
)


def _load_native() -> Any:
    """Load the PyO3 extension from the vendored .so file."""
    so_path = _VENDOR_DIR / _TEX_MITHRIL_SO_NAME
    if not so_path.exists():
        raise RuntimeError(
            f"{_NATIVE_NOT_AVAILABLE_MSG} (looked at {so_path})"
        )
    spec = importlib.util.spec_from_file_location("tex_mithril", str(so_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"{_NATIVE_NOT_AVAILABLE_MSG} (could not load spec from {so_path})"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Lazy-load: import-time failure would prevent the package from importing
# in environments without the native ext, e.g. Render free tier.
_native: Any | None = None


def _get_native() -> Any:
    global _native
    if _native is None:
        _native = _load_native()
    return _native


def is_native_available() -> bool:
    """Probe whether the PyO3 binding can be loaded."""
    try:
        _get_native()
        return True
    except Exception:
        return False


# --- Public API --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MithrilParams:
    """Parameter set for a Mithril threshold ML-DSA-44 quorum."""

    t: int  # threshold (parties needed to sign)
    n: int  # total parties
    base_algorithm: str = "ml-dsa-44"  # only ML-DSA-44 in upstream v0.3


# All 15 (T, N) parameter sets supported by ePrint 2026/013, Figure 8.
SUPPORTED_PARAMS: tuple[tuple[int, int], ...] = (
    (2, 2), (2, 3), (3, 3), (2, 4), (3, 4), (4, 4),
    (2, 5), (3, 5), (4, 5), (5, 5),
    (2, 6), (3, 6), (4, 6), (5, 6), (6, 6),
)


@dataclass(frozen=True)
class MithrilThresholdSdk:
    """
    Wrapper around the Rust ``ThresholdMlDsa44Sdk`` (Mithril).

    Holds the n-party private key set internally (in the Rust struct).
    In a true distributed deployment the keys would be on n separate
    HSMs; this in-process SDK is the testing/single-org form.

    Use ``threshold_sign(active, msg)`` to produce a signature; use
    ``verify(msg, sig)`` for self-verification or ``verify_fips204(pk,
    msg, sig)`` for verification under an arbitrary FIPS 204 verifier.
    """

    _native_sdk: Any
    params: MithrilParams

    @property
    def public_key(self) -> bytes:
        """The packed FIPS 204 public key (1312 bytes for ML-DSA-44)."""
        return self._native_sdk.public_key()

    @property
    def num_parties(self) -> int:
        return self._native_sdk.num_parties()

    def threshold_sign(self, active: list[int] | tuple[int, ...], msg: bytes) -> bytes:
        """
        Produce a bit-for-bit FIPS 204 signature via the Mithril MPC.

        ``active`` must be a strictly-ascending sequence of party indices
        of length exactly ``self.params.t``. The signature output is
        2420 bytes (ML-DSA-44 §8) and verifies under any standard ML-DSA-44
        verifier.

        Raises ``RuntimeError`` if the MPC exceeds its retry budget
        (rejection sampling is probabilistic; for some (T, N) configurations
        K-parallel repetitions reduce expected attempts to <2).
        """
        if len(active) != self.params.t:
            raise ValueError(
                f"active set length {len(active)} != t={self.params.t}"
            )
        for i in range(1, len(active)):
            if active[i] <= active[i - 1]:
                raise ValueError(
                    "active set must be strictly ascending (no duplicates)"
                )
        active_bytes = bytes(active)
        msg_bytes = bytes(msg) if not isinstance(msg, bytes) else msg

        try:
            sig = self._native_sdk.threshold_sign(active_bytes, msg_bytes)
        except RuntimeError as exc:
            emit_event(
                "pqcrypto.mithril.sign_failed",
                t=self.params.t,
                n=self.params.n,
                active=list(active),
                error=str(exc),
            )
            raise

        emit_event(
            "pqcrypto.mithril.threshold_signed",
            t=self.params.t,
            n=self.params.n,
            active=list(active),
            base_algorithm=self.params.base_algorithm,
            signature_bytes=len(sig),
            message_bytes=len(msg_bytes),
            scheme="mithril-eprint-2026-013",
        )
        return bytes(sig)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """Self-verify under this SDK's public key (convenience wrapper)."""
        ok = self._native_sdk.verify(msg, sig)
        emit_event(
            "pqcrypto.mithril.verified",
            ok=bool(ok),
            message_bytes=len(msg),
            signature_bytes=len(sig),
        )
        return bool(ok)


def distributed_keygen(
    t: int,
    n: int,
    *,
    seed: bytes | None = None,
    max_retries: int = 100,
) -> MithrilThresholdSdk:
    """
    Generate a fresh Mithril threshold ML-DSA-44 key set.

    Parameters
    ----------
    t, n : int
        Threshold and total parties. Must be one of ``SUPPORTED_PARAMS``.
    seed : bytes, optional
        32-byte seed for deterministic keygen (testing only). If None,
        a fresh seed is drawn from ``secrets.token_bytes(32)``.
    max_retries : int
        Maximum protocol attempts before the keygen gives up (rejection
        sampling is probabilistic; the default of 100 is safe even for
        the (5, 6) and (6, 6) configurations whose K parameter is highest).
    """
    if (t, n) not in SUPPORTED_PARAMS:
        raise ValueError(
            f"(t={t}, n={n}) not in Mithril SUPPORTED_PARAMS — see ePrint "
            f"2026/013 Figure 8 for the 15 allowed combinations: "
            f"{SUPPORTED_PARAMS}"
        )
    if seed is None:
        seed = secrets.token_bytes(32)
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

    native = _get_native()
    native_sdk = native.MithrilSdk(seed, t, n, max_retries)
    sdk = MithrilThresholdSdk(
        _native_sdk=native_sdk,
        params=MithrilParams(t=t, n=n),
    )
    emit_event(
        "pqcrypto.mithril.keygen",
        t=t,
        n=n,
        base_algorithm="ml-dsa-44",
        scheme="mithril-eprint-2026-013",
        public_key_bytes=len(sdk.public_key),
    )
    return sdk


def verify_fips204(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a Mithril-produced signature under the standard FIPS 204 verifier.

    This is the headline property of Mithril: signatures verify with any
    unmodified ML-DSA-44 verifier. Use this function to confirm that the
    signature is genuinely FIPS 204-compatible (the ``MithrilThresholdSdk.verify``
    method routes through the same Rust crate, so this is the same code
    path — but expressed as "verify against an arbitrary public key" rather
    than "verify against this SDK's own key", which is closer to the
    deployment model).
    """
    native = _get_native()
    return bool(native.verify_fips204(public_key, message, signature))
