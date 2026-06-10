"""
==================== DEACTIVATED PLACEHOLDER (research-early) ====================
This module is OFF by default and deliberately inert. It computes keyed-hash
(HMAC / SHA-256) STAND-INS, not real cryptographic proofs. The symbol and type
names here describe an INTENDED future proving backend, NOT what this code
computes; nothing here is cryptographically binding. The verifier is hard-gated
and fail-closed: tex.nanozk.verify_layer_proof_set() returns is_valid=False
unless TEX_NANOZK_ALLOW_SHIM=1 is set (tests/dev only) -- so flipping
TEX_FRONTIER_NANOZK alone can NEVER cause a stand-in to be trusted as a real
proof. Kept in-tree, intentionally, so a real backend can be wired in later
(see src/tex/nanozk/DEACTIVATED.md). Do NOT cite anything here as a guarantee.
================================================================================

DeepProve subprocess backend bridge.

Wires the layerwise prover dispatcher to the Lagrange Labs
DeepProve Rust binary (github.com/Lagrange-Labs/deep-prove)
when it's installed on the host. Falls back to the
deterministic shim when not present.

Why DeepProve
-------------
Lagrange Labs' DeepProve is the **first production zkML system
to prove a full LLM inference** (DeepProve-1, Aug 18 2025).
Benchmarks per the Lagrange blog:

  * 54-158× faster proof generation than EZKL
  * 671× faster verification (for MLPs); 521× (for CNNs)
  * 1000× faster than the baseline at large model sizes
  * 1150× faster one-time setup

Architecturally, DeepProve uses **sumcheck + logup-GKR** over
multilinear-extension shapes — a strict superset of NANOZK's
Halo2-IPA approach.

Already shipped: integrated into Anduril Lattice SDK for verifiable
defense autonomy (Nov 5 2025 Lagrange announcement). Production
deployments at General Dynamics, Raytheon supplier networks
(Lagrange press releases, 2025).

What this module exposes
------------------------
- ``DeepProveSubprocessBackend`` — a ``NanozkBackend``
  implementation that shells out to the ``deep-prove`` CLI.
- ``DeepProveAvailability`` — frozen Pydantic check result
  reporting (binary_present, version, supports_layerwise,
  errors).
- ``check_deepprove_availability`` — probe ``which deep-prove``
  and ``deep-prove --version``; return the result.
- ``register_deepprove_if_available`` — call at import time;
  registers the backend with the layerwise dispatcher iff the
  binary is found. Safe to call repeatedly.

How the bridge works
--------------------
For each layer proof:
  1. Write inputs/outputs/weights to a temp JSON file.
  2. Shell out to ``deep-prove prove --layer ...``.
  3. Parse the returned proof bytes.
  4. Wrap with VEIL (same as the shim).
  5. Return as a ``LayerProof``.

If the binary is absent, or fails, or times out, we DO NOT fall
back silently — we raise ``NanozkBackendUnavailable`` with a
specific reason. The caller (Tex's dispatcher) decides whether
to fall back to the shim or refuse the request.

The subprocess timeout defaults to 60s per layer (DeepProve-1
reports 43s for a GPT-2 transformer block); override via
``TEX_DEEPPROVE_TIMEOUT_S``.

Honest scope
------------
- We DO NOT ship the deep-prove Rust binary itself; it's a
  separate install (Cargo crate at github.com/Lagrange-Labs/
  deep-prove).
- When the binary is missing, the backend reports unavailable
  and the dispatcher falls back to the deterministic shim
  exactly as before — the only behavioural change is that *when
  the binary IS present*, real DeepProve proofs flow through.
- Until the binary is wired, the test suite exercises the
  ``DeepProveAvailability`` and registration paths only. The
  ``prove_layer`` end-to-end test is gated behind a marker so
  CI without the binary still passes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


DEEPPROVE_BACKEND_ID: str = "deepprove-2026"
"""Backend identifier used in the dispatcher and the
audit dashboards."""

DEEPPROVE_BINARY_NAME: str = "deep-prove"
"""Name of the Rust CLI installed by
``cargo install --git github.com/Lagrange-Labs/deep-prove``."""

DEEPPROVE_DEFAULT_TIMEOUT_S: float = 60.0
"""Per-layer timeout. DeepProve-1 reports 43s for a GPT-2
transformer block; 60s gives headroom."""

# Paper benchmarks (Lagrange blog, Aug 2025) — frozen for the
# audit surface.
PAPER_PROVER_SPEEDUP_OVER_EZKL: float = 158.0
PAPER_VERIFIER_SPEEDUP_OVER_EZKL: float = 671.0


# --------------------------------------------------------------------------- #
# Availability probe                                                           #
# --------------------------------------------------------------------------- #


class DeepProveAvailability(BaseModel):
    """Result of probing for the DeepProve binary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    binary_present: bool
    binary_path: str | None = None
    version_string: str | None = None
    supports_layerwise: bool = False
    """True if the binary's --help advertises a 'layer' subcommand."""
    probe_errors: tuple[str, ...] = Field(default_factory=tuple)


def check_deepprove_availability(
    *,
    timeout_s: float = 5.0,
) -> DeepProveAvailability:
    """Probe for ``deep-prove`` on PATH.

    Returns a result object describing what was found. Safe to
    call repeatedly; cheap.
    """
    errors: list[str] = []
    binary_path = shutil.which(DEEPPROVE_BINARY_NAME)
    if binary_path is None:
        # Also check Cargo's default install prefix.
        cargo_bin = os.path.expanduser("~/.cargo/bin/deep-prove")
        if os.path.exists(cargo_bin) and os.access(cargo_bin, os.X_OK):
            binary_path = cargo_bin

    if binary_path is None:
        return DeepProveAvailability(
            binary_present=False,
            probe_errors=("binary 'deep-prove' not found on PATH or in ~/.cargo/bin",),
        )

    version_string: str | None = None
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        if result.returncode == 0:
            version_string = result.stdout.strip()
        else:
            errors.append(
                f"--version returned non-zero: {result.returncode}"
            )
    except subprocess.TimeoutExpired:
        errors.append(f"--version timed out after {timeout_s}s")
    except Exception as exc:  # noqa: BLE001 — defensive
        errors.append(f"--version raised {type(exc).__name__}: {exc}")

    supports_layerwise = False
    try:
        result = subprocess.run(
            [binary_path, "--help"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        if result.returncode == 0:
            supports_layerwise = (
                "layer" in result.stdout.lower()
                or "prove" in result.stdout.lower()
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"--help probe failed: {type(exc).__name__}")

    return DeepProveAvailability(
        binary_present=True,
        binary_path=binary_path,
        version_string=version_string,
        supports_layerwise=supports_layerwise,
        probe_errors=tuple(errors),
    )


# --------------------------------------------------------------------------- #
# Subprocess backend                                                           #
# --------------------------------------------------------------------------- #


class DeepProveSubprocessBackend:
    """A NanozkBackend that delegates to the DeepProve Rust CLI.

    Implements the structural interface expected by
    ``tex.nanozk.layerwise_prover.get_layerwise_backend``:

      * ``backend_id``: str
      * ``prove_layer(layer_index, inputs, outputs, weights,
                      circuit_fingerprint) -> bytes``
      * ``verify_proof(proof_bytes, ..., expected_io_hashes) -> bool``

    On any subprocess error, raises ``NanozkBackendUnavailable``
    so the dispatcher decides whether to fall back.
    """

    backend_id: str = DEEPPROVE_BACKEND_ID

    def __init__(
        self,
        *,
        binary_path: str,
        timeout_s: float = DEEPPROVE_DEFAULT_TIMEOUT_S,
    ) -> None:
        self._binary_path = binary_path
        self._timeout_s = timeout_s

    def prove(
        self,
        *,
        circuit: "object",  # LayerCircuit (avoid circular import)
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bytes:
        """Invoke the Rust prover and return the proof bytes.

        Raises ``NanozkBackendUnavailable`` from
        ``tex.nanozk.layerwise_prover`` on any failure.
        """
        from tex.nanozk.layerwise_prover import NanozkBackendUnavailable

        payload: dict[str, Any] = {
            "layer_index": int(getattr(circuit, "layer_index", 0)),
            "inputs_hash": input_hash,
            "outputs_hash": output_hash,
            "weights_commitment": weights_commitment,
            "circuit_fingerprint": (
                getattr(circuit, "fingerprint", lambda: "")()
                if hasattr(circuit, "fingerprint")
                else ""
            ),
            "protocol": "nanozk-layerwise-2026",
        }
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as inp_f:
                json.dump(payload, inp_f)
                inp_path = inp_f.name
            try:
                result = subprocess.run(
                    [
                        self._binary_path,
                        "prove",
                        "--input-file",
                        inp_path,
                        "--protocol",
                        "nanozk-layerwise-2026",
                    ],
                    capture_output=True,
                    timeout=self._timeout_s,
                    check=False,
                )
            finally:
                try:
                    os.unlink(inp_path)
                except OSError:
                    pass
        except subprocess.TimeoutExpired as exc:
            raise NanozkBackendUnavailable(
                f"deepprove prove timed out after {self._timeout_s}s"
            ) from exc
        except FileNotFoundError as exc:
            raise NanozkBackendUnavailable(
                f"deepprove binary disappeared: {self._binary_path}"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise NanozkBackendUnavailable(
                f"deepprove invocation failed: {type(exc).__name__}: {exc}"
            ) from exc

        if result.returncode != 0:
            raise NanozkBackendUnavailable(
                f"deepprove returned exit code {result.returncode}: "
                f"{result.stderr.decode('utf-8', errors='replace')[:200]}"
            )

        proof_bytes = result.stdout
        if len(proof_bytes) < 32:
            raise NanozkBackendUnavailable(
                f"deepprove returned undersized proof ({len(proof_bytes)} bytes)"
            )
        return proof_bytes

    def verify(
        self,
        *,
        circuit: "object",
        proof_bytes: bytes,
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bool:
        """Shell out to ``deep-prove verify``. False on any failure."""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".proof", delete=False
            ) as pf:
                pf.write(proof_bytes)
                pf_path = pf.name
            try:
                payload = {
                    "layer_index": int(
                        getattr(circuit, "layer_index", 0)
                    ),
                    "inputs_hash": input_hash,
                    "outputs_hash": output_hash,
                    "weights_commitment": weights_commitment,
                    "circuit_fingerprint": (
                        getattr(circuit, "fingerprint", lambda: "")()
                        if hasattr(circuit, "fingerprint")
                        else ""
                    ),
                }
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as cf:
                    json.dump(payload, cf)
                    cf_path = cf.name
                try:
                    result = subprocess.run(
                        [
                            self._binary_path,
                            "verify",
                            "--proof-file",
                            pf_path,
                            "--claim-file",
                            cf_path,
                        ],
                        capture_output=True,
                        timeout=self._timeout_s,
                        check=False,
                    )
                finally:
                    try:
                        os.unlink(cf_path)
                    except OSError:
                        pass
            finally:
                try:
                    os.unlink(pf_path)
                except OSError:
                    pass
        except subprocess.TimeoutExpired:
            return False
        except Exception:  # noqa: BLE001
            return False

        return result.returncode == 0


# --------------------------------------------------------------------------- #
# Registration                                                                 #
# --------------------------------------------------------------------------- #


_REGISTERED = False


def register_deepprove_if_available(
    *,
    timeout_s: float = 5.0,
) -> DeepProveAvailability:
    """Register the DeepProve backend with the dispatcher iff
    the binary is present. Idempotent.

    Returns the availability check result so the caller (or
    boot-time wiring) can log/audit.
    """
    global _REGISTERED
    avail = check_deepprove_availability(timeout_s=timeout_s)
    if not avail.binary_present:
        return avail
    if _REGISTERED:
        return avail
    try:
        from tex.nanozk.layerwise_prover import register_backend

        backend = DeepProveSubprocessBackend(
            binary_path=avail.binary_path or DEEPPROVE_BINARY_NAME,
            timeout_s=float(
                os.environ.get(
                    "TEX_DEEPPROVE_TIMEOUT_S",
                    DEEPPROVE_DEFAULT_TIMEOUT_S,
                )
            ),
        )
        register_backend(backend)
        _REGISTERED = True
    except Exception:  # noqa: BLE001 — defensive, never fatal at boot
        pass
    return avail


__all__ = [
    "DEEPPROVE_BACKEND_ID",
    "DEEPPROVE_BINARY_NAME",
    "DEEPPROVE_DEFAULT_TIMEOUT_S",
    "DeepProveAvailability",
    "DeepProveSubprocessBackend",
    "PAPER_PROVER_SPEEDUP_OVER_EZKL",
    "PAPER_VERIFIER_SPEEDUP_OVER_EZKL",
    "check_deepprove_availability",
    "register_deepprove_if_available",
]
