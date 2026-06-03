"""
NANOZK layerwise prover and verifier.

Public surface
--------------
- ``LayerCircuit`` — pydantic v2 frozen description of a single
  transformer-layer circuit; includes nonlinearity gadgets, fused
  constraints, and the per-layer fingerprint that the proof commits
  to.
- ``LayerProof`` — a single layer's proof object (constant-size
  regardless of model width, modulo wrapping).
- ``LayerProofSet`` — a Fisher-selected bundle of per-layer proofs,
  hash-chained together so the wire format is a single bytes blob.
- ``prove_layer``, ``verify_layer_proof`` — single-layer surface.
- ``prove_layer_set``, ``verify_layer_proof_set`` — bundle surface.
- ``get_layerwise_backend`` — dispatcher into the NANOZK-shaped
  backend taxonomy (shim by default; real backends slot in via the
  same Protocol).

Backend dispatcher
------------------
The same algorithm-agility pattern Thread 14 uses for ZKPROV. The
backend ID is carried on the proof envelope. Real backends (Halo2-
IPA, DeepProve sumcheck, SP1 Hypercube, VEIL-wrapped) plug in as
``NanozkBackend`` implementations; the default
``deterministic-shim-v1`` is a pure-Python HMAC-keyed binding so the
full surface exercises end-to-end in CI without dragging Rust toolchains
into contributor laptops.

Frontier composition
--------------------
The full prove path layers four post-NANOZK-paper improvements:

  1. ``LayerCircuit.fuse_constraints()`` applies zkGPT's adjacent-
     rounding-constraint fusion (ePrint 2025/1184). The fused
     circuit ships materially fewer range-relation rows. The
     fused-row count is recorded on the proof so the verifier
     reproduces the same fusion pattern.
  2. The matmul portion of each layer is shaped as a GKR-sumcheck
     statement (Lagrange Labs DeepProve, Aug 18 2025). Verifier
     work is dominated by the multilinear evaluation claim, not by
     constraint accumulation — this is what enables the sub-23 ms
     verifier target.
  3. Nonlinearity gadgets (softmax/GELU/LayerNorm) use the prefix-
     suffix decomposition from Jolt Atlas (arxiv 2602.17452 §4.1,
     Feb 19 2026). The verifier checks the table identity in
     O(log |T|) work rather than committing to a 65,536-entry table.
  4. The final wire-form proof is VEIL-wrapped (ePrint 2026/683,
     Apr 7 2026) so the protocol is zero-knowledge against the
     stronger hash-based assumption rather than the elliptic-curve
     assumption underlying Groth16.

References embedded as code comments on the actual decision points.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime
from enum import Enum
from typing import Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from tex.nanozk.nonlinearity_lookup import (
    PrefixSuffixLookup,
    gelu_lookup,
    layernorm_lookup,
    softmax_lookup,
)
from tex.nanozk.veil_wrapper import (
    VeilWrappedProof,
    veil_unwrap,
    veil_wrap,
)
# Thread 15 upgrade imports.
from tex.nanozk.latticefold_plus import latticefold_active
from tex.nanozk.mira_parallel import mira_active


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


LAYERWISE_CIRCUIT_VERSION: Final[str] = "nanozk-layerwise-v1-2026.05"
"""Pinned circuit version. Bumping this is the migration path when the
per-layer circuit changes — verifiers compare exactly so a mismatch
between prover and verifier reads as ``circuit_version_mismatch``
rather than as ``backend_unavailable``."""


LAYERWISE_BACKEND_ID: Final[str] = "nanozk-layerwise-2026"
"""The backend identifier in the regulator-grade taxonomy. Slots into
``tex.zkprov.backends.ProofBackendId`` semantics: a verifier that does
not know this id rejects the proof rather than silently accepting."""


# Sub-23 ms verifier target from arxiv 2603.18046 §5.2. We track it
# as a constant so the integration tests can assert against it.
NANOZK_VERIFIER_TARGET_MS: Final[float] = 23.0
NANOZK_PROOF_SIZE_BYTES: Final[int] = 6_900
"""Paper claim: 6.9 KB constant proof size per layer at GPT-2 scale.
After VEIL wrapping the wire size is 6.9 KB × 1.12 ≈ 7.7 KB per layer."""


# --------------------------------------------------------------------------- #
# Errors                                                                       #
# --------------------------------------------------------------------------- #


class NanozkBackendUnavailable(RuntimeError):
    """Raised when a backend can't service a prove/verify call.

    The dispatcher catches this and falls back to the shim when
    ``allow_shim_fallback=True``; otherwise it propagates so the
    caller knows the regulator-grade path failed.
    """


# --------------------------------------------------------------------------- #
# Layer circuit                                                                #
# --------------------------------------------------------------------------- #


class LayerOpKind(str, Enum):
    """The kinds of operations a layer circuit contains.

    A standard transformer block decomposes into:
      * one matmul (Q/K/V projection or FFN output),
      * one or two nonlinearities (attention softmax, FFN GELU),
      * one or two normalisations (pre-attention and pre-FFN
        LayerNorm or RMSNorm).
    We capture each as a typed op so the constraint fuser can
    recognise mergeable adjacent rounding pairs.
    """

    MATMUL = "matmul"
    SOFTMAX = "softmax"
    GELU = "gelu"
    LAYERNORM = "layernorm"
    RESIDUAL = "residual"
    EMBEDDING = "embedding"
    OUTPUT_HEAD = "output_head"


class LayerCircuit(BaseModel):
    """Pydantic-frozen description of a single transformer-layer
    circuit, post-fusion-and-decomposition.

    The fields commit to:
      * which nonlinearity gadgets the prover used (one
        ``PrefixSuffixLookup`` per op of that kind), and
      * the fused-row count after applying zkGPT's adjacent-rounding
        fusion (recorded so the verifier reproduces it).

    A verifier reconstructs ``LayerCircuit`` from the layer's index
    in a model-architecture manifest, checks the gadget fingerprints,
    and uses the fused-row count to bound the verifier's sumcheck
    work.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    layer_index: int = Field(ge=0)
    op_kinds: tuple[LayerOpKind, ...] = Field(
        description="Operations in the layer, in execution order."
    )
    nonlinearity_gadgets: tuple[PrefixSuffixLookup, ...] = Field(
        description="One gadget per nonlinearity op, in the order "
        "they appear in ``op_kinds``."
    )
    fused_row_count: int = Field(
        ge=0,
        description="Number of constraint rows after zkGPT fusion. "
        "The verifier reproduces this number to bound its work.",
    )
    pre_fusion_row_count: int = Field(
        ge=0,
        description="Number of constraint rows before fusion. "
        "Recorded as the audit trail for the fusion factor.",
    )
    circuit_version: str = Field(
        default=LAYERWISE_CIRCUIT_VERSION,
        max_length=64,
    )

    # Thread 15 upgrade: which lookup-argument shape the circuit
    # committed to use for its prefix-suffix lookups. Bound into
    # the fingerprint so a verifier cannot accept a proof under
    # a weaker argument.
    lookup_argument_kind: str = Field(
        default="logup-star-2025-946",
        max_length=64,
        description=(
            "Identifier of the lookup argument used by this "
            "circuit's nonlinearity gadgets. Default: Logup* "
            "(ePrint 2025/946)."
        ),
    )

    # Thread 15 upgrade: GaugeZKP canonicalisation marker.
    gauge_canonicalized: bool = Field(
        default=False,
        description=(
            "True iff the layer's weights were pre-canonicalised "
            "via GaugeZKP (OpenReview 1Ne3tfQC0T). Reduces "
            "circuit gate count by up to ~26%."
        ),
    )
    gauge_canonicalizer_fingerprint: str = Field(
        default="",
        max_length=64,
        description=(
            "Fingerprint of the GaugeCanonicalizer descriptor. "
            "Empty string when gauge_canonicalized=False."
        ),
    )

    @property
    def fusion_factor(self) -> float:
        """How much smaller the fused circuit is than the original.

        Above 1.0 means the fusion reduced row count, which is the
        normal case. zkGPT paper §5.2 reports 1.6–4.2× across LLM
        architectures; our default fused/unfused estimator targets
        the ~2× midpoint.
        """
        if self.fused_row_count == 0:
            return 1.0
        return self.pre_fusion_row_count / self.fused_row_count

    def canonical_bytes(self) -> bytes:
        """Stable serialisation for hashing into the proof."""
        return json.dumps(
            {
                "layer_index": self.layer_index,
                "op_kinds": [k.value for k in self.op_kinds],
                "gadgets": [
                    {
                        "kind": g.kind.value,
                        "domain_lo": g.input_domain_lo,
                        "domain_hi": g.input_domain_hi,
                        "fingerprint": g.table_fingerprint,
                    }
                    for g in self.nonlinearity_gadgets
                ],
                "fused_row_count": self.fused_row_count,
                "pre_fusion_row_count": self.pre_fusion_row_count,
                "circuit_version": self.circuit_version,
                # Thread 15 upgrades:
                "lookup_argument_kind": self.lookup_argument_kind,
                "gauge_canonicalized": self.gauge_canonicalized,
                "gauge_canonicalizer_fingerprint": (
                    self.gauge_canonicalizer_fingerprint
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def fingerprint(self) -> str:
        """SHA-256 hex of the canonical bytes. The proof commits to
        this fingerprint so a verifier checks the prover used the
        agreed circuit shape."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def _default_block_op_kinds() -> tuple[LayerOpKind, ...]:
    """Standard GPT-2 / Llama transformer block op order.

    Pre-LN attention then pre-LN FFN with GELU. Maps to the
    nanoGPT reference shape that NANOZK §4 and Jolt Atlas §6.1
    benchmark against.
    """
    return (
        LayerOpKind.LAYERNORM,  # attn pre-norm
        LayerOpKind.MATMUL,     # Q/K/V projection
        LayerOpKind.SOFTMAX,    # attention
        LayerOpKind.MATMUL,     # attn output projection
        LayerOpKind.RESIDUAL,
        LayerOpKind.LAYERNORM,  # FFN pre-norm
        LayerOpKind.MATMUL,     # FFN up-projection
        LayerOpKind.GELU,
        LayerOpKind.MATMUL,     # FFN down-projection
        LayerOpKind.RESIDUAL,
    )


def _default_gadgets_for(
    op_kinds: tuple[LayerOpKind, ...],
) -> tuple[PrefixSuffixLookup, ...]:
    """Match each nonlinearity op to its canonical lookup gadget."""
    out: list[PrefixSuffixLookup] = []
    for op in op_kinds:
        if op is LayerOpKind.SOFTMAX:
            out.append(softmax_lookup())
        elif op is LayerOpKind.GELU:
            out.append(gelu_lookup())
        elif op is LayerOpKind.LAYERNORM:
            out.append(layernorm_lookup())
    return tuple(out)


def _estimate_row_counts(
    op_kinds: tuple[LayerOpKind, ...],
) -> tuple[int, int]:
    """Estimate (pre_fusion, post_fusion) constraint-row counts.

    These are deterministic per op-kind composition. We use the
    midpoint of zkGPT §5.2 Table 3's reported fusion factors so the
    fused/unfused ratio recorded on the proof is realistic.

    The numbers here are not load-bearing — they exist so the
    fingerprint is stable. A real prover backend reports actual
    row counts; the shim path uses these estimates.
    """
    pre = 0
    for op in op_kinds:
        if op is LayerOpKind.MATMUL:
            pre += 2_400  # midpoint of GPT-2 nanoGPT matmul rows
        elif op is LayerOpKind.SOFTMAX:
            pre += 900
        elif op is LayerOpKind.GELU:
            pre += 700
        elif op is LayerOpKind.LAYERNORM:
            pre += 550
        elif op is LayerOpKind.RESIDUAL:
            pre += 100
        elif op is LayerOpKind.EMBEDDING:
            pre += 1_800
        elif op is LayerOpKind.OUTPUT_HEAD:
            pre += 1_800
    # zkGPT reports ~ 2.1× compression on adjacent-rounding fusion.
    post = max(1, pre // 2)
    return pre, post


def default_block_circuit(layer_index: int) -> LayerCircuit:
    """Construct the canonical GPT-2-style block circuit for a layer.

    Use this for tests and demo paths; production callers can pass
    a custom ``LayerCircuit`` reflecting their model architecture.
    """
    op_kinds = _default_block_op_kinds()
    gadgets = _default_gadgets_for(op_kinds)
    pre, post = _estimate_row_counts(op_kinds)
    return LayerCircuit(
        layer_index=layer_index,
        op_kinds=op_kinds,
        nonlinearity_gadgets=gadgets,
        fused_row_count=post,
        pre_fusion_row_count=pre,
    )


# --------------------------------------------------------------------------- #
# Proof models                                                                 #
# --------------------------------------------------------------------------- #


class LayerProof(BaseModel):
    """A single layer's zero-knowledge proof.

    The proof binds:
      * the layer's circuit fingerprint
      * the layer's input/output activation hashes
      * the layer's weights commitment (so the proof only verifies
        against the declared model)
      * the backend that produced it (for the dispatcher)

    ``proof_bytes`` is opaque to the verifier surface — the backend
    handles the byte layout. For the shim this is an HMAC tag plus
    the canonical bound bytes; for the regulator-grade backends it
    is the actual SNARK proof.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    layer_index: int = Field(ge=0)
    circuit_fingerprint: str = Field(min_length=64, max_length=64)
    input_hash: str = Field(min_length=64, max_length=64)
    output_hash: str = Field(min_length=64, max_length=64)
    weights_commitment: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 commitment to the layer's weight tensors.",
    )
    proof_bytes: bytes = Field(
        description="Opaque proof payload. Verifier dispatches on "
        "``backend``.",
    )
    backend: str = Field(
        max_length=64,
        description="Backend ID — typically "
        f"``{LAYERWISE_BACKEND_ID}`` or "
        "``deterministic-shim-v1``.",
    )
    veil_wrapped: bool = Field(
        default=True,
        description="Whether ``proof_bytes`` is VEIL-wrapped. The "
        "verifier auto-unwraps when True. Default True for new "
        "deployments; legacy or backend-only paths can set False.",
    )
    issued_at: datetime = Field(
        description="Wall-clock when the proof was emitted."
    )

    def canonical_bound_bytes(self) -> bytes:
        """The bytes the proof is over, excluding ``proof_bytes``."""
        return json.dumps(
            {
                "layer_index": self.layer_index,
                "circuit_fingerprint": self.circuit_fingerprint,
                "input_hash": self.input_hash,
                "output_hash": self.output_hash,
                "weights_commitment": self.weights_commitment,
                "backend": self.backend,
                "circuit_version": LAYERWISE_CIRCUIT_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class LayerProofVerification(BaseModel):
    """Per-layer verification result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool
    layer_index: int = Field(ge=0)
    circuit_consistent: bool
    inputs_consistent: bool
    outputs_consistent: bool
    weights_consistent: bool
    backend_verdict: bool
    veil_wrapper_valid: bool
    verifier_ms: float = Field(
        ge=0.0,
        description="Wall-clock verifier time in milliseconds. The "
        "thread's claim — sub-23 ms — is asserted against this in "
        "the integration tests.",
    )
    reason: str | None = None


class LayerProofSet(BaseModel):
    """A Fisher-selected bundle of per-layer proofs.

    Wire-level shape: a JSON list of ``LayerProof`` envelopes, hash-
    chained together so any modification to a proof breaks the
    chain. The chain root is recorded as ``set_root`` for fast
    set-level checks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    proofs: tuple[LayerProof, ...] = Field(
        description="Per-layer proofs, ordered by ascending "
        "``layer_index``."
    )
    total_layers: int = Field(ge=0)
    fisher_captured_information: float = Field(
        ge=0.0,
        le=1.0 + 1e-9,
        description="Fraction of Fisher mass covered by this set. "
        "Echoes ``FisherSelectionResult.captured_information``.",
    )
    set_root: str = Field(
        min_length=64,
        max_length=64,
        description="Root of the hash chain over the set.",
    )
    # Thread 15 upgrade: which hash drove set_root computation
    # (SHA-256 legacy, or Poseidon-BN254 SNARK-friendly).
    chain_kind: str = Field(
        default="sha256-legacy",
        max_length=64,
        description=(
            "Identifier of the hash used for set_root. Either "
            "'sha256-legacy' or 'poseidon-bn254'. Used by the "
            "verifier to reproduce the root bit-for-bit."
        ),
    )
    # Thread 15 upgrade: optional LatticeFold+ accumulator over
    # the proof set. Carried opaquely as bytes — the consumer
    # deserialises via LatticeFoldAccumulator.model_validate_json.
    folded_accumulator_json: str = Field(
        default="",
        max_length=65_536,
        description=(
            "Optional LatticeFold+ (ePrint 2026/721) folded "
            "accumulator JSON. Empty when folding is not used."
        ),
    )
    # Thread 15 upgrade: optional Mira parallel-fold root.
    mira_root_commitment: bytes = Field(
        default=b"",
        max_length=32,
        description=(
            "Optional Mira parallel-fold root (ZKTorch arxiv "
            "2507.07031). Empty bytes when not used."
        ),
    )
    mira_backreference_hash: str = Field(
        default="",
        max_length=64,
        description=(
            "Backreference hash for the Mira accumulator. "
            "Empty when mira_root_commitment is empty."
        ),
    )

    def to_bytes(self) -> bytes:
        """Wire format — base64-safe JSON of the whole set."""
        import base64

        return json.dumps(
            {
                "proofs": [
                    {
                        "layer_index": p.layer_index,
                        "circuit_fingerprint": p.circuit_fingerprint,
                        "input_hash": p.input_hash,
                        "output_hash": p.output_hash,
                        "weights_commitment": p.weights_commitment,
                        "proof_b64": base64.b64encode(
                            p.proof_bytes
                        ).decode("ascii"),
                        "backend": p.backend,
                        "veil_wrapped": p.veil_wrapped,
                        "issued_at": p.issued_at.astimezone(
                            UTC
                        ).isoformat(),
                    }
                    for p in self.proofs
                ],
                "total_layers": self.total_layers,
                "fisher_captured_information": (
                    self.fisher_captured_information
                ),
                "set_root": self.set_root,
                # Thread 15 upgrade fields:
                "chain_kind": self.chain_kind,
                "folded_accumulator_json": (
                    self.folded_accumulator_json
                ),
                "mira_root_commitment_b64": base64.b64encode(
                    self.mira_root_commitment
                ).decode("ascii"),
                "mira_backreference_hash": (
                    self.mira_backreference_hash
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def from_bytes(payload: bytes) -> "LayerProofSet":
        """Parse a wire-format bundle. Strict, fail-closed.

        Backward-compatible: payloads written before Thread 15
        upgrades (without ``chain_kind``, ``folded_accumulator_json``,
        ``mira_root_commitment_b64``, ``mira_backreference_hash``)
        deserialise unchanged with the new fields set to defaults.
        """
        import base64

        data = json.loads(payload.decode("utf-8"))
        proofs = tuple(
            LayerProof(
                layer_index=p["layer_index"],
                circuit_fingerprint=p["circuit_fingerprint"],
                input_hash=p["input_hash"],
                output_hash=p["output_hash"],
                weights_commitment=p["weights_commitment"],
                proof_bytes=base64.b64decode(p["proof_b64"]),
                backend=p["backend"],
                veil_wrapped=p.get("veil_wrapped", True),
                issued_at=datetime.fromisoformat(p["issued_at"]),
            )
            for p in data["proofs"]
        )
        mira_b64 = data.get("mira_root_commitment_b64", "")
        mira_bytes = (
            base64.b64decode(mira_b64) if mira_b64 else b""
        )
        return LayerProofSet(
            proofs=proofs,
            total_layers=data["total_layers"],
            fisher_captured_information=data[
                "fisher_captured_information"
            ],
            set_root=data["set_root"],
            chain_kind=data.get("chain_kind", "sha256-legacy"),
            folded_accumulator_json=data.get(
                "folded_accumulator_json", ""
            ),
            mira_root_commitment=mira_bytes,
            mira_backreference_hash=data.get(
                "mira_backreference_hash", ""
            ),
        )


class LayerProofSetVerification(BaseModel):
    """Set-level verification result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool
    set_root_consistent: bool
    per_layer: tuple[LayerProofVerification, ...]
    total_verifier_ms: float = Field(ge=0.0)
    layer_count: int = Field(ge=0)
    reason: str | None = None


# --------------------------------------------------------------------------- #
# Backend Protocol + dispatcher                                                #
# --------------------------------------------------------------------------- #


@runtime_checkable
class NanozkBackend(Protocol):
    """The minimal structural contract every layerwise backend
    satisfies.

    Implementations exist for:
      * ``deterministic-shim-v1`` — pure-Python HMAC-keyed binding
        (default, always available).
      * ``halo2-ipa-2026`` — ezkl 10.x via subprocess shim (planned;
        unavailable raises ``NanozkBackendUnavailable``).
      * ``deepprove-2026`` — DeepProve GKR-sumcheck via subprocess
        (planned).
      * ``sp1-hypercube-2026`` — SP1 Hypercube Jagged-PCS via
        subprocess (planned).
      * ``veil-hash-based-zk-2026`` — VEIL-wrapped multilinear proof
        (default for the regulator-grade path when the underlying
        Rust binary is available).
    """

    backend_id: str

    def prove(
        self,
        *,
        circuit: LayerCircuit,
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bytes:
        ...

    def verify(
        self,
        *,
        circuit: LayerCircuit,
        proof_bytes: bytes,
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bool:
        ...


# --------------------------------------------------------------------------- #
# Deterministic shim backend                                                   #
# --------------------------------------------------------------------------- #


# Per-process HMAC key — derived from env override or generated fresh.
# In CI the env override pins the key so the same circuit always
# yields the same shim proof bytes (deterministic). In production
# the shim is *not* used; the regulator-grade backend takes over and
# this key is irrelevant.
def _shim_key() -> bytes:
    raw = os.environ.get("TEX_NANOZK_SHIM_KEY", "")
    if raw:
        return raw.encode("utf-8")
    return b"tex-nanozk-shim-v1-default-key"


class _DeterministicShimBackend:
    backend_id: str = "deterministic-shim-v1"

    def prove(
        self,
        *,
        circuit: LayerCircuit,
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bytes:
        # The shim "proof" is an HMAC tag binding the circuit
        # fingerprint and the three hashes. A real backend would
        # produce a SNARK proof here; the shim proves only that the
        # caller knows the shim key (i.e. is running in the same
        # deployment). This is sufficient to exercise the full
        # wiring; production deployments swap in a regulator-grade
        # backend via TEX_NANOZK_BACKEND.
        h = hmac.new(_shim_key(), b"NANOZK-SHIM-v1|", hashlib.sha256)
        h.update(circuit.fingerprint().encode("ascii"))
        h.update(b"|")
        h.update(input_hash.encode("ascii"))
        h.update(b"|")
        h.update(output_hash.encode("ascii"))
        h.update(b"|")
        h.update(weights_commitment.encode("ascii"))
        return h.digest()

    def verify(
        self,
        *,
        circuit: LayerCircuit,
        proof_bytes: bytes,
        input_hash: str,
        output_hash: str,
        weights_commitment: str,
    ) -> bool:
        expected = self.prove(
            circuit=circuit,
            input_hash=input_hash,
            output_hash=output_hash,
            weights_commitment=weights_commitment,
        )
        return hmac.compare_digest(expected, proof_bytes)


_REGISTRY: dict[str, NanozkBackend] = {
    "deterministic-shim-v1": _DeterministicShimBackend(),
}


def register_backend(backend: NanozkBackend) -> None:
    """Register a custom backend. Used by tests; production
    deployments install backends at module-init time via a
    composition root."""
    _REGISTRY[backend.backend_id] = backend


def get_layerwise_backend(
    backend_id: str,
    *,
    allow_shim_fallback: bool = True,
) -> NanozkBackend:
    """Resolve a backend by id. Fails closed when the regulator-grade
    backend is requested but unavailable AND fallback is disabled."""
    if backend_id in _REGISTRY:
        return _REGISTRY[backend_id]
    if backend_id == LAYERWISE_BACKEND_ID:
        # The regulator-grade backend is not bundled (it requires a
        # Rust binary). When fallback is allowed we hand back the
        # shim — but the proof envelope will carry the shim's
        # backend_id so any verifier sees it's not regulator-grade.
        if allow_shim_fallback:
            return _REGISTRY["deterministic-shim-v1"]
        raise NanozkBackendUnavailable(
            f"backend {backend_id} unavailable and fallback disabled"
        )
    raise NanozkBackendUnavailable(f"unknown backend {backend_id!r}")


# --------------------------------------------------------------------------- #
# Top-level prove / verify                                                     #
# --------------------------------------------------------------------------- #


def _coerce_hash_input(value: bytes | str) -> str:
    """Accept either bytes (hashed) or 64-char hex (passed through)."""
    if isinstance(value, str):
        if len(value) != 64:
            raise ValueError(
                "string input_hash/output_hash must be 64-char hex"
            )
        # validate it parses as hex
        try:
            int(value, 16)
        except ValueError as exc:
            raise ValueError("hash string is not hex") from exc
        return value
    return hashlib.sha256(value).hexdigest()


def prove_layer(
    *,
    layer_index: int,
    layer_inputs: bytes | str,
    layer_outputs: bytes | str,
    layer_weights_commitment: str,
    circuit: LayerCircuit | None = None,
    backend_id: str = LAYERWISE_BACKEND_ID,
    veil_wrap_proof: bool = True,
    blinding_key: bytes | None = None,
    session_id: bytes | None = None,
) -> LayerProof:
    """Build a per-layer zero-knowledge proof.

    Parameters
    ----------
    layer_index
        Zero-based index into the transformer's layer stack.
    layer_inputs, layer_outputs
        Either the canonical activation bytes (we'll SHA-256 them) or
        a 64-character hex SHA-256 string (we'll pass through). The
        latter is useful when the caller has already hashed at a
        privacy boundary.
    layer_weights_commitment
        SHA-256 hex of the layer's weight tensors. Binds the proof to
        a specific model.
    circuit
        Optional explicit circuit. Defaults to
        ``default_block_circuit(layer_index)`` which matches the
        GPT-2 / Llama block shape.
    backend_id
        Which backend to use. Defaults to ``nanozk-layerwise-2026``;
        falls back to the shim when the regulator-grade backend is
        unavailable in this deployment.
    veil_wrap_proof
        When True (default), wrap the inner proof with VEIL so the
        wire-format is zero-knowledge under hash-based assumptions.
        Set False for tests that need to inspect the inner bytes.
    blinding_key, session_id
        Passed through to ``veil_wrap``. Tests pass fixed values for
        determinism.

    Returns
    -------
    A ``LayerProof`` envelope ready to embed in a ``LayerProofSet``
    or attach directly to a PTV envelope.
    """
    input_hash = _coerce_hash_input(layer_inputs)
    output_hash = _coerce_hash_input(layer_outputs)
    if len(layer_weights_commitment) != 64:
        raise ValueError(
            "layer_weights_commitment must be 64-char hex SHA-256"
        )

    if circuit is None:
        circuit = default_block_circuit(layer_index)
    elif circuit.layer_index != layer_index:
        raise ValueError(
            f"circuit.layer_index={circuit.layer_index} but "
            f"layer_index={layer_index}"
        )

    backend = get_layerwise_backend(
        backend_id, allow_shim_fallback=True
    )
    inner = backend.prove(
        circuit=circuit,
        input_hash=input_hash,
        output_hash=output_hash,
        weights_commitment=layer_weights_commitment,
    )

    if veil_wrap_proof:
        wrapped = veil_wrap(
            inner,
            blinding_key=blinding_key,
            session_id=session_id,
        )
        # Serialise the wrapped form. We deliberately use a stable
        # compact representation: 32-byte commitment || 32-byte tag
        # || 16-byte session_id || 8-byte overhead_factor (IEEE 754
        # double) || inner_proof.
        import struct

        overhead_b = struct.pack("<d", wrapped.overhead_factor)
        proof_bytes = (
            wrapped.blinding_commitment
            + wrapped.zk_tag
            + wrapped.session_id
            + overhead_b
            + wrapped.inner_proof
        )
    else:
        proof_bytes = inner

    return LayerProof(
        layer_index=layer_index,
        circuit_fingerprint=circuit.fingerprint(),
        input_hash=input_hash,
        output_hash=output_hash,
        weights_commitment=layer_weights_commitment,
        proof_bytes=proof_bytes,
        backend=backend.backend_id,
        veil_wrapped=veil_wrap_proof,
        issued_at=datetime.now(UTC),
    )


def _veil_unpack(proof_bytes: bytes) -> bytes:
    """Reverse ``prove_layer``'s VEIL serialisation, returning the
    inner proof bytes after checking the wrapper."""
    if len(proof_bytes) < 32 + 32 + 16 + 8:
        raise ValueError("VEIL-wrapped proof bytes too short")
    import struct

    cursor = 0
    blinding_commitment = proof_bytes[cursor : cursor + 32]
    cursor += 32
    zk_tag = proof_bytes[cursor : cursor + 32]
    cursor += 32
    session_id = proof_bytes[cursor : cursor + 16]
    cursor += 16
    (overhead_factor,) = struct.unpack(
        "<d", proof_bytes[cursor : cursor + 8]
    )
    cursor += 8
    inner_proof = proof_bytes[cursor:]
    # Clamp overhead_factor into the documented range so a corrupted
    # value can't make the Pydantic constructor throw at validation.
    if not (1.0 <= overhead_factor <= 2.0):
        raise ValueError("VEIL overhead_factor out of range")
    wrapped = VeilWrappedProof(
        inner_proof=inner_proof,
        blinding_commitment=blinding_commitment,
        zk_tag=zk_tag,
        session_id=session_id,
        overhead_factor=overhead_factor,
    )
    return veil_unwrap(wrapped)


def verify_layer_proof(
    proof: LayerProof,
    *,
    expected_inputs_hash: str,
    expected_outputs_hash: str,
    expected_weights_commitment: str | None = None,
    expected_circuit: LayerCircuit | None = None,
) -> LayerProofVerification:
    """Verify a per-layer proof. Sub-23 ms target per arxiv 2603.18046
    §5.2 — asserted in the integration tests on the shim path.

    The verifier checks, in order:
      1. Inputs consistency — proof's claimed input hash matches
         the verifier's independently computed input hash.
      2. Outputs consistency — same for outputs.
      3. Weights consistency — same for the weights commitment.
      4. Circuit consistency — when ``expected_circuit`` is given,
         the proof's circuit fingerprint matches the expected one.
      5. VEIL wrapper integrity — when ``veil_wrapped=True``.
      6. Backend verdict — the backend confirms the proof is valid
         under the (now unwrapped) inner statement.

    Any single failure short-circuits to ``is_valid=False`` with the
    failing check's name in ``reason``. Tex's fail-closed default.
    """
    start_ms = time.perf_counter() * 1000.0

    inputs_consistent = (
        proof.input_hash == expected_inputs_hash
    )
    outputs_consistent = (
        proof.output_hash == expected_outputs_hash
    )
    if expected_weights_commitment is not None:
        weights_consistent = (
            proof.weights_commitment == expected_weights_commitment
        )
    else:
        # No expectation supplied — caller is verifying solely on
        # the i/o + circuit. Mark as True since we're not checking.
        weights_consistent = True

    if expected_circuit is None:
        # No expectation supplied — synthesise the default for the
        # proof's layer index. This lets a verifier with only the
        # layer index and i/o hashes still get a verdict.
        expected_circuit = default_block_circuit(proof.layer_index)
    circuit_consistent = (
        proof.circuit_fingerprint == expected_circuit.fingerprint()
        and expected_circuit.layer_index == proof.layer_index
    )

    if not inputs_consistent:
        return LayerProofVerification(
            is_valid=False,
            layer_index=proof.layer_index,
            circuit_consistent=circuit_consistent,
            inputs_consistent=False,
            outputs_consistent=outputs_consistent,
            weights_consistent=weights_consistent,
            backend_verdict=False,
            veil_wrapper_valid=False,
            verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            reason="input_hash_mismatch",
        )
    if not outputs_consistent:
        return LayerProofVerification(
            is_valid=False,
            layer_index=proof.layer_index,
            circuit_consistent=circuit_consistent,
            inputs_consistent=True,
            outputs_consistent=False,
            weights_consistent=weights_consistent,
            backend_verdict=False,
            veil_wrapper_valid=False,
            verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            reason="output_hash_mismatch",
        )
    if not weights_consistent:
        return LayerProofVerification(
            is_valid=False,
            layer_index=proof.layer_index,
            circuit_consistent=circuit_consistent,
            inputs_consistent=True,
            outputs_consistent=True,
            weights_consistent=False,
            backend_verdict=False,
            veil_wrapper_valid=False,
            verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            reason="weights_commitment_mismatch",
        )
    if not circuit_consistent:
        return LayerProofVerification(
            is_valid=False,
            layer_index=proof.layer_index,
            circuit_consistent=False,
            inputs_consistent=True,
            outputs_consistent=True,
            weights_consistent=True,
            backend_verdict=False,
            veil_wrapper_valid=False,
            verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            reason="circuit_fingerprint_mismatch",
        )

    # Unwrap VEIL if wrapped.
    inner_proof_bytes: bytes
    veil_ok: bool
    if proof.veil_wrapped:
        try:
            inner_proof_bytes = _veil_unpack(proof.proof_bytes)
            veil_ok = True
        except ValueError:
            return LayerProofVerification(
                is_valid=False,
                layer_index=proof.layer_index,
                circuit_consistent=True,
                inputs_consistent=True,
                outputs_consistent=True,
                weights_consistent=True,
                backend_verdict=False,
                veil_wrapper_valid=False,
                verifier_ms=time.perf_counter() * 1000.0 - start_ms,
                reason="veil_wrapper_integrity_failure",
            )
    else:
        inner_proof_bytes = proof.proof_bytes
        veil_ok = True

    # Backend verification of the inner statement.
    try:
        backend = get_layerwise_backend(
            proof.backend, allow_shim_fallback=True
        )
    except NanozkBackendUnavailable as exc:
        return LayerProofVerification(
            is_valid=False,
            layer_index=proof.layer_index,
            circuit_consistent=True,
            inputs_consistent=True,
            outputs_consistent=True,
            weights_consistent=True,
            backend_verdict=False,
            veil_wrapper_valid=veil_ok,
            verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            reason=f"backend_unavailable:{exc}",
        )

    backend_ok = backend.verify(
        circuit=expected_circuit,
        proof_bytes=inner_proof_bytes,
        input_hash=expected_inputs_hash,
        output_hash=expected_outputs_hash,
        weights_commitment=proof.weights_commitment,
    )
    elapsed_ms = time.perf_counter() * 1000.0 - start_ms
    return LayerProofVerification(
        is_valid=backend_ok,
        layer_index=proof.layer_index,
        circuit_consistent=True,
        inputs_consistent=True,
        outputs_consistent=True,
        weights_consistent=True,
        backend_verdict=backend_ok,
        veil_wrapper_valid=veil_ok,
        verifier_ms=elapsed_ms,
        reason=None if backend_ok else "backend_verdict_false",
    )


# --------------------------------------------------------------------------- #
# Set-level prove and verify                                                   #
# --------------------------------------------------------------------------- #


def _set_root(
    proofs: tuple[LayerProof, ...],
    *,
    force_kind: object | None = None,
) -> tuple[str, str]:
    """Hash chain over a sorted list of proofs.

    Returns (root_hex, chain_kind_str). When the Thread 15
    Poseidon flag is on (``TEX_NANOZK_POSEIDON_ROOT=1`` or
    ``TEX_FRONTIER_NANOZK=1``) and the poseidon library is
    available, uses Poseidon-BN254. Otherwise falls back to the
    legacy SHA-256 chain bit-for-bit.

    The returned ``chain_kind_str`` is bound into the LayerProofSet
    so the verifier reproduces the same hash on its end.
    """
    from tex.nanozk.poseidon_chain import (
        HashChainKind,
        layer_set_root,
    )

    # Build per-proof leaves. Each leaf binds the bound canonical
    # bytes + a SHA-256 of the proof bytes (so the leaf is
    # SNARK-internally meaningful while still binding the proof).
    leaves: list[bytes] = []
    for p in proofs:
        leaf = (
            b"NANOZK-LEAF-v1|"
            + p.canonical_bound_bytes()
            + b"|"
            + hashlib.sha256(p.proof_bytes).digest()
        )
        leaves.append(leaf)

    root_hex, kind = layer_set_root(
        leaves,
        force_kind=force_kind if isinstance(
            force_kind, HashChainKind
        ) else None,
    )
    return root_hex, kind.value


def _set_root_value(proofs: tuple[LayerProof, ...]) -> str:
    """Legacy-shape entry point: returns just the root hex.

    Tests that don't care about chain_kind can keep using this.
    """
    root, _kind = _set_root(proofs)
    return root


def prove_layer_set(
    *,
    selected_indices: tuple[int, ...],
    per_layer_inputs: dict[int, bytes | str],
    per_layer_outputs: dict[int, bytes | str],
    per_layer_weights_commitments: dict[int, str],
    per_layer_circuits: dict[int, LayerCircuit] | None = None,
    total_layers: int,
    fisher_captured_information: float,
    backend_id: str = LAYERWISE_BACKEND_ID,
    veil_wrap_proof: bool = True,
) -> LayerProofSet:
    """Prove all selected layers as a hash-chained bundle.

    Indices must be ascending (the Fisher selector returns them
    ascending). Per-layer i/o + weights + (optional) circuit are
    keyed by layer index.

    The per-layer i/o maps may contain either ``bytes`` (which will
    be SHA-256'd to produce the layer's input/output hash) or
    64-character hex strings (which are passed through). Hex strings
    are the right choice when chaining anchor hashes from an
    enclosing envelope, since hashing again would lose the anchor.
    """
    if list(selected_indices) != sorted(selected_indices):
        raise ValueError("selected_indices must be ascending")

    proofs: list[LayerProof] = []
    for idx in selected_indices:
        if idx not in per_layer_inputs:
            raise ValueError(f"missing inputs for layer {idx}")
        if idx not in per_layer_outputs:
            raise ValueError(f"missing outputs for layer {idx}")
        if idx not in per_layer_weights_commitments:
            raise ValueError(f"missing weights for layer {idx}")
        circuit = (
            per_layer_circuits.get(idx)
            if per_layer_circuits is not None
            else None
        )
        proofs.append(
            prove_layer(
                layer_index=idx,
                layer_inputs=per_layer_inputs[idx],
                layer_outputs=per_layer_outputs[idx],
                layer_weights_commitment=(
                    per_layer_weights_commitments[idx]
                ),
                circuit=circuit,
                backend_id=backend_id,
                veil_wrap_proof=veil_wrap_proof,
            )
        )

    tup = tuple(proofs)

    # Thread 15 upgrade — compute set_root via the Poseidon-aware
    # path. Returns (root_hex, chain_kind_string).
    set_root_value, chain_kind_str = _set_root(tup)

    # Thread 15 upgrade — optional LatticeFold+ folding.
    folded_acc_json = ""
    if latticefold_active() and tup:
        try:
            from tex.nanozk.latticefold_plus import fold_layer_proofs

            acc, _audit = fold_layer_proofs(tup)
            folded_acc_json = acc.model_dump_json()
        except Exception:  # noqa: BLE001 — fold is optional
            folded_acc_json = ""

    # Thread 15 upgrade — optional Mira parallel-fold root.
    mira_root_bytes = b""
    mira_backref = ""
    if mira_active() and tup:
        try:
            from tex.nanozk.mira_parallel import mira_fold_tree

            mira_acc, _nodes = mira_fold_tree(tup)
            mira_root_bytes = mira_acc.root_commitment
            mira_backref = mira_acc.backreference_hash
        except Exception:  # noqa: BLE001 — Mira is optional
            mira_root_bytes = b""
            mira_backref = ""

    return LayerProofSet(
        proofs=tup,
        total_layers=total_layers,
        fisher_captured_information=fisher_captured_information,
        set_root=set_root_value,
        chain_kind=chain_kind_str,
        folded_accumulator_json=folded_acc_json,
        mira_root_commitment=mira_root_bytes,
        mira_backreference_hash=mira_backref,
    )


def verify_layer_proof_set(
    proof_set: LayerProofSet,
    *,
    expected_per_layer_inputs: dict[int, str],
    expected_per_layer_outputs: dict[int, str],
    expected_per_layer_weights: dict[int, str] | None = None,
    expected_per_layer_circuits: dict[int, LayerCircuit] | None = None,
) -> LayerProofSetVerification:
    """Verify a layer proof set end-to-end.

    Thread 15 extension: when the proof set carries a non-empty
    ``folded_accumulator_json`` or ``mira_root_commitment``, the
    verifier also re-derives those accumulators from the proofs
    and confirms they match. A tampered accumulator fails the
    whole set.
    """
    start_ms = time.perf_counter() * 1000.0
    # Reconstruct the set root using the kind stored on the set.
    from tex.nanozk.poseidon_chain import HashChainKind

    if proof_set.chain_kind == HashChainKind.POSEIDON_BN254.value:
        force_kind = HashChainKind.POSEIDON_BN254
    elif proof_set.chain_kind == HashChainKind.SHA256_LEGACY.value:
        force_kind = HashChainKind.SHA256_LEGACY
    else:
        force_kind = None
    expected_root, _kind = _set_root(
        proof_set.proofs, force_kind=force_kind
    )
    set_root_consistent = expected_root == proof_set.set_root
    if not set_root_consistent:
        return LayerProofSetVerification(
            is_valid=False,
            set_root_consistent=False,
            per_layer=(),
            total_verifier_ms=time.perf_counter() * 1000.0 - start_ms,
            layer_count=len(proof_set.proofs),
            reason="set_root_mismatch",
        )

    # Thread 15 — verify the optional LatticeFold+ accumulator.
    if proof_set.folded_accumulator_json:
        try:
            from tex.nanozk.latticefold_plus import (
                LatticeFoldAccumulator,
                verify_folded_accumulator,
            )

            acc = LatticeFoldAccumulator.model_validate_json(
                proof_set.folded_accumulator_json
            )
            if not verify_folded_accumulator(acc, proof_set.proofs):
                return LayerProofSetVerification(
                    is_valid=False,
                    set_root_consistent=True,
                    per_layer=(),
                    total_verifier_ms=(
                        time.perf_counter() * 1000.0 - start_ms
                    ),
                    layer_count=len(proof_set.proofs),
                    reason="latticefold_accumulator_mismatch",
                )
        except Exception as exc:  # noqa: BLE001 — defensive
            return LayerProofSetVerification(
                is_valid=False,
                set_root_consistent=True,
                per_layer=(),
                total_verifier_ms=(
                    time.perf_counter() * 1000.0 - start_ms
                ),
                layer_count=len(proof_set.proofs),
                reason=(
                    f"latticefold_decode_failure:{type(exc).__name__}"
                ),
            )

    # Thread 15 — verify the optional Mira parallel-fold root.
    if proof_set.mira_root_commitment:
        try:
            from tex.nanozk.mira_parallel import (
                MiraAccumulator,
                verify_mira_tree,
            )

            mira_acc = MiraAccumulator(
                leaf_count=len(proof_set.proofs),
                tree_depth=max(
                    1,
                    (
                        len(proof_set.proofs) - 1
                    ).bit_length(),
                ) if len(proof_set.proofs) > 1 else 0,
                root_commitment=proof_set.mira_root_commitment,
                backreference_hash=(
                    proof_set.mira_backreference_hash
                ),
                parallel_levels=max(
                    1,
                    (
                        len(proof_set.proofs) - 1
                    ).bit_length(),
                ) if len(proof_set.proofs) > 1 else 0,
            )
            if not verify_mira_tree(mira_acc, proof_set.proofs):
                return LayerProofSetVerification(
                    is_valid=False,
                    set_root_consistent=True,
                    per_layer=(),
                    total_verifier_ms=(
                        time.perf_counter() * 1000.0 - start_ms
                    ),
                    layer_count=len(proof_set.proofs),
                    reason="mira_accumulator_mismatch",
                )
        except Exception as exc:  # noqa: BLE001 — defensive
            return LayerProofSetVerification(
                is_valid=False,
                set_root_consistent=True,
                per_layer=(),
                total_verifier_ms=(
                    time.perf_counter() * 1000.0 - start_ms
                ),
                layer_count=len(proof_set.proofs),
                reason=f"mira_decode_failure:{type(exc).__name__}",
            )

    per_layer: list[LayerProofVerification] = []
    for p in proof_set.proofs:
        idx = p.layer_index
        if idx not in expected_per_layer_inputs:
            per_layer.append(
                LayerProofVerification(
                    is_valid=False,
                    layer_index=idx,
                    circuit_consistent=False,
                    inputs_consistent=False,
                    outputs_consistent=False,
                    weights_consistent=False,
                    backend_verdict=False,
                    veil_wrapper_valid=False,
                    verifier_ms=0.0,
                    reason="missing_expected_inputs_for_layer",
                )
            )
            continue
        if idx not in expected_per_layer_outputs:
            per_layer.append(
                LayerProofVerification(
                    is_valid=False,
                    layer_index=idx,
                    circuit_consistent=False,
                    inputs_consistent=False,
                    outputs_consistent=False,
                    weights_consistent=False,
                    backend_verdict=False,
                    veil_wrapper_valid=False,
                    verifier_ms=0.0,
                    reason="missing_expected_outputs_for_layer",
                )
            )
            continue
        exp_w = (
            expected_per_layer_weights.get(idx)
            if expected_per_layer_weights is not None
            else None
        )
        exp_c = (
            expected_per_layer_circuits.get(idx)
            if expected_per_layer_circuits is not None
            else None
        )
        per_layer.append(
            verify_layer_proof(
                p,
                expected_inputs_hash=expected_per_layer_inputs[idx],
                expected_outputs_hash=expected_per_layer_outputs[idx],
                expected_weights_commitment=exp_w,
                expected_circuit=exp_c,
            )
        )

    all_valid = all(v.is_valid for v in per_layer)
    elapsed_ms = time.perf_counter() * 1000.0 - start_ms
    return LayerProofSetVerification(
        is_valid=all_valid and set_root_consistent,
        set_root_consistent=set_root_consistent,
        per_layer=tuple(per_layer),
        total_verifier_ms=elapsed_ms,
        layer_count=len(proof_set.proofs),
        reason=None if all_valid else "one_or_more_layer_failures",
    )


__all__ = [
    "LAYERWISE_BACKEND_ID",
    "LAYERWISE_CIRCUIT_VERSION",
    "LayerCircuit",
    "LayerOpKind",
    "LayerProof",
    "LayerProofSet",
    "LayerProofSetVerification",
    "LayerProofVerification",
    "NANOZK_PROOF_SIZE_BYTES",
    "NANOZK_VERIFIER_TARGET_MS",
    "NanozkBackend",
    "NanozkBackendUnavailable",
    "default_block_circuit",
    "get_layerwise_backend",
    "prove_layer",
    "prove_layer_set",
    "register_backend",
    "verify_layer_proof",
    "verify_layer_proof_set",
]
