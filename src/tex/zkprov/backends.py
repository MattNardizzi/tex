"""
Pluggable ZK-proof backend dispatcher for ZKPROV.

This is the ZK-side analogue of ``tex.pqcrypto.algorithm_agility``.
A ``ProvenanceProof`` carries a ``backend`` tag and an opaque
``proof_bytes`` payload; the actual circuit instantiation lives
behind the ``ProofBackend`` Protocol below.

Why a dispatcher
----------------
The May-2026 ZKML landscape is moving fast. Each backend below has
a documented role and a known-good upstream:

- ``halo2-ipa-2026``   — ezkl on PyPI (v23.0.5, released 2026-02-20),
  Halo2 Plonkish arithmetization. **The "ipa" in the id is a
  historical label, not a property claim**: upstream ezkl has removed
  the IPA commitment — main is KZG-only (``DEFAULT_COMMITMENT =
  "kzg"``, src/commands.rs:73), and KZG relies on a universal,
  circuit-independent SRS from a trusted-setup ceremony, so the
  earlier "no trusted setup" claim no longer holds. The id string is
  serialized into existing proofs (wire format), so it is kept and
  documented rather than renamed. Verified against
  github.com/zkonduit/ezkl + docs.ezkl.xyz on 2026-06-10.
- ``deepprove-2026``   — Lagrange Labs DeepProve, Rust crate
  released Feb 23 2026, 158x faster than ezkl on MLP/CNN, GPT-2 /
  LLAMA / Gemma3 inference proofs. Backed by GKR sumcheck + lookup
  arguments. We dispatch via a thin subprocess shim when the binary
  is available; otherwise fall through to ezkl. **No incumbent in
  the agent-governance market has wired DeepProve.**
- ``jolt-sumcheck-2026``  — a16z JOLT zkVM with Twist & Shout
  memory-checking (Feb 2026). Sum-check + lookup singularity, ~3x
  prover speedup. Listed for completeness; ZKPROV's RISC-V circuit
  description path is a backlog item.
- ``latticefold-plus-2026``  — Boneh-Chen post-quantum folding
  scheme. The Apr 2026 ℓ2-norm improvement (eprint 2026/721) gives
  it ~2x lower prover cost than the 2025 baseline. The PQ path is
  why Tex can credibly say "ZKPROV survives Q-Day"; SCITT ARP
  (draft-hillier-scitt-arp-00, May 1 2026) explicitly references
  PQ-secure folding as a deployment option for cross-sovereign
  audit chains.
- ``deterministic-shim-v1``  — pure-Python audit-only fallback. It
  emits a structurally identical proof envelope using HMAC and
  SHA-256, so the entire surface (commit → prove → verify →
  evidence chain hookup) exercises end-to-end on contributor
  laptops, Render free tier, CI, and the integration tests that
  back the wired CLAIMS.md entry. The shim's ``backend`` tag is
  loud enough that production deployments cannot accidentally
  consume it: ``deterministic-shim-v1`` is never accepted by
  Article 53(1)(d) regulator-grade verification (see
  ``regulator_grade=True`` flag on ``verify_proof``).

The Protocol below is intentionally narrow. The interesting design
work lives in the manifest (what's being proved) and the commitment
(how it's bound). The backend is a swappable kernel.

Cite: arxiv 2510.16830 (VFT) §IV.B; eprint 2026/721 (LatticeFold+ ℓ2);
a16z Twist & Shout (Feb 2026); ezkl docs (2026).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol, runtime_checkable


class ProofBackendId(str, Enum):
    """Identifier carried inside every ``ProvenanceProof``.

    The enum is intentionally string-valued so it survives a JSON
    round-trip through the evidence chain.
    """

    # NOTE: "ipa" here is a historical label — upstream ezkl is KZG-only
    # as of v23.0.5 (verified 2026-06-10; see Halo2IpaBackend). The value
    # is serialized into existing proof envelopes, so renaming it would
    # be a wire-format break; it stays as a label, not a property claim.
    HALO2_IPA_2026 = "halo2-ipa-2026"
    DEEPPROVE_2026 = "deepprove-2026"
    JOLT_SUMCHECK_2026 = "jolt-sumcheck-2026"
    LATTICEFOLD_PLUS_2026 = "latticefold-plus-2026"
    # SP1 Hypercube: Succinct multilinear-polynomial zkVM, on
    # Ethereum mainnet since Feb 19 2026; 99.7% of L1 blocks proved
    # in <12s on 16 RTX 5090 GPUs (Succinct blog Nov 18 2025 /
    # mainnet announcement Feb 19 2026). The proof system is not
    # natively ZK — it gains zero-knowledge by being wrapped in
    # VEIL below. Stack-compatible with SP1 Turbo for migration.
    SP1_HYPERCUBE_2026 = "sp1-hypercube-2026"
    # VEIL: Verifiable Encapsulation of Interactive proofs with Low
    # overhead. Compiler that adds ZK to hash-based multilinear
    # proof systems with ~3% prover overhead, ~22% verifier
    # overhead, ~12% proof-size overhead. Plausibly post-quantum
    # on hash assumptions alone — no elliptic curves involved.
    # Dalal, Hemo, Rabinovich, Rothblum, eprint 2026/683 (Apr 8
    # 2026); Succinct blog "VEIL adds zero-knowledge to hash-based
    # proof systems with only a 3% increase in prover time"
    # (May 1 2026). Composes with SP1 Hypercube and any future
    # FRI/multilinear prover.
    VEIL_HASH_BASED_ZK_2026 = "veil-hash-based-zk-2026"
    # schnorr-fuse-zk-v1: the first **wired and runnable** non-shim L1 backend.
    # A pure-Python discrete-log Σ-protocol (Pedersen + Fiat–Shamir + OR-bit
    # range proofs, ``tex.zkprov.schnorr_group``) that proves the PDP
    # decision-relation FUSE kernel over private scores
    # (``tex.zkprov.zk_fuse``). Unlike every entry above it, it does NOT raise
    # BackendUnavailable — it runs offline with no binary, no SRS, no enclave.
    # It is a REAL, hiding, sound, publicly-verifiable proof (the property the
    # HMAC shim never had), but it is NOT a succinct SNARK (proofs are ~hundreds
    # of KB) and is ``research-early`` / unaudited / pre-quantum (2048-bit DLog,
    # ~112-bit classical). See ``_REGULATOR_GRADE`` below for the honest tier.
    SCHNORR_FUSE_ZK_V1 = "schnorr-fuse-zk-v1"
    # schnorr-verdict-zk-v1: the hiding sibling of schnorr-fuse-zk-v1. SAME
    # discrete-log Σ-protocol toolkit (``tex.zkprov.zk_fuse.prove_verdict`` /
    # ``verify_verdict``, scheme constant ``VERDICT_SCHEME``), SAME maturity
    # collar (real DLog argument, research-early, unaudited, NON-succinct, no
    # soundness against the dev key holder, pre-quantum 2048-bit). The ONLY
    # difference vs the fuse backend: it proves the THRESHOLD verdict over the
    # per-stream scores while ALSO hiding the fused score itself — the public
    # input is ``verdict`` + thresholds + weights, never ``fused_q``. Like the
    # fuse backend it runs offline today and refuses the router-skipped path.
    SCHNORR_VERDICT_ZK_V1 = "schnorr-verdict-zk-v1"
    DETERMINISTIC_SHIM_V1 = "deterministic-shim-v1"


# The **non-shim, real-proof** tier: a backend here produces a genuine
# cryptographic argument (not the symmetric keyed-hash stand-in), so the
# verifier may report ``regulator_grade=True`` and a composition may treat it as
# "green" rather than "green_test_mode". Honesty caveat: membership is the TIER,
# not a completed certification.
#   * HALO2/DEEPPROVE/JOLT/LATTICEFOLD/SP1/VEIL — RUNTIME-DEPENDENT regulator-
#     grade SNARK backends (raise BackendUnavailable until their binary/circuit
#     ships); only THESE are intended for an audited Article 53(1)(d) deployment.
#   * SCHNORR_FUSE_ZK_V1 / SCHNORR_VERDICT_ZK_V1 — REAL but ``research-early``,
#     unaudited, NON-succinct DLog arguments that actually run today.
#     "regulator-grade" here means "non-shim real proof", NOT "audited SNARK".
#     Do not cite either as Article-53 certified; cite them as real, hiding,
#     sound, offline proofs (the fuse variant publishes ``fused_q``, the verdict
#     variant additionally HIDES it). The shim is excluded from this set entirely.
_REGULATOR_GRADE: Final[frozenset[ProofBackendId]] = frozenset({
    ProofBackendId.HALO2_IPA_2026,
    ProofBackendId.DEEPPROVE_2026,
    ProofBackendId.JOLT_SUMCHECK_2026,
    ProofBackendId.LATTICEFOLD_PLUS_2026,
    ProofBackendId.SP1_HYPERCUBE_2026,
    ProofBackendId.VEIL_HASH_BASED_ZK_2026,
    ProofBackendId.SCHNORR_FUSE_ZK_V1,
    ProofBackendId.SCHNORR_VERDICT_ZK_V1,
})


def is_regulator_grade(backend: ProofBackendId) -> bool:
    """Whether a backend is in the **non-shim, real-proof** tier (see
    ``_REGULATOR_GRADE``).

    The deterministic shim is fine for unit tests and the end-to-end wiring
    proof, but is a keyed-hash stand-in, never a real proof. The SNARK members
    are RUNTIME-DEPENDENT; ``schnorr-fuse-zk-v1`` is a real DLog argument that
    runs today but is research-early/unaudited — "regulator-grade" names the
    tier, not a completed Article 53(1)(d) certification.
    """
    return backend in _REGULATOR_GRADE


# --------------------------------------------------------------------------- #
# Statement                                                                   #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ProvenanceStatement:
    """The public input + claim that the proof is over.

    The backend takes this and the (possibly private) witness and
    produces ``proof_bytes`` such that
    ``verify(proof_bytes, statement) == True`` iff:

      1. The response was produced by a model whose parameters
         hash to ``model_commitment_hash`` (32 bytes hex).
      2. That model was fine-tuned from ``base_model_sha256``
         (carried in the manifest, public).
      3. Training touched only records committed to under
         ``dataset_commitment_id`` (the ``DatasetCommitment``).
      4. The bound prompt attribute set
         (``prompt_attribute_hash``) was honored.
      5. Per-source ``max_epoch_participation`` was not exceeded
         (VFT quota counter).

    Statement is **all public**. The dataset itself, individual
    records, and model parameters are never on the statement.
    """

    response_sha256_hex: str
    prompt_sha256_hex: str
    prompt_attribute_hash: str
    model_commitment_hash: str
    dataset_commitment_id: str
    manifest_root_hash: str
    poseidon_root_hex: str
    circuit_version: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "response_sha256": self.response_sha256_hex,
                "prompt_sha256": self.prompt_sha256_hex,
                "prompt_attribute_hash": self.prompt_attribute_hash,
                "model_commitment_hash": self.model_commitment_hash,
                "dataset_commitment_id": self.dataset_commitment_id,
                "manifest_root_hash": self.manifest_root_hash,
                "poseidon_root_hex": self.poseidon_root_hex,
                "circuit_version": self.circuit_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Backend Protocol                                                            #
# --------------------------------------------------------------------------- #

@runtime_checkable
class ProofBackend(Protocol):
    """The minimal structural contract every backend satisfies."""

    backend_id: ProofBackendId

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        ...

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        ...


# --------------------------------------------------------------------------- #
# Deterministic shim backend                                                  #
# --------------------------------------------------------------------------- #
#
# Pure-Python, sub-millisecond. The shim's "proof" is an HMAC-SHA256
# tag binding (statement, private_witness). Verification compares
# against a recomputed expected tag using the same key. Verification
# requires the private witness too, which is reasonable for unit
# tests but obviously NOT zero-knowledge. The whole point of the
# shim tag is to drive the wiring (route → backend → store → evidence
# chain) end-to-end without dragging liboqs / ezkl-Rust /
# DeepProve-CUDA into CI. Tests for regulator-grade backends are
# marked `regulator_grade` and skip when the binary is missing.

# Test/dev key fixed via env var. Unrelated to production CA signing.
_SHIM_KEY_ENV = "TEX_ZKPROV_SHIM_KEY"
_SHIM_KEY_DEFAULT = (
    b"tex-zkprov-shim-key-do-not-use-in-production-this-is-32+bytes-long"
)


def _resolve_shim_key() -> bytes:
    """Resolve the HMAC key for the deterministic shim backend."""
    env = os.environ.get(_SHIM_KEY_ENV)
    if env:
        # Allow hex- or raw-string env values, normalize to bytes.
        try:
            return bytes.fromhex(env)
        except ValueError:
            return env.encode("utf-8")
    return _SHIM_KEY_DEFAULT


@dataclass(frozen=True, slots=True)
class DeterministicShimBackend:
    """Pure-Python audit-only backend.

    Use cases:
      * Unit tests that exercise the full wiring without ezkl/liboqs.
      * Demo curl scripts on contributor laptops.
      * CI runs on Render free tier.

    The shim is **not** zero-knowledge and **not** regulator-grade.
    Production deployments configure a regulator-grade backend via
    the manifest's ``proof_backend`` field, and
    ``verify_proof(regulator_grade=True)`` rejects shim proofs.
    """

    backend_id: ProofBackendId = ProofBackendId.DETERMINISTIC_SHIM_V1

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        msg = (
            b"tex/zkprov/shim-v1\x00"
            + statement.canonical_bytes()
            + b"\x00"
            + hashlib.sha256(private_witness).digest()
        )
        tag = hmac.new(_resolve_shim_key(), msg, hashlib.sha256).digest()
        envelope = {
            "backend": self.backend_id.value,
            "tag": tag.hex(),
            "witness_sha256": hashlib.sha256(private_witness).hexdigest(),
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        try:
            envelope = json.loads(proof_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if envelope.get("backend") != self.backend_id.value:
            return False
        tag_hex = envelope.get("tag")
        witness_hash_hex = envelope.get("witness_sha256")
        if not isinstance(tag_hex, str) or not isinstance(witness_hash_hex, str):
            return False
        try:
            tag = bytes.fromhex(tag_hex)
            witness_digest = bytes.fromhex(witness_hash_hex)
        except ValueError:
            return False
        msg = (
            b"tex/zkprov/shim-v1\x00"
            + statement.canonical_bytes()
            + b"\x00"
            + witness_digest
        )
        expected = hmac.new(_resolve_shim_key(), msg, hashlib.sha256).digest()
        return hmac.compare_digest(expected, tag)


# --------------------------------------------------------------------------- #
# Schnorr fuse-relation backend — the first wired, RUNNABLE non-shim backend  #
# --------------------------------------------------------------------------- #
#
# Unlike every SNARK backend below (which raise BackendUnavailable until a
# binary/circuit/SRS ships), this one runs offline today in pure Python. It
# proves the PDP decision-relation FUSE kernel (``tex.zkprov.zk_fuse``): that
# the public fused score is the round-half-up, clamped, policy-weighted fusion
# of PRIVATE, range-bounded per-stream risk scores — hiding the scores, sound
# under discrete log, publicly verifiable with no shared secret, no enclave, no
# blockchain. It is real (NOT the keyed-hash stand-in) but research-early /
# unaudited / non-succinct / pre-quantum (2048-bit DLog). It applies to the
# FUSE path only: a router-skipped (structural short-circuit) statement has no
# fuse to prove and ``prove`` refuses it.
#
# It reads the arbitration statement's structured fields
# (``stream_scores_q`` / ``weights_q`` / ``fused_q`` / ``scale``) by duck typing
# — it is only ever dispatched for an ``ArbitrationStatement`` — and does NOT
# import ``tex.zkpdp`` (no layering cycle). The per-score scores are the PRIVATE
# witness: ``verify`` never consumes them, only the public weights + fused_q.

@dataclass(frozen=True, slots=True)
class SchnorrFuseZkBackend:
    """Discrete-log Σ-protocol backend over the arbitration fuse relation."""

    backend_id: ProofBackendId = ProofBackendId.SCHNORR_FUSE_ZK_V1

    @staticmethod
    def _streams(statement) -> list[tuple[str, int, int]]:  # type: ignore[no-untyped-def]
        scores = list(statement.stream_scores_q)
        weights = list(statement.weights_q)
        streams: list[tuple[str, int, int]] = []
        for (sn, sv), (wn, wv) in zip(scores, weights):
            if sn != wn:
                raise ValueError(
                    "schnorr-fuse-zk-v1: stream/weight key order mismatch "
                    f"({sn!r} != {wn!r})"
                )
            streams.append((sn, int(wv), int(sv)))
        return streams

    def prove(self, *, statement, private_witness: bytes) -> bytes:  # type: ignore[no-untyped-def]
        from tex.zkprov import zk_fuse

        if getattr(statement, "router_skipped", False):
            raise zk_fuse.FuseProofError(
                "schnorr-fuse-zk-v1 attests the FUSE path; a router-skipped "
                "(structural short-circuit) statement has no fuse to prove — "
                "its FORBID is a public structural fact, not a fused score"
            )
        return zk_fuse.prove_fuse(
            scale=int(statement.scale),
            fused_q=int(statement.fused_q),
            streams=self._streams(statement),
        )

    def verify(self, *, statement, proof_bytes: bytes) -> bool:  # type: ignore[no-untyped-def]
        from tex.zkprov import zk_fuse

        if getattr(statement, "router_skipped", False):
            return False
        weights = [(str(n), int(w)) for n, w in statement.weights_q]
        return zk_fuse.verify_fuse(
            scale=int(statement.scale),
            fused_q=int(statement.fused_q),
            weights=weights,
            proof_bytes=proof_bytes,
        )


# --------------------------------------------------------------------------- #
# Schnorr VERDICT backend — the hiding sibling of the fuse backend            #
# --------------------------------------------------------------------------- #
#
# Same construction, same maturity collar (a real DLog argument, research-early,
# unaudited, NON-succinct, no soundness against the dev key holder, pre-quantum
# 2048-bit DLog) as ``SchnorrFuseZkBackend`` — it shares the SAME crypto
# (``zk_fuse.prove_verdict`` / ``verify_verdict``, scheme ``VERDICT_SCHEME``).
# The ONLY increment: it proves the THRESHOLD verdict the PRIVATE per-stream
# scores yield while ALSO hiding the fused score itself. Where the fuse backend
# publishes ``fused_q`` and proves the fusion arithmetic binds to it, this one
# never reads ``fused_q`` at all — the public input is ``verdict`` + the
# thresholds + the weights, and the verifier derives the verdict's accumulator
# region from the public thresholds (``zk_fuse.verdict_acc_interval``). It reads
# the arbitration statement's structured fields by duck typing (it is only ever
# dispatched for the hiding arbitration statement) and, like the fuse backend,
# applies to the FUSE path only: a router-skipped (structural short-circuit)
# statement has no fuse to prove and ``prove`` refuses it.

@dataclass(frozen=True, slots=True)
class SchnorrVerdictZkBackend:
    """Discrete-log Σ-protocol backend over the arbitration verdict relation,
    hiding the fused score (the increment over ``SchnorrFuseZkBackend``)."""

    backend_id: ProofBackendId = ProofBackendId.SCHNORR_VERDICT_ZK_V1

    @staticmethod
    def _streams(statement) -> list[tuple[str, int, int]]:  # type: ignore[no-untyped-def]
        scores = list(statement.stream_scores_q)
        weights = list(statement.weights_q)
        streams: list[tuple[str, int, int]] = []
        for (sn, sv), (wn, wv) in zip(scores, weights):
            if sn != wn:
                raise ValueError(
                    "schnorr-verdict-zk-v1: stream/weight key order mismatch "
                    f"({sn!r} != {wn!r})"
                )
            streams.append((sn, int(wv), int(sv)))
        return streams

    def prove(self, *, statement, private_witness: bytes) -> bytes:  # type: ignore[no-untyped-def]
        from tex.zkprov import zk_fuse

        if getattr(statement, "router_skipped", False):
            raise zk_fuse.FuseProofError(
                "schnorr-verdict-zk-v1 attests the FUSE-path verdict; a "
                "router-skipped (structural short-circuit) statement has no "
                "fuse to prove — its FORBID is a public structural fact, not a "
                "fused score"
            )
        # NOTE: deliberately does NOT read ``statement.fused_q`` — the fused
        # score is the value this backend HIDES. The public claim is the
        # verdict + thresholds; the scores are the private witness.
        return zk_fuse.prove_verdict(
            scale=int(statement.scale),
            verdict=str(statement.verdict),
            permit_q=int(statement.permit_q),
            forbid_q=int(statement.forbid_q),
            streams=self._streams(statement),
        )

    def verify(self, *, statement, proof_bytes: bytes) -> bool:  # type: ignore[no-untyped-def]
        from tex.zkprov import zk_fuse

        if getattr(statement, "router_skipped", False):
            return False
        weights = [(str(n), int(w)) for n, w in statement.weights_q]
        return zk_fuse.verify_verdict(
            scale=int(statement.scale),
            verdict=str(statement.verdict),
            permit_q=int(statement.permit_q),
            forbid_q=int(statement.forbid_q),
            weights=weights,
            proof_bytes=proof_bytes,
        )


# --------------------------------------------------------------------------- #
# Halo2 backend (via ezkl) — id "halo2-ipa-2026" is a historical label        #
# --------------------------------------------------------------------------- #
#
# ezkl ships on PyPI (v23.0.5 as of 2026-02-20; verified against
# github.com/zkonduit/ezkl and docs.ezkl.xyz on 2026-06-10) and uses
# Halo2 as its proving system. Commitments: upstream is now KZG-only
# (DEFAULT_COMMITMENT = "kzg", src/commands.rs:73); the IPA variant
# this backend was named after has been removed, and no IPA references
# remain on main. KZG relies on a UNIVERSAL (circuit-independent)
# structured reference string produced by a trusted-setup ceremony —
# universal, not per-deployment/per-circuit, so no per-customer
# ceremony is needed, but "no trusted setup" is no longer true of this
# backend and must not be claimed. (The original rationale — avoiding
# a per-deployment proving-key ceremony as a governance liability —
# survives under a universal SRS; the blanket claim does not.)
#
# The full ezkl integration writes the circuit description and
# witness to disk, runs the ezkl CLI, and reads back the proof
# bytes. For the inline integration in this thread we keep the
# import lazy and the binary check gated; if ezkl is not installed
# we surface a structured ``BackendUnavailable`` error so the
# dispatcher can fall back to the shim with a loud log.

class BackendUnavailable(RuntimeError):
    """Raised when a regulator-grade backend is configured but the
    underlying binary / Python package is not installed."""


@dataclass(frozen=True, slots=True)
class Halo2IpaBackend:
    """Halo2 backend via ezkl — the "IPA" in the name is historical.

    Upstream status (verified 2026-06-10): ezkl v23.0.5, Halo2 proving
    system, KZG-only commitments — the IPA option this class was named
    after was removed upstream, and with it the "no trusted setup"
    property the old docstring claimed. KZG uses a universal
    (circuit-independent) trusted-setup SRS, not a per-deployment
    ceremony. The class and id keep their names because
    ``halo2-ipa-2026`` is serialized into existing proof envelopes;
    treat both as labels, not commitment-scheme claims.

    The wire format of ``proof_bytes`` is::

      {
        "backend": "halo2-ipa-2026",
        "proof": "<hex>",          # raw bytes from ezkl.prove()
        "vk_hash": "<hex>",        # SHA-256 of the verifying key
        "circuit_version": "v1",
      }

    Lazy-imports ``ezkl`` so the module is importable without it.
    """

    backend_id: ProofBackendId = ProofBackendId.HALO2_IPA_2026

    def _require_ezkl(self):  # type: ignore[no-untyped-def]
        try:
            import ezkl  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover — environment-dependent
            raise BackendUnavailable(
                "ezkl is not installed. Add `pip install ezkl` to your "
                "deployment, or fall back to the deterministic shim "
                "backend for non-regulator-grade flows."
            ) from exc
        return ezkl

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        # The full ezkl integration requires an ONNX-shaped circuit
        # description matching the ZKPROV statement (record membership
        # + manifest binding). The circuit lives in
        # ``tex.zkprov.circuits.zkprov_v1.onnx`` (out-of-tree binary
        # artifact). Until the circuit is checked in alongside the
        # rest of the build, this function raises BackendUnavailable
        # with a clear remediation message. The wiring around it is
        # complete: route → store → evidence chain hook all exercise
        # via the shim, and switching to this Halo2 backend is a
        # one-line change in the manifest.
        self._require_ezkl()
        raise BackendUnavailable(
            "halo2-ipa-2026 requires the bundled ZKPROV circuit at "
            "tex/zkprov/circuits/zkprov_v1.onnx, which is built "
            "out-of-band from the ML manifest. Ship the artifact, "
            "then this backend produces real Halo2 (KZG) proofs via "
            "ezkl — note the id's 'ipa' suffix is historical. The "
            "deterministic shim handles wiring end-to-end in the "
            "meantime; the Article 53(1)(d) regulator-grade verifier "
            "rejects shim proofs (see is_regulator_grade)."
        )

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        self._require_ezkl()
        raise BackendUnavailable(
            "halo2-ipa-2026 verifier requires the bundled verifying "
            "key. See tex.zkprov.backends.Halo2IpaBackend.prove for "
            "the circuit artifact dependency."
        )


# --------------------------------------------------------------------------- #
# DeepProve backend (Lagrange Labs, Rust crate, Feb 23 2026)                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class DeepProveBackend:
    """Lagrange Labs DeepProve backend.

    Rust crate, GKR sumcheck + logup lookup arguments. 158x faster
    than ezkl on the benchmarked CNN/MLP workloads, 671x faster
    verification. Production-deployed at Anduril, Lockheed, Oracle
    Cloud sovereign environments. **Zero competitors in the agent-
    governance market have wired DeepProve** as of May 2026.

    The integration is a subprocess shim against the
    ``Lagrange-Labs/deep-prove`` CLI. Until that binary is in
    `PATH`, this backend raises ``BackendUnavailable`` with
    remediation pointers.
    """

    backend_id: ProofBackendId = ProofBackendId.DEEPPROVE_2026

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        raise BackendUnavailable(
            "deepprove-2026 requires the Lagrange-Labs/deep-prove "
            "binary in PATH (Rust, install via `cargo install --git "
            "https://github.com/Lagrange-Labs/deep-prove`). Once "
            "available, the backend shells out with the ZKPROV "
            "circuit description in DeepProve's IR format. "
            "Wiring exercises end-to-end via the shim today."
        )

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        raise BackendUnavailable("deepprove-2026 verifier: see prove() for status.")


# --------------------------------------------------------------------------- #
# LatticeFold+ backend (Boneh-Chen, Apr 2026 ℓ2 improvement)                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class LatticeFoldPlusBackend:
    """LatticeFold+ folding scheme backend.

    Post-quantum recursive aggregation per eprint 2026/721 (April
    2026). Sized for the moment cryptography-agile organizations
    cite the ML-DSA / ML-KEM / SLH-DSA NIST suite as the
    "transition baseline" and need a folding scheme that survives
    Q-Day.

    Nethermind has an implementation under active development; no
    Python binding exists as of May 2026, so this backend is
    structurally complete but routes to BackendUnavailable.
    The PQ path is what makes "ZKPROV survives the cryptographic
    transition timeline" a defensible claim — the SCITT ARP draft
    (May 1 2026) explicitly cites PQ-secure folding as a deployment
    requirement for cross-sovereign reconciliation.
    """

    backend_id: ProofBackendId = ProofBackendId.LATTICEFOLD_PLUS_2026

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        raise BackendUnavailable(
            "latticefold-plus-2026 is post-quantum reserved. No "
            "Python binding ships in May 2026; Nethermind reference "
            "implementation expected H2 2026. Manifest can declare "
            "this backend today; resolution happens when the binding "
            "lands. The PQ statement IS the deliverable here — Tex "
            "is the only agent-governance platform whose commitment "
            "scheme is upgradeable to a PQ folding scheme without a "
            "wire-format break."
        )

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        raise BackendUnavailable("latticefold-plus-2026 verifier: see prove() for status.")


# --------------------------------------------------------------------------- #
# SP1 Hypercube backend (Succinct, mainnet Feb 19 2026)                       #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class SP1HypercubeBackend:
    """Succinct SP1 Hypercube zkVM backend.

    Multilinear-polynomial proof system that hit Ethereum mainnet
    on Feb 19 2026. Proves 99.7% of L1 Ethereum blocks in under 12
    seconds using 16 NVIDIA RTX 5090 GPUs — the first "real-time
    proving at home" milestone. Stack-compatible with SP1 Turbo;
    migration is "minimal changes" per the Succinct release notes.

    The relevance to ZKPROV is: SP1 is a general-purpose RISC-V
    zkVM, so a ZKPROV verifier circuit compiled to RISC-V runs on
    it. This is the path to a real-time per-decision provenance
    proof on commodity GPU hardware — what every other backend in
    this dispatcher is *trying* to be.

    **Caveat: SP1 Hypercube is not natively zero-knowledge.** Its
    succinctness is the point; the ZK property comes from wrapping
    it in ``VEIL_HASH_BASED_ZK_2026`` (eprint 2026/683, Apr 8 2026),
    which adds the ZK overhead at ~3% prover cost. Tex's
    ``proof_backend = "sp1-hypercube-2026"`` is interpreted as
    "SP1 Hypercube wrapped in VEIL" — the dispatcher composes them
    when both are declared in the manifest. Until then this slot
    is reserved and raises ``BackendUnavailable`` with the binary
    install pointer.

    References
    ----------
    - Succinct blog, "Proving Ethereum in Real-Time" (May 20, 2025).
    - Succinct blog, "Real-time Proving at Home: 99.7% of L1 blocks
      on 16 GPUs" (Nov 18, 2025).
    - Succinct blog, "SP1 Hypercube Is Now Live on Mainnet"
      (Feb 19, 2026).
    - John Guibas, Ron Rothblum: novel multilinear polynomial
      arithmetization replacing Plonkish in SP1 Turbo. Formal
      verification of RISC-V constraints with Nethermind + EF.
    """

    backend_id: ProofBackendId = ProofBackendId.SP1_HYPERCUBE_2026

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        raise BackendUnavailable(
            "sp1-hypercube-2026 requires the SP1 SDK in PATH "
            "(install via Succinct's `sp1up` script; see "
            "https://docs.succinct.xyz). The ZKPROV circuit is "
            "compiled to RISC-V and proved through the Hypercube "
            "prover network; ZK property comes from wrapping in "
            "VEIL (veil-hash-based-zk-2026). Wiring is exercised "
            "via the deterministic shim today; switching to "
            "SP1 Hypercube is a one-line change in the manifest "
            "(`proof_backend`)."
        )

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        raise BackendUnavailable("sp1-hypercube-2026 verifier: see prove() for status.")


# --------------------------------------------------------------------------- #
# VEIL backend (Dalal-Hemo-Rabinovich-Rothblum, eprint 2026/683)              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class VeilHashBasedZkBackend:
    """VEIL compiler: ZK wrapper for hash-based multilinear proof systems.

    Decouples the protocol's algebraic interactions from the
    cryptographic hashing and applies a ZK wrapper solely to the
    algebraic components. Result: a simple, **plausibly
    post-quantum**, ZK protocol that achieves a minimal prover
    overhead of (1+o(1)). The April 2026 proof-of-concept reports:

      * prover overhead     ~3%
      * verifier overhead   ~22%
      * proof-size overhead ~12%

    over a 31-bit base prime field on a trace of 2^29 field
    elements. The PQ posture is genuinely better than
    LatticeFold+: VEIL is hash-based end to end, so security
    reduces to the collision-resistance of the underlying hash —
    no lattice assumptions, no elliptic curves, no trusted setup.

    Why it matters for ZKPROV
    -------------------------
    Today's ZKPROV statement is bound to an ML-DSA-65-signed
    commitment (PQ for signing) and a Halo2/KZG proof via ezkl
    (classical pre-quantum on the SNARK side; the "halo2-ipa-2026"
    id is a historical label). VEIL closes the SNARK-side
    PQ gap by giving the manifest a backend whose security is
    purely hash-based. This is what makes "ZKPROV survives Q-Day"
    true at every layer of the stack, not just at the signing
    layer.

    Implementation status (May 2026)
    --------------------------------
    The Succinct team's PoC implementation is in the SP1 codebase
    repository, not yet a standalone Python-bindable library. The
    dispatcher slot is reserved and raises BackendUnavailable
    until the Succinct Rust binding lands; wiring exercises today
    through the deterministic shim.

    References
    ----------
    - Dalal, Hemo, Rabinovich, Rothblum. "VEIL: Lightweight
      Zero-Knowledge for Hash-Based Multilinear Proof Systems."
      IACR ePrint 2026/683 (Apr 8 2026).
    - Succinct blog, "VEIL: Adding Zero-Knowledge to Hash-based
      Proof Systems" (May 1 2026).
    """

    backend_id: ProofBackendId = ProofBackendId.VEIL_HASH_BASED_ZK_2026

    def prove(self, *, statement: ProvenanceStatement, private_witness: bytes) -> bytes:
        raise BackendUnavailable(
            "veil-hash-based-zk-2026 has no standalone Python "
            "binding yet — the PoC lives inside the SP1 repository "
            "as a compiler wrapper around hash-based multilinear "
            "provers. When the Succinct binding lands, this backend "
            "becomes a generic ZK-wrapping shim around whichever "
            "non-ZK hash-based prover the manifest declares (today "
            "that means sp1-hypercube-2026). Wiring exercises today "
            "via the deterministic shim; the post-quantum claim is "
            "preserved structurally — the manifest is upgradeable."
        )

    def verify(self, *, statement: ProvenanceStatement, proof_bytes: bytes) -> bool:
        raise BackendUnavailable("veil-hash-based-zk-2026 verifier: see prove() for status.")


# --------------------------------------------------------------------------- #
# Dispatcher                                                                  #
# --------------------------------------------------------------------------- #

def get_proof_backend(backend_id: ProofBackendId | str) -> ProofBackend:
    """Resolve a backend identifier to a concrete provider.

    Strings are accepted for convenience (the manifest carries a
    raw string in ``proof_backend``); they're parsed through the
    enum so unknown identifiers fail loudly.
    """
    if isinstance(backend_id, str):
        try:
            backend_id = ProofBackendId(backend_id)
        except ValueError as exc:
            raise ValueError(
                f"unknown ZKPROV backend identifier {backend_id!r}; "
                f"see ProofBackendId for the supported set"
            ) from exc

    if backend_id is ProofBackendId.DETERMINISTIC_SHIM_V1:
        return DeterministicShimBackend()
    if backend_id is ProofBackendId.SCHNORR_FUSE_ZK_V1:
        return SchnorrFuseZkBackend()
    if backend_id is ProofBackendId.SCHNORR_VERDICT_ZK_V1:
        return SchnorrVerdictZkBackend()
    if backend_id is ProofBackendId.HALO2_IPA_2026:
        return Halo2IpaBackend()
    if backend_id is ProofBackendId.DEEPPROVE_2026:
        return DeepProveBackend()
    if backend_id is ProofBackendId.JOLT_SUMCHECK_2026:
        # JOLT-via-RISC-V is a backlog item; for now route to the
        # PQ backend's BackendUnavailable surface so the calling
        # code can do a clean fallback.
        raise BackendUnavailable(
            "jolt-sumcheck-2026 is reserved. ZKPROV's RISC-V circuit "
            "shim is on the post-thread-14 backlog; the Twist & Shout "
            "memory-checking arguments (a16z, Feb 2026) give ~3x "
            "additional prover speedup once integrated."
        )
    if backend_id is ProofBackendId.LATTICEFOLD_PLUS_2026:
        return LatticeFoldPlusBackend()
    if backend_id is ProofBackendId.SP1_HYPERCUBE_2026:
        return SP1HypercubeBackend()
    if backend_id is ProofBackendId.VEIL_HASH_BASED_ZK_2026:
        return VeilHashBasedZkBackend()

    raise ValueError(f"unhandled backend id: {backend_id}")  # pragma: no cover


def resolve_backend_with_fallback(
    backend_id: ProofBackendId | str,
    *,
    allow_shim_fallback: bool = False,
) -> ProofBackend:
    """Resolve a backend, optionally falling back to the shim.

    ``allow_shim_fallback=True`` is the default for unit-test runners
    and the local demo. Production callers set it to False so a
    misconfigured backend surfaces loudly instead of silently
    downgrading to a non-regulator-grade proof.
    """
    try:
        backend = get_proof_backend(backend_id)
    except BackendUnavailable:
        if allow_shim_fallback:
            return DeterministicShimBackend()
        raise

    # Halo2/DeepProve/LatticeFold+ raise BackendUnavailable when
    # prove() is called, not at construction. We probe once at
    # resolution time when ``allow_shim_fallback`` is set so the
    # caller doesn't have to wrap each prove() in try/except.
    if allow_shim_fallback and isinstance(
        backend,
        (
            Halo2IpaBackend,
            DeepProveBackend,
            LatticeFoldPlusBackend,
            SP1HypercubeBackend,
            VeilHashBasedZkBackend,
        ),
    ):
        try:
            # Cheap probe: call _require_ezkl on Halo2IpaBackend,
            # otherwise skip (Rust binary probes are too expensive).
            if isinstance(backend, Halo2IpaBackend):
                backend._require_ezkl()
            else:
                # Rust binaries: we *don't* run a real check, we just
                # accept the backend at the configuration layer and
                # let prove() raise if it isn't there.
                pass
        except BackendUnavailable:
            return DeterministicShimBackend()

    return backend


__all__ = [
    "ProofBackendId",
    "ProofBackend",
    "ProvenanceStatement",
    "BackendUnavailable",
    "DeterministicShimBackend",
    "SchnorrFuseZkBackend",
    "SchnorrVerdictZkBackend",
    "Halo2IpaBackend",
    "DeepProveBackend",
    "LatticeFoldPlusBackend",
    "SP1HypercubeBackend",
    "VeilHashBasedZkBackend",
    "get_proof_backend",
    "resolve_backend_with_fallback",
    "is_regulator_grade",
]
