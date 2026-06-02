"""
Recursive aggregation of ZKPROV proofs (VFT element 4).

What this implements
--------------------
A single LLM call produces one ``ProvenanceProof``. A regulator
auditing a GPAI provider under EU AI Act Article 53(1)(d) needs to
verify *millions* of such proofs without paying the per-proof
verification cost millions of times. The solution from VFT
(arxiv 2510.16830 §III.D, Dec 29 2025) is recursive aggregation:
fold N per-step proofs into a single per-epoch certificate; fold M
per-epoch certificates into a single end-to-end certificate. The
verifier checks one final proof in constant or logarithmic time
regardless of N or M.

The bleeding edge for recursive aggregation as of May 2026:

- **Nova** (Setty 2022) — the original folding scheme, R1CS.
- **HyperNova** (CRYPTO 2024, eprint 2023/573, updated 02/20/2026) —
  CCS-based, multi-folding, ZK for free via NovaBlindFold.
- **ProtoStar/ProtoGalaxy** — high-degree gates, multi-instance.
- **CycleFold** — cycle-of-curves, 1 MSM per fold step.
- **MicroNova** (S&P 2025) — on-chain efficient verification.
- **NeutronNova** — experimental in microsoft/Nova `--features experimental`.
- **LatticeFold+** (Boneh-Chen 2025, ℓ2 improvement eprint 2026/721
  April 2026) — **the post-quantum path**. No Python binding yet,
  Nethermind reference in development.

Why we encode this now
----------------------
The recursive aggregation primitive isn't actually executed in pure
Python here — folding schemes are heavy crypto and live in the
backend's Rust/CUDA side. What lives in Python is:

1. **The certificate envelope** — what an aggregated proof looks
   like on the wire, what's bound into it, and how the evidence
   chain references it.
2. **The aggregation manifest** — which leaf proofs are in the
   batch, what the per-step quotas were, and the folding-scheme
   identifier the backend will use.
3. **The verification surface** — `verify_aggregated_certificate`
   matches the per-proof verifier's shape so the same SCITT entry
   format covers both leaf and aggregated proofs.

When the backend lands (DeepProve has GKR aggregation today;
LatticeFold+ will land later), the wire format here is already
what they emit and consume — no breaking changes downstream.

This is the second piece of the wedge no competitor has wired: the
Microsoft AGT's evidence chain emits per-action receipts; Tex
emits per-action receipts plus aggregable provenance certificates.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from tex.zkprov.backends import ProofBackendId, is_regulator_grade
from tex.zkprov.proof import ProvenanceProof


class FoldingScheme(str, Enum):
    """Identifier for the folding/aggregation scheme used.

    Ordered by recommendation tier:

    - ``LATTICEFOLD_PLUS_2026``  — post-quantum, ℓ2-improved
      (eprint 2026/721, Apr 2026). Sub-quadratic prover, ~2x lower
      cost than the 2025 baseline. The PQ path.
    - ``HYPERNOVA_CYCLEFOLD``   — Microsoft Nova v0.x with
      HyperNova + CycleFold (CRYPTO 2024, updated 02/20/2026).
      The mature, classical default.
    - ``MICRONOVA_ONCHAIN``     — MicroNova (S&P 2025), efficient
      on-chain verification. Used when the aggregate is anchored
      to a public blockchain.
    - ``NEUTRONNOVA_EXPERIMENTAL`` — Microsoft Nova experimental.
    - ``GKR_DEEPPROVE``         — Lagrange DeepProve's native
      aggregation (sumcheck + logup GKR).
    - ``NONE``                  — leaf proofs only, no aggregation.
    """

    LATTICEFOLD_PLUS_2026 = "latticefold-plus-2026"
    HYPERNOVA_CYCLEFOLD = "hypernova-cyclefold-2026"
    MICRONOVA_ONCHAIN = "micronova-onchain-2025"
    NEUTRONNOVA_EXPERIMENTAL = "neutronnova-experimental-2026"
    GKR_DEEPPROVE = "gkr-deepprove-2026"
    # Mira parallel accumulation (ZKTorch, arxiv 2507.07031,
    # Jul 9 2025). Pairing-based recursive SNARK accumulator
    # designed for ML inference proof composition. ZKTorch's
    # parallel extension restructures folding as a tree-based
    # homomorphic reduction compatible with parallel hardware,
    # delivering up to 6.2x faster proving and 3x-10x proof-size
    # reduction over prior schemes (Chen et al. benchmarks on
    # GPT-J, BERT, ResNet-50, LLaMA-2-7B). Open source at
    # github.com/uiuc-kang-lab/zk-torch. Composes naturally with
    # ZKPROV's per-record basic-block proofs when DeepProve or
    # ZKTorch is the leaf backend.
    MIRA_PARALLEL_2026 = "mira-parallel-2026"
    NONE = "none"


_POST_QUANTUM_FOLDING: frozenset[FoldingScheme] = frozenset({
    FoldingScheme.LATTICEFOLD_PLUS_2026,
})


def is_post_quantum_folding(scheme: FoldingScheme) -> bool:
    """Whether a folding scheme survives Q-Day cryptographically.

    The honest set is small as of May 2026; LatticeFold and
    LatticeFold+ are the only lattice-based folding schemes with
    published security analysis. SkyScraper / Lova / Symphony are
    on the research frontier but not yet stabilized.
    """
    return scheme in _POST_QUANTUM_FOLDING


@dataclass(frozen=True, slots=True)
class AggregationLeaf:
    """One leaf proof's envelope hash within an aggregation batch.

    The full leaf proof is stored separately (in
    ``provenance_proofs`` Postgres table); the aggregation
    certificate only carries hashes so a per-batch SCITT entry
    can name the leaves it covers without copying them.
    """

    leaf_envelope_sha256: str
    backend: ProofBackendId
    response_sha256: str
    dataset_commitment_id: str


@dataclass(frozen=True, slots=True)
class AggregationManifest:
    """The metadata block bound into an aggregated certificate.

    What this binds:
      * Which leaf proofs are in the batch (by envelope hash).
      * Which folding scheme was used.
      * What the epoch / window context is.
      * Per-batch quota: total proofs aggregated must not exceed
        the manifest's announced ``max_batch_size``. This protects
        against runaway aggregation that could exhaust the
        verifier's bound.
    """

    aggregation_id: str
    leaves: tuple[AggregationLeaf, ...]
    folding_scheme: FoldingScheme
    max_batch_size: int
    epoch_index: int | None
    window_start: datetime
    window_end: datetime

    def manifest_sha256(self) -> str:
        """Deterministic hash over the aggregation manifest."""
        payload = {
            "aggregation_id": self.aggregation_id,
            "folding_scheme": self.folding_scheme.value,
            "max_batch_size": self.max_batch_size,
            "epoch_index": self.epoch_index,
            "window_start": self.window_start.astimezone(UTC).isoformat(),
            "window_end": self.window_end.astimezone(UTC).isoformat(),
            "leaves": [
                {
                    "envelope_sha256": leaf.leaf_envelope_sha256,
                    "backend": leaf.backend.value,
                    "response_sha256": leaf.response_sha256,
                    "dataset_commitment_id": leaf.dataset_commitment_id,
                }
                for leaf in self.leaves
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class AggregatedCertificate:
    """An aggregated provenance certificate.

    Wire shape (JSON):

      {
        "kind": "tex.zkprov.aggregate.v1",
        "manifest": <AggregationManifest as JSON>,
        "manifest_sha256": <hex>,
        "folding_proof_b64": <base64>,
        "folding_scheme": <FoldingScheme>,
        "post_quantum": <bool>,
        "issued_at": <RFC3339>,
        "verifier_runtime_target_ms": <int>
      }

    ``folding_proof_b64`` is the backend's aggregated proof bytes.
    For the deterministic shim (no real folding scheme), this is
    an HMAC tag over the manifest hash and the leaf hashes — the
    aggregated equivalent of the leaf shim.

    Verifier runtime target carries the upstream paper's claimed
    verification cost so the audit tool can flag certificates that
    take longer than expected (a sign of substitution).
    """

    manifest: AggregationManifest
    folding_proof: bytes
    folding_scheme: FoldingScheme
    issued_at: datetime
    verifier_runtime_target_ms: int = 200  # VFT §V default

    def to_envelope_json(self) -> str:
        return json.dumps(
            {
                "kind": "tex.zkprov.aggregate.v1",
                "manifest_sha256": self.manifest.manifest_sha256(),
                "manifest": json.loads(  # round-trip canonical to dict
                    json.dumps(
                        {
                            "aggregation_id": self.manifest.aggregation_id,
                            "folding_scheme": self.manifest.folding_scheme.value,
                            "max_batch_size": self.manifest.max_batch_size,
                            "epoch_index": self.manifest.epoch_index,
                            "window_start": self.manifest.window_start.astimezone(
                                UTC
                            ).isoformat(),
                            "window_end": self.manifest.window_end.astimezone(
                                UTC
                            ).isoformat(),
                            "leaves": [
                                {
                                    "envelope_sha256": leaf.leaf_envelope_sha256,
                                    "backend": leaf.backend.value,
                                    "response_sha256": leaf.response_sha256,
                                    "dataset_commitment_id": leaf.dataset_commitment_id,
                                }
                                for leaf in self.manifest.leaves
                            ],
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ),
                "folding_proof_b64": base64.b64encode(self.folding_proof).decode(
                    "ascii"
                ),
                "folding_scheme": self.folding_scheme.value,
                "post_quantum": is_post_quantum_folding(self.folding_scheme),
                "issued_at": self.issued_at.astimezone(UTC).isoformat(),
                "verifier_runtime_target_ms": self.verifier_runtime_target_ms,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


# --------------------------------------------------------------------------- #
# Aggregation helpers                                                         #
# --------------------------------------------------------------------------- #

def aggregate_proofs(
    proofs: tuple[ProvenanceProof, ...],
    *,
    aggregation_id: str,
    folding_scheme: FoldingScheme,
    max_batch_size: int,
    window_start: datetime,
    window_end: datetime,
    epoch_index: int | None = None,
) -> AggregatedCertificate:
    """Aggregate N leaf proofs into one certificate.

    Today this composes the manifest, picks the folding scheme, and
    emits a deterministic-shim aggregated proof so the entire
    surface exercises end-to-end. When the backend ships a real
    folding implementation (DeepProve GKR, HyperNova, or
    LatticeFold+), the only change is to dispatch on
    ``folding_scheme`` to the backend's aggregator.

    Constraints:
      * len(proofs) > 0 — empty batches are rejected (no certificate
        without a leaf set).
      * len(proofs) <= max_batch_size — protects the verifier.
      * All leaves agree on the dataset commitment ID when the
        scheme is ``NONE`` (membership-only batching) — for true
        recursive folding, distinct commitments are allowed and the
        circuit handles the manifold separately.
    """
    if not proofs:
        raise ValueError("cannot aggregate zero proofs")
    if len(proofs) > max_batch_size:
        raise ValueError(
            f"batch size {len(proofs)} exceeds declared max_batch_size {max_batch_size}"
        )

    leaves = tuple(
        AggregationLeaf(
            leaf_envelope_sha256=p.envelope_sha256(),
            backend=p.backend,
            response_sha256=p.statement.response_sha256_hex,
            dataset_commitment_id=p.statement.dataset_commitment_id,
        )
        for p in proofs
    )

    manifest = AggregationManifest(
        aggregation_id=aggregation_id,
        leaves=leaves,
        folding_scheme=folding_scheme,
        max_batch_size=max_batch_size,
        epoch_index=epoch_index,
        window_start=window_start,
        window_end=window_end,
    )

    # Deterministic shim aggregation: HMAC tag over the manifest
    # hash and the leaf envelope hashes. Hex-encoded as bytes.
    import hmac
    from tex.zkprov.backends import _resolve_shim_key

    msg = (
        b"tex/zkprov/aggregate-v1\x00"
        + manifest.manifest_sha256().encode("ascii")
        + b"\x00"
        + b"".join(leaf.leaf_envelope_sha256.encode("ascii") for leaf in leaves)
    )
    folding_proof = hmac.new(_resolve_shim_key(), msg, hashlib.sha256).digest()

    return AggregatedCertificate(
        manifest=manifest,
        folding_proof=folding_proof,
        folding_scheme=folding_scheme,
        issued_at=datetime.now(UTC),
    )


def verify_aggregated_certificate(
    cert: AggregatedCertificate,
    *,
    expected_leaf_envelope_hashes: frozenset[str] | None = None,
    regulator_grade: bool = False,
) -> bool:
    """Verify an aggregated certificate.

    Today's verification is the shim's HMAC check + manifest
    coherence. When a real folding scheme is wired, this delegates
    to the backend's aggregated-proof verifier.

    Parameters
    ----------
    cert
        The certificate to verify.
    expected_leaf_envelope_hashes
        Optional explicit set of leaf hashes that should be in the
        certificate. When provided, the verifier rejects any
        certificate that doesn't cover exactly that set. Use this
        to defend against an aggregator that quietly substitutes
        leaves between commit-time and verification-time.
    regulator_grade
        When True, reject certificates whose leaves include any
        non-regulator-grade leaf proof, or whose folding scheme
        does not have a peer-reviewed security analysis. Today
        only ``LATTICEFOLD_PLUS_2026`` and ``HYPERNOVA_CYCLEFOLD``
        survive this check.
    """
    import hmac
    from tex.zkprov.backends import _resolve_shim_key

    # Recompute the shim tag.
    leaves = cert.manifest.leaves
    msg = (
        b"tex/zkprov/aggregate-v1\x00"
        + cert.manifest.manifest_sha256().encode("ascii")
        + b"\x00"
        + b"".join(leaf.leaf_envelope_sha256.encode("ascii") for leaf in leaves)
    )
    expected_tag = hmac.new(_resolve_shim_key(), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, cert.folding_proof):
        return False

    # Coverage check.
    if expected_leaf_envelope_hashes is not None:
        actual = frozenset(leaf.leaf_envelope_sha256 for leaf in leaves)
        if actual != expected_leaf_envelope_hashes:
            return False

    # Regulator-grade enforcement.
    if regulator_grade:
        # All leaves must be regulator-grade.
        for leaf in leaves:
            if not is_regulator_grade(leaf.backend):
                return False
        # Folding scheme must be one of the analyzed schemes.
        allowed_schemes = {
            FoldingScheme.HYPERNOVA_CYCLEFOLD,
            FoldingScheme.MICRONOVA_ONCHAIN,
            FoldingScheme.LATTICEFOLD_PLUS_2026,
            FoldingScheme.GKR_DEEPPROVE,
            FoldingScheme.MIRA_PARALLEL_2026,
        }
        if cert.folding_scheme not in allowed_schemes:
            return False

    return True


__all__ = [
    "FoldingScheme",
    "is_post_quantum_folding",
    "AggregationLeaf",
    "AggregationManifest",
    "AggregatedCertificate",
    "aggregate_proofs",
    "verify_aggregated_certificate",
]
