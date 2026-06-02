"""
Dataset manifest with EU AI Act Article 53(1)(d) TDS Template binding.

Frontier delta vs. ZKPROV (arxiv 2506.20915)
--------------------------------------------
ZKPROV's original construction commits to a Merkle root over dataset
records plus an attribute-schema hash. That's sufficient for the
"was-this-record-used" proof but is silent on the regulatory binding
that customers actually need.

This module extends the commitment surface with the five elements that
the post-ZKPROV state of the art (VFT, arxiv 2510.16830 v3, Dec 29 2025)
proved necessary for a defensible training-data attestation:

1. **Data sources** — pinned URIs / dataset IDs with cryptographic content
   addressing so a regulator can mechanically check the manifest against
   the auditable summary published per Article 53(1)(d).
2. **Preprocessing** — content-addressed serialization of the cleaning /
   tokenization pipeline so the audit covers "what was actually fed to the
   optimizer", not "what was downloaded from huggingface".
3. **Licenses** — explicit license tags per source so the EU AI Office's
   "respect copyright opt-outs" obligation is mechanically verifiable.
4. **Per-epoch quota counters** — VFT's headline contribution. The
   manifest declares an upper bound on how many gradient steps each
   source may participate in; the proof then attests the bound was not
   exceeded. This is what the EU AI Office "post-market training" audit
   regime needs and is absent from ZKPROV.
5. **EU AI Act TDS Template fields** — the European Commission's
   "Training Data Summary" template (published 24 July 2025) made
   specific categorical disclosures mandatory. We carry those fields
   in the manifest so a single artifact answers both the cryptographic
   provenance question and the regulatory disclosure question.

Why this matters for Tex
------------------------
Microsoft Agent Governance Toolkit (Apr 2 2026) — the primary OSS
competitor — does identity, policy, runtime gates. **It does not do
training-data provenance.** No incumbent in the May 2026 landscape
(Noma, Zenity, Pillar, Lakera, Lagrange-as-AI-only, Mastercard
Verifiable Intent) has shipped a regulator-grade training-data
attestation surface. This module is the wedge.

Wire format
-----------
The manifest is a frozen Pydantic v2 model (Section 3 of the standing
orders). The canonical-JSON form is what's actually fed into the
Merkle leaves and into the CA signature; ``manifest_root_hash`` is
the deterministic content hash you reference downstream.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------- #
# License taxonomy                                                            #
# --------------------------------------------------------------------------- #
#
# The EU AI Office GPAI Code of Practice (final June 2026) and the
# Training Data Summary template (July 2025) both reference SPDX
# identifiers as the canonical machine-readable license tag. We stay
# strictly within that taxonomy so the manifest is consumable by the
# AI Office's audit tooling without translation.

class LicenseTag(str, Enum):
    """SPDX-aligned license tags carried in the manifest.

    Only the identifiers permitted by the EU AI Office TDS Template are
    enumerated here. ``PROPRIETARY_PRIVATE``, ``SYNTHETIC``, and
    ``USER_DATA`` are the template's own non-SPDX categorical buckets.
    """

    CC0_1_0 = "CC0-1.0"
    CC_BY_4_0 = "CC-BY-4.0"
    CC_BY_SA_4_0 = "CC-BY-SA-4.0"
    APACHE_2_0 = "Apache-2.0"
    MIT = "MIT"
    BSD_3_CLAUSE = "BSD-3-Clause"
    GPL_3_0 = "GPL-3.0-only"
    PUBLIC_DOMAIN = "PublicDomain"

    # Non-SPDX TDS Template categories (Article 53(1)(d) public summary).
    PROPRIETARY_PRIVATE = "TDS:Proprietary-Private"
    PROPRIETARY_LICENSED = "TDS:Proprietary-Licensed"
    SCRAPED_PUBLIC = "TDS:Scraped-Public"
    SYNTHETIC = "TDS:Synthetic"
    USER_DATA = "TDS:User-Data"


# --------------------------------------------------------------------------- #
# TDS Template source category — EU AI Office, 24 July 2025                   #
# --------------------------------------------------------------------------- #

class TDSSourceCategory(str, Enum):
    """Article 53(1)(d) Training Data Summary Template source categories.

    These are the exact buckets defined in the European Commission's
    mandatory template (24 July 2025). Every ``DataSource`` in the
    manifest is classified into exactly one of these so the manifest
    can be projected onto the public summary without further mapping.
    """

    PUBLICLY_AVAILABLE_DATASET = "publicly-available-dataset"
    PRIVATELY_LICENSED_DATASET = "privately-licensed-dataset"
    SCRAPED_WEB_CONTENT = "scraped-web-content"
    USER_DATA = "user-data"
    SYNTHETIC_DATA = "synthetic-data"
    OTHER = "other"


# --------------------------------------------------------------------------- #
# Data source                                                                 #
# --------------------------------------------------------------------------- #

class DataSource(BaseModel):
    """A single content-addressed data source.

    A ``DataSource`` is what the regulator will ultimately audit. It
    pins the source by both human-readable identifier (``source_uri``,
    e.g. ``hf://allenai/dolma/v1.7`` or ``s3://acme-research/q3-2025``)
    and by content hash. The content hash is what's actually carried
    into the Merkle leaves; the URI is metadata.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(
        min_length=1,
        max_length=200,
        description="Stable identifier for this source within the manifest.",
    )
    source_uri: str = Field(
        min_length=1,
        max_length=2048,
        description="Locator for the source: HF dataset URI, S3 path, etc.",
    )
    content_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of the raw source contents.",
    )
    record_count: int = Field(
        ge=0,
        description="Number of records contributed by this source.",
    )
    tds_category: TDSSourceCategory
    license: LicenseTag
    license_extra: str = Field(
        default="",
        max_length=4096,
        description=(
            "Free-text license clarifications (e.g. CC-BY attribution "
            "string, opt-out URL). The TDS Template makes this optional."
        ),
    )

    # VFT element 1 — per-source quota. The proof attests
    # ``epochs_consumed <= max_epoch_participation`` for each source.
    max_epoch_participation: int = Field(
        ge=0,
        description=(
            "Upper bound on the number of training epochs in which this "
            "source's records may participate. VFT-style quota counter."
        ),
    )

    @field_validator("content_sha256", mode="before")
    @classmethod
    def _normalize_hex(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("content_sha256 must be a string.")
        normalized = value.strip().lower()
        if len(normalized) != 64:
            raise ValueError("content_sha256 must be 64 hex chars.")
        if any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("content_sha256 must be lowercase hex.")
        return normalized


# --------------------------------------------------------------------------- #
# Preprocessing step                                                          #
# --------------------------------------------------------------------------- #

class PreprocessingStep(BaseModel):
    """Content-addressed preprocessing step.

    VFT showed that without committing to the preprocessing pipeline,
    the dataset commitment is gameable: the prover can use authorized
    *records* but route them through an unauthorized cleaning step
    (PII removal disabled, deduplication rigged, tokenizer swapped).
    Each step here is a tagged hash of the actual code that ran.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    code_sha256: str = Field(min_length=64, max_length=64)
    config_sha256: str = Field(min_length=64, max_length=64)
    order: int = Field(ge=0, description="Position in the preprocessing pipeline.")

    @field_validator("code_sha256", "config_sha256", mode="before")
    @classmethod
    def _hex(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("hash must be string")
        n = value.strip().lower()
        if len(n) != 64 or any(c not in "0123456789abcdef" for c in n):
            raise ValueError("must be 64-char lowercase hex")
        return n


# --------------------------------------------------------------------------- #
# Manifest                                                                    #
# --------------------------------------------------------------------------- #

class DatasetManifest(BaseModel):
    """Full VFT-extended dataset manifest.

    This is the artifact that the CA signs. The downstream Merkle tree
    and ZK proof statements reference the manifest by its
    ``manifest_root_hash`` (the SHA-256 of the canonical-JSON
    serialization of this object with ``manifest_root_hash`` excluded).

    Cite: arxiv 2510.16830 §III.A (commitment design), European
    Commission TDS Template (24 July 2025), GPAI CoP Transparency
    Chapter (final June 2026).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str = Field(min_length=1, max_length=200)
    model_card_uri: str = Field(
        min_length=1,
        max_length=2048,
        description="URI of the public model card (TDS Template §4.2).",
    )
    model_provider: str = Field(
        min_length=1,
        max_length=200,
        description="Legal entity name of the GPAI provider.",
    )
    sources: tuple[DataSource, ...] = Field(min_length=1, max_length=4096)
    preprocessing: tuple[PreprocessingStep, ...] = Field(min_length=0, max_length=64)

    # VFT element 3 — declared training program. We carry only the
    # parameters that the regulator needs to verify the manifest is
    # consistent with the published TDS; the full optimizer trace
    # lives in the proof, not here.
    total_training_epochs: int = Field(
        ge=1,
        description="Total training epochs the manifest authorizes.",
    )
    base_model_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="Content hash of the public initialization checkpoint.",
    )

    # EU AI Office TDS Template §3 — temporal scope.
    training_window_start: datetime
    training_window_end: datetime

    # Algorithm-agility tag for the dataset Merkle hash and the proof
    # backend. Two strings rather than booleans / enums here because
    # we want explicit version pinning that ages well alongside the
    # ``tex.pqcrypto.algorithm_agility`` enum.
    merkle_hash_alg: str = Field(
        default="poseidon-bn254-t3",
        max_length=128,
        description=(
            "Identifier for the ZK-friendly hash used in the Merkle "
            "tree. Default is Poseidon (Grassi-Khovratovich-"
            "Rechberger-Roy-Schofnegger, USENIX Security 2021, "
            "eprint 2019/458) parameterized for BN254 with t=3 "
            "(rate=2, capacity=1), alpha=5, RF=8, RP=57, "
            "128-bit security. ``poseidon2-bn254-t3`` is the upgrade "
            "path (eprint 2023/323, ~30% fewer Plonk constraints) "
            "and ``sha256-reduced-bn254`` is the fallback when the "
            "``poseidon-hash`` PyPI package is unavailable. "
            "Regulator-grade verification refuses the SHA-256 "
            "fallback the same way it refuses the deterministic-"
            "shim proof backend."
        ),
    )
    proof_backend: str = Field(
        default="halo2-ipa-2026",
        max_length=128,
        description=(
            "Identifier for the SNARK proving system used downstream. "
            "Halo2-IPA is no-trusted-setup; LatticeFold+ (eprint "
            "2026/721, Apr 2026) is the post-quantum path. The actual "
            "backend resolution lives in tex.zkprov.backends."
        ),
    )

    issued_at: datetime
    valid_until: datetime

    @field_validator("base_model_sha256", mode="before")
    @classmethod
    def _hex_root(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("base_model_sha256 must be a string")
        n = value.strip().lower()
        if len(n) != 64 or any(c not in "0123456789abcdef" for c in n):
            raise ValueError("base_model_sha256 must be 64 hex chars")
        return n

    @field_validator("sources")
    @classmethod
    def _unique_source_ids(cls, value: tuple[DataSource, ...]) -> tuple[DataSource, ...]:
        ids = [s.source_id for s in value]
        if len(set(ids)) != len(ids):
            raise ValueError("DataSource.source_id must be unique within a manifest.")
        return value

    @field_validator("preprocessing")
    @classmethod
    def _ordered_preprocessing(
        cls,
        value: tuple[PreprocessingStep, ...],
    ) -> tuple[PreprocessingStep, ...]:
        # Step order must form a contiguous 0..N-1 sequence.
        orders = [p.order for p in value]
        if orders and sorted(orders) != list(range(len(orders))):
            raise ValueError(
                "PreprocessingStep.order must be a contiguous 0..N-1 sequence."
            )
        return value

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical-JSON encoding of the manifest.

        This is what the CA signs and what gets fed into the
        Merkle/proof-context binding. Field ordering is alphabetic,
        timestamps are RFC 3339 UTC.
        """
        payload: dict[str, object] = {
            "manifest_id": self.manifest_id,
            "model_card_uri": self.model_card_uri,
            "model_provider": self.model_provider,
            "base_model_sha256": self.base_model_sha256,
            "total_training_epochs": self.total_training_epochs,
            "merkle_hash_alg": self.merkle_hash_alg,
            "proof_backend": self.proof_backend,
            "training_window_start": self.training_window_start.astimezone(UTC).isoformat(),
            "training_window_end": self.training_window_end.astimezone(UTC).isoformat(),
            "issued_at": self.issued_at.astimezone(UTC).isoformat(),
            "valid_until": self.valid_until.astimezone(UTC).isoformat(),
            "sources": [
                {
                    "source_id": s.source_id,
                    "source_uri": s.source_uri,
                    "content_sha256": s.content_sha256,
                    "record_count": s.record_count,
                    "tds_category": s.tds_category.value,
                    "license": s.license.value,
                    "license_extra": s.license_extra,
                    "max_epoch_participation": s.max_epoch_participation,
                }
                for s in self.sources
            ],
            "preprocessing": [
                {
                    "name": p.name,
                    "code_sha256": p.code_sha256,
                    "config_sha256": p.config_sha256,
                    "order": p.order,
                }
                for p in self.preprocessing
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def manifest_root_hash(self) -> str:
        """SHA-256 of the canonical encoding. Hex.

        SHA-256 here is the public, audit-side identifier (matches
        EvidenceRecord.payload_sha256 conventions). The ZK-friendly
        Poseidon2 root over individual records is computed separately
        by ``tex.zkprov.commitment.build_merkle_root`` and is what's
        actually constrained inside the circuit.
        """
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# TDS public summary projection                                               #
# --------------------------------------------------------------------------- #

class TDSPublicSummary(BaseModel):
    """Projection of a manifest onto the Article 53(1)(d) public summary.

    This is what providers publish to satisfy the August 2 2026
    transparency obligation. It contains only the categorical buckets
    and aggregates that the TDS Template marks as public, never the
    per-record content hashes from the underlying manifest.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    model_provider: str
    model_card_uri: str
    records_by_category: dict[str, int]
    licenses_present: tuple[str, ...]
    training_window_start: datetime
    training_window_end: datetime
    manifest_root_hash: str = Field(
        min_length=64,
        max_length=64,
        description=(
            "Public reference to the underlying signed manifest. A "
            "regulator who needs more detail than the public summary "
            "uses this hash to request the private manifest from the "
            "provider; downstream ZKPROV proofs then bind each model "
            "output to a record IN that manifest."
        ),
    )


def project_to_tds_summary(manifest: DatasetManifest) -> TDSPublicSummary:
    """Build the public Article 53(1)(d) summary from a full manifest."""
    by_cat: dict[str, int] = {}
    for src in manifest.sources:
        by_cat[src.tds_category.value] = by_cat.get(src.tds_category.value, 0) + src.record_count

    licenses_seen = tuple(sorted({s.license.value for s in manifest.sources}))

    return TDSPublicSummary(
        manifest_id=manifest.manifest_id,
        model_provider=manifest.model_provider,
        model_card_uri=manifest.model_card_uri,
        records_by_category=by_cat,
        licenses_present=licenses_seen,
        training_window_start=manifest.training_window_start,
        training_window_end=manifest.training_window_end,
        manifest_root_hash=manifest.manifest_root_hash(),
    )


__all__ = [
    "LicenseTag",
    "TDSSourceCategory",
    "DataSource",
    "PreprocessingStep",
    "DatasetManifest",
    "TDSPublicSummary",
    "project_to_tds_summary",
]
