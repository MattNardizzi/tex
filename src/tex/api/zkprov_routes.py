"""
``/v1/zkprov`` API surface — Thread 14.

Endpoints
---------
* ``POST /v1/zkprov/issue-commitment``  — issue a CA-signed
  DatasetCommitment over a record set + manifest.
* ``POST /v1/zkprov/prove``             — generate a ProvenanceProof
  binding a (prompt, response, attributes) tuple to a committed
  dataset.
* ``POST /v1/zkprov/verify``            — verify a ProvenanceProof.
  This is the acceptance-criterion-4 endpoint.
* ``POST /v1/zkprov/aggregate``         — fold N leaf proofs into a
  single AggregatedCertificate (VFT element 4 + LatticeFold+
  post-quantum folding for eligible deployments).
* ``POST /v1/zkprov/narrow``            — project a DatasetManifest
  to a SCITT-ARP NarrowedClaim (draft-hillier-scitt-arp-00,
  May 1 2026).
* ``GET  /v1/zkprov/proof/{envelope_sha256}`` — retrieve a stored
  proof from the durable provenance_proofs store.
* ``GET  /v1/zkprov/health``            — feature-flag + store
  availability surface for ops.

Design properties
-----------------
1. All endpoints route through the same in-module primitives in
   ``tex.zkprov.*`` so external auditors use the same code path
   used internally on ``/v1/guardrail`` augmentation.
2. All request/response models are Pydantic v2
   ``frozen=True, extra="forbid"`` per Section 3.
3. **Authentication is required** (Wave-0 credibility floor): the router
   carries a ``RequireScope("evidence:read")`` dependency, so every
   endpoint needs an authenticated principal. Endpoints that mint a
   CA-signed commitment or generate/persist a proof (``issue-commitment``,
   ``prove``) additionally require ``evidence:write``. Against a keyless
   dev backend (no ``TEX_API_KEYS``) the anonymous principal carries
   every scope. The cryptographic envelope is still the bearer of trust
   for *verification*; auth gates *who may call the surface*. (Same
   posture as ``/v1/vet/*``.)
4. The proof envelope is delivered as a JSON string field (the
   canonical envelope JSON), not a re-parsed object, so the
   wire is byte-stable and the SHA-256 reference can be
   recomputed by any consumer.
5. The Postgres store is constructed lazily and module-scoped so
   the API surface is functional out-of-the-box on environments
   without DATABASE_URL (it falls back to in-memory and logs).
"""

from __future__ import annotations

import base64
import functools
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope
from tex.stores.provenance_proofs_postgres import PostgresProvenanceProofStore
from tex.zkprov.backends import ProofBackendId, is_regulator_grade
from tex.zkprov.commitment import (
    DatasetCommitment,
    deterministic_test_ca,
    issue_commitment,
    verify_commitment_signature,
    verify_commitment_valid,
)
from tex.zkprov.manifest import (
    DatasetManifest,
    DataSource,
    LicenseTag,
    PreprocessingStep,
    TDSPublicSummary,
    TDSSourceCategory,
    project_to_tds_summary,
)
from tex.zkprov.proof import (
    CIRCUIT_VERSION,
    ProofVerification,
    ProvenanceProof,
    generate_proof,
    verify_proof,
)
from tex.zkprov.recursive import (
    AggregatedCertificate,
    FoldingScheme,
    aggregate_proofs,
    verify_aggregated_certificate,
)
from tex.zkprov.scitt_arp import (
    ARPPredicate,
    ARPPredicateLibrary,
    NarrowedClaim,
    narrow_manifest_data_volume,
    narrow_manifest_license_family,
    narrow_manifest_temporal_window,
)


__all__ = ["router"]


# Baseline: every /v1/zkprov/* route requires an authenticated principal
# carrying ``evidence:read``; minting/persisting endpoints elevate to
# ``evidence:write`` per-route. Router-level wiring makes a future
# unauthenticated route impossible to ship by accident.
router = APIRouter(
    prefix="/v1/zkprov",
    tags=["zkprov"],
    dependencies=[Depends(RequireScope("evidence:read"))],
)

_REQUIRE_WRITE = Depends(RequireScope("evidence:write"))


# Module-scoped store. Lazy-built so import-time has no DB I/O.
@functools.lru_cache(maxsize=1)
def _store() -> PostgresProvenanceProofStore:
    return PostgresProvenanceProofStore()


# --------------------------------------------------------------------------- #
# Common DTOs                                                                  #
# --------------------------------------------------------------------------- #


class _DataSourceDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(min_length=1, max_length=200)
    source_uri: str = Field(min_length=1, max_length=2048)
    content_sha256: str = Field(min_length=64, max_length=64)
    record_count: int = Field(ge=0)
    tds_category: TDSSourceCategory
    license: LicenseTag
    license_extra: str = Field(default="", max_length=4096)
    max_epoch_participation: int = Field(ge=0)

    def to_domain(self) -> DataSource:
        return DataSource(
            source_id=self.source_id,
            source_uri=self.source_uri,
            content_sha256=self.content_sha256,
            record_count=self.record_count,
            tds_category=self.tds_category,
            license=self.license,
            license_extra=self.license_extra,
            max_epoch_participation=self.max_epoch_participation,
        )


class _PreprocessingStepDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    code_sha256: str = Field(min_length=64, max_length=64)
    config_sha256: str = Field(min_length=64, max_length=64)
    order: int = Field(ge=0)

    def to_domain(self) -> PreprocessingStep:
        return PreprocessingStep(
            name=self.name,
            code_sha256=self.code_sha256,
            config_sha256=self.config_sha256,
            order=self.order,
        )


class _ManifestDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str = Field(min_length=1, max_length=200)
    model_card_uri: str = Field(min_length=1, max_length=2048)
    model_provider: str = Field(min_length=1, max_length=200)
    sources: tuple[_DataSourceDTO, ...] = Field(min_length=1, max_length=4096)
    preprocessing: tuple[_PreprocessingStepDTO, ...] = Field(
        default=(), max_length=64
    )
    total_training_epochs: int = Field(ge=1)
    base_model_sha256: str = Field(min_length=64, max_length=64)
    training_window_start: datetime
    training_window_end: datetime
    merkle_hash_alg: str = Field(default="poseidon2-bn254-t3", max_length=128)
    proof_backend: str = Field(default="halo2-ipa-2026", max_length=128)
    issued_at: datetime
    valid_until: datetime

    def to_domain(self) -> DatasetManifest:
        return DatasetManifest(
            manifest_id=self.manifest_id,
            model_card_uri=self.model_card_uri,
            model_provider=self.model_provider,
            sources=tuple(s.to_domain() for s in self.sources),
            preprocessing=tuple(p.to_domain() for p in self.preprocessing),
            total_training_epochs=self.total_training_epochs,
            base_model_sha256=self.base_model_sha256,
            training_window_start=self.training_window_start,
            training_window_end=self.training_window_end,
            merkle_hash_alg=self.merkle_hash_alg,
            proof_backend=self.proof_backend,
            issued_at=self.issued_at,
            valid_until=self.valid_until,
        )


class _CommitmentEnvelopeDTO(BaseModel):
    """Wire form of a DatasetCommitment.

    Bytes fields are base64-encoded so the envelope is pure-JSON-safe.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str
    manifest_root_hash: str
    poseidon_root_hex: str
    audit_root_hex: str
    record_count: int
    schema_canonical_hash: str
    issued_at: datetime
    valid_until: datetime
    ca_algorithm: str  # SignatureAlgorithm.value
    ca_signature_b64: str
    ca_public_key_b64: str
    ca_key_id: str

    @staticmethod
    def from_domain(c: DatasetCommitment) -> "_CommitmentEnvelopeDTO":
        return _CommitmentEnvelopeDTO(
            dataset_id=c.dataset_id,
            manifest_root_hash=c.manifest_root_hash,
            poseidon_root_hex=c.poseidon_root_hex,
            audit_root_hex=c.audit_root_hex,
            record_count=c.record_count,
            schema_canonical_hash=c.schema_canonical_hash,
            issued_at=c.issued_at,
            valid_until=c.valid_until,
            ca_algorithm=c.ca_algorithm.value,
            ca_signature_b64=base64.b64encode(c.ca_signature).decode("ascii"),
            ca_public_key_b64=base64.b64encode(c.ca_public_key).decode("ascii"),
            ca_key_id=c.ca_key_id,
        )

    def to_domain(self) -> DatasetCommitment:
        from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

        return DatasetCommitment(
            dataset_id=self.dataset_id,
            manifest_root_hash=self.manifest_root_hash,
            poseidon_root_hex=self.poseidon_root_hex,
            audit_root_hex=self.audit_root_hex,
            record_count=self.record_count,
            schema_canonical_hash=self.schema_canonical_hash,
            issued_at=self.issued_at,
            valid_until=self.valid_until,
            ca_algorithm=SignatureAlgorithm(self.ca_algorithm),
            ca_signature=base64.b64decode(self.ca_signature_b64),
            ca_public_key=base64.b64decode(self.ca_public_key_b64),
            ca_key_id=self.ca_key_id,
        )


# --------------------------------------------------------------------------- #
# /issue-commitment                                                            #
# --------------------------------------------------------------------------- #


class IssueCommitmentRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str = Field(min_length=1, max_length=200)
    record_bytes_b64: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    manifest: _ManifestDTO
    schema_canonical_json_b64: str = Field(min_length=1)
    valid_for_seconds: int = Field(default=365 * 24 * 3600, ge=60, le=10 * 365 * 24 * 3600)

    # The CA key. Production deployments POST a key-id reference
    # into an HSM keystore here; tests/demos use the deterministic
    # Ed25519 factory.
    use_deterministic_test_ca: bool = Field(default=False)
    test_ca_label: str = Field(default="default", max_length=200)


class IssueCommitmentResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    commitment: _CommitmentEnvelopeDTO
    tds_public_summary: TDSPublicSummary


@router.post(
    "/issue-commitment",
    response_model=IssueCommitmentResponse,
    dependencies=[_REQUIRE_WRITE],
)
def issue_commitment_endpoint(body: IssueCommitmentRequest) -> IssueCommitmentResponse:
    if not body.use_deterministic_test_ca:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Production CA flow requires posting an HSM key-id "
                "reference; this route currently supports only the "
                "deterministic test CA (set use_deterministic_test_ca "
                "to True). The deterministic test CA is Ed25519-based "
                "and intended for tests, demos, and integration "
                "exercises only — never for regulator-grade signing."
            ),
        )
    try:
        records = tuple(base64.b64decode(r) for r in body.record_bytes_b64)
        schema_bytes = base64.b64decode(body.schema_canonical_json_b64)
        manifest = body.manifest.to_domain()
        ca = deterministic_test_ca(body.test_ca_label)
        commitment = issue_commitment(
            dataset_id=body.dataset_id,
            dataset_records=records,
            manifest=manifest,
            ca_keypair=ca,
            schema_canonical_json=schema_bytes,
            valid_for_seconds=body.valid_for_seconds,
        )
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return IssueCommitmentResponse(
        commitment=_CommitmentEnvelopeDTO.from_domain(commitment),
        tds_public_summary=project_to_tds_summary(manifest),
    )


# --------------------------------------------------------------------------- #
# /prove                                                                       #
# --------------------------------------------------------------------------- #


class ProveRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    response: str = Field(min_length=0, max_length=1_048_576)
    prompt: str = Field(min_length=0, max_length=1_048_576)
    prompt_attributes: dict[str, Any] = Field(default_factory=dict)
    model_commitment_hash: str = Field(min_length=64, max_length=64)
    commitment: _CommitmentEnvelopeDTO
    manifest: _ManifestDTO
    private_witness_b64: str = Field(min_length=1)
    allow_shim_fallback: bool = Field(default=True)
    backend_override: str | None = Field(default=None, max_length=128)
    decision_id: UUID | None = None
    persist_to_store: bool = Field(default=False)
    tenant_id: str = Field(default="default", max_length=200)


class ProveResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_envelope_json: str
    proof_envelope_sha256: str
    backend: str
    is_regulator_grade: bool


@router.post(
    "/prove",
    response_model=ProveResponse,
    dependencies=[_REQUIRE_WRITE],
)
def prove_endpoint(body: ProveRequest) -> ProveResponse:
    try:
        commitment = body.commitment.to_domain()
        manifest = body.manifest.to_domain()
        witness = base64.b64decode(body.private_witness_b64)
        backend_override = (
            ProofBackendId(body.backend_override) if body.backend_override else None
        )
        proof = generate_proof(
            response=body.response,
            prompt=body.prompt,
            prompt_attributes=body.prompt_attributes,
            model_commitment_hash=body.model_commitment_hash,
            commitment=commitment,
            manifest=manifest,
            private_witness=witness,
            allow_shim_fallback=body.allow_shim_fallback,
            backend_override=backend_override,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    envelope_json = proof.to_envelope_json()
    env_hash = proof.envelope_sha256()

    if body.persist_to_store:
        decision_id = body.decision_id or uuid4()
        try:
            _store().save(decision_id=decision_id, proof=proof, tenant_id=body.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=f"failed to persist proof: {exc}",
            ) from exc

    return ProveResponse(
        proof_envelope_json=envelope_json,
        proof_envelope_sha256=env_hash,
        backend=proof.backend.value,
        is_regulator_grade=is_regulator_grade(proof.backend),
    )


# --------------------------------------------------------------------------- #
# /verify                                                                      #
# --------------------------------------------------------------------------- #


class VerifyRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_envelope_json: str = Field(min_length=1, max_length=10 * 1_048_576)
    expected_commitment: _CommitmentEnvelopeDTO
    expected_response_sha256_hex: str = Field(min_length=64, max_length=64)
    regulator_grade: bool = Field(default=False)


class VerifyResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool
    is_regulator_grade: bool
    statement_consistent: bool
    backend_verdict: bool
    commitment_signature_valid: bool
    commitment_in_lifetime: bool
    statement_binds_commitment: bool
    reason: str | None = None


@router.post("/verify", response_model=VerifyResponse)
def verify_endpoint(body: VerifyRequest) -> VerifyResponse:
    try:
        proof = ProvenanceProof.from_envelope_json(body.proof_envelope_json)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"malformed proof envelope: {exc}",
        ) from exc

    expected = body.expected_commitment.to_domain()
    result: ProofVerification = verify_proof(
        proof,
        expected_dataset_commitment=expected,
        expected_response_sha256_hex=body.expected_response_sha256_hex,
        regulator_grade=body.regulator_grade,
    )
    return VerifyResponse(**result.summary_dict)


# --------------------------------------------------------------------------- #
# /aggregate                                                                   #
# --------------------------------------------------------------------------- #


class AggregateRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    aggregation_id: str = Field(min_length=1, max_length=200)
    proof_envelopes_json: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    folding_scheme: FoldingScheme = FoldingScheme.HYPERNOVA_CYCLEFOLD
    max_batch_size: int = Field(ge=1, le=10_000)
    window_start: datetime
    window_end: datetime
    epoch_index: int | None = None


class AggregateResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate_envelope_json: str
    folding_scheme: str
    post_quantum: bool
    leaf_count: int


@router.post("/aggregate", response_model=AggregateResponse)
def aggregate_endpoint(body: AggregateRequest) -> AggregateResponse:
    try:
        proofs = tuple(
            ProvenanceProof.from_envelope_json(env) for env in body.proof_envelopes_json
        )
        cert: AggregatedCertificate = aggregate_proofs(
            proofs,
            aggregation_id=body.aggregation_id,
            folding_scheme=body.folding_scheme,
            max_batch_size=body.max_batch_size,
            window_start=body.window_start,
            window_end=body.window_end,
            epoch_index=body.epoch_index,
        )
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    from tex.zkprov.recursive import is_post_quantum_folding

    return AggregateResponse(
        certificate_envelope_json=cert.to_envelope_json(),
        folding_scheme=cert.folding_scheme.value,
        post_quantum=is_post_quantum_folding(cert.folding_scheme),
        leaf_count=len(cert.manifest.leaves),
    )


# --------------------------------------------------------------------------- #
# /narrow — SCITT ARP                                                          #
# --------------------------------------------------------------------------- #


class NarrowRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest: _ManifestDTO
    predicate: ARPPredicate
    cutoff_date: datetime | None = None  # only used for TEMPORAL_WINDOW_OVERLAP


class NarrowResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_root_hash: str
    predicate: str
    predicate_value: str
    policy_version_hash: str
    pattern_library_hash: str
    divergence_axis: str
    asserted_at: datetime


@router.post("/narrow", response_model=NarrowResponse)
def narrow_endpoint(body: NarrowRequest) -> NarrowResponse:
    manifest = body.manifest.to_domain()
    library = ARPPredicateLibrary.default()
    try:
        if body.predicate is ARPPredicate.DATA_VOLUME_BUCKET:
            claim = narrow_manifest_data_volume(manifest, library)
        elif body.predicate is ARPPredicate.LICENSE_FAMILY_PRESENT:
            claim = narrow_manifest_license_family(manifest, library)
        elif body.predicate is ARPPredicate.TEMPORAL_WINDOW_OVERLAP:
            if body.cutoff_date is None:
                raise HTTPException(
                    status_code=400,
                    detail="cutoff_date required for TEMPORAL_WINDOW_OVERLAP",
                )
            claim = narrow_manifest_temporal_window(
                manifest, library, cutoff=body.cutoff_date
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"narrowing for predicate {body.predicate.value} "
                    f"is not yet implemented; supported predicates: "
                    f"DATA_VOLUME_BUCKET, LICENSE_FAMILY_PRESENT, "
                    f"TEMPORAL_WINDOW_OVERLAP"
                ),
            )
    except HTTPException:
        raise
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return NarrowResponse(
        manifest_root_hash=claim.manifest_root_hash,
        predicate=claim.predicate.value,
        predicate_value=claim.predicate_value,
        policy_version_hash=claim.policy_version_hash,
        pattern_library_hash=claim.pattern_library_hash,
        divergence_axis=claim.divergence_axis,
        asserted_at=claim.asserted_at,
    )


# --------------------------------------------------------------------------- #
# /proof/{envelope_sha256}                                                     #
# --------------------------------------------------------------------------- #


class GetProofResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    envelope_sha256: str
    envelope_json: str
    backend: str
    is_regulator_grade: bool
    issued_at: datetime
    dataset_commitment_id: str
    manifest_root_hash: str


@router.get("/proof/{envelope_sha256}", response_model=GetProofResponse)
def get_proof_endpoint(envelope_sha256: str = Path(min_length=64, max_length=64)) -> GetProofResponse:
    row = _store().get(envelope_sha256)
    if row is None:
        raise HTTPException(status_code=404, detail="proof not found")
    return GetProofResponse(
        envelope_sha256=row["proof_envelope_sha256"],
        envelope_json=row["envelope_json"]
        if isinstance(row["envelope_json"], str)
        else json.dumps(row["envelope_json"]),
        backend=row["backend"],
        is_regulator_grade=row["is_regulator_grade"],
        issued_at=row["issued_at"],
        dataset_commitment_id=row["dataset_commitment_id"],
        manifest_root_hash=row["manifest_root_hash"],
    )


# --------------------------------------------------------------------------- #
# /health                                                                      #
# --------------------------------------------------------------------------- #


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool
    store_kind: str
    proof_count_in_memory: int
    circuit_version: str
    merkle_hash_in_use: str
    supported_backends: tuple[str, ...]
    supported_folding_schemes: tuple[str, ...]
    standards_pinned: dict[str, str]


@router.get("/health", response_model=HealthResponse)
def health_endpoint() -> HealthResponse:
    from tex.zkprov.commitment import merkle_hash_algorithm_in_use
    from tex.zkprov.integration import is_zkprov_enabled

    store = _store()
    store_kind = "postgres" if not store._disabled else "in-memory"

    return HealthResponse(
        enabled=is_zkprov_enabled(),
        store_kind=store_kind,
        proof_count_in_memory=len(store),
        circuit_version=CIRCUIT_VERSION,
        merkle_hash_in_use=merkle_hash_algorithm_in_use(),
        supported_backends=tuple(b.value for b in ProofBackendId),
        supported_folding_schemes=tuple(f.value for f in FoldingScheme),
        standards_pinned={
            "zkprov": "arxiv 2506.20915 (Dec 18 2025)",
            "vft": "arxiv 2510.16830 v3 (Dec 29 2025)",
            "latticefold_plus_l2": "eprint 2026/721 (Apr 19 2026)",
            "veil_hash_based_zk": "eprint 2026/683 (Apr 8 2026); "
            "Succinct blog May 1 2026",
            "sp1_hypercube": "Succinct, mainnet Feb 19 2026; "
            "99.7%% L1 blocks <12s on 16 RTX 5090 GPUs",
            "twist_and_shout": "a16z Feb 2026",
            "deepprove_public_release": "Lagrange Labs (Feb 23 2026)",
            "mira_parallel_accumulation": "arxiv 2507.07031 / ZKTorch; "
            "3x-10x proof size reduction, 6.2x faster proving",
            "scitt_arp": "draft-hillier-scitt-arp-00 (May 1 2026)",
            "nabaos": "arxiv 2603.10060 (Mar 9 2026)",
            "eu_ai_act_article_53_1_d": "TDS Template 24 Jul 2025; "
            "enforcement Aug 2 2026; fines up to €15M / 3% global revenue",
            "fips_204_ml_dsa": "NIST FIPS 204 (Aug 2024); "
            "CNSA 2.0 timeline 2030/2035",
            "poseidon_merkle_hash": "Grassi et al. USENIX Security 2021 "
            "(eprint 2019/458) — BN254 t=3 alpha=5 RF=8 RP=57 128-bit",
        },
    )
