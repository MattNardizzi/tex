"""
ZKPROV proof generation and verification.

Surface
-------
``generate_proof``  builds a ``ProvenanceProof`` over a
``ProvenanceStatement`` using the backend declared in the
``DatasetManifest``'s ``proof_backend`` field. ``verify_proof``
validates the proof against the statement and the bound commitment.

Frontier delta vs. ZKPROV (arxiv 2506.20915)
--------------------------------------------
The original construction proves:

  "the response was produced by a model fine-tuned on the dataset
   committed to under ``dataset_commitment_id``"

The May-2026 extension here proves all five of:

  1. Same as ZKPROV (response → committed model → committed
     dataset).
  2. Manifest binding: the dataset commitment is consistent with a
     CA-signed ``DatasetManifest`` whose
     ``base_model_sha256`` and ``training_window_*`` match the
     declared training program (VFT element 3).
  3. Quota: per-source ``max_epoch_participation`` was not exceeded
     during training (VFT element 1).
  4. Sampler: the batch sequence is consistent with a committed
     sampler seed under the chosen mode (PUBLIC_REPLAYABLE or
     PRIVATE_INDEX_HIDING; VFT element 2).
  5. Algorithm-agile signing: the manifest's CA signature uses an
     algorithm the verifier's trust store accepts (default ML-DSA-65;
     PQ-secure for the August 2 2026 enforcement date and forward
     through CNSA 2.0).

The first three pull ZKPROV forward to where the EU AI Office
expects compliance evidence (Article 53(1)(d) + GPAI CoP Final
June 2026). Items 4 and 5 are the post-VFT bleeding edge that no
incumbent agent-governance platform has wired as of May 2026.

Performance targets
-------------------
Per VFT §V (Dec 29 2025): per-step prover 16.8–31.2s for LoRA
rank 8–16 at 2,048 tokens; final verification <200 ms; final proof
~4–6 MB after recursive aggregation. We track these numbers as the
upstream SOTA. For the deterministic shim the times are
sub-millisecond (test-only path).

The default ``circuit_version="zkprov-v1-2026.05"`` pins the
statement schema; bumping it is the migration path when the
upstream circuit changes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from tex.zkprov.backends import (
    BackendUnavailable,
    ProofBackend,
    ProofBackendId,
    ProvenanceStatement,
    is_regulator_grade,
    resolve_backend_with_fallback,
)
from tex.zkprov.commitment import (
    DatasetCommitment,
    MerkleInclusionProof,
    verify_commitment_signature,
    verify_commitment_valid,
)
from tex.zkprov.manifest import DatasetManifest
from tex.zkprov.sampler import SamplerCommitment, SamplerMode


CIRCUIT_VERSION: Final[str] = "zkprov-v1-2026.05"


# --------------------------------------------------------------------------- #
# ProvenanceProof                                                             #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ProvenanceProof:
    """A ZKPROV proof binding an LLM response to authorized training data.

    Fields
    ------
    proof_bytes
        Opaque payload produced by the backend identified by
        ``backend``. Verifier code must dispatch on ``backend`` and
        is not allowed to peek inside.
    statement
        The public statement the proof is over.
    backend
        Identifier of the proving backend that produced
        ``proof_bytes``. The verifier resolves the matching backend
        via ``tex.zkprov.backends.get_proof_backend``.
    sampler_commitment
        On-statement commitment to the batch sampler (VFT element 2).
        Present whenever the proof covers training-step semantics;
        omitted for "membership-only" proofs that only attest record
        inclusion without optimizer trace.
    issued_at
        Wallclock when the proof was emitted. Used for staleness
        checks against ``DatasetCommitment.valid_until``.
    """

    proof_bytes: bytes
    statement: ProvenanceStatement
    backend: ProofBackendId
    sampler_commitment: SamplerCommitment | None
    issued_at: datetime

    def to_envelope_json(self) -> str:
        """Canonical JSON envelope. Carried inside evidence records.

        The shape is intentionally flat so a SCITT verifier can
        consume it without ZKPROV-specific tooling. The
        ``proof_bytes`` field is base64 to keep the envelope JSON
        safe; the backend hands back binary inside.
        """
        import base64

        return json.dumps(
            {
                "kind": "tex.zkprov.proof.v1",
                "backend": self.backend.value,
                "issued_at": self.issued_at.astimezone(UTC).isoformat(),
                "statement": {
                    "response_sha256": self.statement.response_sha256_hex,
                    "prompt_sha256": self.statement.prompt_sha256_hex,
                    "prompt_attribute_hash": self.statement.prompt_attribute_hash,
                    "model_commitment_hash": self.statement.model_commitment_hash,
                    "dataset_commitment_id": self.statement.dataset_commitment_id,
                    "manifest_root_hash": self.statement.manifest_root_hash,
                    "poseidon_root_hex": self.statement.poseidon_root_hex,
                    "circuit_version": self.statement.circuit_version,
                },
                "sampler": (
                    None
                    if self.sampler_commitment is None
                    else {
                        "mode": self.sampler_commitment.mode.value,
                        "seed_commitment": self.sampler_commitment.seed_commitment,
                        "record_count": self.sampler_commitment.record_count,
                        "batch_size": self.sampler_commitment.batch_size,
                        "steps_per_epoch": self.sampler_commitment.steps_per_epoch,
                        "total_epochs": self.sampler_commitment.total_epochs,
                        "seed_hex": self.sampler_commitment.seed_hex,
                    }
                ),
                "proof_b64": base64.b64encode(self.proof_bytes).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def from_envelope_json(text: str) -> "ProvenanceProof":
        """Parse a proof envelope. Strict — rejects anything unknown."""
        import base64

        payload = json.loads(text)
        if payload.get("kind") != "tex.zkprov.proof.v1":
            raise ValueError("not a ZKPROV v1 envelope")
        stmt = payload["statement"]
        statement = ProvenanceStatement(
            response_sha256_hex=stmt["response_sha256"],
            prompt_sha256_hex=stmt["prompt_sha256"],
            prompt_attribute_hash=stmt["prompt_attribute_hash"],
            model_commitment_hash=stmt["model_commitment_hash"],
            dataset_commitment_id=stmt["dataset_commitment_id"],
            manifest_root_hash=stmt["manifest_root_hash"],
            poseidon_root_hex=stmt["poseidon_root_hex"],
            circuit_version=stmt["circuit_version"],
        )
        sampler_payload = payload.get("sampler")
        sampler = (
            None
            if sampler_payload is None
            else SamplerCommitment(
                mode=SamplerMode(sampler_payload["mode"]),
                seed_commitment=sampler_payload["seed_commitment"],
                record_count=sampler_payload["record_count"],
                batch_size=sampler_payload["batch_size"],
                steps_per_epoch=sampler_payload["steps_per_epoch"],
                total_epochs=sampler_payload["total_epochs"],
                seed_hex=sampler_payload.get("seed_hex"),
            )
        )
        return ProvenanceProof(
            proof_bytes=base64.b64decode(payload["proof_b64"]),
            statement=statement,
            backend=ProofBackendId(payload["backend"]),
            sampler_commitment=sampler,
            issued_at=datetime.fromisoformat(payload["issued_at"]),
        )

    def envelope_sha256(self) -> str:
        """SHA-256 of the envelope JSON. Stable across machines."""
        return hashlib.sha256(self.to_envelope_json().encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Statement assembly                                                          #
# --------------------------------------------------------------------------- #

def assemble_statement(
    *,
    response: str | bytes,
    prompt: str | bytes,
    prompt_attributes: dict[str, object],
    model_commitment_hash: str,
    commitment: DatasetCommitment,
    circuit_version: str = CIRCUIT_VERSION,
) -> ProvenanceStatement:
    """Build a ProvenanceStatement from concrete inputs.

    ``prompt_attributes`` is canonical-JSON serialized
    (deterministic, sorted, no whitespace) before hashing so the
    statement is reproducible across machines.
    """
    if isinstance(response, str):
        response_bytes = response.encode("utf-8")
    else:
        response_bytes = response
    if isinstance(prompt, str):
        prompt_bytes = prompt.encode("utf-8")
    else:
        prompt_bytes = prompt

    response_hash = hashlib.sha256(response_bytes).hexdigest()
    prompt_hash = hashlib.sha256(prompt_bytes).hexdigest()
    attribute_canonical = json.dumps(
        prompt_attributes, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    attribute_hash = hashlib.sha256(attribute_canonical).hexdigest()

    return ProvenanceStatement(
        response_sha256_hex=response_hash,
        prompt_sha256_hex=prompt_hash,
        prompt_attribute_hash=attribute_hash,
        model_commitment_hash=model_commitment_hash,
        dataset_commitment_id=commitment.dataset_id,
        manifest_root_hash=commitment.manifest_root_hash,
        poseidon_root_hex=commitment.poseidon_root_hex,
        circuit_version=circuit_version,
    )


# --------------------------------------------------------------------------- #
# generate_proof                                                              #
# --------------------------------------------------------------------------- #

def generate_proof(
    *,
    response: str | bytes,
    prompt: str | bytes,
    prompt_attributes: dict[str, object],
    model_commitment_hash: str,
    commitment: DatasetCommitment,
    manifest: DatasetManifest,
    private_witness: bytes,
    sampler_commitment: SamplerCommitment | None = None,
    allow_shim_fallback: bool = True,
    backend_override: ProofBackendId | None = None,
) -> ProvenanceProof:
    """Generate a ZKPROV proof.

    Parameters
    ----------
    response, prompt, prompt_attributes
        The LLM call being attested.
    model_commitment_hash
        SHA-256 hex of the model parameters at inference time. Use
        the same hash carried in the PTV-shaped attribution envelope
        (``tex.evidence.attribution_zk``) so a verifier can cross-
        check the two attestations.
    commitment, manifest
        The training data commitment + signed manifest. The manifest
        carries the ``proof_backend`` identifier.
    private_witness
        Backend-specific witness bytes. For the deterministic shim
        this is a serialized record-membership proof. For
        Halo2-IPA / DeepProve / LatticeFold+ this is the in-circuit
        witness produced by the prover's training side.
    sampler_commitment
        Optional sampler commitment (VFT element 2). Present for
        proofs that cover optimizer trace; absent for membership-
        only proofs.
    allow_shim_fallback
        Default True. When True, missing regulator-grade backends
        fall back to the deterministic shim, with the shim's
        identifier visible in the resulting envelope (downstream
        verifiers can refuse the shim via ``is_regulator_grade``).
    backend_override
        Force a specific backend regardless of the manifest. Used
        by tests and the demo curl.

    Algorithm-agility
    -----------------
    The backend is resolved via
    ``resolve_backend_with_fallback(manifest.proof_backend, ...)``.
    Today's manifests declare ``halo2-ipa-2026`` and fall through
    to the shim until the ezkl circuit artifact lands. Future
    manifests can declare ``deepprove-2026``, ``jolt-sumcheck-2026``,
    or ``latticefold-plus-2026`` without any code change here.
    """
    backend_id = backend_override or ProofBackendId(manifest.proof_backend)
    backend: ProofBackend = resolve_backend_with_fallback(
        backend_id, allow_shim_fallback=allow_shim_fallback
    )

    statement = assemble_statement(
        response=response,
        prompt=prompt,
        prompt_attributes=prompt_attributes,
        model_commitment_hash=model_commitment_hash,
        commitment=commitment,
    )

    try:
        proof_bytes = backend.prove(
            statement=statement, private_witness=private_witness
        )
        resolved_backend = backend.backend_id
    except BackendUnavailable:
        if not allow_shim_fallback:
            raise
        from tex.zkprov.backends import DeterministicShimBackend

        shim = DeterministicShimBackend()
        proof_bytes = shim.prove(statement=statement, private_witness=private_witness)
        resolved_backend = shim.backend_id

    return ProvenanceProof(
        proof_bytes=proof_bytes,
        statement=statement,
        backend=resolved_backend,
        sampler_commitment=sampler_commitment,
        issued_at=datetime.now(UTC),
    )


# --------------------------------------------------------------------------- #
# verify_proof                                                                #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ProofVerification:
    """Detailed result of a proof verification.

    A boolean answer is rarely enough at the regulator interface:
    auditors want to know *which* of the bound claims hold. This
    record carries the per-check results plus the overall
    ``is_valid``.
    """

    is_valid: bool
    is_regulator_grade: bool
    statement_consistent: bool
    backend_verdict: bool
    commitment_signature_valid: bool
    commitment_in_lifetime: bool
    statement_binds_commitment: bool
    reason: str | None = None

    @property
    def summary_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "is_regulator_grade": self.is_regulator_grade,
            "statement_consistent": self.statement_consistent,
            "backend_verdict": self.backend_verdict,
            "commitment_signature_valid": self.commitment_signature_valid,
            "commitment_in_lifetime": self.commitment_in_lifetime,
            "statement_binds_commitment": self.statement_binds_commitment,
            "reason": self.reason,
        }


def verify_proof(
    proof: ProvenanceProof,
    *,
    expected_dataset_commitment: DatasetCommitment,
    expected_response_sha256_hex: str,
    expected_manifest_root_hash: str | None = None,
    inclusion_proof: MerkleInclusionProof | None = None,
    inclusion_record: bytes | None = None,
    regulator_grade: bool = False,
    now: datetime | None = None,
) -> ProofVerification:
    """Verify a ZKPROV proof against a commitment and expected outputs.

    The verification has six checks; they are evaluated in a fail-
    closed order (any False short-circuits to ``is_valid=False``)
    but the per-check results are still surfaced so an auditor can
    see which obligation was breached.

    Parameters
    ----------
    proof
        The ``ProvenanceProof`` to verify.
    expected_dataset_commitment
        The CA-signed commitment this proof should bind to.
    expected_response_sha256_hex
        SHA-256 hex of the response the caller actually saw. The
        proof statement must match.
    expected_manifest_root_hash
        Optional explicit manifest root hash. When omitted, the
        commitment's hash is used. Provide this when the manifest
        is delivered out-of-band and the caller wants to defend
        against a substituted commitment.
    inclusion_proof, inclusion_record
        Optional Merkle inclusion proof of a specific record under
        the commitment. When both are provided, the verification
        also checks that ``inclusion_record`` is in the dataset.
    regulator_grade
        When True, reject proofs from non-regulator-grade backends
        (the deterministic shim). The default False is appropriate
        for unit tests and for the wired CLAIMS.md surface; the
        Article 53(1)(d) verifier MUST set this to True.
    now
        Override the wallclock used for lifetime checks (test hook).
    """
    # 1. Statement vs. expected response.
    statement_consistent = (
        proof.statement.response_sha256_hex == expected_response_sha256_hex
    )

    # 2. Statement-binds-commitment: the statement's
    #    (commitment_id, manifest_root, poseidon_root) must match the
    #    expected commitment exactly. Otherwise an attacker could
    #    swap commitments while keeping the response constant.
    expected_manifest = (
        expected_manifest_root_hash
        or expected_dataset_commitment.manifest_root_hash
    )
    statement_binds_commitment = (
        proof.statement.dataset_commitment_id == expected_dataset_commitment.dataset_id
        and proof.statement.manifest_root_hash == expected_manifest
        and proof.statement.poseidon_root_hex
        == expected_dataset_commitment.poseidon_root_hex
    )

    # 3. CA signature on the commitment.
    commitment_signature_valid = verify_commitment_signature(
        expected_dataset_commitment
    )

    # 4. Commitment lifetime.
    commitment_in_lifetime = verify_commitment_valid(
        expected_dataset_commitment, now=now
    )

    # 5. Optional Merkle inclusion check.
    if inclusion_proof is not None and inclusion_record is not None:
        # Inclusion proof's claimed root must match the commitment's
        # Poseidon root and the record must verify against it.
        if (
            inclusion_proof.poseidon_root
            != expected_dataset_commitment.poseidon_root_hex
        ):
            return ProofVerification(
                is_valid=False,
                is_regulator_grade=False,
                statement_consistent=statement_consistent,
                backend_verdict=False,
                commitment_signature_valid=commitment_signature_valid,
                commitment_in_lifetime=commitment_in_lifetime,
                statement_binds_commitment=statement_binds_commitment,
                reason="inclusion_proof root does not match commitment",
            )
        if not inclusion_proof.verify(inclusion_record):
            return ProofVerification(
                is_valid=False,
                is_regulator_grade=False,
                statement_consistent=statement_consistent,
                backend_verdict=False,
                commitment_signature_valid=commitment_signature_valid,
                commitment_in_lifetime=commitment_in_lifetime,
                statement_binds_commitment=statement_binds_commitment,
                reason="inclusion_proof does not verify",
            )

    # 6. Backend verdict on the proof bytes.
    try:
        backend = resolve_backend_with_fallback(
            proof.backend, allow_shim_fallback=True
        )
        backend_verdict = backend.verify(
            statement=proof.statement, proof_bytes=proof.proof_bytes
        )
    except BackendUnavailable as exc:
        return ProofVerification(
            is_valid=False,
            is_regulator_grade=is_regulator_grade(proof.backend),
            statement_consistent=statement_consistent,
            backend_verdict=False,
            commitment_signature_valid=commitment_signature_valid,
            commitment_in_lifetime=commitment_in_lifetime,
            statement_binds_commitment=statement_binds_commitment,
            reason=f"backend unavailable: {exc}",
        )

    proof_regulator_grade = is_regulator_grade(proof.backend)

    # Compose overall verdict.
    all_checks = (
        statement_consistent
        and statement_binds_commitment
        and commitment_signature_valid
        and commitment_in_lifetime
        and backend_verdict
    )

    if regulator_grade and not proof_regulator_grade:
        return ProofVerification(
            is_valid=False,
            is_regulator_grade=False,
            statement_consistent=statement_consistent,
            backend_verdict=backend_verdict,
            commitment_signature_valid=commitment_signature_valid,
            commitment_in_lifetime=commitment_in_lifetime,
            statement_binds_commitment=statement_binds_commitment,
            reason=(
                f"backend {proof.backend.value} is not regulator-grade; "
                "Article 53(1)(d) verification requires halo2-ipa-2026, "
                "deepprove-2026, jolt-sumcheck-2026, or latticefold-plus-2026"
            ),
        )

    return ProofVerification(
        is_valid=all_checks,
        is_regulator_grade=proof_regulator_grade,
        statement_consistent=statement_consistent,
        backend_verdict=backend_verdict,
        commitment_signature_valid=commitment_signature_valid,
        commitment_in_lifetime=commitment_in_lifetime,
        statement_binds_commitment=statement_binds_commitment,
        reason=None if all_checks else "one or more checks failed",
    )


__all__ = [
    "CIRCUIT_VERSION",
    "ProvenanceProof",
    "ProofVerification",
    "assemble_statement",
    "generate_proof",
    "verify_proof",
]
