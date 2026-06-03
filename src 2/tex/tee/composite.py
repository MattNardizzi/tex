"""
Composite CPU+GPU TEE attestation envelope and EAT-AI claims (Thread 12 TEE).

This module defines the on-the-wire data structures Tex uses to:

  1. Carry a composite Intel Trust Authority (ITA) JWT inside an evidence
     record. The JWT contains BOTH the CPU TEE evidence (Intel TDX, AMD
     SEV-SNP) AND the GPU TEE evidence (NVIDIA H100/H200/B200) in a single
     verifier-issued token signed with PS384 (or RS256 via the MAA
     adapter).
  2. Carry EAT-AI claims (``draft-messous-eat-ai-01``, Feb 23 2026) — the
     first IETF EAT profile specifically for autonomous AI agents.

Why this exists
---------------
The repo already has ``src/tex/evidence/tee_binding.py``, but that module
handles NRAS *GPU-only* attestation tokens and is wired only into the
post-hoc attribution path (``record_attribution``). The canonical decision
path (``record_decision``) — every request to ``/v1/guardrail`` — does not
carry a hardware-rooted attestation today.

Section 1.4 of the standing reference and the Thread 12 spec require
**composite** CPU+GPU attestation via Intel Trust Authority's
``/appraisal/v2/attest`` endpoint with ``attest_type=tdx+nvgpu``. The
``ITAConnector.get_token_v2(tdx_args, gpu_args)`` Python method (Intel's
``trustauthority-client-for-python``) is the canonical issuance path. The
resulting JWT carries top-level ``tdx`` and ``nvgpu`` claim blocks per
the ITA documented composite-attestation token shape.

State of the art (May 18 2026)
------------------------------
* Intel Trust Authority composite attestation:
  https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html
  ``ITAConnector.get_token_v2(tdx_args, gpu_args) -> GetTokenResponse``.
  PS384 token signing, ``appraisal.ver=2``, ``nvgpu`` + ``tdx`` blocks.
* NVIDIA Blackwell Confidential Computing + NVLink encryption is GA on
  the 590-series driver for 8-GPU B200 systems (May 2026).
* ``draft-messous-eat-ai-01`` (Feb 23 2026) — EAT profile for AI agents
  with CBOR keys -75000..-75012:
    -75000 ai-model-id (URN)
    -75001 ai-model-hash (digest)
    -75002 model-arch-digest (digest)
    -75003 training-data-id
    -75004 training-geo-region (ISO 3166-1)
    -75005 dp-epsilon
    -75006 input-policy-digest (digest)
    -75007 allowed-slice-types
    -75008 data-retention-policy
    -75009 owner-id
    -75010 capabilities
    -75011 allowed-apis
    -75012 ai-sbom-ref
* arxiv 2605.03213 (Forough et al., May 7 2026): "compound attestation
  for multi-hop agent chains" is named as an open challenge. Tex's
  ``compound_chain`` field is the production answer.
* arxiv 2604.23280 (CrossGuard, Apr 28 2026): TEE measurement bound to
  agent credential via instance nonce derived from a per-decision
  binding value. Tex derives the ITA attestation nonce from a SHA-256
  of ``decision_id`` so a captured JWT cannot be replayed across
  decisions — closes the cloneability gap the paper identifies.
* draft-ietf-rats-ear-03 (Mar 15 2026): Tex's verification result
  embeds an AR4SI-style trustworthiness vector so verifiers don't have
  to re-derive it from raw claims.

Pydantic discipline
-------------------
Every model on this module is ``frozen=True, extra="forbid"`` per the
project-wide pydantic-v2 strict rule. Carriage inside the canonical
JSONL evidence chain is done via ``model_dump(mode="json")`` from the
evidence recorder.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


__all__ = [
    "CpuTeeType",
    "GpuTeeType",
    "EatAiDigest",
    "EatAiClaims",
    "CompositeAttestationEnvelope",
    "CompoundAttestationLink",
    "TrustworthinessVector",
    "CompositeVerificationResult",
]


# --------------------------------------------------------------------------- #
# Hardware enums                                                              #
# --------------------------------------------------------------------------- #


class CpuTeeType(str, enum.Enum):
    """Supported CPU TEE technologies in composite attestation."""

    TDX = "intel-tdx"
    """Intel Trust Domain Extensions (TDX). ITA primary support."""

    SEV_SNP = "amd-sev-snp"
    """AMD SEV-SNP. ITA preview support per April 2026 release notes."""

    ARM_CCA = "arm-cca"
    """ARM Confidential Compute Architecture. NDSS 2026 SoK paper
    identifies this as the emerging edge-class TEE."""


class GpuTeeType(str, enum.Enum):
    """Supported GPU TEE technologies."""

    NVIDIA_HOPPER = "nvidia-hopper-cc"
    """NVIDIA H100/H200 confidential compute. AES-256-GCM encrypted HBM."""

    NVIDIA_BLACKWELL = "nvidia-blackwell-cc"
    """NVIDIA B200/B300 with inline NVLink encryption (TEE-I/O capable)."""


# --------------------------------------------------------------------------- #
# EAT-AI (draft-messous-eat-ai-01) digest                                     #
# --------------------------------------------------------------------------- #


class EatAiDigest(BaseModel):
    """Algorithm-agile digest per ``draft-messous-eat-ai-01`` §4.1.2.

    The draft defines a digest as a two-element array ``[alg, hash]``
    where ``alg`` is the IANA COSE algorithm identifier (or its text
    string) and ``hash`` is the digest output bytes (carried base64url
    here for JSON transport). This wrapping lets us add SHA3-256 or
    post-quantum hashes without churning every claim.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    alg: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "IANA COSE algorithm identifier. Common values: 'SHA-256' "
            "('-16'), 'SHA-384' ('-44'), 'SHA3-256' ('-45'). Both the "
            "integer label and the named string are accepted."
        ),
    )
    hash_b64: str = Field(
        min_length=1,
        max_length=256,
        description="base64url-encoded digest output bytes.",
    )

    @field_validator("alg", mode="before")
    @classmethod
    def normalize_alg(cls, value: Any) -> str:
        if isinstance(value, int):
            # Per IANA COSE registry: -16 -> SHA-256, -44 -> SHA-384,
            # -45 -> SHA3-256. We accept either representation.
            mapping = {-16: "SHA-256", -44: "SHA-384", -45: "SHA3-256"}
            return mapping.get(value, str(value))
        if not isinstance(value, str):
            raise TypeError("alg must be a COSE alg string or integer")
        normalized = value.strip()
        if not normalized:
            raise ValueError("alg must not be blank")
        return normalized


# --------------------------------------------------------------------------- #
# EAT-AI claims (draft-messous-eat-ai-01)                                     #
# --------------------------------------------------------------------------- #


class EatAiClaims(BaseModel):
    """EAT-AI claim set per ``draft-messous-eat-ai-01``.

    Carried inside the composite attestation envelope as an OPTIONAL
    sub-block. When present, the verifier checks model-integrity claims
    against operator-provided expected values; the result is recorded
    into the trustworthiness vector.

    Only the *generic, domain-agnostic* claims from §4.1 are wired by
    default. The 5G/6G domain-specific claims from §4.2
    (training_geo_region, allowed_slice_types) are accepted but not
    interpreted by Tex's generic verifier — operators with telecom
    deployments can wire them in policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ai_model_id: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "URN-formatted model identifier per §4.1.1. Examples: "
            "'urn:uuid:f81d4fae-...', 'urn:ietf:ai:model:llama3-8b', "
            "'urn:dev:example.com:tex-judge-v3'."
        ),
    )
    ai_model_hash: EatAiDigest | None = Field(
        default=None,
        description="Cryptographic hash of the serialized model weights "
        "(SafeTensors / ONNX file). Per §4.1.2 algorithm-agile digest.",
    )
    model_arch_digest: EatAiDigest | None = Field(
        default=None,
        description="Cryptographic hash of the model computational graph.",
    )
    training_data_id: str | None = Field(
        default=None,
        max_length=256,
        description="Unique ID of the training dataset (URN or opaque).",
    )
    dp_epsilon: float | None = Field(
        default=None,
        ge=0.0,
        description="Differential-privacy epsilon used during training.",
    )
    input_policy_digest: EatAiDigest | None = Field(
        default=None,
        description="Cryptographic hash of the inference input policy.",
    )
    data_retention_policy: str | None = Field(
        default=None,
        max_length=64,
        description="e.g. 'none', 'session', '24h', '30d'.",
    )
    owner_id: str | None = Field(
        default=None,
        max_length=256,
        description="Identity of the principal that owns the agent.",
    )
    capabilities: tuple[str, ...] = Field(
        default=(),
        description="High-level functions ('email-send', 'tool-use', ...).",
    )
    allowed_apis: tuple[str, ...] = Field(
        default=(),
        description="Specific endpoints/URIs the agent may call.",
    )
    ai_sbom_ref: str | None = Field(
        default=None,
        max_length=1024,
        description="URI or digest reference to the agent's SBOM (SPDX, "
        "CycloneDX). Per §4.1.3.",
    )

    # Optional 5G/6G claims (§4.2) — accepted but not interpreted by the
    # default verifier. Operators with telecom deployments interpret in
    # policy.
    training_geo_region: tuple[str, ...] = Field(
        default=(),
        description="ISO 3166-1 alpha-2 codes (e.g. ['DE', 'FR']).",
    )
    allowed_slice_types: tuple[str, ...] = Field(
        default=(),
        description="3GPP-defined slice types (e.g. ['eMBB', 'URLLC']).",
    )

    def to_cwt_int_map(self) -> dict[int, Any]:
        """Serialize to a CWT integer-keyed claim map per §7.2.

        This is the canonical wire form for CBOR EAT-AI tokens. The
        ITA token transport uses JWT (text keys) per §7.3, so this
        method is provided primarily for verifier interop with CBOR
        producers (e.g. EDGE devices using cose-cbor).
        """
        out: dict[int, Any] = {}
        if self.ai_model_id is not None:
            out[-75000] = self.ai_model_id
        if self.ai_model_hash is not None:
            out[-75001] = [self.ai_model_hash.alg, self.ai_model_hash.hash_b64]
        if self.model_arch_digest is not None:
            out[-75002] = [self.model_arch_digest.alg, self.model_arch_digest.hash_b64]
        if self.training_data_id is not None:
            out[-75003] = self.training_data_id
        if self.training_geo_region:
            out[-75004] = list(self.training_geo_region)
        if self.dp_epsilon is not None:
            out[-75005] = self.dp_epsilon
        if self.input_policy_digest is not None:
            out[-75006] = [
                self.input_policy_digest.alg,
                self.input_policy_digest.hash_b64,
            ]
        if self.allowed_slice_types:
            out[-75007] = list(self.allowed_slice_types)
        if self.data_retention_policy is not None:
            out[-75008] = self.data_retention_policy
        if self.owner_id is not None:
            out[-75009] = self.owner_id
        if self.capabilities:
            out[-75010] = list(self.capabilities)
        if self.allowed_apis:
            out[-75011] = list(self.allowed_apis)
        if self.ai_sbom_ref is not None:
            out[-75012] = self.ai_sbom_ref
        return out


# --------------------------------------------------------------------------- #
# Compound chain link (arxiv 2605.03213 §VII open challenge)                  #
# --------------------------------------------------------------------------- #


class CompoundAttestationLink(BaseModel):
    """A single hop in a compound attestation chain.

    Forough et al. (arxiv 2605.03213, May 7 2026) identify "compound
    attestation for multi-hop agent chains" as an OPEN challenge — no
    production framework binds per-hop hardware attestations into a
    coherent chain.

    Tex's design: each agent hop (planner → executor → tool-call) emits
    its own composite ITA JWT and records the previous hop's
    ``jwt_sha256`` here. The aggregate chain is verifiable end-to-end:
    a verifier walks back through ``previous_jwt_sha256`` re-validating
    each ITA token in isolation, then asserts the chain is unbroken
    via the recorded hashes. The Tex evidence record already
    hash-chains decisions; this field gives the same property to TEE
    attestations crossing agent boundaries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    hop_index: int = Field(
        ge=0,
        description="0 for the originating agent, increments per hop.",
    )
    agent_id: str = Field(
        min_length=1,
        max_length=256,
        description="Identifier of the agent that produced this hop's "
        "attestation. Bound to the JWT via ITA verifier_instance_ids.",
    )
    jwt_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of the ITA JWT bytes for this hop.",
    )
    previous_jwt_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of the previous hop's ITA JWT, "
        "or None for the originating hop.",
    )


# --------------------------------------------------------------------------- #
# Composite envelope                                                          #
# --------------------------------------------------------------------------- #


class CompositeAttestationEnvelope(BaseModel):
    """The payload carried inside every TEE-bound evidence record.

    Mirrored into ``EvidenceRecord.payload_json`` (canonical JSON) so
    that the SHA-256 hash chain cryptographically covers it. The
    envelope holds:

      * the raw ITA composite JWT (or only its digest when
        ``include_full_jwt=False`` to keep payloads small);
      * a parsed-out summary of the TDX and GPU claim blocks (so
        verifiers don't need to re-parse the JWT to filter);
      * the optional EAT-AI claim set;
      * the optional compound-attestation chain link.

    Trust model: the envelope itself is not signed. Its authenticity
    derives from (a) the embedded ITA JWT's signature, verified by
    ``verify_attestation``, and (b) the parent ``EvidenceRecord``'s
    SHA-256 record_hash that covers ``payload_json`` containing this
    envelope.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # --- Token transport ---
    ita_jwt: str | None = Field(
        default=None,
        max_length=32_000,
        description="Composite ITA JWT (header.payload.signature). "
        "Carried in full for verifiers that want to re-check; can be "
        "elided to only the digest for size-sensitive evidence stores.",
    )
    ita_jwt_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of the ITA JWT bytes. Always set.",
    )

    # --- Identity / freshness ---
    issuer: str = Field(
        min_length=1,
        max_length=512,
        description="ITA 'iss' claim. Verifier checks against expected.",
    )
    nonce: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Caller-supplied freshness nonce. Per CrossGuard "
            "(arxiv 2604.23280, Apr 28 2026) Tex binds the nonce to "
            "decision_id via SHA-256 so the JWT cannot be replayed across "
            "decisions."
        ),
    )

    # --- CPU TEE summary ---
    cpu_tee_type: CpuTeeType
    tdx_mrtd: str | None = Field(
        default=None,
        min_length=64,
        max_length=128,
        description="Intel TDX measurement of the TD's initial state.",
    )
    tdx_rtmr0: str | None = Field(
        default=None,
        min_length=64,
        max_length=128,
        description="Runtime measurement register 0 (firmware/OS).",
    )
    tdx_tcb_status: str | None = Field(
        default=None,
        max_length=64,
        description="Intel TDX TCB status: 'UpToDate', 'SWHardeningNeeded', "
        "'ConfigurationNeeded', etc.",
    )
    tdx_is_debuggable: bool | None = Field(
        default=None,
        description="True iff the TD is in debug mode. MUST be False for "
        "production decisions.",
    )

    # --- GPU TEE summary ---
    gpu_tee_type: GpuTeeType
    gpu_measurement_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of GPU attestation measurement.",
    )
    gpu_hwmodel: str | None = Field(
        default=None,
        max_length=32,
        description="GPU model (GH100, GH200, GB200, ...).",
    )
    gpu_driver_version: str | None = Field(
        default=None,
        max_length=64,
        description="NVIDIA driver version reported in nvgpu sub-claim.",
    )
    gpu_overall_result: bool = Field(
        default=False,
        description="True iff the ITA verifier returned "
        "'measres=comparison-successful' for the GPU sub-claim AND "
        "'x-nvidia-gpu-attestation-report-signature-verified=true'.",
    )

    # --- EAT-AI claims (draft-messous-eat-ai-01) ---
    eat_ai: EatAiClaims | None = Field(
        default=None,
        description="Optional EAT-AI claim set per draft-messous-eat-ai-01.",
    )

    # --- Compound attestation chain (arxiv 2605.03213) ---
    compound_link: CompoundAttestationLink | None = Field(
        default=None,
        description="Optional link into a multi-hop compound attestation "
        "chain. Set when this decision is part of a multi-agent flow.",
    )

    # --- Lifecycle ---
    test_mode: bool = Field(
        default=False,
        description="True iff the envelope was produced in dev/test mode "
        "(no real hardware). Auditors must reject test_mode=True for "
        "production evidence.",
    )
    ita_attest_type: str = Field(
        default="tdx+nvgpu",
        description="Echo of the ITA --attest_type used to issue the JWT. "
        "One of 'tdx', 'nvgpu', 'tdx+nvgpu'. Tex always uses composite "
        "'tdx+nvgpu' in production.",
    )


# --------------------------------------------------------------------------- #
# Trustworthiness vector (draft-ietf-rats-ear-03)                             #
# --------------------------------------------------------------------------- #


class _TrustState(str, enum.Enum):
    """AR4SI trustworthiness values per draft-ietf-rats-ear-03.

    Each axis takes one of these values. EAR collapses them into a
    single normalized trust vector so a relying party doesn't need
    deep TEE-specific knowledge to act on the result.
    """

    AFFIRMING = "affirming"
    """Strong positive evidence for this axis (best)."""

    WARNING = "warning"
    """The verifier can attest, but evidence is incomplete."""

    CONTRAINDICATED = "contraindicated"
    """Verifier found evidence inconsistent with trust."""

    NONE = "none"
    """Verifier cannot speak to this axis."""


class TrustworthinessVector(BaseModel):
    """AR4SI trustworthiness vector per draft-ietf-rats-ear-03 §3.

    Embedded in the verification result so callers see a normalized
    judgement without having to interpret raw TDX RTMRs or NRAS
    detailed-result blocks. This is the "appraisal output" Tex hands
    to relying parties.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    instance_identity: _TrustState = Field(
        default=_TrustState.NONE,
        description="Did the attester prove its identity? Affirming iff "
        "the ITA token's UEID/measurements match expected.",
    )
    configuration: _TrustState = Field(
        default=_TrustState.NONE,
        description="Is the platform configured securely? Affirming iff "
        "TDX is non-debuggable AND tcb_status=='UpToDate'.",
    )
    executables: _TrustState = Field(
        default=_TrustState.NONE,
        description="Are the executables trusted? Affirming iff measurements "
        "match expected and EAT-AI ai_model_hash matches (if provided).",
    )
    hardware: _TrustState = Field(
        default=_TrustState.NONE,
        description="Is the hardware trusted? Affirming iff GPU result is "
        "true and the certificate chain validated.",
    )
    runtime_opaque: _TrustState = Field(
        default=_TrustState.NONE,
        description="Is the runtime environment opaque to outside parties? "
        "Affirming iff the TEE is enabled (TDX active, GPU CC mode on).",
    )

    @classmethod
    def all_none(cls) -> "TrustworthinessVector":
        return cls()


class CompositeVerificationResult(BaseModel):
    """Result of verifying a CompositeAttestationEnvelope.

    Fail-closed: if any check fails, ``ok`` is False and ``reason``
    names the specific failure. The trustworthiness vector still
    populates (with contraindicated/none axes) so callers can
    inspect what failed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    reason: str = Field(
        min_length=1,
        max_length=256,
        description="Stable, short, machine-readable reason code. "
        "'ok' on success; specific failure code otherwise.",
    )
    test_mode: bool = False
    trustworthiness: TrustworthinessVector
    cpu_tee_type: CpuTeeType | None = None
    gpu_tee_type: GpuTeeType | None = None
    tdx_mrtd: str | None = None
    gpu_measurement_sha256: str | None = None
    issuer: str | None = None
    expires_at_unix: int | None = None
    eat_ai_subjects: tuple[str, ...] = Field(
        default=(),
        description="Names of EAT-AI claims that were both present AND "
        "verified against operator-expected values (e.g. ('ai_model_id', "
        "'ai_model_hash')).",
    )
