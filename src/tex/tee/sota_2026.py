"""
Tex Thread 12+ — May-2026 bleeding-edge SOTA augmentations.

This module layers the bleeding-edge May-18-2026 frontier additions on
top of the canonical composite attestation envelope. Each augmentation
implements a published-but-not-yet-shipped 2026 IETF draft, arxiv
preprint, or hardware-vendor preview. Nothing here is generally
available in any competing agent-governance product as of May 18 2026
— this is what the standard says exists, before the standards bodies
finalise it and before competitors catch up.

The augmentations
-----------------

1.  ``MeasuredComponent`` — implements
    ``draft-ietf-rats-eat-measured-component-12`` (IESG Last Call
    closed Jan 26 2026, becoming RFC). The EAT "measured-components"
    claim is the canonical IETF way to bundle multiple measured
    artifacts (model weights, policy bundles, retrieval indices)
    alongside the platform attestation. Tex emits one
    MeasuredComponent per agent artifact loaded into the runtime.

2.  ``CoRimReferenceValue`` — implements selected fields of
    ``draft-ietf-rats-corim-10`` (March 2 2026). CoRIM is the IETF
    canonical format for the *Reference Values* a Verifier matches
    Evidence against. We carry a compact reference-value summary in
    the envelope so a downstream verifier can do offline policy
    checking without fetching a separate CoRIM document from the
    operator's manifest service.

3.  ``cose_alg_id_for(algorithm)`` — maps Tex algorithm-agility
    enum entries to the COSE Algorithms Registry numbers requested
    by ``draft-ietf-cose-dilithium-11`` (Nov 15 2025): -48 for
    ML-DSA-44, -49 for ML-DSA-65, -50 for ML-DSA-87. Plus the
    JOSE/COSE composite labels from ``draft-ietf-jose-pq-composite-
    sigs-01`` (Feb 27 2026) — hex byte values for COMPSIG-MLDSA65-
    Ed25519-SHA512 etc.

4.  ``GpuTeePlatform.VERA_RUBIN_NVL72`` — adds NVIDIA's announced
    rack-scale CC platform. Tex sees this as a single logical GPU
    TEE that spans the rack via NVLink and NVLink-C2C, with
    attestation aggregated across all 72 GPUs.

5.  ``DriverPinning`` — driver-version pinning. NVIDIA R590 TRD1
    (Dec 2025 GA) is the first driver supporting Blackwell PPCIE
    multi-GPU and TDISP on Jetson AGX Thor. ``DriverPinning`` lets
    operators reject attestations from any driver version other
    than the explicitly approved one — the canonical defence
    against driver-downgrade attacks.

6.  ``TdispEvidence`` — captures evidence from the TEE Device
    Interface Security Protocol (PCIe SIG, finalised 2024,
    NVIDIA-shipping 2026). TDISP attests that the PCIe device is in
    a trusted state for DMA into TEE memory — closing the gap
    between CPU-TEE memory protections and the GPU's DMA engine.

7.  ``MultiGpuBatch`` — represents the up-to-8-GPU batch
    attestation supported by ITA composite v2. Lets one request
    cover an entire H100 NVL or B200 8x system without 8 separate
    JWTs.

8.  ``PersistentMemoryAttestation`` — addresses arxiv 2605.03213
    §VI "end-to-end protection of persistent agent memory remains
    an open problem". We carry SHA-3-256 digests of every persistent
    memory region (vector store snapshot, fine-tuned adapter, KV
    cache pinned to disk) at the moment of the decision. The
    digest list is signed inside the same envelope so any
    out-of-band mutation invalidates the attestation.

9.  ``ScittReceipt`` — implements the receipt shape from
    ``draft-ietf-scitt-architecture-22`` (Oct 10 2025). When a
    composite envelope is registered with a SCITT transparency
    service, the receipt links the envelope to a position in an
    append-only Merkle tree. The receipt is small (≤512 bytes) but
    gives the relying party a global ordering guarantee that the
    JWT alone does not provide.

10. ``TcbAdvisoryCheck`` — Intel publishes a continuous stream of
    security advisories tied to TDX. The ``attester_advisory_ids``
    claim in an ITA JWT lists the advisories that apply to the
    current TCB level. ``TcbAdvisoryCheck`` lets operators
    blocklist specific advisory IDs (e.g. an active vulnerability
    that Intel hasn't yet rolled into a TCB-R) so an attestation
    that names a blocked advisory immediately fails.

11. ``TsmEventLog`` — Linux 6.7+ exposes the runtime measurement
    event log via the TSM ConfigFS interface at
    ``/sys/kernel/config/tsm/report/<id>/runtime_data``. The event
    log binds the attested boot measurements to the actual code
    sequence the kernel saw at boot. ``TsmEventLog`` carries the
    event log SHA-256 inside the envelope and exposes a helper to
    re-hash it on the verify side.

12. ``LongHaulNonce`` — extends the CrossGuard binding with two
    additional nonces:

      * a *transcript* nonce that hashes every input message into
        the agent's running transcript chain, so downstream verifiers
        can detect mid-session transcript tampering, and

      * a *fleet-uniqueness* nonce that hashes the operator's fleet
        ID into the binding so two operators running the same
        software/model/policy cannot replay each other's decisions.
        This addresses the cross-deployment replay class identified
        in CrossGuard (arxiv 2604.23280 §6.2).
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ===========================================================================
# 1.  draft-ietf-rats-eat-measured-component-12
# ===========================================================================


class MeasuredComponent(BaseModel):
    """One element of the EAT ``measured-components`` claim.

    Per ``draft-ietf-rats-eat-measured-component-12`` §4.2 a measured
    component carries an identifier (name+version), a list of signers
    (parties who endorse this measurement), 64-bit profile-defined
    flags, and the cryptographic digest of the sampled state.

    We use this for every agent-loaded artifact: model weights, policy
    bundles, retrieval indices, tool manifests, fine-tuned adapters,
    pinned tokenizers. The IETF profile-flags field is used for the
    profile-private bitfield documented in the Tex EAT-AI profile
    (`tex_eat_ai_profile_flags` in CLAIMS.md).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=256)
    """Human-readable identifier (e.g. ``llama3-8b-instruct``,
    ``policy-bundle-v3``, ``faiss-index-mainline``)."""

    version: str = Field(min_length=1, max_length=64)
    """Semantic version of the component (free-form text; the
    draft adopts CoSWID version-scheme conventions per RFC 9393)."""

    digest_alg: str = Field(min_length=3, max_length=32)
    """COSE-registered hash alg name: ``sha-256``, ``sha-384``,
    ``sha3-256``, ``blake3-256``, etc."""

    digest_b64: str = Field(min_length=32, max_length=256)
    """Base64url-encoded digest of the canonical serialised
    component bytes."""

    signers: tuple[str, ...] = ()
    """Optional list of opaque signer thumbprints. Per the draft, any
    of an X.509 cert, raw public key, COSE-Key Thumbprint
    (RFC 9679), or other identifier may go here."""

    flags: int = Field(default=0, ge=0, le=2**64 - 1)
    """64-bit profile-defined bitfield. The Tex profile uses bits 0..7
    for component-type (0=model, 1=policy, 2=retrieval-index,
    3=tool-manifest, 4=fine-tuned-adapter, 5=tokenizer, 6=template,
    7=other), bit 16 for ``trusted_by_signers``, bit 17 for
    ``in_tee_memory``, bit 18 for ``immutable_during_session``."""


# ===========================================================================
# 2.  draft-ietf-rats-corim-10  (selected fields)
# ===========================================================================


class CoRimReferenceValue(BaseModel):
    """Compact CoRIM Reference Value triple.

    Per ``draft-ietf-rats-corim-10`` §5.1.4 a Reference Value is a
    "triple" linking a subject (the measured environment) to an object
    (the expected digest) via a predicate (the measurement type).
    We carry the minimal triple needed for offline appraisal —
    a downstream Verifier sees ``[subject_class_id, predicate,
    object_digest]`` and matches against fresh evidence without
    fetching a separate CoRIM CBOR document.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_class_id: str = Field(min_length=1, max_length=256)
    """UUID/URN of the environment class. For Tex's TDX measurements
    we use ``urn:tex:env-class:tdx-runtime``; for the GPU,
    ``urn:tex:env-class:gpu-runtime``."""

    predicate: Literal[
        "tdx_mrtd",
        "tdx_rtmr0",
        "tdx_rtmr1",
        "tdx_rtmr2",
        "tdx_rtmr3",
        "gpu_measurement",
        "model_weights",
        "policy_bundle",
        "retrieval_index",
    ]
    """The measurement-type the Reference Value applies to."""

    object_digest_alg: str = Field(min_length=3, max_length=32)
    object_digest_hex: str = Field(min_length=32, max_length=256)

    authority: str = Field(min_length=1, max_length=512)
    """The CoRIM issuer — typically ``urn:tex:operator:<tenant-id>``."""


# ===========================================================================
# 3.  COSE / JOSE algorithm number mapping (PQ + composite)
# ===========================================================================


# COSE Algorithms Registry entries requested by
# draft-ietf-cose-dilithium-11 §8.1.1 (IANA registrations pending).
# Negative integer assignments are reserved for non-encryption
# signing algorithms per RFC 9053.
COSE_ALG_ML_DSA_44: int = -48
COSE_ALG_ML_DSA_65: int = -49
COSE_ALG_ML_DSA_87: int = -50

# COSE Algorithms Registry entries requested by
# draft-ietf-jose-pq-composite-sigs-01 §6.1 — JOSE/COSE composite
# labels are byte strings, not integers. The hex values below are
# the verbatim "COMPSIG-..." byte sequences from the draft's Table 4.
JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512: bytes = bytes.fromhex(
    "434F4D505349472D4D4C44534136352D456432353531392D534841353132"
)
JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256: bytes = bytes.fromhex(
    "434F4D505349472D4D4C44534138372D45643434382D5348414B45323536"
)


def cose_alg_id_for(algorithm_name: str) -> int | None:
    """Map a Tex algorithm-agility name to its COSE Algorithms id.

    Returns None when no IANA number applies (e.g. for classical
    PS384/RS256/ES384, the existing COSE registry numbers from RFC
    9053 are -37, -257, -36 respectively and the operator can use
    those directly).
    """
    mapping: dict[str, int] = {
        "ml-dsa-44": COSE_ALG_ML_DSA_44,
        "ml-dsa-65": COSE_ALG_ML_DSA_65,
        "ml-dsa-87": COSE_ALG_ML_DSA_87,
        "blake3-ml-dsa-65": COSE_ALG_ML_DSA_65,  # Same wire format
        "ps384": -37,
        "rs256": -257,
        "es384": -36,
        "es256": -7,
        "ed25519": -8,
    }
    return mapping.get(algorithm_name.lower())


# ===========================================================================
# 4.  Vera Rubin NVL72 — May-2026 newest CC platform tag
# ===========================================================================


class GpuTeePlatform(str, Enum):
    """Extended GPU TEE platform tags layered on top of GpuTeeType.

    The base ``GpuTeeType`` enum in ``composite.py`` covers
    ``NVIDIA_HOPPER`` (H100/H200) and ``NVIDIA_BLACKWELL`` (B200/B300).
    This enum extends to the May-2026 announced platforms beyond.
    """

    HOPPER_H100 = "nvidia-h100-cc"
    HOPPER_H200 = "nvidia-h200-cc"
    BLACKWELL_B200 = "nvidia-b200-cc-tee-io"
    BLACKWELL_B300 = "nvidia-b300-cc-tee-io"
    BLACKWELL_GB200 = "nvidia-gb200-grace-cc"
    BLACKWELL_GB300 = "nvidia-gb300-grace-cc"
    BLACKWELL_RTX_PRO_6000 = "nvidia-rtx-pro-6000-blackwell-cc"
    """RTX PRO 6000 Blackwell Server Edition, CC support added in
    R580 TRD1 (per NVIDIA Trusted Computing Solutions release notes,
    Dec 2025)."""

    JETSON_AGX_THOR = "nvidia-jetson-agx-thor-cc-tdisp"
    """Jetson AGX Thor (Blackwell GPU) with CC + TDISP. Edge agent
    deployment platform."""

    VERA_RUBIN_NVL72 = "nvidia-vera-rubin-nvl72-rack-cc"
    """Vera Rubin NVL72 — world's first rack-scale CC platform. One
    72-GPU NVLink domain attested as a single TEE via NVLink + NVLink
    C2C. Announced May 2026."""


# ===========================================================================
# 5.  Driver pinning — defence against driver-downgrade attacks
# ===========================================================================


class DriverPinning(BaseModel):
    """Driver-version pinning for the GPU attestation.

    Defence against attestation-replay-after-driver-downgrade: an
    attacker who can get the runtime onto an older signed-but-buggy
    driver may bypass NVLink encryption or skip SPDM authentication.
    The pinning policy says "only these driver versions are acceptable
    for this fleet". Mismatch → reject the attestation.

    Reference: NVIDIA Trusted Computing Solutions R590 TRD1 GA release
    notes (Dec 2025); driver 590.48.01 is the first GA build
    supporting Blackwell PPCIE multi-GPU with the IV-exhaustion fix
    for H100 CC (key rotation guidance in §"Known Issues").
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_driver_version: str = Field(min_length=1, max_length=32)
    """Inclusive minimum (semver-ish, e.g. ``590.48.01``)."""

    pinned_driver_versions: tuple[str, ...] = ()
    """If non-empty, the driver MUST be on this allowlist. Used for
    locked-down environments that don't auto-upgrade."""

    blocked_driver_versions: tuple[str, ...] = ()
    """Explicit blocklist for known-buggy drivers, even if the version
    satisfies ``min_driver_version``."""


# ===========================================================================
# 6.  TDISP evidence — TEE Device Interface Security Protocol
# ===========================================================================


class TdispEvidence(BaseModel):
    """TEE Device Interface Security Protocol evidence.

    TDISP is the PCIe SIG protocol (PCIe 6.0 ECN, finalised 2024) that
    binds a PCIe device to a TEE via a per-device attestation report.
    NVIDIA Jetson AGX Thor ships TDISP as of 2026; Blackwell server
    SKUs are gaining support throughout 2026. TDISP closes the gap
    between CPU-TEE memory protections and GPU DMA — without TDISP,
    a compromised hypervisor can swap the DMA target after the GPU
    has been attested.

    The evidence carries the TDISP Device Interface Report bytes,
    along with the parsed fields the Verifier needs to make a policy
    decision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_interface_report_sha256: str = Field(min_length=64, max_length=64)
    device_certificate_chain_sha256: str = Field(min_length=64, max_length=64)
    interface_id: str = Field(min_length=1, max_length=64)
    """PCIe BDF or canonical interface identifier."""

    lock_state: Literal["unlocked", "config-locked", "run-locked", "error"]
    """TDISP lock state at the time of evidence collection. Production
    workloads MUST observe ``run-locked``."""

    is_dev_stub: bool = False


# ===========================================================================
# 7.  Multi-GPU batch attestation (ITA supports up to 8 in one request)
# ===========================================================================


class MultiGpuBatch(BaseModel):
    """Multi-GPU batch attestation summary.

    Per Intel Trust Authority docs (April 2026), composite attestation
    supports up to 8 NVIDIA confidential-computing GPUs simultaneously
    via a single request. The resulting JWT has a ``nvgpu`` block
    that is structurally an array (rather than a single object). We
    summarise the batch here so policy can match against the full
    set rather than just the first GPU.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    gpu_count: int = Field(ge=1, le=8)
    gpu_measurement_sha256_list: tuple[str, ...]
    gpu_hwmodel_list: tuple[str, ...]
    all_measres_successful: bool
    all_secboot: bool

    nvlink_topology: Literal["pcie-only", "nvlink", "nvlink-nvswitch", "nvlink-c2c"] = "nvlink"


# ===========================================================================
# 8.  Persistent agent memory attestation — arxiv 2605.03213 §VI
# ===========================================================================


class PersistentMemoryRegion(BaseModel):
    """One persistent agent-memory region with its digest.

    arxiv 2605.03213 (Forough et al., May 7 2026) flags persistent
    agent memory — vector stores, fine-tuned adapters, KV caches —
    as an open problem: "end-to-end protection of persistent agent
    memory remains" unsolved. The standard composite envelope
    attests the platform but says nothing about the on-disk state
    the agent loads back into RAM after a restart.

    Tex's answer: hash every persistent memory region at the moment
    the decision is made, and carry the digests inside the same
    attestation envelope. Any out-of-band mutation between decisions
    invalidates the attestation because the digest at decision time
    will no longer match the digest at load time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    region_kind: Literal[
        "vector_store",
        "fine_tuned_adapter",
        "kv_cache",
        "tool_state",
        "session_transcript",
        "long_term_memory",
    ]
    region_id: str = Field(min_length=1, max_length=256)
    """Stable identifier — typically a URI or UUID. Stays the same
    across decisions for the same memory region; the digest is what
    changes."""

    size_bytes: int = Field(ge=0, le=2**62)
    digest_alg: Literal["sha-256", "sha-384", "sha3-256", "blake3-256"] = "sha3-256"
    digest_hex: str = Field(min_length=32, max_length=256)

    last_modified_at_unix: float | None = None
    """Optional last-modified timestamp from the underlying storage.
    Used for tamper-evidence cross-checks against the FS."""

    in_tee_memory: bool = False
    """True iff this region is loaded into TEE-protected memory at
    the moment of measurement. Persistent-disk regions are loaded
    into TEE memory only briefly during query."""


# ===========================================================================
# 9.  SCITT receipt — draft-ietf-scitt-architecture-22
# ===========================================================================


class ScittReceipt(BaseModel):
    """Receipt issued by a SCITT Transparency Service.

    Per ``draft-ietf-scitt-architecture-22`` §3.4 a receipt is the
    transparency log's confirmation that a signed statement
    (the composite envelope JWT, in our case) has been registered on
    the ledger. Receipts are small (≤512 bytes) but give the relying
    party a global ordering guarantee — any equivocation by the
    transparency service is detectable via gossip-based audit.

    Tex's transparency service of choice is operator-configurable
    via ``TEX_SCITT_TS_URL``. The shipped client supports the
    Microsoft Code Transparency Service shape (CCF / COSE_Sign1).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts_iss: str = Field(min_length=1, max_length=512)
    """Issuer URI of the transparency service."""

    receipt_b64: str = Field(min_length=1, max_length=4096)
    """Base64-encoded COSE_Sign1 receipt bytes."""

    leaf_index: int = Field(ge=0, le=2**62)
    tree_size_at_registration: int = Field(ge=1, le=2**62)
    registered_at_unix: float = Field(ge=0)

    statement_sha256: str = Field(min_length=64, max_length=64)
    """SHA-256 of the SCITT signed-statement bytes (the
    COSE_Sign1 envelope wrapping the composite JWT)."""


# ===========================================================================
# 10. TCB advisory ID check
# ===========================================================================


_BLOCK_ADVISORIES_ENV = "TEX_TEE_BLOCKED_ADVISORY_IDS"


@dataclass(frozen=True, slots=True)
class TcbAdvisoryCheckResult:
    ok: bool
    matched_advisories: tuple[str, ...]
    blocked_advisories: tuple[str, ...]


def check_tcb_advisories(
    attester_advisory_ids: tuple[str, ...],
    *,
    blocked_overrides: tuple[str, ...] | None = None,
) -> TcbAdvisoryCheckResult:
    """Check the ITA ``attester_advisory_ids`` claim against a blocklist.

    Intel publishes a continuous stream of security advisories tied
    to TDX (the ``attester_advisory_ids`` claim, e.g.
    ``INTEL-SA-00837``, ``INTEL-SA-01058``). Operators configure a
    blocklist via the ``TEX_TEE_BLOCKED_ADVISORY_IDS`` env var
    (comma-separated). When an attestation names a blocked
    advisory, the verifier returns ``ok=False``.

    The blocklist is the canonical way to fail-close on a known
    vulnerability faster than Intel's own TCB-R cadence allows.
    Per the ITA docs, "Intel Trust Authority always evaluates TCB
    status against the latest TCB info from Intel PCS" — but that
    only flips ``attester_tcb_status`` to ``OutOfDate`` *after*
    Intel publishes a TCB recovery. The blocklist lets the operator
    enforce mitigation immediately, on hardware that is still
    technically ``UpToDate`` per Intel's clock.
    """
    blocked: tuple[str, ...]
    if blocked_overrides is not None:
        blocked = tuple(b.strip() for b in blocked_overrides if b.strip())
    else:
        env_value = os.environ.get(_BLOCK_ADVISORIES_ENV, "")
        blocked = tuple(b.strip() for b in env_value.split(",") if b.strip())
    matched = tuple(a for a in attester_advisory_ids if a in blocked)
    return TcbAdvisoryCheckResult(
        ok=(len(matched) == 0),
        matched_advisories=matched,
        blocked_advisories=blocked,
    )


# ===========================================================================
# 11. Linux 6.7+ TSM ConfigFS event log binding
# ===========================================================================


class TsmEventLog(BaseModel):
    """Linux TSM ConfigFS runtime event log binding.

    Linux 6.7+ exposes the TDX runtime measurement event log via the
    TSM ConfigFS interface. Each entry is a (PCR-equivalent index,
    extend-event-type, digest) tuple. The full event log replays
    deterministically into the TDX RTMR0..3 measurements — i.e. if
    the verifier replays the event log it should arrive at the same
    rtmr0..3 values that appear in the ITA composite token.

    We carry only the SHA-256 of the event log (≤32 bytes) plus the
    expected RTMR0..3 values, so the verifier has the full
    cryptographic chain from "what kernel saw" → "what RTMR holds"
    → "what ITA signed".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_log_sha256: str = Field(min_length=64, max_length=64)
    event_count: int = Field(ge=0, le=2**31 - 1)

    expected_rtmr0: str = Field(min_length=96, max_length=96)
    expected_rtmr1: str = Field(min_length=96, max_length=96)
    expected_rtmr2: str = Field(min_length=96, max_length=96)
    expected_rtmr3: str = Field(min_length=96, max_length=96)


# ===========================================================================
# 12. Long-haul / multi-nonce binding
# ===========================================================================


@dataclass(frozen=True, slots=True)
class LongHaulNonce:
    """Three-nonce CrossGuard binding for long-running and multi-fleet agents.

    Extends the base CrossGuard binding from ``attestation_client``
    with two additional nonces:

      * ``transcript_nonce``: rolling hash of the conversation
        transcript up to and including the current input. Lets the
        verifier detect transcript tampering — an attacker who can
        rewrite earlier turns produces a transcript hash that does
        not match the chain.

      * ``fleet_nonce``: SHA-256 of the operator's fleet ID
        concatenated with the decision ID. Prevents one operator
        from replaying another operator's attestation (the
        CrossGuard §6.2 cross-deployment replay class).

    All three nonces are folded into a single composite nonce that
    goes into the ITA report-data slot.
    """

    decision_nonce: str
    transcript_nonce: str
    fleet_nonce: str
    composite_nonce: str

    @classmethod
    def build(
        cls,
        *,
        decision_id: str,
        request_id: str,
        transcript_sha256: str,
        fleet_id: str,
    ) -> "LongHaulNonce":
        """Build the three-nonce binding.

        ``decision_nonce`` uses the same construction as
        ``attestation_client.decision_bound_nonce`` so all existing
        verifiers stay compatible. ``transcript_nonce`` and
        ``fleet_nonce`` are returned as the lower 32 hex chars
        (128 bits) of their respective SHA-256s. The composite
        nonce is SHA-256 of the three nonces concatenated, again
        truncated to 128 bits. Tex's ITA submitter uses
        ``composite_nonce`` as the canonical CrossGuard nonce.
        """
        from tex.tee.attestation_client import decision_bound_nonce

        d = decision_bound_nonce(decision_id, request_id)
        t = hashlib.sha256(
            b"tex-transcript:v1|" + transcript_sha256.encode("utf-8"),
        ).hexdigest()[:32]
        f = hashlib.sha256(
            b"tex-fleet:v1|" + fleet_id.encode("utf-8") + b"|" + decision_id.encode("utf-8"),
        ).hexdigest()[:32]
        composite = hashlib.sha256(
            b"tex-longhaul:v1|" + d.encode() + b"|" + t.encode() + b"|" + f.encode(),
        ).hexdigest()[:32]
        return cls(
            decision_nonce=d,
            transcript_nonce=t,
            fleet_nonce=f,
            composite_nonce=composite,
        )


# ===========================================================================
# Top-level augmentation envelope
# ===========================================================================


class Sota2026Augmentation(BaseModel):
    """The full May-2026 SOTA augmentation block.

    Tex's composite attestation envelope embeds one of these in the
    ``sota_2026`` field. None of the sub-fields are required — each
    is optional so operators can adopt the augmentations
    incrementally. The verifier matches whatever is present against
    its own policy and ignores absent fields.

    This is the production-grade home for:

      * EAT measured components (per artifact loaded)
      * CoRIM reference values (for offline appraisal)
      * Driver pinning (defence against downgrade)
      * TDISP evidence (defence against DMA-swap)
      * Multi-GPU batch summary (rack-scale CC)
      * Persistent memory attestation (open problem closed)
      * SCITT receipt (transparency-log binding)
      * TCB advisory check result (faster-than-Intel mitigation)
      * TSM event log binding (full chain "kernel→RTMR→ITA")
      * Long-haul nonce binding (transcript + fleet)
      * COSE algorithm IDs for the operator's PQ-agile re-signing
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    measured_components: tuple[MeasuredComponent, ...] = ()
    corim_reference_values: tuple[CoRimReferenceValue, ...] = ()

    gpu_platform: GpuTeePlatform | None = None
    driver_pinning: DriverPinning | None = None
    tdisp_evidence: TdispEvidence | None = None
    multi_gpu_batch: MultiGpuBatch | None = None

    persistent_memory_regions: tuple[PersistentMemoryRegion, ...] = ()
    tsm_event_log: TsmEventLog | None = None

    scitt_receipt: ScittReceipt | None = None

    tcb_advisory_ids: tuple[str, ...] = ()
    """Verbatim from the ITA ``attester_advisory_ids`` claim. The
    verifier matches these against the operator blocklist via
    ``check_tcb_advisories``."""

    longhaul_nonce_present: bool = False
    """True iff a three-nonce binding was used. The composite nonce
    is what appears in the ITA report-data, but downstream verifiers
    that don't know about LongHaulNonce will still accept the
    attestation."""

    cose_alg_id: int | None = None
    """The COSE algorithm number per
    ``draft-ietf-cose-dilithium-11`` if this envelope is being
    re-signed for transparency-log inclusion. None means classical
    PS384 (the ITA-issued default)."""


# ===========================================================================
# 13. SOTA-2026 verifier helpers
# ===========================================================================


@dataclass(frozen=True, slots=True)
class Sota2026VerifyOutcome:
    """Outcome of the SOTA-2026 augmentation checks.

    Used by the canonical verifier when the augmentation is present.
    The base composite verification still produces its own
    ``CompositeVerificationResult``; this struct is a side-channel of
    detailed sub-checks the relying party can consult.
    """

    ok: bool
    reasons: tuple[str, ...]
    measured_components_count: int
    corim_match_count: int
    driver_pinning_satisfied: bool | None
    tdisp_locked: bool | None
    advisory_check_ok: bool | None
    tsm_event_log_consistent: bool | None
    persistent_memory_count: int
    scitt_registered: bool


def verify_sota_2026(
    aug: Sota2026Augmentation,
    *,
    actual_driver_version: str | None = None,
    actual_rtmr0_through_3: tuple[str, str, str, str] | None = None,
    require_scitt: bool = False,
    require_tdisp_run_locked: bool = False,
) -> Sota2026VerifyOutcome:
    """Verify the SOTA-2026 augmentation block.

    All checks are optional — if an augmentation sub-field is None or
    empty, the corresponding check is skipped (returns True). The
    verifier returns ``ok=False`` only on present-but-failed
    sub-checks.
    """
    reasons: list[str] = []

    driver_pinning_satisfied: bool | None = None
    if aug.driver_pinning is not None:
        if actual_driver_version is None:
            driver_pinning_satisfied = False
            reasons.append("driver_pinning_no_actual_version")
        else:
            ok_p = True
            dp = aug.driver_pinning
            if actual_driver_version in dp.blocked_driver_versions:
                ok_p = False
                reasons.append(f"driver_blocked:{actual_driver_version}")
            if dp.pinned_driver_versions and actual_driver_version not in dp.pinned_driver_versions:
                ok_p = False
                reasons.append(f"driver_not_pinned:{actual_driver_version}")
            if _semver_lt(actual_driver_version, dp.min_driver_version):
                ok_p = False
                reasons.append(f"driver_below_min:{actual_driver_version}<{dp.min_driver_version}")
            driver_pinning_satisfied = ok_p

    tdisp_locked: bool | None = None
    if aug.tdisp_evidence is not None:
        tdisp_locked = aug.tdisp_evidence.lock_state == "run-locked"
        if require_tdisp_run_locked and not tdisp_locked:
            reasons.append(f"tdisp_not_run_locked:{aug.tdisp_evidence.lock_state}")

    advisory_check_ok: bool | None = None
    if aug.tcb_advisory_ids:
        adv_result = check_tcb_advisories(aug.tcb_advisory_ids)
        advisory_check_ok = adv_result.ok
        if not adv_result.ok:
            reasons.append(f"advisory_blocked:{','.join(adv_result.matched_advisories)}")

    tsm_event_log_consistent: bool | None = None
    if aug.tsm_event_log is not None and actual_rtmr0_through_3 is not None:
        tel = aug.tsm_event_log
        actual_r0, actual_r1, actual_r2, actual_r3 = actual_rtmr0_through_3
        tsm_event_log_consistent = (
            actual_r0 == tel.expected_rtmr0
            and actual_r1 == tel.expected_rtmr1
            and actual_r2 == tel.expected_rtmr2
            and actual_r3 == tel.expected_rtmr3
        )
        if not tsm_event_log_consistent:
            reasons.append("tsm_event_log_rtmr_mismatch")

    scitt_registered = aug.scitt_receipt is not None
    if require_scitt and not scitt_registered:
        reasons.append("scitt_receipt_required_but_missing")

    return Sota2026VerifyOutcome(
        ok=(len(reasons) == 0),
        reasons=tuple(reasons),
        measured_components_count=len(aug.measured_components),
        corim_match_count=len(aug.corim_reference_values),
        driver_pinning_satisfied=driver_pinning_satisfied,
        tdisp_locked=tdisp_locked,
        advisory_check_ok=advisory_check_ok,
        tsm_event_log_consistent=tsm_event_log_consistent,
        persistent_memory_count=len(aug.persistent_memory_regions),
        scitt_registered=scitt_registered,
    )


def _semver_lt(a: str, b: str) -> bool:
    """Numeric tuple comparison for driver-version strings.

    Handles the NVIDIA pattern (e.g. ``590.48.01``) and falls back to
    string comparison on anything non-numeric.
    """
    def _parse(v: str) -> tuple[Any, ...]:
        parts: list[Any] = []
        for chunk in v.split("."):
            chunk_strip = chunk.strip()
            try:
                parts.append((0, int(chunk_strip)))
            except ValueError:
                parts.append((1, chunk_strip))
        return tuple(parts)
    return _parse(a) < _parse(b)


__all__ = [
    # EAT measured-components
    "MeasuredComponent",
    # CoRIM
    "CoRimReferenceValue",
    # COSE PQ algorithm IDs
    "COSE_ALG_ML_DSA_44",
    "COSE_ALG_ML_DSA_65",
    "COSE_ALG_ML_DSA_87",
    "JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512",
    "JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256",
    "cose_alg_id_for",
    # Hardware platforms
    "GpuTeePlatform",
    "DriverPinning",
    "TdispEvidence",
    "MultiGpuBatch",
    # Persistent memory & event log
    "PersistentMemoryRegion",
    "TsmEventLog",
    # SCITT transparency
    "ScittReceipt",
    # TCB advisory blocklist
    "TcbAdvisoryCheckResult",
    "check_tcb_advisories",
    # Long-haul nonce binding
    "LongHaulNonce",
    # Top-level
    "Sota2026Augmentation",
    "Sota2026VerifyOutcome",
    "verify_sota_2026",
]
