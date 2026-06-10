from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "EvidenceRecord",
    "EvidenceKind",
    "EvidenceMaturity",
    "TexEvidence",
]


class EvidenceRecord(BaseModel):
    """
    Append-only audit record for a Tex decision.

    This is the atomic unit written into the evidence log and hash chain.
    It is intentionally narrow and stable:
    - identifies the decision and request
    - captures the serialized payload being chained
    - stores the cryptographic linkage to the previous record
    - records when the entry was written

    The evidence layer should be tamper-evident, not overloaded with business
    logic. Rich decision semantics belong in the Decision model; this record is
    the durable audit envelope around that data.

    Verification of record_hash against payload_json + previous_hash belongs in
    the evidence chain layer, not here. That logic should be implemented in
    tex.evidence.chain so chain verification stays centralized and consistent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4)
    decision_id: UUID
    request_id: UUID

    record_type: str = Field(
        min_length=1,
        max_length=100,
        description="Stable type identifier such as 'decision' or 'outcome'.",
    )
    payload_json: str = Field(
        min_length=2,
        description="Canonical serialized JSON payload included in the evidence chain.",
    )

    payload_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of payload_json.",
    )
    previous_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Hash of the previous evidence record in the chain, if any.",
    )
    record_hash: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest for this chained evidence record.",
    )

    policy_version: str = Field(
        min_length=1,
        max_length=100,
        description="Policy version active when the decision was made.",
    )

    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("record_type", "payload_json", "policy_version", mode="before")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("Value must be a string.")
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value must not be blank.")
        return normalized

    @field_validator("payload_sha256", "record_hash", mode="before")
    @classmethod
    def validate_required_sha256_hex(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("Hash value must be a string.")
        normalized = value.strip().lower()
        if len(normalized) != 64:
            raise ValueError("Hash values must be 64-character SHA-256 hex digests.")
        allowed = set("0123456789abcdef")
        if any(char not in allowed for char in normalized):
            raise ValueError(
                "Hash values must contain only lowercase hexadecimal characters."
            )
        return normalized

    @field_validator("previous_hash", mode="before")
    @classmethod
    def validate_optional_sha256_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("previous_hash must be a string when provided.")
        normalized = value.strip().lower()
        if len(normalized) != 64:
            raise ValueError("previous_hash must be a 64-character SHA-256 hex digest.")
        allowed = set("0123456789abcdef")
        if any(char not in allowed for char in normalized):
            raise ValueError(
                "previous_hash must contain only lowercase hexadecimal characters."
            )
        return normalized


# ===========================================================================
# TexEvidence — the typed e-value snapshot (the truth track's interface)
# ===========================================================================
#
# What this is, and why it sits next to EvidenceRecord
# ----------------------------------------------------
# ``EvidenceRecord`` above is the *audit envelope*: the tamper-evident,
# hash-chained container a decision is sealed into. ``TexEvidence`` is the
# *statistical payload* that envelope will carry — one immutable, sealable
# snapshot of a single evidence stream's e-value at one look.
#
# It is the interface other tracks build against: the abstain track turns
# its OPE / CRC / drift-rate signals into ``TexEvidence`` values, the struct
# track turns its structural signals into ``TexEvidence`` values, and the
# multiplicative e-value spine (a later PR) composes them into one sealed
# scalar. Getting the *type* right now — before five producers and one
# combiner depend on it — is the point of shipping it first and alone.
#
# The one honesty problem this type exists to solve
# -------------------------------------------------
# The brief asks for "one Ville-bounded sealed scalar" composed from CRC +
# OPE + drift + per-agent + voice-error. But, verified against the live code
# this session, those signals are NOT the same mathematical object:
#
#   * drift  (``drift/_anytime_valid.py``) emits ``log_e_value`` — a genuine
#     mixture *test martingale*, an e-process: ``E_{H0}[E_tau] <= 1`` at every
#     stopping time, so Ville's inequality gives
#     ``P(sup_t E_t >= 1/alpha) <= alpha``. This is a true e-value.
#   * OPE    (``learning/ope.py``) returns ``OPEReport.upper_bound`` — an
#     anytime-valid *confidence-sequence bound*. Dual to an e-process, but the
#     returned object is a bound, NOT an e-value, until explicitly inverted.
#   * CRC    (``engine/crc_gate.py``) emits a ``CRCCertificate`` — a one-shot,
#     offline, frozen RCPS ``(alpha, delta)`` guarantee about a fixed
#     estimator. It is a static *calibration certificate*, never a
#     per-decision e-value. Multiplying it into a running product is a
#     category error.
#
# The combination math (retrieved & verified this session):
#   * The PRODUCT of e-values is an e-value only when they are sequential /
#     conditional on one filtration (running product = a test supermartingale;
#     Grünwald–de Heide–Koolen, "Safe Testing", JRSS-B 2024, Prop. 2), of
#     which independence is the unconditional special case.
#   * Under ARBITRARY dependence the *only* admissible symmetric merge is the
#     weighted arithmetic MEAN (Vovk–Wang, "The only admissible way of merging
#     arbitrary e-values", Biometrika 2025 / arXiv:2409.19888, Thm 1; and
#     "E-values: Calibration, combination, and applications", Ann. Statist.
#     2021). The product is NOT a valid merge under arbitrary dependence.
#   * Cross-filtration evidence may not be naively merged at all; it needs an
#     adjuster (Choe–Ramdas, "Combining Evidence Across Filtrations",
#     JRSS-B 2026 / arXiv:2402.09698).
#
# So a single scalar that multiplies all five and is *labelled* "Ville-bounded"
# would be a fabricated guarantee — the exact ``nanozk`` failure mode (a
# stats-sounding name the body does not deliver) this project exists to never
# repeat. ``TexEvidence`` makes *that specific composite lie* un-declarable:
# ``kind`` says what the scalar provably IS, ``is_true_e_value`` says whether the
# Ville bound actually holds, and a ``model_validator`` refuses the
# self-contradictory over-claims — so a calibration certificate (CRC) or a raw
# confidence-sequence bound (OPE) can never enter a product *as a true e-value*.
# The spine (later) reads these fields — never a name — to decide which merge is
# legal.
#
# Honest limit (stated up front, not buried): this type prevents a producer
# from *declaring* a contradictory over-claim. It does NOT verify the
# underlying martingale math — a producer that stamps ``kind=e_process,
# is_true_e_value=True`` on something that is not actually a martingale is
# lying in the data, and only a per-stream property test (``E_{H0}[E] <= 1``
# under the null — a later PR, same bar as the verdict-path coverage rule) can
# catch that. The type moves the trust boundary to a small, auditable set of
# vetted emitters; it does not eliminate it.


class EvidenceKind(StrEnum):
    """What a sealed evidence scalar *provably is* — the field that keeps the
    name honest. Composition dispatches on this, never on a producer's name.

    Only ``E_PROCESS`` and ``E_VALUE`` natively carry a Ville bound and may
    enter a product. ``CONFIDENCE_SEQUENCE_BOUND`` and
    ``CALIBRATION_CERTIFICATE`` are *not* e-values; they are admitted to the
    type so they can be sealed honestly and used as fail-closed gates, but the
    spine must refuse to multiply them (a calibration certificate) or require
    an explicit calibrator first (a confidence-sequence bound).
    """

    # A non-negative test (super)martingale snapshot: an e-variable at EVERY
    # stopping time. Ville-bounded. drift/_anytime_valid.py emits this.
    E_PROCESS = "e_process"
    # A single-shot true e-value: E_{H0}[E] <= 1 at one fixed look.
    E_VALUE = "e_value"
    # An anytime-valid confidence-sequence / upper bound (e.g. OPE). Dual to an
    # e-process but NOT itself an e-value until an explicit calibrator inverts
    # it. Never Ville-bounded as stored.
    CONFIDENCE_SEQUENCE_BOUND = "confidence_sequence_bound"
    # A frozen, one-shot RCPS (alpha, delta) calibration guarantee (e.g. CRC).
    # A static gate, NOT a per-decision e-value — never multipliable.
    CALIBRATION_CERTIFICATE = "calibration_certificate"


class EvidenceMaturity(StrEnum):
    """The constitution's maturity tag, carried in the sealed bytes rather than
    in prose so a relying party reads it off the ledger, not a docstring.

    Orthogonal to ``EvidenceKind`` / ``is_true_e_value`` on purpose: statistical
    validity and engineering readiness are different axes. The drift e-process
    today is a real test martingale (a true e-value) but is ``RESEARCH_SOLID``,
    not ``PRODUCTION`` — it is not yet benchmarked in CI. A future ECDSA-sealed,
    CI-benchmarked drift certificate could become ``PRODUCTION`` without any
    change to combiner behaviour.
    """

    PRODUCTION = "production"
    RESEARCH_SOLID = "research_solid"
    RESEARCH_EARLY = "research_early"
    SPECULATIVE = "speculative"


class TexEvidence(BaseModel):
    """One immutable, ledger-sealable snapshot of an evidence stream's e-value.

    The atomic unit the multiplicative e-value spine composes. Pure data, no
    streaming state: the mutable accumulator (drift's ``AnytimeValidEProcess``,
    a future per-agent or voice-error process) lives in the engine and emits
    one frozen ``TexEvidence`` per look. Frozen + ``extra="forbid"`` to match
    every ``domain/`` sibling and to be safe to hand into the hash chain.

    The scalar is stored in LOG space (``log_e_value``) for three reasons:
    sequential evidence multiplies and so *adds* in logs (the spine composes by
    addition), log space is numerically stable against overflow, and it matches
    ``drift._anytime_valid.AnytimeValidCertificate.log_e_value`` exactly so the
    drift adapter is a field copy, not a silent rename. ``e_value`` is a derived
    property so the canonical seal stays log-scale.

    Validity is self-describing and replay-checkable: ``kind``,
    ``is_true_e_value``, ``sequentially_predictable`` and ``calibrator`` are all
    sealed, so a verifier replaying the ledger can re-confirm that any
    composition was mathematically legal by reading the data — not by trusting
    Tex. See the module banner above for the e-value math and the honest limit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4)
    # The decision this look belongs to, when it belongs to one. A streaming
    # monitor's standalone snapshot may have none; the per-decision spine sets
    # it. Joins to EvidenceRecord.decision_id when present.
    decision_id: UUID | None = None

    # Which emitter produced this ('drift' | 'ope' | 'crc' | 'per_agent:<id>' |
    # 'voice_error'). Diagnostic and grouping only — NEVER trusted for dispatch.
    stream_id: str = Field(min_length=1, max_length=200)

    kind: EvidenceKind
    maturity: EvidenceMaturity

    # The load-bearing honesty flag: True iff E_{H0}[exp(log_e_value)] <= 1
    # holds for THIS construction, so the Ville bound and a Ville p-value are
    # licensed. The model_validator below refuses the dishonest combinations
    # (a calibration certificate, or a raw confidence-sequence bound, can never
    # set this True).
    is_true_e_value: bool

    # THE canonical scalar: log E_t. Finite-only so canonical JSON and the seal
    # can never trip on NaN/inf — clip in the e-process, not here.
    log_e_value: float

    # The null H0 this snapshot tests. Composition is only meaningful across a
    # shared null; the spine refuses mixed-H0 tuples.
    null_hypothesis_id: str = Field(min_length=1, max_length=200)
    # The information set / look schedule this is valid in. Cross-filtration
    # combination is illegal without an adjuster (Choe–Ramdas); the spine
    # refuses mixed-filtration tuples rather than silently mis-merging.
    filtration_id: str = Field(min_length=1, max_length=200)

    # The error budget the producer designed against, if any. Ville threshold
    # is 1/alpha. None when the snapshot targets no fixed level.
    alpha: float | None = Field(default=None, gt=0.0, lt=1.0)

    # True iff this snapshot is an e-variable conditional on this stream's own
    # past under THIS filtration (E_{H0}[E_i | past] <= 1) — the condition that
    # licenses the running PRODUCT within a stream (Safe Testing Prop. 2).
    # False forbids multiplication of this factor.
    sequentially_predictable: bool = False

    # Names a transform that derived log_e_value from a non-e-value source
    # ('p_to_e:integrated', 'adjuster:mixture'); None means raw native
    # emission. Required (non-None) for a confidence-sequence bound to ever be
    # is_true_e_value — so a conversion is always recorded in the seal.
    calibrator: str | None = Field(default=None, max_length=200)

    # Step count t — joins to the raw stream so an auditor can reconstruct E_t.
    sample_size: int = Field(default=0, ge=0)

    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # ------------------------------------------------------------- validators
    @field_validator("log_e_value")
    @classmethod
    def _finite_log_e_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError(
                "log_e_value must be finite (no NaN/inf) — clip in the "
                "e-process, not in the sealed snapshot."
            )
        return float(value)

    @field_validator("stream_id", "null_hypothesis_id", "filtration_id")
    @classmethod
    def _nonblank_identifier(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("identifier must be a string.")
        normalized = value.strip()
        if not normalized:
            raise ValueError("identifier must not be blank.")
        return normalized

    @field_validator("calibrator")
    @classmethod
    def _nonblank_optional_calibrator(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("calibrator must be a string when provided.")
        normalized = value.strip()
        if not normalized:
            raise ValueError("calibrator must not be blank when provided.")
        return normalized

    @model_validator(mode="after")
    def _honesty_invariants(self) -> "TexEvidence":
        """Refuse the self-contradictory OVER-claims at construction.

        Every rule fires in one direction only — it blocks claiming the Ville
        guarantee where the construction does not license it. Honest
        UNDER-claiming (e.g. ``kind=E_PROCESS`` with ``is_true_e_value=False``
        for a not-yet-validated research stream) is always allowed.
        """
        if self.is_true_e_value:
            if self.kind is EvidenceKind.CALIBRATION_CERTIFICATE:
                raise ValueError(
                    "a calibration_certificate is a frozen one-shot guarantee, "
                    "never a per-decision e-value; is_true_e_value must be False."
                )
            if (
                self.kind is EvidenceKind.CONFIDENCE_SEQUENCE_BOUND
                and self.calibrator is None
            ):
                raise ValueError(
                    "a confidence_sequence_bound is not an e-value until an "
                    "explicit calibrator inverts it; set calibrator or "
                    "is_true_e_value=False."
                )
            if (
                self.kind is EvidenceKind.E_PROCESS
                and not self.sequentially_predictable
            ):
                raise ValueError(
                    "an e_process is an e-variable at every stopping time and "
                    "must be sequentially_predictable to be a true e-value."
                )
        return self

    # ------------------------------------------------------------- derived API
    @property
    def e_value(self) -> float:
        """``E_t = exp(log_e_value)``. Derived, never stored, so the seal stays
        log-scale. Evidential only when ``is_true_e_value`` — for a bound or a
        certificate this is just ``exp`` of a descriptive log."""
        return math.exp(self.log_e_value)

    @property
    def ville_p_value(self) -> float | None:
        """The anytime-valid p-value ``min(1, 1/E_t)`` — but ONLY when this is a
        true e-value. Returns ``None`` otherwise: a confidence-sequence bound or
        a frozen certificate has no Ville p-value, and fabricating one is the
        lie this type exists to prevent."""
        if not self.is_true_e_value:
            return None
        if self.log_e_value <= 0.0:
            return 1.0
        return min(1.0, math.exp(-self.log_e_value))

    def is_ville_significant_at(self, alpha: float) -> bool:
        """True iff this snapshot rejects its ``H0`` at level ``alpha`` with an
        anytime-valid guarantee. Raises for a non-e-value — you cannot
        Ville-test a confidence-sequence bound or a frozen certificate. Mirrors
        ``drift._anytime_valid.AnytimeValidCertificate.is_significant_at``."""
        if not 0.0 < alpha < 1.0:
            raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")
        p = self.ville_p_value
        if p is None:
            raise ValueError(
                f"kind {self.kind} carries no Ville bound; cannot test at alpha."
            )
        return p < alpha

    # ------------------------------------------------------------- sealing
    def canonical_payload(self) -> dict[str, object]:
        """The ordered, JSON-safe dict that is sealed. Every material field is
        present; UUIDs and the timestamp are stringified so the form is stable
        and explicit (not reliant on an encoder default)."""
        return {
            "evidence_id": str(self.evidence_id),
            "decision_id": str(self.decision_id) if self.decision_id else None,
            "stream_id": self.stream_id,
            "kind": self.kind.value,
            "maturity": self.maturity.value,
            "is_true_e_value": self.is_true_e_value,
            "log_e_value": self.log_e_value,
            "null_hypothesis_id": self.null_hypothesis_id,
            "filtration_id": self.filtration_id,
            "alpha": self.alpha,
            "sequentially_predictable": self.sequentially_predictable,
            "calibrator": self.calibrator,
            "sample_size": self.sample_size,
            "recorded_at": self.recorded_at.isoformat(),
        }

    def canonical_json(self) -> str:
        """Stable serialization for the hash chain — sorted keys, tight
        separators, identical idiom to ``provenance/ledger.py:_stable_json`` so a
        ``TexEvidence`` sealed into the ledger re-serializes byte-identically.

        Float note: CPython's ``json`` emits the shortest round-tripping repr
        for a finite float, so ``log_e_value`` is byte-stable on the same value;
        a cross-implementation verifier must match that convention."""
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def payload_sha256(self) -> str:
        """SHA-256 hex digest of ``canonical_json()`` — the payload hash the
        chain layer links. Provided so the standalone offline verifier (a later
        PR) recomputes it the same way the sealer did."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()