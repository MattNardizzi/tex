"""
[Architecture: Voice cognition / Layer 5 (Evidence)] — Wave 2 L11, the SEAL HALF.

What this is (ROADMAP.md:286, the split): commit the entailment scorer's
IDENTITY — ``model_id``, ``model_loaded``, the honest threshold label, and the
calibration-corpus digest — into the ECDSA voice-attestation chain, so that a
model swap or a corpus-byte flip FAILS REPLAY. The closed-world
conformal-entailment half stays research-grade and is NOT built here: ``import
transformers`` raises in this environment, there is no live prose verbalizer,
and the certified-limit literature says embedding/NLI conformal detectors
collapse on real hallucinations (arXiv:2512.15068, "The Semantic Illusion:
Certified Limits of Embedding-Based Hallucination Detection in RAG Systems" —
re-fetched 2026-06-11: 100% false-positive rate at target coverage on
HaluEval-class data; the disclaimers in this module exist so we never
over-promise what that paper shows breaking).

NAMING HONESTY: the FILE is named ``entailment_cert.py`` by the track plan; the
artifact it produces is deliberately an ``EntailmentCommitment`` — a sealed
statement of WHAT WOULD SCORE, never a certificate that anything was scored.
No "certificate" object is constructible here, and nothing this module
produces is a user-facing string (commitments live in the sealed chain, not in
spoken answers).

THE CENTRAL HONESTY FACT — λ̂ is now COMPUTABLE but the LIVE commitment seals
its ABSENCE. ``voice_gate.calibrate`` implements the Mohri–Hashimoto split
conformal quantile over a scorer that emits scores (``NeuralNLIScorer.score``).
Schema v2 therefore makes ``lambda_hat: float`` and ``calibrated: bool``
CONSTRUCTIBLE — but only as a COHERENT block (every calibration field travels
together; ``calibrated`` ⟺ a λ̂ ⟺ a backend ⟺ α ⟺ n ⟺ a bound corpus), and the
``"field"`` corpus kind is admissible ONLY behind the real loaded
transformers backend (a placeholder/stub scorer can never earn ``"field"``;
that is the load-bearing pin). What stays true here and now:

* The real scorer cannot run in this environment (``import transformers``
  raises) and no FIELD NLI corpus exists. So the LIVE commitment —
  ``commitment_for_scorer(NeuralNLIScorer())`` — is the absence:
  ``lambda_hat=None``, ``calibrated=False``, ``model_loaded=False``. The
  capstone derives ``entailment="blocked"`` from exactly that (compose.py).
* Rejected design (still rejected, now precisely): sealing a synthetic λ̂ AS
  IF it were a field guarantee. A synthetic-corpus λ̂ is a real conformal
  quantile of THAT distribution, but it certifies nothing about real spoken
  answers (arXiv:2512.15068). v2 keeps it honest structurally:
  ``scorer_backend`` and ``model_loaded`` record which scorer produced the
  number, ``calibration_corpus_kind`` records synthetic-vs-field, and the
  capstone promotes to green ONLY for ``model_loaded ∧ scorer_backend=neural
  ∧ corpus_kind=field``. A stub λ̂ self-labels and never reaches green.
* NOT a name collision: ``lambda_hat`` in ``engine/crc_gate.py`` is the RCPS
  permit cutoff — a different λ̂. This module inherits only its discipline
  (no number without calibration), not its meaning.

What a verifier gets — three proofs, NEVER collapsed (attestation.py:22-26):

1. the hash CHAIN proves INTEGRITY + ORDERING of the records as a sequence;
2. each record's SIGNATURE proves AUTHORSHIP of one sealed act — but the
   voice chain's key is EPHEMERAL per attestor with no rotation
   (attestation.py:32-36), so an adversary can re-mint a fresh,
   internally-valid chain around a swapped ``model_id``;
3. only the PINNED public key turns "internally consistent" into "Tex wrote
   this" — without the pin, authorship is reported ``None`` = UNVERIFIED
   (the M0b tamper-then-resign lesson, bench/wave2_corpus/loaders.py:281-286).

Maturity: the sealing crypto rides the production primitives (ECDSA-P256
today — ``EvidenceChainSigner`` via ``VoiceAttestor``; PQ is
RUNTIME-DEPENDENT). The commitment discipline is ``research-grade`` per
ROADMAP.md:286. The entailment half is BLOCKED/UNVERIFIED on torch/GPU (M0c
probes) + a field NLI corpus (M0b built the harness; collection is blocked on
real-world inputs). Live wiring is DEFERRED to the voice track: one line
riding ``voice_ask._gate_summary``'s ``gate`` dict, which is already sealed
per answer (the L2 seam-deferral precedent) — this module sits BESIDE the
seam and is callable from it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tex.evidence.seal import PQ_SIGNATURE_FIELD, verify_payload_signature
from tex.voice.attestation import (
    VoiceAttestationRecord,
    VoiceAttestor,
    _sha256_hex,
    _stable_json,
)
from tex.voice.voice_gate import (
    ENTAILMENT_BACKEND_NEURAL,
    ENTAILMENT_BACKEND_STUB,
    THRESHOLD_LABEL,
    Calibration,
    NeuralNLIScorer,
)

if TYPE_CHECKING:  # the corpus types stay a bench-side concern; no runtime import
    from tex.bench.wave2_corpus.loaders import LoadedCorpus

__all__ = [
    "CALIBRATED_THRESHOLD_LABEL",
    "COMMITMENT_DIMENSION",
    "COMMITMENT_SCHEMA",
    "ENTAILMENT_HALF_BLOCKED",
    "ENTAILMENT_HALF_GREEN",
    "GATE_COMMITMENT_HASH_KEY",
    "GATE_COMMITMENT_KEY",
    "NO_VERDICT_MARKER",
    "EntailmentCommitment",
    "EntailmentCommitmentVerification",
    "commitment_for_scorer",
    "commitment_from_calibration",
    "commitment_from_corpus",
    "entailment_half_status",
    "seal_entailment_commitment",
    "verify_entailment_commitment",
]

# The capstone L11 entailment-half labels. Defined HERE (the commitment's own
# module) so compose / manifest / verify all derive the half from one rule and
# can never drift.
ENTAILMENT_HALF_GREEN = "green"
ENTAILMENT_HALF_BLOCKED = "blocked"

COMMITMENT_SCHEMA = "tex.voice/entailment_commitment.v2"

# Where the commitment rides inside a VoiceAttestor.seal() payload: the
# free-form ``gate`` dict (``record_type`` is hard-coded "voice_attestation",
# attestation.py:114-137, and voice_ask._gate_summary already populates
# ``gate`` per answer — the natural carrier for the eventual live wiring).
GATE_COMMITMENT_KEY = "entailment_commitment"
GATE_COMMITMENT_HASH_KEY = "entailment_commitment_sha256"

# A standalone commitment seal is an identity act, not a spoken answer. The
# ``verdict`` field of its attestation payload carries this marker — outside
# the PERMIT/ABSTAIN/FORBID alphabet on purpose, so sealing a commitment can
# never fabricate a verdict event (tested).
NO_VERDICT_MARKER = "(no-verdict:entailment-commitment)"
COMMITMENT_DIMENSION = "entailment-commitment"

# The loader-gate vocabulary values this schema accepts. v2 admits "field"
# (the seal-half deferred it to "the schema version that also makes calibrated
# constructible") — but ONLY behind the real loaded scorer (the validator's
# field-pin). ``commitment_from_corpus`` still binds synthetic only, because it
# builds an UNCALIBRATED commitment and a field binding needs a real calibration.
_SYNTHETIC_KIND = "synthetic"
_FIELD_KIND = "field"

# The honest threshold label for a CALIBRATED commitment. Vocabulary-clean by
# construction (no "guarantee" / "coverage" / "1-alpha"): the validity is named
# precisely as marginal and distribution-bound. The absence commitment keeps
# voice_gate.THRESHOLD_LABEL ("UNCALIBRATED").
CALIBRATED_THRESHOLD_LABEL = (
    "split-conformal lambda-hat (Mohri-Hashimoto 2024, arXiv:2402.10978); "
    "marginal validity over the calibration distribution only, "
    "exchangeability-dependent, not worst-case, research-early"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ].+)?$")


def _default_model_id() -> str:
    # The CONFIGURED scorer identity, read from the seam's own default
    # (voice_gate.py:184) so the two can never silently drift. ``_model_id``
    # is private with no accessor; reading it is an identity lookup and does
    # NOT imply the scorer runs — ``scorer.name`` stays "neural-nli(off)".
    return NeuralNLIScorer()._model_id  # noqa: SLF001


class EntailmentCommitment(BaseModel):
    """The sealed identity of the entailment scorer + its calibration, if any.

    v2 makes a calibrated commitment constructible — but only as a COHERENT
    block (the validator below). The default constructor still yields the
    ABSENCE: an uncalibrated, not-loaded scorer's identity. A dishonest value
    cannot be constructed because the validator refuses every incoherent
    combination (calibrated without a λ̂, a λ̂ out of [0,1], ``model_loaded``
    without the neural backend, a ``"field"`` corpus behind a stub, …).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", protected_namespaces=())

    schema_version: str = Field(default=COMMITMENT_SCHEMA)
    model_id: str = Field(
        default_factory=_default_model_id,
        min_length=1,
        description="The CONFIGURED scorer identity (what WOULD load) — never a claim that it runs.",
    )
    model_loaded: bool = Field(
        default=False,
        description="True ONLY when a real transformers model loaded (⟺ scorer_backend is the neural one). False in this env BY DESIGN.",
    )
    threshold_label: str = Field(
        default=THRESHOLD_LABEL,
        min_length=1,
        description="THRESHOLD_LABEL (UNCALIBRATED) for the absence; CALIBRATED_THRESHOLD_LABEL-derived for a calibrated commitment.",
    )
    lambda_hat: float | None = Field(
        default=None,
        description="The conformal SCORE threshold (Mohri-Hashimoto), in [0,1]; None ⟺ uncalibrated. Present ⟺ calibrated.",
    )
    calibrated: bool = Field(
        default=False,
        description="True ⟺ a real conformal λ̂ was computed from a scorer's scores over a bound corpus.",
    )
    scorer_backend: Literal["transformers-cross-encoder", "deterministic-stub"] | None = Field(
        default=None,
        description="Which scorer produced the λ̂ — so a stub λ̂ can never masquerade as the real model's. Present ⟺ calibrated.",
    )
    calibration_alpha: float | None = Field(
        default=None,
        description="The conformal miss level α ∈ (0,1). Present ⟺ calibrated.",
    )
    calibration_n: int | None = Field(
        default=None,
        description="Calibration-set size n ≥ 1. Present ⟺ calibrated.",
    )
    calibration_manifest_sha256: str | None = Field(
        default=None,
        description="SHA-256 of the exact calibration-corpus bytes (hash, never store — attestation.py:128-130 discipline).",
    )
    calibration_corpus_id: str | None = Field(default=None)
    calibration_corpus_kind: Literal["synthetic", "field"] | None = Field(
        default=None,
        description="synthetic = no field claim; field is admissible only behind the real loaded neural backend (validator pin).",
    )
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @model_validator(mode="after")
    def _validate(self) -> "EntailmentCommitment":
        if self.schema_version != COMMITMENT_SCHEMA:
            raise ValueError(
                f"unknown commitment schema {self.schema_version!r}; this build reads "
                f"{COMMITMENT_SCHEMA!r} only (fail closed on unknown layouts)"
            )
        if not _ISO_RE.match(self.created_at):
            raise ValueError(f"created_at must be ISO-8601-shaped, got {self.created_at!r}")

        # ── corpus block: all-or-nothing, hash well-formed ──────────────────
        corpus_fields = (
            self.calibration_manifest_sha256,
            self.calibration_corpus_id,
            self.calibration_corpus_kind,
        )
        corpus_present = [f is not None for f in corpus_fields]
        if any(corpus_present) and not all(corpus_present):
            raise ValueError(
                "calibration_manifest_sha256 / calibration_corpus_id / "
                "calibration_corpus_kind travel together: bind a corpus fully or not at all"
            )
        if self.calibration_manifest_sha256 is not None and not _SHA256_RE.match(
            self.calibration_manifest_sha256
        ):
            raise ValueError("calibration_manifest_sha256 must be 64 lowercase hex characters")

        # ── calibration block: all-or-nothing, and == calibrated ────────────
        calib_block = (
            self.lambda_hat,
            self.scorer_backend,
            self.calibration_alpha,
            self.calibration_n,
        )
        block_present = [f is not None for f in calib_block]
        if any(block_present) and not all(block_present):
            raise ValueError(
                "the calibration block (lambda_hat / scorer_backend / "
                "calibration_alpha / calibration_n) travels together: a partial "
                "calibration is a fabricated quantile"
            )
        if self.calibrated != all(block_present):
            raise ValueError(
                "calibrated must be True iff the calibration block is fully "
                "present (no calibrated=True without a λ̂; no λ̂ without calibrated)"
            )

        if self.calibrated:
            if not 0.0 <= float(self.lambda_hat) <= 1.0:  # type: ignore[arg-type]
                raise ValueError(f"lambda_hat must lie in [0,1], got {self.lambda_hat!r}")
            if not 0.0 < float(self.calibration_alpha) < 1.0:  # type: ignore[arg-type]
                raise ValueError(
                    f"calibration_alpha must lie in (0,1), got {self.calibration_alpha!r}"
                )
            if int(self.calibration_n) < 1:  # type: ignore[arg-type]
                raise ValueError("calibration_n must be >= 1")
            if not all(corpus_present):
                raise ValueError(
                    "a calibrated commitment must name the corpus it calibrated "
                    "over (bind calibration_manifest_sha256 / corpus_id / kind)"
                )

        # ── model_loaded ⟺ the real neural backend ──────────────────────────
        if self.model_loaded and self.scorer_backend != ENTAILMENT_BACKEND_NEURAL:
            raise ValueError(
                "model_loaded=True is constructible only with scorer_backend="
                f"{ENTAILMENT_BACKEND_NEURAL!r} (a loaded model is the only thing "
                "that earns it)"
            )
        if self.scorer_backend == ENTAILMENT_BACKEND_NEURAL and not self.model_loaded:
            raise ValueError(
                "scorer_backend is the neural cross-encoder but model_loaded=False "
                "— the neural λ̂ can only come from a loaded model"
            )

        # ── the load-bearing pin: field is earned ONLY by the real model ────
        if self.calibration_corpus_kind == _FIELD_KIND and not (
            self.calibrated and self.model_loaded
        ):
            raise ValueError(
                "a 'field' corpus kind is constructible only behind a real, "
                "loaded neural calibration — a stub or uncalibrated 'field' "
                "binding would be a field guarantee Tex did not earn"
            )
        return self

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical encoding — the same ``_stable_json`` the
        voice chain hashes (byte-pinned to ``evidence.seal._stable_json`` by
        tests/voice/test_voice_attestation.py). Shape precedent:
        ``zkprov.manifest.DatasetManifest.canonical_bytes``."""
        return _stable_json(self.model_dump()).encode("utf-8")

    def commitment_sha256(self) -> str:
        """SHA-256 hex of the canonical encoding — the replay anchor."""
        return _sha256_hex(_stable_json(self.model_dump()))


def entailment_half_status(commitment: EntailmentCommitment) -> str:
    """Derive the capstone L11 entailment-half label from a commitment.

    GREEN only for a real field certification: a λ̂ from the loaded neural
    backend, calibrated over a ``"field"`` corpus. Everything else is BLOCKED —
    the absence (live), or a synthetic/stub calibration that validates the
    pipeline end to end but earns no field guarantee. The schema validator
    already makes a ``"field"`` kind unconstructible without the loaded neural
    backend, so this predicate cannot be satisfied by a stub; it is the SINGLE
    rule compose / manifest / verify share."""
    if (
        commitment.calibrated
        and commitment.model_loaded
        and commitment.scorer_backend == ENTAILMENT_BACKEND_NEURAL
        and commitment.calibration_corpus_kind == _FIELD_KIND
        and commitment.lambda_hat is not None
    ):
        return ENTAILMENT_HALF_GREEN
    return ENTAILMENT_HALF_BLOCKED


def commitment_for_scorer(
    scorer: NeuralNLIScorer,
    *,
    calibration_manifest_sha256: str | None = None,
    calibration_corpus_id: str | None = None,
    calibration_corpus_kind: Literal["synthetic"] | None = None,
) -> EntailmentCommitment:
    """Build the ABSENCE commitment from the live seam's own scorer instance.

    This is the uncalibrated path (``calibrated=False``, ``model_loaded=False``).
    Fail-closed: if ``scorer.load()`` returns True the scorer is actually
    running, and an uncalibrated commitment would understate it — raise and
    direct the caller to ``commitment_from_calibration`` (calibrate, then seal
    the real λ̂) rather than sealing ``model_loaded=False`` for a live model.
    Only the no-claim ``"synthetic"`` corpus kind is bindable here (an
    uncalibrated commitment may record "what corpus WOULD be used"; a field
    binding needs a real calibration — the schema's field-pin).
    """
    if scorer.load():
        raise ValueError(
            "scorer.load() returned True; commitment_for_scorer seals a NOT-LOADED "
            "scorer only — calibrate via commitment_from_calibration and seal the "
            "real lambda-hat rather than an uncalibrated commitment for a live model"
        )
    return EntailmentCommitment(
        model_id=scorer._model_id,  # noqa: SLF001 — identity lookup, not a status claim
        calibration_manifest_sha256=calibration_manifest_sha256,
        calibration_corpus_id=calibration_corpus_id,
        calibration_corpus_kind=calibration_corpus_kind,
    )


def commitment_from_corpus(
    corpus: "LoadedCorpus",
    *,
    corpus_sha256: str,
    scorer: NeuralNLIScorer | None = None,
) -> EntailmentCommitment:
    """Bind the commitment to an M0b NLI corpus artifact (the OPTIONAL path).

    ``corpus`` must come from ``bench.wave2_corpus.loaders.load_corpus`` (the
    kind gate) and ``corpus_sha256`` from the artifact's exact bytes
    (``loaders.corpus_digest``). Only the no-claim ``"synthetic"`` kind is
    bindable in schema v1 — even a LoadedCorpus hand-built with
    ``kind="field"`` (the M0b direct-caller residual) is refused here, because
    this schema has no field slot to put it in.
    """
    if corpus.consumer != "nli":
        raise ValueError(f"not an NLI corpus: consumer={corpus.consumer!r}")
    if corpus.kind != _SYNTHETIC_KIND:
        raise ValueError(
            f"commitment_from_corpus binds {_SYNTHETIC_KIND!r}-kind corpora only, got "
            f"{corpus.kind!r}; an UNCALIBRATED commitment cannot earn a field binding — "
            "calibrate the real loaded scorer and use commitment_from_calibration"
        )
    if corpus.provenance is not None and corpus.provenance.corpus_sha256 != corpus_sha256:
        raise ValueError(
            "corpus_sha256 contradicts the corpus's sealed provenance "
            f"({corpus_sha256[:12]}… vs {corpus.provenance.corpus_sha256[:12]}…)"
        )
    return commitment_for_scorer(
        scorer if scorer is not None else NeuralNLIScorer(),
        calibration_manifest_sha256=corpus_sha256,
        calibration_corpus_id=corpus.corpus_id,
        calibration_corpus_kind=_SYNTHETIC_KIND,
    )


def commitment_from_calibration(
    calibration: Calibration,
    *,
    calibration_manifest_sha256: str,
    calibration_corpus_id: str,
    calibration_corpus_kind: Literal["synthetic", "field"],
) -> EntailmentCommitment:
    """Seal a CALIBRATED commitment from a ``voice_gate.calibrate`` result.

    This is the path that becomes GREEN-eligible: it carries the real λ̂, the
    backend that produced it, α, n, and the corpus binding. The validator (not
    this builder) is the enforcer, but we pre-check the load-bearing pin so the
    error names the cause: a ``"field"`` calibration MUST come from the real
    loaded neural backend — a deterministic stub calibrates the PIPELINE on
    synthetic data, never a field guarantee.

    ``calibration_manifest_sha256`` / ``calibration_corpus_id`` come from the
    M0b artifact (``loaders.corpus_digest`` / the corpus id); ``corpus_kind``
    is the loader-EARNED kind (``LoadedCorpus.kind``), never a hand-typed string.
    """
    if (
        calibration_corpus_kind == _FIELD_KIND
        and calibration.scorer_backend != ENTAILMENT_BACKEND_NEURAL
    ):
        raise ValueError(
            "a 'field' calibration must come from the real neural scorer, not "
            f"{calibration.scorer_backend!r}: a stub calibrates the pipeline on "
            "synthetic data and can never earn a field binding"
        )
    threshold_label = (
        f"{CALIBRATED_THRESHOLD_LABEL}; alpha={calibration.alpha}; "
        f"n={calibration.n}; corpus={calibration_corpus_kind}; "
        f"backend={calibration.scorer_backend}"
    )
    return EntailmentCommitment(
        model_id=calibration.model_id,
        model_loaded=calibration.model_loaded,
        threshold_label=threshold_label,
        lambda_hat=calibration.lambda_hat,
        calibrated=True,
        scorer_backend=calibration.scorer_backend,
        calibration_alpha=calibration.alpha,
        calibration_n=calibration.n,
        calibration_manifest_sha256=calibration_manifest_sha256,
        calibration_corpus_id=calibration_corpus_id,
        calibration_corpus_kind=calibration_corpus_kind,
    )


# ── sealing ──────────────────────────────────────────────────────────────────


def seal_entailment_commitment(
    attestor: VoiceAttestor,
    commitment: EntailmentCommitment,
    *,
    transcript: str = "",
    routed_dimension: str | None = COMMITMENT_DIMENSION,
    verdict: str = NO_VERDICT_MARKER,
    answer: str = "",
    object_: dict[str, Any] | None = None,
    proof_ref: dict[str, Any] | None = None,
    gate: dict[str, Any] | None = None,
    tenant: str | None = None,
) -> VoiceAttestationRecord:
    """Seal one commitment into the voice chain, riding the ``gate`` dict.

    Defaults seal a standalone identity act (marker verdict, empty answer);
    the keyword passthrough is the exact shape the deferred live wiring uses —
    hand it the per-answer ``_gate_summary`` dict and the real verdict/answer,
    and the commitment travels inside the same sealed record.
    """
    gate_payload = dict(gate or {})
    if GATE_COMMITMENT_KEY in gate_payload or GATE_COMMITMENT_HASH_KEY in gate_payload:
        raise ValueError(
            f"gate dict already carries {GATE_COMMITMENT_KEY!r}/"
            f"{GATE_COMMITMENT_HASH_KEY!r} — refusing to overwrite a prior commitment"
        )
    gate_payload[GATE_COMMITMENT_KEY] = commitment.model_dump()
    gate_payload[GATE_COMMITMENT_HASH_KEY] = commitment.commitment_sha256()
    return attestor.seal(
        transcript=transcript,
        routed_dimension=routed_dimension,
        verdict=verdict,
        answer=answer,
        object_=object_,
        proof_ref=proof_ref,
        gate=gate_payload,
        tenant=tenant,
    )


# ── verification ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EntailmentCommitmentVerification:
    """The replay verdict, with the three proofs kept SEPARATE.

    - ``chain_intact``        — hash-chain integrity + ordering of the records.
    - ``signatures_valid``    — every record's embedded signature self-verifies
                                (authorship of each act by SOME key).
    - ``authorship_ok``       — every embedded key equals the PINNED key.
                                ``None`` == UNVERIFIED: no pin was supplied, and
                                a re-minted chain under a fresh key would pass
                                everything else (attestation.py:32-36).
    - ``model_id_ok``         — every commitment names ``expected_model_id``.
    - ``commitment_hashes_ok``— each embedded commitment re-validates against
                                schema v1 and its recomputed ``commitment_sha256``
                                matches the sealed one.
    - ``manifest_ok``         — the sealed corpus digest equals the digest the
                                verifier recomputed from the bytes they hold;
                                ``None`` == no expected digest supplied.
    """

    chain_intact: bool
    record_count: int
    signatures_valid: bool
    authorship_ok: bool | None
    commitments: tuple[EntailmentCommitment, ...]
    model_id_ok: bool
    commitment_hashes_ok: bool
    manifest_ok: bool | None
    issues: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """Everything CHECKABLE held. ``authorship_ok is None`` still passes
        here — integrity is never authorship; read ``authorship_ok``
        separately before trusting WHO sealed the chain."""
        return (
            self.chain_intact
            and self.signatures_valid
            and len(self.commitments) > 0
            and self.model_id_ok
            and self.commitment_hashes_ok
            and self.manifest_ok is not False
            and self.authorship_ok is not False
        )


def verify_entailment_commitment(
    records: Sequence[VoiceAttestationRecord],
    *,
    expected_model_id: str,
    pinned_public_key_b64: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> EntailmentCommitmentVerification:
    """Replay-verify the chain and every commitment riding in it.

    Walks the handed records with the chain's own math (byte-identical
    ``_stable_json``), verifies each embedded signature, compares embedded
    keys to the pin when one is supplied (``verify_bundle``'s semantics,
    bench/evidence_bundle.py:226-247), then re-validates each embedded
    commitment, recomputes its hash, and checks the model identity and —
    when given — the corpus digest. Never raises on tampered input; every
    failure is a named issue.
    """
    issues: list[str] = []

    # 1. the chain — integrity + ordering (mirrors VoiceAttestor.verify_chain).
    chain_intact = True
    previous_hash: str | None = None
    for idx, rec in enumerate(records):
        payload_sha256 = _sha256_hex(_stable_json(rec.payload))
        record_hash = _sha256_hex(
            _stable_json({"payload_sha256": payload_sha256, "previous_hash": previous_hash})
        )
        if (
            rec.previous_hash != previous_hash
            or rec.payload_sha256 != payload_sha256
            or rec.record_hash != record_hash
        ):
            chain_intact = False
            issues.append(f"chain_break_at:{idx}")
            break
        previous_hash = rec.record_hash

    # 2. signatures (self-verifying) + the optional key pin.
    signatures_valid = len(records) > 0
    all_keys_pinned = True
    for idx, rec in enumerate(records):
        if not verify_payload_signature(rec.payload):
            signatures_valid = False
            issues.append(f"signature_invalid_at:{idx}")
        block = rec.payload.get(PQ_SIGNATURE_FIELD)
        embedded_key = block.get("public_key_b64") if isinstance(block, dict) else None
        if pinned_public_key_b64 is not None and embedded_key != pinned_public_key_b64:
            all_keys_pinned = False
            issues.append(f"key_pin_mismatch_at:{idx}")
    authorship_ok: bool | None
    if pinned_public_key_b64 is None:
        authorship_ok = None  # UNVERIFIED — say so, never imply more
    else:
        authorship_ok = all_keys_pinned and signatures_valid

    # 3. the commitments riding in the gate dicts.
    commitments: list[EntailmentCommitment] = []
    model_id_ok = True
    hashes_ok = True
    manifest_ok: bool | None = None if expected_manifest_sha256 is None else True
    for idx, rec in enumerate(records):
        gate = rec.payload.get("gate")
        if not isinstance(gate, dict) or GATE_COMMITMENT_KEY not in gate:
            continue
        try:
            commitment = EntailmentCommitment.model_validate(gate[GATE_COMMITMENT_KEY])
        except Exception as exc:  # noqa: BLE001 — malformed claim is a verdict, not a crash
            hashes_ok = False
            issues.append(f"commitment_payload_invalid_at:{idx}:{exc.__class__.__name__}")
            continue
        commitments.append(commitment)
        if commitment.commitment_sha256() != gate.get(GATE_COMMITMENT_HASH_KEY):
            hashes_ok = False
            issues.append(f"commitment_hash_mismatch_at:{idx}")
        if commitment.model_id != expected_model_id:
            model_id_ok = False
            issues.append(
                f"model_id_mismatch_at:{idx}:{commitment.model_id!r}!={expected_model_id!r}"
            )
        if (
            expected_manifest_sha256 is not None
            and commitment.calibration_manifest_sha256 != expected_manifest_sha256
        ):
            manifest_ok = False
            issues.append(f"calibration_manifest_mismatch_at:{idx}")

    if not commitments:
        model_id_ok = False
        hashes_ok = False
        if expected_manifest_sha256 is not None:
            # The caller expected a digest and NOTHING carried one — that is a
            # failed check, never a vacuous pass.
            manifest_ok = False
        issues.append("no_entailment_commitment_in_records")

    return EntailmentCommitmentVerification(
        chain_intact=chain_intact,
        record_count=len(records),
        signatures_valid=signatures_valid,
        authorship_ok=authorship_ok,
        commitments=tuple(commitments),
        model_id_ok=model_id_ok,
        commitment_hashes_ok=hashes_ok,
        manifest_ok=manifest_ok,
        issues=tuple(issues),
    )
