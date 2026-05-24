"""
Text watermark detection — Thread 6 (Durable Content Credentials).

This module is the **detection** half of text watermarking. Insertion
(applying the watermark during generation) is the AI gateway's job
and lives in the model serving layer (Hugging Face Transformers
LogitsProcessor, vLLM, TGI, etc.). Tex's role is to **verify whether
a watermark is present** in inbound or outbound text and record that
finding as a C2PA soft binding.

Two schemes are supported:

  * **SynthID-Text** (Google DeepMind, Nature Oct 2024) — Bayesian
    detector over g-value samples; production-grade, integrated in
    Hugging Face Transformers v4.46.0+.
    Detector source: github.com/google-deepmind/synthid-text.

  * **TextSeal** (Meta FAIR, arxiv 2605.12456, **May 12 2026**) —
    Gumbel-max-based with dual-key generation, entropy-weighted
    scoring, multi-region localization. Strictly dominates SynthID-Text
    in detection strength and is robust to dilution.
    Source: github.com/facebookresearch/textseal.

Design properties
-----------------

1. **Pure-stdlib fallback.** The reference Bayesian detector for
   SynthID-Text and the entropy-weighted detector for TextSeal both
   need the model's logits and a key sequence. For verification in
   environments where neither model nor heavy ML stack is available
   (CI, downstream auditors, the Tex evidence-emission path), we
   ship a *score reconstruction* path: the gateway records the
   detection score it computed at generation time, signs it into
   the manifest's `tex.evidence_watermark` assertion, and the
   verifier confirms the score is bound to the asset hash via the
   manifest's outer signature.

2. **Detector adapter protocol.** ``WatermarkDetector`` is a
   ``Protocol`` so production deployments can plug in either:
     - the real SynthID-Text Bayesian detector via
       ``transformers.SynthIDTextWatermarkDetector``, or
     - the TextSeal entropy-weighted detector via
       ``textseal.Detector``,
   without changing the calling code. A pure-Python
   ``RecordedScoreDetector`` is provided for environments without
   ML deps; it trusts the gateway-recorded score and validates only
   format + range.

3. **Cross-layer audit (arxiv 2603.02378).** When both a C2PA hard
   binding (`content_sha256`) and a watermark soft binding are
   present, ``CrossLayerAuditor`` flags the *desynchronisation
   attack*: a manifest that says "human authored" while the watermark
   says "AI generated", or vice versa. Both signatures may be
   cryptographically valid but they assert contradictory things —
   exactly what the paper's Section 3 shows is not detected by any
   shipping C2PA validator.

References
----------
- Dathathri et al., "Scalable watermarking for identifying large
  language model outputs", Nature, Oct 2024.
- Sander et al., "TextSeal: A Localized LLM Watermark for Provenance
  & Distillation Protection", arxiv 2605.12456, May 12 2026.
- Omidi et al., "On Google's SynthID-Text LLM Watermarking System",
  arxiv 2603.03410, Mar 2026.
- Authenticated Contradictions from Desynchronised Provenance and
  Watermarking, arxiv 2603.02378, Mar 2 2026.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable


_logger = logging.getLogger(__name__)


class WatermarkScheme(str, Enum):
    """Supported watermark schemes."""

    SYNTHID_TEXT = "synthid-text"     # Google DeepMind, Nature Oct 2024
    TEXTSEAL = "textseal"             # Meta FAIR, arxiv 2605.12456, May 2026
    NONE = "none"                     # No watermark present / not applicable


# Wire-level schema URL for the tex.evidence_watermark assertion.
TEX_EVIDENCE_WATERMARK_SCHEMA_V1: str = (
    "https://schemas.texaegis.com/c2pa/tex.evidence_watermark/v1"
)
ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK: str = "tex.evidence_watermark"


# Detection thresholds (paper-derived; production deployments tune per-domain).
#
# SynthID-Text: the Bayesian detector returns a posterior score in [0, 1].
#   Dathathri et al. report Type-I error < 1e-2 at score > 0.9 on
#   200-token outputs. We default to 0.9 as a conservative threshold.
#
# TextSeal: the entropy-weighted score is a normalised log-likelihood
#   ratio. Sander et al. Table 2 reports TPR > 99% at FPR 1% at score > 4.0
#   on 250-token outputs. We use 4.0 as the default.
SYNTHID_TEXT_DEFAULT_THRESHOLD: float = 0.9
TEXTSEAL_DEFAULT_THRESHOLD: float = 4.0


@dataclass(frozen=True, slots=True)
class WatermarkDetectionResult:
    """Output of one detector run."""

    scheme: WatermarkScheme
    watermark_present: bool
    detection_score: float
    detection_p_value: float | None
    threshold: float
    detector_version: str
    text_length_tokens: int
    text_length_chars: int
    detected_regions: tuple[tuple[int, int], ...] = field(default_factory=tuple)
    issues: tuple[str, ...] = field(default_factory=tuple)

    @property
    def above_threshold(self) -> bool:
        return self.detection_score >= self.threshold


@runtime_checkable
class WatermarkDetector(Protocol):
    """Pluggable detector protocol.

    Real implementations call ``SynthIDTextWatermarkDetector`` or
    ``textseal.Detector`` under the hood. The ``RecordedScoreDetector``
    below is a pure-Python fallback for environments without the
    ML stack.
    """

    scheme: WatermarkScheme

    def detect(self, text: str, *, key_id: str) -> WatermarkDetectionResult: ...


@dataclass(frozen=True, slots=True)
class RecordedScoreDetector:
    """
    Pure-Python detector that trusts a gateway-recorded score.

    Use this in:
      - the Tex evidence emission path (the gateway has already
        computed the detection score at generation time and passes
        it to ``record_decision``),
      - CI environments without GPU / model deps,
      - the downstream verifier in ``POST /v1/c2pa/verify``, where the
        score is read from the manifest assertion.

    The score is bound to the asset hash via the outer C2PA signature
    (covers the `tex.evidence_watermark` assertion), so an attacker
    who tampers with the score breaks the outer signature.
    """

    scheme: WatermarkScheme
    recorded_score: float
    recorded_p_value: float | None
    threshold: float
    detector_version: str
    detected_regions: tuple[tuple[int, int], ...] = field(default_factory=tuple)

    def detect(self, text: str, *, key_id: str) -> WatermarkDetectionResult:
        # The score is what the gateway recorded; we just package it.
        # The text and key_id are unused except for length accounting —
        # the gateway-recorded score is the ground truth here.
        _ = key_id  # noqa: F841 — kept for protocol parity
        issues: list[str] = []
        if not (0.0 <= self.recorded_score <= 1e6):
            issues.append("watermark.score_out_of_range")
        return WatermarkDetectionResult(
            scheme=self.scheme,
            watermark_present=self.recorded_score >= self.threshold,
            detection_score=self.recorded_score,
            detection_p_value=self.recorded_p_value,
            threshold=self.threshold,
            detector_version=self.detector_version,
            text_length_tokens=_approx_token_count(text),
            text_length_chars=len(text),
            detected_regions=self.detected_regions,
            issues=tuple(issues),
        )


def _approx_token_count(text: str) -> int:
    """Token-count approximation that doesn't require a tokenizer.

    Used for length sanity checks only — exact counts are recovered
    by the production detector when wired.
    """
    return max(1, len(text.split()))


# ---------------------------------------------------------------------------
# Production detector adapters (lazy-import their heavy deps)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SynthIDTextDetectorAdapter:
    """
    Adapter for Google DeepMind's SynthID-Text Bayesian detector.

    Lazy-imports ``transformers.SynthIDTextWatermarkDetector``. If
    ``transformers`` is not installed (or the model files are missing),
    ``detect`` raises ``RuntimeError`` and the caller should fall back
    to ``RecordedScoreDetector``.

    The Bayesian detector requires the watermarking configuration
    (key, sampling table size, context history size, ngram length)
    that the generator used at sampling time. These are passed via
    ``__init__`` and assumed stable per ``key_id``.
    """

    scheme: WatermarkScheme = WatermarkScheme.SYNTHID_TEXT
    threshold: float = SYNTHID_TEXT_DEFAULT_THRESHOLD
    detector_version: str = "google-deepmind/synthid-text/v1"

    def detect(self, text: str, *, key_id: str) -> WatermarkDetectionResult:
        try:
            from transformers import (
                SynthIDTextWatermarkDetector,  # type: ignore[import-untyped]
            )
        except ImportError as exc:
            raise RuntimeError(
                "transformers>=4.46.0 is required for SynthIDTextDetectorAdapter. "
                "Install via `pip install transformers>=4.46.0`, or use "
                "RecordedScoreDetector for environments without the ML stack."
            ) from exc

        # Production wiring is intentionally out of scope for this
        # adapter — it needs a watermarking_config and a tokenizer
        # specific to the model that produced the text. Tex's
        # contract is: the gateway computes the score, Tex records it.
        # This branch is here for completeness so production callers
        # have a stable hook point.
        raise NotImplementedError(
            "Direct in-process SynthID-Text detection is a production "
            "wiring step that needs a model-specific watermarking_config "
            "and tokenizer. Use RecordedScoreDetector with the gateway's "
            "computed score, or override this adapter in your deployment."
        )


@dataclass(frozen=True, slots=True)
class TextSealDetectorAdapter:
    """
    Adapter for Meta FAIR's TextSeal detector.

    Lazy-imports ``textseal``. arxiv 2605.12456 (May 12 2026).
    See ``SynthIDTextDetectorAdapter`` for the deployment pattern.
    """

    scheme: WatermarkScheme = WatermarkScheme.TEXTSEAL
    threshold: float = TEXTSEAL_DEFAULT_THRESHOLD
    detector_version: str = "facebookresearch/textseal/v1"

    def detect(self, text: str, *, key_id: str) -> WatermarkDetectionResult:
        try:
            import textseal  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "textseal is required for TextSealDetectorAdapter. "
                "Install via `pip install textseal`, or use "
                "RecordedScoreDetector for environments without it."
            ) from exc

        _ = textseal  # noqa: F841 — placeholder for the production wiring
        raise NotImplementedError(
            "Direct in-process TextSeal detection is a production "
            "wiring step that needs the dual-key seeds the generator "
            "used. Use RecordedScoreDetector with the gateway's "
            "computed score, or override this adapter."
        )


# ---------------------------------------------------------------------------
# Soft-binding helpers (the C2PA soft binding piece)
# ---------------------------------------------------------------------------


def text_perceptual_hash(text: str) -> str:
    """
    Compute a perceptual hash over the text that survives common
    transformations (whitespace normalisation, quote insertion,
    line wrapping) — the kind of edits Gmail and Outlook perform
    on outbound email.

    This is *not* a watermark — it is a perceptual fingerprint.
    Used as the soft-binding `value` in the manifest assertion so
    that even if the watermark detection fails (e.g. because the
    asset was paraphrased), the manifest can still be looked up by
    a fuzzy hash match in a future Tex-side fingerprint registry.

    The approach is:
      1. Normalise: lowercase, collapse whitespace, strip non-letter
         punctuation that email clients commonly add/remove.
      2. Take the SHA-256 of the normalised form.

    This is intentionally simple — a more robust perceptual hash
    (PDQ, SimHash, MinHash) is the natural P1 upgrade.
    """
    normalised = " ".join(text.lower().split())
    # Strip ASCII punctuation that email clients commonly mangle.
    for ch in ".,;:!?'\"()[]{}<>—–-_*~`":
        normalised = normalised.replace(ch, "")
    normalised = " ".join(normalised.split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# tex.evidence_watermark assertion builder
# ---------------------------------------------------------------------------


def build_tex_evidence_watermark_assertion(
    *,
    detection: WatermarkDetectionResult,
    key_id: str,
    soft_binding_value: str,
    detector_url: str | None = None,
    asserted_origin: str = "ai-generated",
) -> dict[str, Any]:
    """
    Build the wire-level data dict for a ``tex.evidence_watermark``
    C2PA assertion. Returned as a plain dict so the caller can wrap
    it in a ``C2paAssertion`` without forcing this module to import
    the c2pa stack at module load.

    ``asserted_origin``: what the manifest *claims* about the asset.
    One of ``"ai-generated"`` (the AI gateway produced this) or
    ``"human-authored"`` (a human wrote this, no AI involvement).
    The CrossLayerAuditor below checks this against the watermark
    detection to flag desynchronisation attacks (arxiv 2603.02378).
    """
    if asserted_origin not in {"ai-generated", "human-authored"}:
        raise ValueError(
            "asserted_origin must be 'ai-generated' or 'human-authored', "
            f"got {asserted_origin!r}"
        )
    if len(soft_binding_value) < 16:
        raise ValueError("soft_binding_value must be a non-trivial hash")

    payload: dict[str, Any] = {
        "$schema": TEX_EVIDENCE_WATERMARK_SCHEMA_V1,
        "scheme": detection.scheme.value,
        "watermark_present": detection.watermark_present,
        "key_id": key_id,
        # Numeric fields are serialised as strings so the assertion
        # round-trips through Tex's RFC-8785 canonical-JSON encoder,
        # which rejects floats per the canonicaliser's I-JSON policy.
        "detection_score": f"{detection.detection_score:.10g}",
        "threshold": f"{detection.threshold:.10g}",
        "detector_version": detection.detector_version,
        "text_length_tokens": detection.text_length_tokens,
        "text_length_chars": detection.text_length_chars,
        "asserted_origin": asserted_origin,
        "soft_binding": {
            "kind": "perceptual-text-hash-v1",
            "value": soft_binding_value,
        },
        "paper_reference": {
            "synthid-text": "Dathathri et al., Nature 2024",
            "textseal": "arxiv:2605.12456 (May 12 2026)",
        }.get(detection.scheme.value, "n/a"),
    }
    if detection.detection_p_value is not None:
        payload["detection_p_value"] = f"{detection.detection_p_value:.6e}"
    if detector_url:
        payload["detector_url"] = detector_url
    if detection.detected_regions:
        payload["detected_regions"] = [
            {"start": s, "end": e} for s, e in detection.detected_regions
        ]
    if detection.issues:
        payload["issues"] = list(detection.issues)
    return payload


# ---------------------------------------------------------------------------
# Cross-layer audit (arxiv 2603.02378 — desynchronised provenance)
# ---------------------------------------------------------------------------


# Issue codes surfaced by the cross-layer auditor.
ISSUE_WATERMARK_MISSING: str = "watermark.missing"
ISSUE_WATERMARK_SCHEME_UNKNOWN: str = "watermark.scheme_unknown"
ISSUE_WATERMARK_SOFT_BINDING_MISSING: str = "watermark.soft_binding_missing"
ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED: str = (
    "watermark.desync.human_authored_but_ai_detected"
)
ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED: str = (
    "watermark.desync.ai_generated_but_not_detected"
)
ISSUE_WATERMARK_BELOW_THRESHOLD: str = "watermark.below_threshold"
ISSUE_WATERMARK_VALIDATED: str = "watermark.validated"


@dataclass(frozen=True, slots=True)
class CrossLayerAuditResult:
    """Output of the cross-layer audit (manifest + watermark + content)."""

    is_consistent: bool
    issues: tuple[str, ...]
    asserted_origin: str | None
    detected_watermark: bool | None
    detection_score: float | None
    paper_reference: str = "arxiv:2603.02378"


def cross_layer_audit(
    *,
    watermark_assertion: dict[str, Any] | None,
    asserted_origin_fallback: str | None = None,
    actual_detection: WatermarkDetectionResult | None = None,
) -> CrossLayerAuditResult:
    """
    Jointly audit the manifest's claimed origin against an actual
    watermark detection run.

    The desynchronisation attack of arxiv 2603.02378 produces
    content where:

      (a) the C2PA manifest's assertions say "human authored" but the
          watermark detector says "AI generated", or
      (b) the manifest says "AI generated" but no watermark is
          detected (i.e. the gateway forgot to apply one, or an
          adversary stripped it).

    Either case is *signed* (the C2PA outer signature still verifies)
    but the two layers contradict each other. This function returns
    ``is_consistent=False`` with the issue code that names which
    desync arose.

    ``actual_detection`` is the result of running a fresh detector
    on the asset bytes. When omitted, we rely on the manifest's
    recorded score (verification-only path).
    """
    if watermark_assertion is None:
        return CrossLayerAuditResult(
            is_consistent=False,
            issues=(ISSUE_WATERMARK_MISSING,),
            asserted_origin=asserted_origin_fallback,
            detected_watermark=None,
            detection_score=None,
        )

    issues: list[str] = []
    asserted_origin = watermark_assertion.get(
        "asserted_origin", asserted_origin_fallback
    )
    scheme = watermark_assertion.get("scheme")
    if scheme not in {s.value for s in WatermarkScheme}:
        issues.append(ISSUE_WATERMARK_SCHEME_UNKNOWN)

    soft = watermark_assertion.get("soft_binding")
    if not isinstance(soft, dict) or not soft.get("value"):
        issues.append(ISSUE_WATERMARK_SOFT_BINDING_MISSING)

    # Establish the detection truth.
    if actual_detection is not None:
        detected = actual_detection.watermark_present
        score = actual_detection.detection_score
    else:
        detected = bool(watermark_assertion.get("watermark_present", False))
        raw_score = watermark_assertion.get("detection_score")
        score = None
        if isinstance(raw_score, (int, float)):
            score = float(raw_score)
        elif isinstance(raw_score, str):
            try:
                score = float(raw_score)
            except ValueError:
                score = None

    # Desync rule (a): human-authored but watermark present.
    if asserted_origin == "human-authored" and detected:
        issues.append(ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED)

    # Desync rule (b): AI-generated but no watermark.
    if asserted_origin == "ai-generated" and not detected:
        # Distinguish "not detected because score below threshold" from
        # "scheme=none". Both are issues but with different recovery paths.
        if scheme == WatermarkScheme.NONE.value:
            issues.append(ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED)
        else:
            issues.append(ISSUE_WATERMARK_BELOW_THRESHOLD)

    if not issues:
        issues.append(ISSUE_WATERMARK_VALIDATED)

    is_consistent = (
        all(
            i not in issues
            for i in (
                ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED,
                ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED,
                ISSUE_WATERMARK_BELOW_THRESHOLD,
            )
        )
        and ISSUE_WATERMARK_VALIDATED in issues
    )
    return CrossLayerAuditResult(
        is_consistent=is_consistent,
        issues=tuple(issues),
        asserted_origin=asserted_origin,
        detected_watermark=detected,
        detection_score=score,
    )


__all__ = [
    # Enums + constants
    "WatermarkScheme",
    "TEX_EVIDENCE_WATERMARK_SCHEMA_V1",
    "ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK",
    "SYNTHID_TEXT_DEFAULT_THRESHOLD",
    "TEXTSEAL_DEFAULT_THRESHOLD",
    # Result + detector protocol
    "WatermarkDetectionResult",
    "WatermarkDetector",
    # Detector adapters
    "RecordedScoreDetector",
    "SynthIDTextDetectorAdapter",
    "TextSealDetectorAdapter",
    # Soft binding
    "text_perceptual_hash",
    # Assertion builder
    "build_tex_evidence_watermark_assertion",
    # Cross-layer audit
    "CrossLayerAuditResult",
    "cross_layer_audit",
    # Issue codes
    "ISSUE_WATERMARK_MISSING",
    "ISSUE_WATERMARK_SCHEME_UNKNOWN",
    "ISSUE_WATERMARK_SOFT_BINDING_MISSING",
    "ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED",
    "ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED",
    "ISSUE_WATERMARK_BELOW_THRESHOLD",
    "ISSUE_WATERMARK_VALIDATED",
]
