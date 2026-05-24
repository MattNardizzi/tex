"""
Thread 6 tests — Durable Content Credentials (watermark + soft binding).

Covers:
  * ``RecordedScoreDetector`` for SynthID-Text and TextSeal.
  * ``build_tex_evidence_watermark_assertion`` builder shape and limits.
  * Perceptual text hash robustness to common email re-encoding.
  * Cross-layer audit detection of arxiv 2603.02378 desynchronisation
    attacks (manifest origin vs watermark detection contradictions).
"""

from __future__ import annotations

import pytest

from tex.c2pa import (
    ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
    SYNTHID_TEXT_DEFAULT_THRESHOLD,
    TEXTSEAL_DEFAULT_THRESHOLD,
    CrossLayerAuditResult,
    RecordedScoreDetector,
    WatermarkScheme,
    build_tex_evidence_watermark_assertion,
    cross_layer_audit,
    text_perceptual_hash,
)
from tex.c2pa.watermark import (
    ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED,
    ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED,
    ISSUE_WATERMARK_BELOW_THRESHOLD,
    ISSUE_WATERMARK_MISSING,
    ISSUE_WATERMARK_SOFT_BINDING_MISSING,
    ISSUE_WATERMARK_VALIDATED,
)


# ---------------------------------------------------------------------------
# RecordedScoreDetector
# ---------------------------------------------------------------------------


class TestRecordedScoreDetectorSynthID:
    def test_score_above_threshold_detected(self):
        det = RecordedScoreDetector(
            scheme=WatermarkScheme.SYNTHID_TEXT,
            recorded_score=0.95,
            recorded_p_value=1e-12,
            threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
            detector_version="google-deepmind/synthid-text/v1",
        )
        result = det.detect("hello world from an AI", key_id="synthid-key-1")
        assert result.watermark_present is True
        assert result.scheme == WatermarkScheme.SYNTHID_TEXT
        assert result.above_threshold is True
        assert result.detection_score == 0.95
        assert result.text_length_chars == len("hello world from an AI")
    def test_score_below_threshold_not_detected(self):
        det = RecordedScoreDetector(
            scheme=WatermarkScheme.SYNTHID_TEXT,
            recorded_score=0.7,
            recorded_p_value=None,
            threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
            detector_version="google-deepmind/synthid-text/v1",
        )
        result = det.detect("some text", key_id="k")
        assert result.watermark_present is False
        assert result.above_threshold is False


class TestRecordedScoreDetectorTextSeal:
    def test_textseal_default_threshold(self):
        det = RecordedScoreDetector(
            scheme=WatermarkScheme.TEXTSEAL,
            recorded_score=5.2,
            recorded_p_value=1e-15,
            threshold=TEXTSEAL_DEFAULT_THRESHOLD,
            detector_version="facebookresearch/textseal/v1",
            detected_regions=((0, 120), (250, 400)),
        )
        result = det.detect(
            "Subject: Tex Aegis pilot\nBody: " + "x" * 500, key_id="textseal-key"
        )
        assert result.watermark_present is True
        assert result.detected_regions == ((0, 120), (250, 400))
        # TextSeal threshold is 4.0; 5.2 is above.
        assert result.above_threshold


# ---------------------------------------------------------------------------
# Assertion builder
# ---------------------------------------------------------------------------


class TestBuildWatermarkAssertion:
    def test_full_payload_is_well_formed(self):
        det = RecordedScoreDetector(
            scheme=WatermarkScheme.TEXTSEAL,
            recorded_score=5.5,
            recorded_p_value=1e-18,
            threshold=TEXTSEAL_DEFAULT_THRESHOLD,
            detector_version="facebookresearch/textseal/v1",
        )
        body = b"this is an ai-generated marketing email body"
        result = det.detect(body.decode(), key_id="k-1")
        payload = build_tex_evidence_watermark_assertion(
            detection=result,
            key_id="k-1",
            soft_binding_value="sha256:" + ("a" * 64),
            asserted_origin="ai-generated",
            detector_url="https://github.com/facebookresearch/textseal",
        )
        assert payload["scheme"] == "textseal"
        assert payload["watermark_present"] is True
        assert payload["asserted_origin"] == "ai-generated"
        assert payload["soft_binding"]["kind"] == "perceptual-text-hash-v1"
        assert payload["soft_binding"]["value"].startswith("sha256:")
        assert "$schema" in payload
        # Paper reference is carried into the assertion.
        assert "2605.12456" in payload["paper_reference"]

    def test_invalid_asserted_origin_rejected(self):
        det = RecordedScoreDetector(
            scheme=WatermarkScheme.SYNTHID_TEXT,
            recorded_score=0.95, recorded_p_value=None,
            threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
            detector_version="v",
        )
        with pytest.raises(ValueError, match="asserted_origin"):
            build_tex_evidence_watermark_assertion(
                detection=det.detect("x", key_id="k"),
                key_id="k",
                soft_binding_value="sha256:" + ("a" * 64),
                asserted_origin="something-else",
            )


# ---------------------------------------------------------------------------
# Perceptual hash
# ---------------------------------------------------------------------------


class TestPerceptualTextHash:
    def test_whitespace_normalisation(self):
        h1 = text_perceptual_hash("Hello recruiter, this is an AI email.")
        h2 = text_perceptual_hash("Hello   recruiter,\n  this  is an AI\temail.")
        assert h1 == h2

    def test_case_normalisation(self):
        h1 = text_perceptual_hash("Hello Sara")
        h2 = text_perceptual_hash("HELLO SARA")
        assert h1 == h2

    def test_punctuation_stripping(self):
        h1 = text_perceptual_hash("Hi, Sara! This is Tex Aegis.")
        h2 = text_perceptual_hash("Hi Sara This is Tex Aegis")
        assert h1 == h2

    def test_different_content_differs(self):
        h1 = text_perceptual_hash("subject line A")
        h2 = text_perceptual_hash("subject line B")
        assert h1 != h2

    def test_hash_is_64_hex(self):
        h = text_perceptual_hash("any text at all")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Cross-layer audit (arxiv 2603.02378)
# ---------------------------------------------------------------------------


def _wm_assertion(*, present: bool, origin: str, scheme: str = "textseal") -> dict:
    """Helper — minimal assertion dict for cross-layer audit tests."""
    return {
        "$schema": "https://schemas.texaegis.com/c2pa/tex.evidence_watermark/v1",
        "scheme": scheme,
        "watermark_present": present,
        "asserted_origin": origin,
        "detection_score": "5.5" if present else "0.2",
        "soft_binding": {"kind": "perceptual-text-hash-v1", "value": "a" * 64},
    }


class TestCrossLayerAudit:
    def test_consistent_ai_generated_with_watermark(self):
        result = cross_layer_audit(
            watermark_assertion=_wm_assertion(present=True, origin="ai-generated")
        )
        assert isinstance(result, CrossLayerAuditResult)
        assert result.is_consistent is True
        assert ISSUE_WATERMARK_VALIDATED in result.issues
        assert result.detected_watermark is True

    def test_consistent_human_authored_without_watermark(self):
        # No watermark + asserted_origin=ai-generated would be a desync.
        # asserted_origin=human-authored + no watermark is *consistent*.
        wm = _wm_assertion(present=False, origin="human-authored", scheme="none")
        result = cross_layer_audit(watermark_assertion=wm)
        assert result.is_consistent is True
        assert ISSUE_WATERMARK_VALIDATED in result.issues

    def test_desync_human_authored_but_watermark_present(self):
        """The arxiv 2603.02378 attack: manifest claims human-authored
        but the watermark detector says AI generated."""
        wm = _wm_assertion(present=True, origin="human-authored")
        result = cross_layer_audit(watermark_assertion=wm)
        assert result.is_consistent is False
        assert ISSUE_DESYNC_HUMAN_AUTHORED_BUT_AI_DETECTED in result.issues
        assert result.paper_reference == "arxiv:2603.02378"

    def test_desync_ai_generated_but_no_watermark_at_all(self):
        """The complementary desync: manifest claims AI-generated, but the
        scheme is "none" (gateway forgot to apply a watermark, or an
        adversary stripped it before signing the manifest)."""
        wm = _wm_assertion(present=False, origin="ai-generated", scheme="none")
        result = cross_layer_audit(watermark_assertion=wm)
        assert result.is_consistent is False
        assert ISSUE_DESYNC_AI_GENERATED_BUT_NOT_DETECTED in result.issues

    def test_desync_ai_generated_but_below_threshold(self):
        """A separate failure mode: scheme is set but score is below
        threshold (could be dilution, paraphrasing, or a tampered score)."""
        wm = _wm_assertion(present=False, origin="ai-generated")
        result = cross_layer_audit(watermark_assertion=wm)
        assert result.is_consistent is False
        assert ISSUE_WATERMARK_BELOW_THRESHOLD in result.issues

    def test_missing_watermark_assertion_flagged(self):
        result = cross_layer_audit(watermark_assertion=None)
        assert ISSUE_WATERMARK_MISSING in result.issues
        assert result.is_consistent is False

    def test_missing_soft_binding_flagged(self):
        wm = _wm_assertion(present=True, origin="ai-generated")
        wm.pop("soft_binding")
        result = cross_layer_audit(watermark_assertion=wm)
        assert ISSUE_WATERMARK_SOFT_BINDING_MISSING in result.issues
