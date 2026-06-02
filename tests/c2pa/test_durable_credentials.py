"""
Tests for tex.c2pa.durable_credentials — multi-layer durable marking
per C2PA Trust Markers spec + EU Code of Practice §Watermark-2.

The TrustMark cryptographic embed path requires PyTorch and is gated;
the structural tests (layer enumeration, fingerprint computation, the
require_watermark_layer guard) run without ML deps.
"""

from __future__ import annotations

import pytest

from tex.c2pa.durable_credentials import (
    DurableLayer,
    DurableMarkingResult,
    attach_durable_marks,
    trustmark_available,
)


def test_durable_layers_enumerated_correctly():
    assert DurableLayer.C2PA_MANIFEST.value == "c2pa_manifest"
    assert DurableLayer.PERCEPTUAL_WATERMARK.value == "perceptual_watermark"
    assert DurableLayer.FINGERPRINT.value == "fingerprint"


def test_attach_durable_marks_applies_manifest_and_fingerprint_layers():
    """Even without TrustMark/PyTorch, the manifest + fingerprint
    layers should always land."""
    result = attach_durable_marks(b"some-content-bytes", manifest_id="urn:uuid:abc")
    assert isinstance(result, DurableMarkingResult)
    assert DurableLayer.C2PA_MANIFEST in result.layers_applied
    assert DurableLayer.FINGERPRINT in result.layers_applied
    assert len(result.perceptual_hash) == 64  # SHA-256 hex
    assert result.manifest_id == "urn:uuid:abc"


def test_require_watermark_layer_raises_when_trustmark_unavailable():
    """When TrustMark isn't installed, require=True must fail-close."""
    if trustmark_available():
        pytest.skip("trustmark IS available; the negative-path test cannot run")
    with pytest.raises(RuntimeError, match="TrustMark"):
        attach_durable_marks(
            b"png-bytes-here",
            manifest_id="urn:uuid:abc",
            require_watermark_layer=True,
        )


def test_empty_content_bytes_rejected():
    with pytest.raises(ValueError, match="content_bytes"):
        attach_durable_marks(b"", manifest_id="urn:uuid:abc")


def test_empty_manifest_id_rejected():
    with pytest.raises(ValueError, match="manifest_id"):
        attach_durable_marks(b"x", manifest_id="")


def test_fingerprint_is_deterministic_for_same_input():
    """The fingerprint is the lookup key into the Tex provenance store;
    it must be stable for the same bytes."""
    a = attach_durable_marks(b"same-bytes", manifest_id="m1")
    b = attach_durable_marks(b"same-bytes", manifest_id="m1")
    assert a.perceptual_hash == b.perceptual_hash


def test_fingerprint_differs_for_different_inputs():
    a = attach_durable_marks(b"bytes-a", manifest_id="m1")
    b = attach_durable_marks(b"bytes-b", manifest_id="m1")
    assert a.perceptual_hash != b.perceptual_hash


def test_trustmark_available_returns_bool():
    """Surface query used by /v1/health — must return a bool, not raise."""
    result = trustmark_available()
    assert isinstance(result, bool)


def test_non_image_bytes_skip_watermark_layer_silently():
    """If content isn't a valid image format, the watermark layer is
    skipped without raising (when require_watermark_layer=False)."""
    result = attach_durable_marks(
        b"not-a-valid-image",
        manifest_id="m1",
        require_watermark_layer=False,
    )
    # Watermark may or may not be in the list depending on TrustMark
    # availability + image-parse success. Manifest + fingerprint must be.
    assert DurableLayer.C2PA_MANIFEST in result.layers_applied
    assert DurableLayer.FINGERPRINT in result.layers_applied
