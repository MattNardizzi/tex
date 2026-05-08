"""
Durable Content Credentials (multi-layer marking).

Per C2PA Trust Markers spec + EU Code of Practice on AI: combines
embedded manifest + watermark + fingerprint for survival across
metadata-stripping platforms.

Priority: P1 — needed once email / social platforms strip embedded C2PA.
"""

from __future__ import annotations


def attach_durable_marks(content_bytes: bytes, manifest_id: str) -> bytes:
    """
    Apply multi-layer durable marking:
      1. Embedded C2PA manifest (primary)
      2. Invisible perceptual watermark (survives transcoding)
      3. Fingerprint registered to Tex provenance database (recovery path)

    TODO(P1): integrate watermark library
    TODO(P1): write fingerprint to provenance store
    """
    raise NotImplementedError("durable credentials — multi-layer marking")
