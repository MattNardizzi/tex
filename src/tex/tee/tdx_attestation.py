"""
Intel TDX (Trusted Domain eXtensions) attestation collector.

Priority: P2.
"""

from __future__ import annotations


def collect_tdx_evidence() -> bytes:
    """
    TODO(P2): bind to TDX attestation collector (configfs-tsm or tdx-attest)
    TODO(P2): produce TD Quote per Intel TDX spec
    """
    raise NotImplementedError("TDX evidence collection")
