#!/usr/bin/env python3
"""
Daily external-anchor job — start (and keep) the provable-age clock.

Submits the current gix checkpoint tree-head to an external RFC 3161 TSA,
verifies the returned token **offline** against the pinned TSA cert, and — only
if it verifies — persists the receipt and publishes the tree-head. This is the
out-of-band, async job the constitution requires: it is NEVER in the hot path of
sealing a decision, every network call is timeout-bounded and retried, and any
failure logs + exits non-zero without wedging anything.

Run (gated — dev stays fully offline unless TEX_EVIDENCE_ANCHOR_ENABLE is set)::

    TEX_EVIDENCE_ANCHOR_ENABLE=1 \
      python scripts/anchor_checkpoint.py --hashes-file record_hashes.txt

    # against a specific TSA / pin / origin:
    TEX_EVIDENCE_ANCHOR_ENABLE=1 \
    TEX_EVIDENCE_ANCHOR_TSA_URL=https://freetsa.org/tsr \
    TEX_EVIDENCE_ANCHOR_TSA_CERT=anchors/tsa/freetsa_cacert.pem \
      python scripts/anchor_checkpoint.py --hashes-file record_hashes.txt

The record-hash source is, in order: ``--hashes-file`` (one 64-hex
``record_hash`` per line — what the live decision ledger exports), else the live
gix publisher registered by ``build_checkpoint_publisher`` (``TEX_GIX_WITNESS``).
With neither, there is nothing to anchor and the job exits cleanly.

Exit codes: 0 = anchored (or nothing to do / disabled); 2 = submission or
verification failed (surfaced, never hidden).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tex.interchange.external_anchor import (  # noqa: E402
    ANCHOR_ENV_ENABLE,
    ANCHOR_ENV_TSA_CERT,
    ANCHOR_ENV_TSA_URL,
    CheckpointAnchorRecord,
    anchor_subject_digest,
    submit_anchor,
    verify_anchor_receipt,
)
from tex.interchange.gix import (  # noqa: E402
    DEFAULT_GIX_ORIGIN,
    CheckpointPublisher,
    get_active_checkpoint_publisher,
)

_log = logging.getLogger("anchor_checkpoint")

_DEFAULT_TSA_URL = "https://freetsa.org/tsr"
_DEFAULT_PIN = "anchors/tsa/freetsa_cacert.pem"
_DEFAULT_AUTHORITY = "freetsa.org"
_DEFAULT_OUT_DIR = "anchors"


class AnchorJobError(RuntimeError):
    """A submission/verification failure — caught by ``main`` and turned into a
    non-zero exit, never propagated into any caller's request path."""


def make_httpx_poster(*, timeout: float, retries: int, backoff: float):
    """A timeout-bounded, retrying RFC 3161 poster. ``httpx`` is imported lazily
    so importing this module (and the offline verify path) needs no network lib.

    Each attempt is bounded by ``timeout`` seconds; total wall time is bounded by
    ``retries × (timeout + backoff)``. Never blocks unbounded — it cannot wedge.
    """

    def poster(url: str, request_der: bytes) -> bytes:
        import httpx  # lazy

        last: Exception | None = None
        for attempt in range(1, retries + 1):
            try:
                with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                    resp = client.post(
                        url,
                        content=request_der,
                        headers={"Content-Type": "application/timestamp-query"},
                    )
                    resp.raise_for_status()
                    return resp.content
            except Exception as exc:  # noqa: BLE001 — retry any transport/HTTP error
                last = exc
                _log.warning("TSA POST attempt %d/%d failed: %s", attempt, retries, exc)
                if attempt < retries:
                    time.sleep(backoff * attempt)
        raise AnchorJobError(f"TSA submission failed after {retries} attempts: {last}")

    return poster


def _read_record_hashes(args: argparse.Namespace) -> tuple[str, list[str]]:
    """Return (origin, record_hashes). Prefer ``--hashes-file``; else the live
    gix publisher; else empty."""
    if args.hashes_file:
        path = Path(args.hashes_file)
        if not path.exists():
            raise AnchorJobError(f"--hashes-file not found: {path}")
        hashes = [
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for h in hashes:
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                raise AnchorJobError(f"not a 64-hex record_hash: {h!r}")
        return (args.origin or DEFAULT_GIX_ORIGIN), hashes

    publisher = get_active_checkpoint_publisher()
    if publisher is not None:
        snap = publisher.current_signed_checkpoint()
        return publisher.origin, list(snap.record_hashes)

    return (args.origin or DEFAULT_GIX_ORIGIN), []


def _append_jsonl(path: Path, obj: dict | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Anchor the current gix checkpoint to an external TSA.")
    parser.add_argument("--hashes-file", help="file of newline-separated 64-hex record_hash values")
    parser.add_argument("--origin", help=f"checkpoint origin (default {DEFAULT_GIX_ORIGIN})")
    parser.add_argument("--tsa-url", default=os.environ.get(ANCHOR_ENV_TSA_URL, _DEFAULT_TSA_URL))
    parser.add_argument("--pin", default=os.environ.get(ANCHOR_ENV_TSA_CERT, _DEFAULT_PIN))
    parser.add_argument("--authority", default=os.environ.get("TEX_EVIDENCE_ANCHOR_AUTHORITY", _DEFAULT_AUTHORITY))
    parser.add_argument("--out-dir", default=os.environ.get("TEX_EVIDENCE_ANCHOR_OUT_DIR", _DEFAULT_OUT_DIR))
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff", type=float, default=2.0)
    args = parser.parse_args(argv)

    # Gate: dev stays fully offline unless explicitly enabled.
    if os.environ.get(ANCHOR_ENV_ENABLE, "").strip().lower() not in {"1", "true", "yes"}:
        _log.info("%s not set — anchoring disabled, nothing to do.", ANCHOR_ENV_ENABLE)
        return 0

    try:
        origin, hashes = _read_record_hashes(args)
        if not hashes:
            _log.info("no record hashes to anchor (no --hashes-file and no live publisher) — exiting 0.")
            return 0

        publisher = CheckpointPublisher(origin=origin, read_record_hashes=lambda: tuple(hashes))
        snapshot = publisher.current_signed_checkpoint()
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        nonce = int.from_bytes(os.urandom(8), "big") or 1
        _log.info("anchoring tree-head origin=%s size=%d root=%s", cp.origin, cp.tree_size, cp.root_hash_hex[:16])

        poster = make_httpx_poster(timeout=args.timeout, retries=args.retries, backoff=args.backoff)
        response_der = submit_anchor(digest, tsa_url=args.tsa_url, nonce=nonce, poster=poster)

        record = CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority=args.authority,
            response_der=response_der,
            request_nonce=nonce,
        )

        # Verify offline BEFORE persisting — an unverifiable receipt is worthless.
        pin_path = Path(args.pin)
        if not pin_path.exists():
            raise AnchorJobError(f"pinned TSA cert not found: {pin_path}")
        pinned_der = _load_cert_der(pin_path)
        result = verify_anchor_receipt(record, pinned_tsa_cert_der=pinned_der, expected_nonce=nonce)
        if not result.ok:
            raise AnchorJobError(f"receipt failed offline verification [{result.failure_code}]: {result.detail}")

        out_dir = Path(args.out_dir)
        _append_jsonl(out_dir / "checkpoint_anchors.jsonl", record.model_dump_json())
        # The second channel — public, no secrets.
        _append_jsonl(
            out_dir / "PUBLISHED_TREE_HEADS.jsonl",
            {
                "origin": cp.origin,
                "tree_size": cp.tree_size,
                "root_hash": cp.root_hash_hex,
                "authority": args.authority,
                "gen_time": result.gen_time.isoformat() if result.gen_time else None,
                "tsa_cert_fingerprint_sha256": result.tsa_cert_fingerprint_sha256,
                "anchored_at": datetime.now(UTC).isoformat(),
            },
        )
        _log.info("ANCHORED: %s", result.summary())
        return 0

    except AnchorJobError as exc:
        _log.error("anchor job failed: %s", exc)
        return 2
    except Exception as exc:  # noqa: BLE001 — last-resort guard; never wedge, always surface
        _log.exception("unexpected anchor job error: %s", exc)
        return 2


def _load_cert_der(path: Path) -> bytes:
    """Load a PEM or DER cert file and return its DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    raw = path.read_bytes()
    cert = (
        x509.load_pem_x509_certificate(raw)
        if b"-----BEGIN CERTIFICATE-----" in raw
        else x509.load_der_x509_certificate(raw)
    )
    return cert.public_bytes(Encoding.DER)


if __name__ == "__main__":
    raise SystemExit(main())
