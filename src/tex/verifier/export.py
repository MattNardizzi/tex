"""
Producer-side bridge: mint a portable verdict bundle from a live Tex ledger.

This is the *producer* half — it MAY touch Tex types and is deliberately kept
out of the checker's trusted computing base (``tex.verifier.check`` imports
nothing from here, and ``tex.verifier.__init__`` does not re-export it). It
exists so a real ``SealedFactLedger`` (or a ``SealedFactBundle`` exported on
``main``) can be turned into the portable, JSON-serializable court-exhibit
schema that ``verify_bundle`` consumes — proving the checker works on genuine
Tex seals, not a synthetic format.

Portable schema (version ``tex-offline-verdict/1``)::

    {
      "bundle_version": "tex-offline-verdict/1",
      "export_name": "<str>",
      "exported_at": "<iso8601>",
      "signing_key_id": "<str>",
      "public_key_b64": "<base64 PEM>",     # the classical (ECDSA) key
      "keys": {"ecdsa-p256": "<base64 PEM>"},
      "records": [
        {
          "sequence": <int>,
          "canonical_payload": { ... },     # EXACTLY what the ledger hashed;
                                            # a sealed monotonicity witness, when
                                            # present, lives in detail
          "payload_sha256": "<hex>",
          "previous_hash": "<hex>|null",
          "record_hash": "<hex>",
          "signatures": [
            {"algorithm": "ecdsa-p256", "signature_b64": "<b64>",
             "public_key_b64": "<base64 PEM>"}
            # a sibling thread may append {"algorithm": "ml-dsa-65", ...}
          ],
          "signing_key_id": "<str>"
        }
      ]
    }

The bridge is duck-typed (it reads ``.fact.canonical_payload()``,
``.payload_sha256``, ``.record_hash`` … off each record) so it does not pull
the model package into anything that imports it.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any, Iterable

from tex.verifier.check import PORTABLE_BUNDLE_VERSION

__all__ = [
    "portable_record",
    "portable_bundle",
    "portable_bundle_from_ledger",
    "portable_bundle_from_sealed_fact_bundle",
]


def _b64(pem: bytes) -> str:
    return base64.b64encode(pem).decode("ascii")


def portable_record(rec: Any, *, public_key_b64: str | None = None) -> dict[str, Any]:
    """One sealed record → its portable form. ``rec`` is any object exposing the
    ledger's ``SealedFactRecord`` surface."""
    return {
        "sequence": int(rec.sequence),
        "canonical_payload": rec.fact.canonical_payload(),
        "payload_sha256": rec.payload_sha256,
        "previous_hash": rec.previous_hash,
        "record_hash": rec.record_hash,
        "signatures": [
            {
                "algorithm": "ecdsa-p256",
                "signature_b64": rec.signature_b64,
                "public_key_b64": public_key_b64,
                "key_id": rec.signing_key_id,
            }
        ],
        "signing_key_id": rec.signing_key_id,
    }


def portable_bundle(
    records: Iterable[Any],
    *,
    public_key_pem: bytes,
    export_name: str,
    signing_key_id: str,
    exported_at: datetime | None = None,
    extra_keys: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Package sealed records + the signing key into a portable bundle dict."""
    pub_b64 = _b64(public_key_pem)
    keys = {"ecdsa-p256": pub_b64}
    for algo, pem in (extra_keys or {}).items():
        keys[algo] = _b64(pem)
    return {
        "bundle_version": PORTABLE_BUNDLE_VERSION,
        "export_name": export_name,
        "exported_at": (exported_at or datetime.now(UTC)).isoformat(),
        "signing_key_id": signing_key_id,
        "public_key_b64": pub_b64,
        "keys": keys,
        "records": [portable_record(r, public_key_b64=pub_b64) for r in records],
    }


def portable_bundle_from_ledger(
    ledger: Any,
    *,
    export_name: str,
    exported_at: datetime | None = None,
) -> dict[str, Any]:
    """Bridge a live ``SealedFactLedger`` (duck-typed) into a portable bundle."""
    return portable_bundle(
        ledger.list_all(),
        public_key_pem=ledger.public_key_pem,
        export_name=export_name,
        signing_key_id=ledger.signing_key_id,
        exported_at=exported_at,
    )


def portable_bundle_from_sealed_fact_bundle(bundle: Any) -> dict[str, Any]:
    """Bridge ``main``'s ``provenance.bundle.SealedFactBundle`` into the
    portable schema (so an already-exported court exhibit verifies through the
    standalone checker)."""
    pem = base64.b64decode(bundle.public_key_b64.encode("ascii"))
    return portable_bundle(
        bundle.records,
        public_key_pem=pem,
        export_name=bundle.export_name,
        signing_key_id=bundle.signing_key_id,
    )
