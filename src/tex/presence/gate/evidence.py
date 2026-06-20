"""Evidence binding for the presence truth-gate.

Every :class:`~tex.presence.contract.PresenceVerdict` the gate seals points at the
REAL sealed rows it recomputed from. This module is the one place that turns a
store row into an :class:`~tex.presence.contract.EvidenceRef` — a tamper-evident,
offline-re-verifiable pointer.

Honesty about the anchor (the nanozk lesson — a name must deliver its property):

  * Some rows already carry a real cryptographic anchor. A ``Decision`` carries
    ``content_sha256`` (a 64-hex SHA-256 of the evaluated content); a
    ``DiscoveryLedgerEntry`` carries ``record_hash`` (the live hash-chain anchor,
    plus ``previous_hash`` as a slice-inclusion witness). We bind those verbatim.
  * Other rows (an ``AgentIdentity``, a ``ConnectorHealth``, a ``ScanRun``) carry
    no sealed digest. For those we COMPUTE a canonical row hash —
    ``sha256(canonical_json(row))`` using the same stable-JSON idiom as
    ``stores/discovery_ledger.py`` — so an offline verifier fetches the row by
    ``record_id`` from ``store`` and recomputes the identical digest. This is an
    honest content anchor, not a chain-membership proof; ``EvidenceRef.field``
    names the quoted field so a verifier knows what the claim read.

What this module deliberately does NOT do: it never reads the full evidence
JSONL chain to resolve a row to its ``EvidenceRecord.record_hash``. The voice
path is latency-sensitive and the gate runs on it; a per-claim disk scan of the
whole chain is the wrong trade. The per-row anchors above are real and
offline-checkable without it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tex.presence.contract import EvidenceRef

__all__ = [
    "canonical_row_hash",
    "ref_for_decision",
    "ref_for_agent",
    "ref_for_action_entry",
    "ref_for_discovery_entry",
    "ref_for_connector_health",
    "ref_for_scan_run",
]


def _stable_json(value: Any) -> str:
    """Sorted-key, tight-separator JSON — byte-identical to the idiom in
    ``stores/discovery_ledger.py`` so a row hashed here re-serializes the same
    way an offline verifier would."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _jsonable(row: Any) -> Any:
    """Best-effort JSON-safe view of a row. Pydantic models go through
    ``model_dump(mode="json")``; objects with ``to_dict`` use it; anything else
    falls back to ``vars`` then ``str`` — so this never raises on the hot path."""
    dump = getattr(row, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json")
        except Exception:  # noqa: BLE001 — defensive on a hot path
            pass
    to_dict = getattr(row, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:  # noqa: BLE001
            pass
    if hasattr(row, "__dict__"):
        return {k: v for k, v in vars(row).items() if not k.startswith("_")}
    if hasattr(row, "__slots__"):
        return {k: getattr(row, k, None) for k in row.__slots__ if not k.startswith("_")}
    return str(row)


def canonical_row_hash(row: Any) -> str:
    """``sha256(canonical_json(row))`` — the recomputable content anchor for a row
    with no sealed digest of its own. 64-char hex; an offline verifier fetches the
    row and recomputes this exactly."""
    return hashlib.sha256(_stable_json(_jsonable(row)).encode("utf-8")).hexdigest()


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(c in "0123456789abcdef" for c in value.lower())


def ref_for_decision(decision: Any, *, field: str = "verdict") -> EvidenceRef:
    """Bind a ``Decision`` row. Prefers the row's own sealed ``content_sha256``
    (a real per-decision SHA-256 anchor); falls back to the canonical row hash if
    that field is absent or malformed."""
    anchor = getattr(decision, "content_sha256", None)
    record_hash = anchor.lower() if _is_hex64(anchor) else canonical_row_hash(decision)
    return EvidenceRef(
        record_id=str(getattr(decision, "decision_id", "")),
        record_hash=record_hash,
        store="decision_store",
        field=field,
    )


def ref_for_agent(agent: Any, *, field: str = "lifecycle_status") -> EvidenceRef:
    return EvidenceRef(
        record_id=str(getattr(agent, "agent_id", "")),
        record_hash=canonical_row_hash(agent),
        store="agent_registry",
        field=field,
    )


def ref_for_action_entry(entry: Any, *, field: str = "verdict") -> EvidenceRef:
    """Bind an ``ActionLedgerEntry``. Prefers its sealed ``content_sha256`` /
    ``evidence_hash`` anchor; falls back to the canonical row hash."""
    anchor = getattr(entry, "content_sha256", None)
    if not _is_hex64(anchor):
        anchor = getattr(entry, "evidence_hash", None)
    record_hash = anchor.lower() if _is_hex64(anchor) else canonical_row_hash(entry)
    return EvidenceRef(
        record_id=str(getattr(entry, "entry_id", "")),
        record_hash=record_hash,
        store="action_ledger",
        field=field,
    )


def ref_for_discovery_entry(entry: Any) -> EvidenceRef:
    """Bind a ``DiscoveryLedgerEntry`` — this one carries the REAL hash-chain
    anchor (``record_hash``) plus ``previous_hash`` as a slice-inclusion
    witness."""
    record_hash = getattr(entry, "record_hash", None)
    record_hash = record_hash.lower() if _is_hex64(record_hash) else canonical_row_hash(entry)
    prior = getattr(entry, "previous_hash", None)
    return EvidenceRef(
        record_id=str(getattr(entry, "sequence", "")),
        record_hash=record_hash,
        store="discovery_ledger",
        field=None,
        prior_link_witness=prior if _is_hex64(prior) else None,
    )


def ref_for_connector_health(health: Any) -> EvidenceRef:
    tenant = getattr(health, "tenant_id", "")
    connector = getattr(health, "connector_name", "")
    return EvidenceRef(
        record_id=f"{tenant}:{connector}",
        record_hash=canonical_row_hash(health),
        store="connector_health_store",
        field="status",
    )


def ref_for_scan_run(run: Any) -> EvidenceRef:
    return EvidenceRef(
        record_id=str(getattr(run, "run_id", "")),
        record_hash=canonical_row_hash(run),
        store="scan_run_store",
        field="status",
    )
