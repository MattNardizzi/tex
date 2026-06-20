"""Evidence-reference construction for the presence read layer.

Every :class:`~tex.presence.contract.ReadTool` returns ``(value, refs)`` where
each ref is a tamper-evident pointer the gate (Session 2) re-verifies by
fetching the same row and recomputing. Two honestly-different kinds of ref exist,
and conflating them would be exactly the ``nanozk`` lie this project exists to
never repeat — a name/structure that does not deliver its property:

* **chain-anchored ref** — the store keeps an append-only hash *chain*
  (``evidence_jsonl``, ``discovery_ledger``, ``governance_snapshots``). The ref
  carries the row's *stored* ``record_hash`` and its predecessor in
  ``prior_link_witness``. This supports a real slice/inclusion re-verification:
  the gate recomputes ``H(payload_sha256 ‖ previous_hash)`` and compares.

* **content-digest ref** — the store has *no* stored chain hash
  (``action_ledger``, ``decision_store``, ``agent_registry``, drift/scan
  stores). The ref carries a SHA-256 computed *here* over the row's canonical
  JSON. This proves only that the brain quoted the row **faithfully** (the gate
  re-fetches the row, recomputes the same digest, and compares) — it is NOT
  evidence of tamper-evident chain membership. ``prior_link_witness`` is
  ``None`` for these, which is the machine-readable signal of the distinction:

      ``ref.prior_link_witness is not None``  ⟺  chain-anchored.

The canonicaliser below is a cross-session contract: the gate MUST reuse
:func:`canonical_sha256` to re-verify a content-digest ref. Keep it stable.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tex.presence.contract import EvidenceRef

__all__ = [
    "canonical_json",
    "canonical_sha256",
    "is_sha256_hex",
    "digest_ref",
    "chained_ref",
    "row_to_jsonable",
]

_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")


def is_sha256_hex(value: Any) -> bool:
    """True iff ``value`` is a 64-char lowercase hex SHA-256 digest."""
    return isinstance(value, str) and bool(_SHA256_HEX.match(value))


def row_to_jsonable(row: Any) -> Any:
    """Return a deterministic, JSON-safe projection of a store row.

    Pydantic rows are dumped with ``mode="json"`` (UUIDs/enums/datetimes become
    stable strings). ``to_dict()``-style rows and plain dicts are passed through
    — they are already JSON-safe by construction in this codebase.
    """
    model_dump = getattr(row, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    to_dict = getattr(row, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return row


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, UTF-8 stable.

    The single source of truth for content-digest hashing. ``default=str`` is a
    safety net for any stray non-JSON scalar; in practice :func:`row_to_jsonable`
    has already normalised the input.
    """
    return json.dumps(
        row_to_jsonable(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def canonical_sha256(obj: Any) -> str:
    """SHA-256 (hex) over :func:`canonical_json` of ``obj``."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def digest_ref(
    *,
    record_id: Any,
    store: str,
    payload: Any,
    field: str | None = None,
) -> EvidenceRef:
    """A **content-digest** ref over a row from a non-chained store.

    Proves faithful quotation, NOT chain membership. ``prior_link_witness`` is
    deliberately left ``None`` so callers/gate can tell this is not chain-anchored.
    """
    return EvidenceRef(
        record_id=str(record_id),
        record_hash=canonical_sha256(payload),
        store=store,
        field=field,
        prior_link_witness=None,
    )


def chained_ref(
    *,
    record_id: Any,
    record_hash: str,
    store: str,
    field: str | None = None,
    previous_hash: str | None = None,
    fallback_payload: Any = None,
) -> EvidenceRef:
    """A **chain-anchored** ref using a row's stored ``record_hash``.

    If the stored hash is missing/malformed (a store contract violation, or an
    empty-string default), we degrade *honestly* to a content-digest ref over
    ``fallback_payload`` rather than emit a bogus chain anchor — the
    ``prior_link_witness`` then reads ``None`` and the claim is no longer
    presented as chain-anchored.
    """
    if is_sha256_hex(record_hash):
        return EvidenceRef(
            record_id=str(record_id),
            record_hash=record_hash,
            store=store,
            field=field,
            prior_link_witness=previous_hash if is_sha256_hex(previous_hash) else None,
        )
    if fallback_payload is None:
        raise ValueError(
            f"chained_ref for {store!r} got a non-SHA256 record_hash "
            f"({record_hash!r}) and no fallback_payload to digest"
        )
    return digest_ref(record_id=record_id, store=store, payload=fallback_payload, field=field)
