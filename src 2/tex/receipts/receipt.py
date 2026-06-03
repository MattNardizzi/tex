"""
Tool execution receipt data model.

Issued by the runtime AFTER a tool call completes. The LLM never holds the
HMAC signing key — it can only reference receipt IDs the runtime issued.

Reference
---------
arxiv 2603.10060 — Tool Receipts, Not Zero-Knowledge Proofs (Basu, Mar 2026).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# Fields excluded from the canonical signing input — the HMAC signature
# itself, and the key id (an opaque pointer that does not authenticate the
# message body). Everything else is bound by the MAC.
_UNSIGNED_FIELDS: frozenset[str] = frozenset({"hmac_signature", "hmac_key_id"})


class ToolExecutionReceipt(BaseModel):
    """
    An HMAC-SHA-256-signed receipt for a single tool invocation.

    Per arxiv 2603.10060, the runtime (not the LLM) issues these receipts
    after each tool call. ``hmac_signature`` is computed over the canonical
    JSON of every other field (see ``canonical_signing_input``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str = Field(min_length=16, max_length=64)
    session_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=256)
    tool_input_hash: str = Field(min_length=64, max_length=64)   # SHA-256 hex
    tool_output_hash: str = Field(min_length=64, max_length=64)  # SHA-256 hex
    result_count: int = Field(ge=0)
    started_at: datetime
    completed_at: datetime
    runtime_version: str = Field(min_length=1, max_length=64)
    hmac_signature: str = Field(min_length=64, max_length=64)    # SHA-256 hex
    hmac_key_id: str = Field(min_length=1, max_length=64)

    def canonical_signing_input(self) -> dict[str, Any]:
        """
        The dict that gets canonicalized and HMAC'd to produce ``hmac_signature``.

        Excludes ``hmac_signature`` (chicken-and-egg) and ``hmac_key_id``
        (opaque pointer, not part of the authenticated message body — the
        verifier looks up the key by id externally).

        Datetimes are serialised to ISO 8601 with timezone for JCS
        compatibility, mirroring the convention in
        ``tex.events.event.Event.canonical_record_input``.
        """
        return {
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "tool_input_hash": self.tool_input_hash,
            "tool_output_hash": self.tool_output_hash,
            "result_count": self.result_count,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "runtime_version": self.runtime_version,
        }


__all__ = ["ToolExecutionReceipt"]
