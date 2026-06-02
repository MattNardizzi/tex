"""
Receipt issuer and verifier (NabaOS).

Issuer
------
Wraps the agent's tool-execution layer. The agent runtime — NOT the LLM —
performs tool calls, computes input/output hashes, and issues receipts.
The LLM receives the tool output plus the receipt ID. Per arxiv 2603.10060,
this is the integrity foundation: the LLM cannot forge an HMAC over data
it never had the key for.

Verifier
--------
Cross-references LLM claims against issued receipts. Any claim that
references a non-existent receipt ID, or whose receipt's HMAC does not
verify, is flagged as hallucinated. Claims are also checked against the
epistemic source taxonomy:

  - PRATYAKSHA: every receipt id must resolve and verify
  - ANUMANA:    at least one parent receipt must resolve and verify
  - SHABDA:     at least one receipt must resolve (it acts as the citation
                pointer to an external source)
  - ABHAVA:     at least one receipt must resolve with result_count == 0
  - UNGROUNDED: never grounded; always flagged

The verifier additionally extracts integer literals from claim_text and
checks them against receipt result_count values, catching the
"count misstatement" hallucination type called out in the abstract
(87.6% detection rate per the paper).

Reference
---------
arxiv 2603.10060 — Tool Receipts, Not Zero-Knowledge Proofs (Basu, Mar 2026).

Performance target
------------------
<15ms per verify_claim() call on a representative fixture
(claim with 3 receipts, store with 100 receipts). See test_receipts.py.

Priority: P0.
"""

from __future__ import annotations

import hmac
import re
import secrets
from datetime import datetime
from hashlib import sha256
from typing import Any

from tex.events._canonical import canonical_json, canonical_sha256
from tex.observability.telemetry import emit_event
from tex.receipts.epistemic_source import EpistemicSource
from tex.receipts.receipt import ToolExecutionReceipt
from tex.receipts.store import ReceiptStore


# Integer literal pattern. Matches positive integers up to 12 digits — wider
# matches risk pulling in dates / years and producing noisy false positives.
# TODO(p1): locale-aware number extraction (commas, "thirty", scientific notation).
_INTEGER_LITERAL = re.compile(r"\b(\d{1,12})\b")

# Receipt ID format: "rcpt-" + 32 hex chars = 37 chars total. Sits inside the
# 16..64 length window enforced by ToolExecutionReceipt.
_RECEIPT_ID_PREFIX = "rcpt-"
_RECEIPT_ID_RANDOM_BYTES = 16  # → 32 hex chars


def _new_receipt_id() -> str:
    return _RECEIPT_ID_PREFIX + secrets.token_hex(_RECEIPT_ID_RANDOM_BYTES)


def _hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()


def _result_count_of(tool_output: Any) -> int:
    """
    Heuristic count of "items returned" by a tool.

    - list / tuple / set / frozenset → len()
    - dict                            → len() (number of keys)
    - None                            → 0
    - everything else                 → 1

    NabaOS uses this for absence-claim verification (ABHAVA → count == 0)
    and for count-misstatement detection (LLM says "5 results" but receipt
    says result_count == 3).
    """
    if tool_output is None:
        return 0
    if isinstance(tool_output, (list, tuple, set, frozenset, dict)):
        return len(tool_output)
    return 1


class ReceiptIssuer:
    """Issues HMAC-SHA-256-signed receipts for tool calls."""

    def __init__(
        self,
        *,
        hmac_key: bytes,
        key_id: str,
        runtime_version: str,
        store: ReceiptStore,
    ) -> None:
        if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) < 16:
            raise ValueError(
                "hmac_key must be at least 16 bytes; got "
                f"{len(hmac_key) if isinstance(hmac_key, (bytes, bytearray)) else 0}"
            )
        if not key_id:
            raise ValueError("key_id must be a non-empty string")
        if not runtime_version:
            raise ValueError("runtime_version must be a non-empty string")
        self._hmac_key = bytes(hmac_key)
        self._key_id = key_id
        self._runtime_version = runtime_version
        self._store = store

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def runtime_version(self) -> str:
        return self._runtime_version

    def issue(
        self,
        *,
        session_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_output: Any,
        started_at_iso: str,
        completed_at_iso: str,
    ) -> ToolExecutionReceipt:
        """
        Issue a receipt for a completed tool call.

        Computes SHA-256 hashes of the canonicalised tool input and output,
        derives ``result_count`` per the NabaOS heuristic, then HMAC-SHA-256
        signs the canonical signing input. The receipt is appended to the
        backing store before being returned.

        Reference
        ---------
        arxiv 2603.10060 §3.1 (receipt issuance protocol).
        """
        if not session_id:
            raise ValueError("session_id must be a non-empty string")
        if not tool_name:
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(tool_input, dict):
            raise TypeError("tool_input must be a dict")

        started_at = self._parse_iso(started_at_iso, field="started_at_iso")
        completed_at = self._parse_iso(completed_at_iso, field="completed_at_iso")
        if completed_at < started_at:
            raise ValueError("completed_at_iso must not precede started_at_iso")

        tool_input_hash = canonical_sha256(tool_input)
        tool_output_hash = canonical_sha256(_canonicalize_output(tool_output))
        result_count = _result_count_of(tool_output)

        # Build the unsigned receipt fields, canonicalise, then MAC.
        unsigned = {
            "receipt_id": _new_receipt_id(),
            "session_id": session_id,
            "tool_name": tool_name,
            "tool_input_hash": tool_input_hash,
            "tool_output_hash": tool_output_hash,
            "result_count": result_count,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "runtime_version": self._runtime_version,
        }
        signature = _hmac_hex(self._hmac_key, canonical_json(unsigned))

        receipt = ToolExecutionReceipt(
            receipt_id=unsigned["receipt_id"],
            session_id=session_id,
            tool_name=tool_name,
            tool_input_hash=tool_input_hash,
            tool_output_hash=tool_output_hash,
            result_count=result_count,
            started_at=started_at,
            completed_at=completed_at,
            runtime_version=self._runtime_version,
            hmac_signature=signature,
            hmac_key_id=self._key_id,
        )
        self._store.append(receipt)

        emit_event(
            "tex.receipts.issued",
            receipt_id=receipt.receipt_id,
            session_id=session_id,
            tool_name=tool_name,
            result_count=result_count,
            key_id=self._key_id,
        )
        return receipt

    @staticmethod
    def _parse_iso(value: str, *, field: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} must be ISO 8601: {value!r}") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{field} must include a timezone: {value!r}")
        return parsed


def _canonicalize_output(tool_output: Any) -> Any:
    """
    Coerce a tool output into something canonical_json accepts.

    Tool outputs in the wild may be arbitrary Python; canonical_json only
    accepts ``str | int | bool | None | dict | list``. This helper:
      - lets canonicalizable values through unchanged
      - converts tuple/set/frozenset to list
      - converts datetime to ISO-8601 string
      - falls back to ``repr`` for anything else (still deterministic for the
        same Python object, and we hash the result so semantic equality
        across processes is best-effort — tools that return non-serialisable
        objects should canonicalise them upstream).

    TODO(p1): a stricter contract that rejects non-serialisable outputs at
    the runtime boundary instead of papering over them here.
    """
    if tool_output is None or isinstance(tool_output, (str, bool, int)):
        return tool_output
    if isinstance(tool_output, datetime):
        if tool_output.tzinfo is None:
            raise ValueError("naive datetime in tool output is not canonicalisable")
        return tool_output.isoformat()
    if isinstance(tool_output, dict):
        return {str(k): _canonicalize_output(v) for k, v in tool_output.items()}
    if isinstance(tool_output, (list, tuple, set, frozenset)):
        return [_canonicalize_output(v) for v in tool_output]
    return repr(tool_output)


class ReceiptVerifier:
    """
    Verifies LLM claims against issued receipts.

    Cross-checks every receipt id referenced by a claim against the backing
    store and re-derives the HMAC. Routes per epistemic source per the
    NabaOS protocol (arxiv 2603.10060).
    """

    def __init__(
        self,
        *,
        hmac_key: bytes,
        key_id: str,
        store: ReceiptStore,
    ) -> None:
        if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        if not key_id:
            raise ValueError("key_id must be a non-empty string")
        self._hmac_key = bytes(hmac_key)
        self._key_id = key_id
        self._store = store

    def verify_claim(
        self,
        *,
        claim_text: str,
        claimed_source: EpistemicSource,
        claimed_receipt_ids: tuple[str, ...],
    ) -> tuple[bool, tuple[str, ...]]:
        """
        Cross-reference an LLM claim against issued receipts.

        Returns
        -------
        (is_grounded, issues)
            ``is_grounded`` is True iff the claim's epistemic backing is
            present and intact. ``issues`` is a tuple of human-readable
            problem strings (empty when grounded).

        Per arxiv 2603.10060:
          - PRATYAKSHA: every claimed receipt id must resolve and HMAC-verify
          - ANUMANA:    at least one parent receipt must resolve and verify
          - SHABDA:     at least one receipt must resolve (citation pointer
                        — the receipt's tool_name + result hash together
                        constitute the citation to the external source)
          - ABHAVA:     at least one receipt must resolve with result_count
                        == 0
          - UNGROUNDED: never grounded — returns (False, ("ungrounded claim",))

        Numerical literals in ``claim_text`` are extracted and matched
        against the resolved receipts' ``result_count`` values to catch
        the "count misstatement" hallucination type (87.6% detection per
        the paper).

        TODO(p1-url-refetch-protocol): the abstract mentions a separate
        cross-checking protocol for URL fabrications via independent
        re-fetching (78.4% catch rate for deep delegation). Out of scope
        for Thread 5 — needs HTTP infrastructure.

        TODO(verify-against-paper-six-types): the abstract names six
        hallucination types but only details three. Confirm the remaining
        three against the full paper before finalising the test fixture.
        """
        if not isinstance(claim_text, str):
            raise TypeError("claim_text must be a string")
        if not isinstance(claimed_source, EpistemicSource):
            raise TypeError("claimed_source must be an EpistemicSource")
        if not isinstance(claimed_receipt_ids, tuple):
            raise TypeError("claimed_receipt_ids must be a tuple")

        issues: list[str] = []

        if claimed_source is EpistemicSource.UNGROUNDED:
            issues.append("ungrounded claim")
            self._emit_verified(
                claim_text=claim_text,
                claimed_source=claimed_source,
                claimed_receipt_ids=claimed_receipt_ids,
                grounded=False,
                issues=tuple(issues),
            )
            return False, tuple(issues)

        # Resolve every claimed id; flag misses as fabrications, flag
        # signature failures as tampering. We always touch every id so that
        # multi-receipt claims surface multi-issue diagnostics.
        resolved: list[ToolExecutionReceipt] = []
        for rid in claimed_receipt_ids:
            receipt = self._store.get(rid)
            if receipt is None:
                issues.append(f"fabricated receipt id: {rid}")
                continue
            if not self._signature_ok(receipt):
                issues.append(f"hmac mismatch on receipt {rid}")
                continue
            resolved.append(receipt)

        # Per-source structural requirements.
        if claimed_source is EpistemicSource.PRATYAKSHA:
            if not claimed_receipt_ids:
                issues.append("pratyaksha claim with no receipt")
        elif claimed_source is EpistemicSource.ANUMANA:
            if not resolved:
                issues.append("anumana claim with no verifiable parent receipt")
        elif claimed_source is EpistemicSource.SHABDA:
            if not resolved:
                issues.append("shabda claim with no citation receipt")
        elif claimed_source is EpistemicSource.ABHAVA:
            if not any(r.result_count == 0 for r in resolved):
                issues.append("abhava claim with no zero-result receipt")

        # Count-misstatement check. For PRATYAKSHA / ANUMANA only — SHABDA
        # cites external sources whose counts we don't model, and ABHAVA
        # is already covered by the zero-result requirement above.
        if claimed_source in (EpistemicSource.PRATYAKSHA, EpistemicSource.ANUMANA):
            count_issue = self._count_misstatement(claim_text, resolved)
            if count_issue is not None:
                issues.append(count_issue)

        grounded = not issues
        self._emit_verified(
            claim_text=claim_text,
            claimed_source=claimed_source,
            claimed_receipt_ids=claimed_receipt_ids,
            grounded=grounded,
            issues=tuple(issues),
        )
        return grounded, tuple(issues)

    def _signature_ok(self, receipt: ToolExecutionReceipt) -> bool:
        """Re-derive the HMAC and constant-time compare."""
        if receipt.hmac_key_id != self._key_id:
            # Different signing key — out of scope for this verifier; treat
            # as not-verifiable so callers can route to a key-aware verifier.
            # TODO(p1): multi-key verifier with per-key_id dispatch.
            return False
        expected = _hmac_hex(self._hmac_key, canonical_json(receipt.canonical_signing_input()))
        return hmac.compare_digest(expected, receipt.hmac_signature)

    @staticmethod
    def _count_misstatement(
        claim_text: str,
        resolved: list[ToolExecutionReceipt],
    ) -> str | None:
        """
        Look for integer literals in ``claim_text`` that no resolved receipt
        accounts for via its ``result_count``.

        Conservative: if any extracted integer matches *any* resolved
        receipt's count (or 0), the claim passes. Only when every extracted
        integer fails to match anything do we flag it. This avoids false
        positives on years, ids, and other non-count integers in the claim
        text.

        TODO(verify-against-paper-six-types): the paper reports 87.6%
        detection on count misstatements; tighten this once the exact
        protocol is confirmed.
        """
        if not resolved:
            return None
        literals = {int(m.group(1)) for m in _INTEGER_LITERAL.finditer(claim_text)}
        if not literals:
            return None
        valid_counts = {0} | {r.result_count for r in resolved}
        unaccounted = literals - valid_counts
        if unaccounted == literals:
            # Every integer in the claim is unaccounted for — likely a count
            # misstatement.
            sample = sorted(unaccounted)[:3]
            return (
                "count misstatement: claim mentions "
                f"{sample} but resolved receipts report counts "
                f"{sorted({r.result_count for r in resolved})}"
            )
        return None

    @staticmethod
    def _emit_verified(
        *,
        claim_text: str,
        claimed_source: EpistemicSource,
        claimed_receipt_ids: tuple[str, ...],
        grounded: bool,
        issues: tuple[str, ...],
    ) -> None:
        event = (
            "tex.receipts.verified"
            if grounded
            else "tex.receipts.hallucination_detected"
        )
        emit_event(
            event,
            claimed_source=claimed_source.value,
            claimed_receipt_ids=list(claimed_receipt_ids),
            grounded=grounded,
            issues=list(issues),
            claim_length=len(claim_text),
        )


__all__ = ["ReceiptIssuer", "ReceiptVerifier"]
