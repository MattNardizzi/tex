"""
[Architecture: Voice cognition] — deterministic intent routing for ``/v1/ask``.

A spoken transcript must be mapped to a *sealed-fact source* before Tex may
answer. That mapping is done here, and it is **deterministic and zero-LLM**:

  1. If the transcript names a record HANDLE — a 64-hex SHA-256 or a UUID —
     it is a *record* query: the operator reached for one exact object.
  2. Otherwise the transcript is scored against a frozen keyword → dimension
     table over the six vigil dimensions. The unique top-scoring dimension
     wins.
  3. No handle and no keyword hit, or a tie between dimensions, routes to
     ABSTAIN. Tex does not guess which sealed fact you meant.

HONEST LIMITATION (enumerated, not hidden): this is keyword routing, not
language understanding. It can confidently route to the *wrong but still
sealed* dimension (a relevance error), but it can never invent a fact — the
answer is filled only from whatever sealed source it lands on, and the gate
re-derives every emitted handle. The failure mode we trade into is "answered a
slightly different true question," never "fabricated." A real semantic router
(an embedding/NLI intent model) is the upgrade seam; it is not built here and
nothing pretends it is.

The transcript is also scanned for an *asserted* verdict word or handle — a
claim the speaker baked into the question ("decision abc… was permitted, right?").
The gate uses that to detect a contradiction with the sealed fact and refuse
(FORBID) rather than politely confirm a falsehood.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

__all__ = ["IntentKind", "HandleKind", "Intent", "route_intent", "DIMENSIONS"]


# The six vigil dimensions, the only sealed-fact sources ``/v1/ask`` answers
# from. Kept in lockstep with ``tex.vigil.explainer._FACT_BUILDERS``.
DIMENSIONS: tuple[str, ...] = (
    "execution",
    "human_decision",
    "evidence",
    "identity",
    "monitoring",
    "discovery",
)


class IntentKind(StrEnum):
    RECORD = "record"        # the operator named one exact sealed object
    DIMENSION = "dimension"  # a question about one of the six sealed dimensions
    ABSTAIN = "abstain"      # no sealed source could be resolved — do not guess


class HandleKind(StrEnum):
    HASH = "hash"
    NAME = "name"  # a UUID / exact identifier — a handle you grab, not comprehend


# A SHA-256 hex digest (the evidence/content anchor) and a canonical UUID.
# Word-boundary anchored so they are matched as standalone tokens.
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_VERDICT_RE = re.compile(r"\b(PERMIT|ABSTAIN|FORBID)\b", re.IGNORECASE)


# Frozen keyword → dimension table. Each keyword is matched as a whole word
# (case-insensitive). The lists are deliberately small and unambiguous; a word
# that could mean two dimensions is left out rather than bias a tie.
_KEYWORDS: dict[str, tuple[str, ...]] = {
    "execution": (
        "forbid", "forbidden", "block", "blocked", "deny", "denied",
        "refused", "stopped", "execution",
    ),
    "human_decision": (
        "awaiting", "waiting", "pending", "held", "hold", "abstain",
        "abstained", "decide", "decision", "human",
    ),
    "evidence": (
        "evidence", "chain", "sealed", "integrity", "ledger", "record",
        "records", "tamper", "intact",
    ),
    "identity": (
        "identity", "agent", "agents", "governance", "governed",
        "ungoverned", "high-risk", "risk",
    ),
    "monitoring": (
        "monitoring", "connector", "connectors", "reporting", "health",
        "silent", "stopped reporting",
    ),
    "discovery": (
        "discovery", "discovered", "new", "scan", "scanned", "found",
        "overnight", "inventory",
    ),
}

# Precompile one whole-word matcher per (dimension, keyword).
_KEYWORD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (dim, re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE))
    for dim, kws in _KEYWORDS.items()
    for kw in kws
)


@dataclass(frozen=True, slots=True)
class Intent:
    """The resolved routing decision for one transcript."""

    kind: IntentKind
    dimension: str | None = None          # set when kind == DIMENSION
    handle: str | None = None             # set when kind == RECORD (the raw handle)
    handle_kind: HandleKind | None = None
    asserted_verdict: str | None = None   # a verdict word baked into the question
    asserted_hashes: tuple[str, ...] = field(default_factory=tuple)
    scores: dict[str, int] = field(default_factory=dict)  # per-dimension keyword hits
    reason: str = ""


def _asserted_handles(transcript: str) -> tuple[str | None, tuple[str, ...]]:
    """Pull a verdict word and any sha256 handles the speaker asserted."""
    vm = _VERDICT_RE.search(transcript)
    asserted_verdict = vm.group(1).upper() if vm else None
    hashes = tuple(m.group(0).lower() for m in _SHA256_RE.finditer(transcript))
    return asserted_verdict, hashes


def route_intent(transcript: str) -> Intent:
    """Map a transcript to a sealed-fact source, deterministically.

    Never raises. An empty or unmatched transcript is an ABSTAIN, not an error
    — silence routes to "I can't ground that," which is the honest answer.
    """
    text = (transcript or "").strip()
    asserted_verdict, asserted_hashes = _asserted_handles(text)

    if not text:
        return Intent(kind=IntentKind.ABSTAIN, reason="empty-transcript")

    # 1) Record handle: a UUID is a decision/agent id (a name you grab); a bare
    #    64-hex is a content/evidence hash. A UUID wins over a hash if both
    #    appear, because the id is the addressable record.
    uuid_m = _UUID_RE.search(text)
    if uuid_m is not None:
        return Intent(
            kind=IntentKind.RECORD,
            handle=uuid_m.group(0),
            handle_kind=HandleKind.NAME,
            asserted_verdict=asserted_verdict,
            asserted_hashes=asserted_hashes,
            reason="uuid-handle",
        )
    sha_m = _SHA256_RE.search(text)
    if sha_m is not None:
        return Intent(
            kind=IntentKind.RECORD,
            handle=sha_m.group(0),
            handle_kind=HandleKind.HASH,
            asserted_verdict=asserted_verdict,
            asserted_hashes=asserted_hashes,
            reason="sha256-handle",
        )

    # 2) Dimension by keyword vote.
    scores: dict[str, int] = {d: 0 for d in DIMENSIONS}
    for dim, pat in _KEYWORD_PATTERNS:
        if pat.search(text):
            scores[dim] += 1

    best = max(scores.values())
    if best == 0:
        return Intent(
            kind=IntentKind.ABSTAIN,
            asserted_verdict=asserted_verdict,
            asserted_hashes=asserted_hashes,
            scores=scores,
            reason="no-keyword-match",
        )

    winners = [d for d, s in scores.items() if s == best]
    if len(winners) != 1:
        # A tie is genuine ambiguity — abstain rather than break it arbitrarily.
        return Intent(
            kind=IntentKind.ABSTAIN,
            asserted_verdict=asserted_verdict,
            asserted_hashes=asserted_hashes,
            scores=scores,
            reason=f"ambiguous-tie:{','.join(sorted(winners))}",
        )

    return Intent(
        kind=IntentKind.DIMENSION,
        dimension=winners[0],
        asserted_verdict=asserted_verdict,
        asserted_hashes=asserted_hashes,
        scores=scores,
        reason="keyword-route",
    )
