"""
MAGE Shadow Memory.

Reference: arxiv 2605.03228 (Wang et al., Stony Brook + Cisco), May 2026.

Inspired by the shadow stack abstraction (Burow et al., 2019), the shadow
memory runs in parallel to the working context. Where working memory
optimises for task completion (potentially diluting safety-critical signal
across long horizons), shadow memory is curated for safety: it preserves
red flags, observed injections, prior denials, and constraint deltas.

Per Eq. 2 of the paper:

    m_t = M(m_{t-1}, s_{t-1})

i.e. the shadow memory is iteratively distilled from the previous shadow
state and the previous (action, observation, instruction) tuple. The full
paper backs M with a small RL-trained LLM (M_θ); we expose that as a
pluggable callable and ship a deterministic offline implementation that
selects entries via keyword-overlap relevance and applies an exponential
TTL decay so stale signals do not dominate downstream judgments.

Append-only invariant is enforced. ``turn_index`` must be strictly
monotonic. The motivation: shadow memory must be auditable evidence for
post-mortem investigation; rewriting history would defeat that property.

Priority: P1.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from tex.observability.telemetry import emit_event, get_logger

_logger = get_logger("tex.runtime.mage.shadow")


@dataclass(frozen=True, slots=True)
class ShadowMemoryEntry:
    """One distilled, safety-critical observation across the trajectory."""

    turn_index: int
    constraint_text: str | None
    risk_signal: str | None
    risk_score: float
    timestamp_iso: str
    source_kind: str = "agent"  # 'user' | 'agent' | 'tool' | 'observation' | 'external'

    def __post_init__(self) -> None:
        if self.turn_index < 0:
            raise ValueError("turn_index must be non-negative")
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError("risk_score must be in [0, 1]")


# A relevance scorer takes (candidate_action, entry) and returns a score in
# [0, 1]. Pluggable so the paper's RL-trained M_θ can substitute for the
# offline path.
RelevanceScorer = Callable[[dict[str, Any], ShadowMemoryEntry], float]


_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]{3,}")


def _tokenize(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_PATTERN.findall(text or "")}


def keyword_overlap_scorer(
    candidate_action: dict[str, Any],
    entry: ShadowMemoryEntry,
) -> float:
    """Default relevance scorer.

    Tokenises the candidate action's tool name + stringified params and the
    entry's constraint + risk signal text; returns Jaccard overlap.
    """
    action_blob_parts = [str(candidate_action.get("tool_name", ""))]
    params = candidate_action.get("tool_params") or candidate_action.get("params") or {}
    if isinstance(params, dict):
        for k, v in params.items():
            action_blob_parts.append(f"{k}={v}")
    action_tokens = _tokenize(" ".join(action_blob_parts))

    entry_blob = " ".join(filter(None, [entry.constraint_text, entry.risk_signal]))
    entry_tokens = _tokenize(entry_blob)

    if not action_tokens or not entry_tokens:
        return 0.0
    inter = action_tokens & entry_tokens
    union = action_tokens | entry_tokens
    return len(inter) / len(union)


class ShadowMemory:
    """Append-only shadow memory.

    Two operations:

      - ``append(entry)``: add a new distilled entry. Enforces strictly
        monotonic ``turn_index``; raises ``ValueError`` on regression.
      - ``distill_for_action_check(candidate_action)``: return the subset of
        entries most relevant to the candidate action, after applying TTL
        decay and a configurable relevance threshold.

    The TTL model: an entry's effective weight at turn ``t_now`` is
    ``risk_score * exp(-decay * (t_now - turn_index))``. Default decay is
    ``ln(2) / half_life`` with a half life of 16 turns (paper §V notes
    cross-turn signal must remain useful out to ~20 turns, so 16 turns is
    a conservative half life).
    """

    def __init__(
        self,
        *,
        relevance_scorer: RelevanceScorer = keyword_overlap_scorer,
        relevance_threshold: float = 0.05,
        ttl_half_life_turns: float = 16.0,
        max_returned: int = 16,
        llm_distiller: Callable[[Iterable[ShadowMemoryEntry], dict[str, Any]],
                                tuple[ShadowMemoryEntry, ...]] | None = None,
    ) -> None:
        self._entries: list[ShadowMemoryEntry] = []
        self._scorer = relevance_scorer
        self._threshold = relevance_threshold
        self._decay = math.log(2.0) / max(ttl_half_life_turns, 1.0)
        self._max_returned = max_returned
        self._llm_distiller = llm_distiller

    # ------------------------------------------------------------------
    def append(self, entry: ShadowMemoryEntry) -> None:
        """Append-only with monotonic turn_index check."""
        if self._entries and entry.turn_index <= self._entries[-1].turn_index:
            raise ValueError(
                f"shadow memory turn_index regressed: last="
                f"{self._entries[-1].turn_index}, new={entry.turn_index}"
            )
        self._entries.append(entry)
        emit_event(
            "mage.shadow.append",
            logger=_logger,
            turn_index=entry.turn_index,
            risk_score=entry.risk_score,
            source_kind=entry.source_kind,
            has_constraint=entry.constraint_text is not None,
        )

    # ------------------------------------------------------------------
    @property
    def entries(self) -> tuple[ShadowMemoryEntry, ...]:
        return tuple(self._entries)

    @property
    def latest_turn(self) -> int:
        return self._entries[-1].turn_index if self._entries else -1

    # ------------------------------------------------------------------
    def distill_for_action_check(
        self,
        candidate_action: dict[str, Any],
        *,
        current_turn: int | None = None,
    ) -> tuple[ShadowMemoryEntry, ...]:
        """Return the relevance-ranked subset of shadow memory for the given
        candidate action, after TTL decay weighting.

        If an LLM distiller is wired (paper-faithful M_θ), it is preferred;
        otherwise the deterministic offline path runs:

          1. score each entry's relevance to the candidate action;
          2. multiply by the TTL decay factor for the current turn;
          3. drop entries below the relevance threshold;
          4. sort descending and return up to ``max_returned``.
        """
        if not self._entries:
            return ()

        if self._llm_distiller is not None:
            try:
                distilled = tuple(self._llm_distiller(self._entries, candidate_action))
                emit_event(
                    "mage.shadow.distilled",
                    logger=_logger,
                    via="llm",
                    n_input=len(self._entries),
                    n_output=len(distilled),
                )
                return distilled
            except Exception as exc:
                # Fall through to deterministic path on M_θ failure.
                emit_event(
                    "mage.shadow.distill_llm_failed",
                    logger=_logger,
                    error_class=type(exc).__name__,
                )

        t_now = current_turn if current_turn is not None else self.latest_turn + 1

        scored: list[tuple[float, ShadowMemoryEntry]] = []
        for entry in self._entries:
            rel = self._scorer(candidate_action, entry)
            age = max(t_now - entry.turn_index, 0)
            decay = math.exp(-self._decay * age)
            weight = rel * decay * (0.5 + 0.5 * entry.risk_score)
            if weight >= self._threshold:
                scored.append((weight, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        result = tuple(e for _, e in scored[: self._max_returned])
        emit_event(
            "mage.shadow.distilled",
            logger=_logger,
            via="offline",
            n_input=len(self._entries),
            n_output=len(result),
            current_turn=t_now,
        )
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds")
