"""
Behavioural distance — graded confidence, never a bare claim.

Given two behavioural signatures, this module returns a calibrated
confidence in [0, 1] that they belong to the *same actor*. The witness
discipline is the whole point: Tex never asserts "these two are the same
agent." It seals "I am 0.92 that these are the same actor, and here is
the evidence." The number is the thing that gets recorded; the merge or
split decision downstream is a human's, surfaced as a held decision when
it matters.

The confidence fuses several independent comparisons, each catching what
the others miss:

  * Stable identity anchors (system prompt / tool manifest / memory
    hashes). When two signatures share these, it is near-dispositive —
    an agent that keeps the same prompt and tool manifest across a
    credential rotation is almost certainly the same actor. This is the
    signal that survives renames and key rotations, which is exactly the
    case directory-based identity cannot follow.
  * Capability-surface overlap (tools, MCP servers, data scopes) by
    Jaccard similarity — what the agent reaches for.
  * Distributional similarity over action types, channels, environments,
    and verdict mix — the *shape* of behaviour, compared by a bounded
    cosine over the shared support.
  * Behavioural moments — proximity of mean risk score and cadence.

Weights are deliberately explicit and conservative. Anchors dominate
when present; absent anchors, the engine leans on overlap and shape but
caps the achievable confidence, because behaviour alone is suggestive,
not dispositive. That cap is honesty, not timidity.
"""

from __future__ import annotations

from typing import Mapping

from tex.provenance.signature import BehavioralSignature

# Weights for the fused score (anchors handled separately, below).
_W_TOOLS = 0.22
_W_MCP = 0.14
_W_SCOPES = 0.14
_W_ACTION = 0.20
_W_CHANNEL = 0.08
_W_ENV = 0.06
_W_VERDICT = 0.08
_W_SCORE = 0.04
_W_CADENCE = 0.04

# When NO stable anchor is shared, behavioural similarity alone cannot
# exceed this confidence. Behaviour is strong evidence, not proof; the
# cap keeps Tex from overclaiming a merge on shape alone.
_NO_ANCHOR_CONFIDENCE_CAP = 0.80

# A single shared strong anchor lifts the floor of confidence to here,
# because matching prompt/tool/memory hashes across signatures is hard to
# forge while remaining a different actor.
_ANCHOR_FLOOR = 0.85
_TWO_ANCHOR_FLOOR = 0.93


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float | None:
    if not a and not b:
        return None  # no information either way
    union = a | b
    if not union:
        return None
    return len(a & b) / len(union)


def _dist_cosine(p: Mapping[str, float], q: Mapping[str, float]) -> float | None:
    """Cosine similarity over the union of keys; None if both empty."""
    keys = set(p) | set(q)
    if not keys:
        return None
    dot = sum(p.get(k, 0.0) * q.get(k, 0.0) for k in keys)
    np = sum(v * v for v in p.values()) ** 0.5
    nq = sum(v * v for v in q.values()) ** 0.5
    if np <= 0.0 or nq <= 0.0:
        return None
    return dot / (np * nq)


def _scalar_proximity(a: float, b: float, scale: float) -> float:
    """1.0 when equal, decaying toward 0 as |a-b| grows relative to scale."""
    if scale <= 0.0:
        return 1.0 if a == b else 0.0
    return max(0.0, 1.0 - abs(a - b) / scale)


def _shared_anchors(a: BehavioralSignature, b: BehavioralSignature) -> int:
    """Count of stable identity anchors that are present and equal in both."""
    count = 0
    if a.system_prompt_hash and a.system_prompt_hash == b.system_prompt_hash:
        count += 1
    if a.tool_manifest_hash and a.tool_manifest_hash == b.tool_manifest_hash:
        count += 1
    if a.memory_hash and a.memory_hash == b.memory_hash:
        count += 1
    return count


def behavioral_confidence(
    a: BehavioralSignature, b: BehavioralSignature
) -> float:
    """
    Calibrated confidence in [0, 1] that ``a`` and ``b`` are the same
    actor. Symmetric. Returns 0.0 if either signature is empty.
    """
    if a.observation_count == 0 or b.observation_count == 0:
        return 0.0

    # --- Distributional + overlap components (the behavioural shape) ---
    components: list[tuple[float, float]] = []  # (similarity, weight)

    for sim, w in (
        (_jaccard(a.tool_set, b.tool_set), _W_TOOLS),
        (_jaccard(a.mcp_set, b.mcp_set), _W_MCP),
        (_jaccard(a.data_scope_set, b.data_scope_set), _W_SCOPES),
        (_dist_cosine(a.action_type_dist, b.action_type_dist), _W_ACTION),
        (_dist_cosine(a.channel_dist, b.channel_dist), _W_CHANNEL),
        (_dist_cosine(a.environment_dist, b.environment_dist), _W_ENV),
        (_dist_cosine(a.verdict_mix, b.verdict_mix), _W_VERDICT),
    ):
        if sim is not None:
            components.append((sim, w))

    # Behavioural moments.
    components.append(
        (_scalar_proximity(a.score_mean, b.score_mean, scale=0.5), _W_SCORE)
    )
    if a.cadence_median_s > 0.0 and b.cadence_median_s > 0.0:
        # Compare cadence on a log scale — orders of magnitude matter,
        # not raw seconds.
        import math

        la, lb = math.log10(a.cadence_median_s + 1.0), math.log10(b.cadence_median_s + 1.0)
        components.append((_scalar_proximity(la, lb, scale=2.0), _W_CADENCE))

    if not components:
        behavioural = 0.0
    else:
        total_w = sum(w for _, w in components)
        behavioural = sum(sim * w for sim, w in components) / total_w

    # --- Fuse with stable anchors ---
    anchors = _shared_anchors(a, b)
    if anchors >= 2:
        # Two matching hard anchors: confidence floored high, then nudged
        # by behavioural agreement.
        return _clamp(max(_TWO_ANCHOR_FLOOR, 0.5 * _TWO_ANCHOR_FLOOR + 0.5 * behavioural + 0.07))
    if anchors == 1:
        return _clamp(max(_ANCHOR_FLOOR, 0.6 * _ANCHOR_FLOOR + 0.4 * behavioural))

    # No shared anchor: behaviour alone, capped. Strong overlap can get
    # close to the cap, but never past it.
    return _clamp(min(behavioural, _NO_ANCHOR_CONFIDENCE_CAP))


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))
