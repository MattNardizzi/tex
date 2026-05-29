"""
Behavioural signature — proving who an agent is by what it does.

Every discovery product in the field identifies an agent by what it (or
its platform) *claims*: a directory entry, an OAuth consent, a self-
declared card, a ``(source, tenant, external_id)`` tuple. Each of those
anchors can be forged, rotated, renamed, or is simply absent for the
shadow agent that has no card and a personal key on a laptop. The newest
research names this as an unsolved gap: self-declaration is forgeable and
no third party attests to what an agent really is.

This module is Tex's answer. It derives an agent's identity from the
causal signature of how it *acts* — the distribution of actions it takes,
the tools and MCP servers it reaches for, the data scopes it touches, the
stable hashes of its system prompt / tool manifest / memory, the verdict
mix it provokes, and the cadence of its behaviour. That signature is the
agent. An agent can rotate its credentials, rename itself, publish a
fresh card, and delete its directory entry — and its behavioural
signature stays the same, because the behaviour is what it is. So the
same primitive catches the actor that lies, the actor that rotates, and
the actor that never had a name to begin with.

Metadata only — never content. The signature is built from *what was
reached for*, never *what was said*. The ``ActionLedgerEntry`` substrate
carries only hashes and structural metadata (it has no prompt or output
text), and crossing that line would turn the provenance log into a
regulated data store and break the privacy posture. The line the egress
plane holds, this module holds too.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

# The observation substrate is the agent action ledger: one immutable,
# content-free entry per gate decision for an agent.
from tex.domain.agent import ActionLedgerEntry


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize(counter: Mapping[str, float]) -> dict[str, float]:
    total = float(sum(counter.values()))
    if total <= 0.0:
        return {}
    return {k: v / total for k, v in counter.items()}


def _quantize(value: float, places: int = 4) -> float:
    """Quantize a float so signature hashes are stable across float noise."""
    return float(round(value, places))


@dataclass(frozen=True, slots=True)
class BehavioralSignature:
    """
    A content-free behavioural fingerprint of one actor over a window of
    observed actions.

    The signature is the *identity by behaviour*. Two signatures are
    compared by :mod:`tex.provenance.distance` to produce a graded
    confidence that they belong to the same actor — never a bare claim.

    Fields are deliberately all distributions, sets, scalar moments, and
    stable hashes: nothing here is the content of any action, only its
    shape. ``signature_hash`` is a stable digest over the quantized
    vector, suitable for sealing into the transparency log.
    """

    observation_count: int

    # Distributions over structural facets (each sums to ~1.0).
    action_type_dist: Mapping[str, float] = field(default_factory=dict)
    channel_dist: Mapping[str, float] = field(default_factory=dict)
    environment_dist: Mapping[str, float] = field(default_factory=dict)
    verdict_mix: Mapping[str, float] = field(default_factory=dict)

    # Capability surface actually exercised (sets, for Jaccard overlap).
    tool_set: frozenset[str] = frozenset()
    mcp_set: frozenset[str] = frozenset()
    data_scope_set: frozenset[str] = frozenset()

    # Scalar behavioural moments.
    score_mean: float = 0.0
    score_std: float = 0.0
    violation_rate: float = 0.0

    # Strong, stable identity anchors. When present these are near-
    # dispositive: an agent that keeps the same system prompt + tool
    # manifest across a credential rotation is almost certainly the same
    # actor. They are hashes, so they carry no content.
    system_prompt_hash: str | None = None
    tool_manifest_hash: str | None = None
    memory_hash: str | None = None

    # Cadence: median inter-action gap in seconds and its dispersion.
    cadence_median_s: float = 0.0
    cadence_dispersion: float = 0.0

    signature_hash: str = ""

    # ------------------------------------------------------------------
    @classmethod
    def from_actions(
        cls, entries: Sequence[ActionLedgerEntry] | Iterable[ActionLedgerEntry]
    ) -> "BehavioralSignature":
        """
        Build a signature from a window of an agent's action-ledger
        entries. The window is the gate's decision stream for one actor.
        """
        items = list(entries)
        n = len(items)
        if n == 0:
            return cls(observation_count=0, signature_hash=_sha256_hex("empty"))

        action_types: Counter[str] = Counter()
        channels: Counter[str] = Counter()
        environments: Counter[str] = Counter()
        verdicts: Counter[str] = Counter()
        tools: set[str] = set()
        mcps: set[str] = set()
        scopes: set[str] = set()
        scores: list[float] = []
        violations = 0

        # Most-recent non-null anchor wins; behaviour-defining and stable.
        sys_hash: str | None = None
        tool_hash: str | None = None
        mem_hash: str | None = None

        timestamps: list[datetime] = []

        for e in items:
            action_types[e.action_type] += 1
            channels[e.channel] += 1
            environments[e.environment] += 1
            verdicts[str(e.verdict)] += 1
            tools.update(e.tools or ())
            mcps.update(e.mcp_server_ids or ())
            scopes.update(e.data_scopes or ())
            scores.append(float(e.final_score))
            if e.capability_violations:
                violations += 1
            if e.system_prompt_hash:
                sys_hash = e.system_prompt_hash
            if e.tool_manifest_hash:
                tool_hash = e.tool_manifest_hash
            if e.memory_hash:
                mem_hash = e.memory_hash
            if e.recorded_at is not None:
                timestamps.append(e.recorded_at)

        score_mean = sum(scores) / len(scores) if scores else 0.0
        if len(scores) > 1:
            var = sum((s - score_mean) ** 2 for s in scores) / len(scores)
            score_std = math.sqrt(var)
        else:
            score_std = 0.0

        cadence_median, cadence_disp = _cadence(timestamps)

        sig = cls(
            observation_count=n,
            action_type_dist=_normalize(action_types),
            channel_dist=_normalize(channels),
            environment_dist=_normalize(environments),
            verdict_mix=_normalize(verdicts),
            tool_set=frozenset(tools),
            mcp_set=frozenset(mcps),
            data_scope_set=frozenset(scopes),
            score_mean=_quantize(score_mean),
            score_std=_quantize(score_std),
            violation_rate=_quantize(violations / n),
            system_prompt_hash=sys_hash,
            tool_manifest_hash=tool_hash,
            memory_hash=mem_hash,
            cadence_median_s=_quantize(cadence_median, 2),
            cadence_dispersion=_quantize(cadence_disp, 4),
            signature_hash="",  # filled below
        )
        return sig._with_hash()

    # ------------------------------------------------------------------
    def _with_hash(self) -> "BehavioralSignature":
        payload = {
            "action_type_dist": {k: _quantize(v) for k, v in self.action_type_dist.items()},
            "channel_dist": {k: _quantize(v) for k, v in self.channel_dist.items()},
            "environment_dist": {k: _quantize(v) for k, v in self.environment_dist.items()},
            "verdict_mix": {k: _quantize(v) for k, v in self.verdict_mix.items()},
            "tool_set": sorted(self.tool_set),
            "mcp_set": sorted(self.mcp_set),
            "data_scope_set": sorted(self.data_scope_set),
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "violation_rate": self.violation_rate,
            "system_prompt_hash": self.system_prompt_hash,
            "tool_manifest_hash": self.tool_manifest_hash,
            "memory_hash": self.memory_hash,
            "cadence_median_s": self.cadence_median_s,
            "cadence_dispersion": self.cadence_dispersion,
        }
        digest = _sha256_hex(_stable_json(payload))
        return BehavioralSignature(
            observation_count=self.observation_count,
            action_type_dist=self.action_type_dist,
            channel_dist=self.channel_dist,
            environment_dist=self.environment_dist,
            verdict_mix=self.verdict_mix,
            tool_set=self.tool_set,
            mcp_set=self.mcp_set,
            data_scope_set=self.data_scope_set,
            score_mean=self.score_mean,
            score_std=self.score_std,
            violation_rate=self.violation_rate,
            system_prompt_hash=self.system_prompt_hash,
            tool_manifest_hash=self.tool_manifest_hash,
            memory_hash=self.memory_hash,
            cadence_median_s=self.cadence_median_s,
            cadence_dispersion=self.cadence_dispersion,
            signature_hash=digest,
        )

    @property
    def is_warm(self) -> bool:
        """
        Whether the signature rests on enough observations to be load-
        bearing. Below this, the engine treats a match as low-confidence
        regardless of similarity — the cold-start honesty constraint.
        """
        return self.observation_count >= WARM_OBSERVATION_THRESHOLD

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "observation_count": self.observation_count,
            "action_type_dist": dict(self.action_type_dist),
            "channel_dist": dict(self.channel_dist),
            "environment_dist": dict(self.environment_dist),
            "verdict_mix": dict(self.verdict_mix),
            "tool_set": sorted(self.tool_set),
            "mcp_set": sorted(self.mcp_set),
            "data_scope_set": sorted(self.data_scope_set),
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "violation_rate": self.violation_rate,
            "system_prompt_hash": self.system_prompt_hash,
            "tool_manifest_hash": self.tool_manifest_hash,
            "memory_hash": self.memory_hash,
            "cadence_median_s": self.cadence_median_s,
            "cadence_dispersion": self.cadence_dispersion,
            "signature_hash": self.signature_hash,
        }


# Below this observation count a signature is "cold": it exists, but the
# engine will not assert a confident identity from it. This is the honest
# floor — an agent that has acted once has a weak fingerprint, and a
# witness states that rather than guessing.
WARM_OBSERVATION_THRESHOLD: int = 8


def _cadence(timestamps: list[datetime]) -> tuple[float, float]:
    """Median inter-action gap (seconds) and a normalized dispersion."""
    if len(timestamps) < 2:
        return 0.0, 0.0
    ordered = sorted(timestamps)
    gaps = [
        (ordered[i + 1] - ordered[i]).total_seconds()
        for i in range(len(ordered) - 1)
    ]
    gaps = [g for g in gaps if g >= 0.0]
    if not gaps:
        return 0.0, 0.0
    gaps.sort()
    mid = len(gaps) // 2
    median = gaps[mid] if len(gaps) % 2 == 1 else (gaps[mid - 1] + gaps[mid]) / 2.0
    if median <= 0.0:
        return median, 0.0
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    # Coefficient of variation, bounded — robust dispersion measure.
    cov = math.sqrt(var) / mean if mean > 0 else 0.0
    return median, min(cov, 4.0)
