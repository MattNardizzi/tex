"""
Emergent norm tracer.

Identifies emergent collective behaviors (collusion, resource hoarding,
implicit unfairness) that no single agent's behavior makes visible.

Approach
--------
arXiv:2604.01151 ("Detecting Multi-Agent Collusion Through Multi-Agent
Interpretability", Schroederdewitt, Rose, Cullen 2026) achieves 1.0 AUROC
in-distribution and 0.60–0.86 zero-shot using **white-box** linear probes
on per-agent activations. The paper itself notes that in highly
adversarial settings without activation access, "collusion detection may
be limited to side channel attacks that indirectly measure the
consequences of covert coordination" (Anwar et al. 2026, cited in §6).

Tex's drift layer operates on the *event stream*, not on agent
activations. We therefore implement the side-channel detection track:

  1. **Action lockstep** — pairwise mutual information between agents'
     action histograms over a sliding window. The canonical
     domain-independent collusion signal (Bonjour, Aggarwal, Bhargava
     2022, "Information theoretic approach to detect collusion in
     multi-agent games", PMLR v180 pp. 223–232). Connected components in
     the high-MI graph above ``min_cluster_size`` are flagged.

  2. **Shared-target convergence** — multiple agents acting on the same
     target entity at a rate disproportionate to the per-target mean.
     Flagged when the per-target Z-score exceeds
     ``target_convergence_threshold`` and ≥ ``min_cluster_size`` distinct
     agents are involved. Catches the institutional-AI "resource
     capture" emergent norm from arXiv:2601.11369 (Cournot table game).

References
----------
- arXiv:2604.01151 (Schroederdewitt et al. 2026) — multi-agent
  interpretability for white-box collusion detection. The white-box
  upgrade path is documented as a TODO below.
- arXiv:2510.04303 (Audit the Whisper, 2026) — covert-channel auditing
  with calibrated false-positive guarantees on COLLUDEBENCH/CASE/Perfect
  Collusion. TODO upgrade path documented.
- PMLR v180 pp. 223–232 (Bonjour et al. 2022) — mutual information
  between actions as the canonical behavioral collusion signal. This is
  what we ship today.
- arXiv:2601.11369 (Bracale, Syrnikov et al. 2026) — institutional AI
  governance graphs; the four Cournot signals (S1–S4) it fires. Tex's
  drift tracer is complementary to those four; see
  ``tex.institutional.oracle`` for S1–S4.

Priority: P1.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event


# Pattern kinds — string constants kept stable for ledger/oracle integration.
PATTERN_ACTION_LOCKSTEP: str = "action_lockstep"
PATTERN_SHARED_TARGET_CONVERGENCE: str = "shared_target_convergence"

_VALID_PATTERN_KINDS: frozenset[str] = frozenset(
    {PATTERN_ACTION_LOCKSTEP, PATTERN_SHARED_TARGET_CONVERGENCE}
)


class EmergentPattern(BaseModel):
    """
    A detected emergent norm pattern.

    Frozen pydantic v2 record so callers can hand it to the institutional
    layer (which will threshold against rule_id) or to the events ledger
    without defensive copies.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern_id: str
    kind: str                          # one of PATTERN_* constants
    agent_ids: tuple[str, ...]         # sorted for canonicalisation
    target_entity_id: str | None
    severity: float = Field(ge=0.0)    # higher → more severe
    detected_at: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)


class EmergentNormTracer:
    """
    Streaming-window emergent norm tracer.

    Stateless across calls — each ``trace_norms`` invocation operates on
    the supplied window. Callers feed in a recent slice of events as
    dicts with at least ``actor_entity_id`` and an action-discriminator
    field; ``target_entity_id`` is used by the shared-target detector
    when present.

    Construction
    ------------
    >>> tracer = EmergentNormTracer()                    # default thresholds
    >>> tracer = EmergentNormTracer(
    ...     mi_threshold_nats=0.1,
    ...     target_convergence_threshold=2.0,
    ...     min_cluster_size=3,
    ... )

    Event-window contract
    ---------------------
    Each event is a ``dict`` carrying at minimum:
      - ``actor_entity_id``: str          — the acting agent
      - ``event_kind`` or ``action``: str  — the action discriminator
      - ``target_entity_id``: str | None   — optional, for shared-target

    Returns
    -------
    A tuple of ``EmergentPattern`` records, sorted by ``severity`` descending.
    """

    def __init__(
        self,
        *,
        window_size: int = 200,
        mi_threshold_nats: float = 0.1,
        target_convergence_threshold: float = 2.0,
        min_cluster_size: int = 3,
        action_field: str = "event_kind",
        bucket_field: str = "step_id",
    ) -> None:
        if window_size < 2:
            raise ValueError(f"window_size must be ≥ 2, got {window_size!r}")
        if mi_threshold_nats <= 0.0:
            raise ValueError(
                f"mi_threshold_nats must be > 0, got {mi_threshold_nats!r}"
            )
        if target_convergence_threshold <= 0.0:
            raise ValueError(
                "target_convergence_threshold must be > 0, "
                f"got {target_convergence_threshold!r}"
            )
        if min_cluster_size < 2:
            raise ValueError(f"min_cluster_size must be ≥ 2, got {min_cluster_size!r}")
        if not action_field:
            raise ValueError("action_field must be non-empty")
        if not bucket_field:
            raise ValueError("bucket_field must be non-empty")

        self._window_size = window_size
        self._mi_threshold = mi_threshold_nats
        self._target_z_threshold = target_convergence_threshold
        self._min_cluster_size = min_cluster_size
        self._action_field = action_field
        self._bucket_field = bucket_field

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def trace_norms(
        self,
        *,
        recent_event_window: tuple[Mapping[str, Any], ...],
    ) -> tuple[EmergentPattern, ...]:
        """
        Returns a tuple of detected emergent-norm patterns with severity scores.

        TODO(P1): correlate per-agent action distributions
            — DONE. ``_detect_action_lockstep`` computes pairwise mutual
              information between per-agent action histograms (Bonjour
              et al. 2022) and clusters high-MI pairs.
        TODO(P1): detect coordinated patterns (price-fixing, resource
                  capture, collusive equilibria) per Institutional AI taxonomy
            — DONE for resource-capture / shared-target convergence via
              ``_detect_shared_target_convergence``. Price-fixing and
              full collusive-equilibrium detection are deferred to the
              institutional/oracle thresholding layer (see
              ``tex.institutional.oracle`` signals S1–S4 from
              arXiv:2601.11369), which consumes the patterns this method
              returns.
        TODO(P1): cite arxiv 2604.01151 for multi-agent collusion detection
                  via interpretability signals
            — Done in module docstring. Tex does not have white-box agent
              activations, so we ship the side-channel (action stream)
              detector path the paper calls out as the fallback when
              activation access is unavailable.
        TODO(P1): upgrade to white-box probe pathway when Tex deployments
            land where activation streams are available — would lift
            AUROC from the 0.6–0.86 zero-shot range we expect from
            side-channel detection to the 1.0 in-distribution / 0.9
            out-of-distribution range the paper achieves.
        TODO(P1): add the Audit-the-Whisper calibrated-false-positive
            wrapper (arXiv:2510.04303) so the tracer's per-pattern severity
            scores carry an explicit type-I error guarantee.
        """
        if not recent_event_window:
            return ()
        # Truncate to ``window_size`` most-recent events. Iteration is
        # O(window_size · agents²) for the MI step so this bound matters.
        events = tuple(recent_event_window[-self._window_size :])
        patterns: list[EmergentPattern] = []
        now = datetime.now(UTC)

        lockstep = self._detect_action_lockstep(events=events, detected_at=now)
        patterns.extend(lockstep)

        target_conv = self._detect_shared_target_convergence(
            events=events, detected_at=now
        )
        patterns.extend(target_conv)

        # Sort by severity descending — operator-friendly default.
        patterns.sort(key=lambda p: (-p.severity, p.pattern_id))

        for p in patterns:
            emit_event(
                "drift.emergent_norm.flagged",
                pattern_id=p.pattern_id,
                kind=p.kind,
                severity=p.severity,
                agent_count=len(p.agent_ids),
                target_entity_id=p.target_entity_id,
            )

        return tuple(patterns)

    # ------------------------------------------------------------------
    # Internals — pattern 1: action lockstep (mutual information)
    # ------------------------------------------------------------------

    def _detect_action_lockstep(
        self,
        *,
        events: tuple[Mapping[str, Any], ...],
        detected_at: datetime,
    ) -> list[EmergentPattern]:
        """
        Cluster agents whose action distributions are anomalously
        synchronised, per pairwise mutual information.

        Method: per Bonjour et al. 2022, MI between two agents' action
        sequences is a domain-independent collusion signal. Two agents
        playing genuinely independent strategies have action MI ≈ 0; two
        agents whose actions encode shared state have MI bounded below by
        the shared-state entropy.

        We bin actions into a categorical histogram per agent (the
        ``action_field`` discriminator), align by event index (joint
        action vectors are constructed from co-located events in the
        window), then compute MI in nats. Pairs above ``mi_threshold_nats``
        form an undirected graph; connected components ≥ ``min_cluster_size``
        are flagged as an action_lockstep pattern.
        """
        # --- 1. per-agent action sequences (preserve order) -----------
        per_agent_actions: dict[str, list[str]] = defaultdict(list)
        for ev in events:
            actor = ev.get("actor_entity_id")
            action = ev.get(self._action_field)
            if not actor or action is None:
                continue
            per_agent_actions[str(actor)].append(str(action))

        # Need at least min_cluster_size active agents to form a cluster.
        active_agents = [
            a for a, seq in per_agent_actions.items() if len(seq) >= 2
        ]
        if len(active_agents) < self._min_cluster_size:
            return []

        # --- 2. align by bucket key and compute pairwise MI -----------
        # Strategy per Bonjour et al. 2022: joint-action pairs are
        # constructed from events that occurred *together* (same logical
        # round / time bucket). We use ``bucket_field`` if present on the
        # event; otherwise fall back to event-list position which gives
        # each event its own singleton bucket. Callers wanting MI-based
        # collusion detection on a real ecosystem stream should pass a
        # bucket key (``step_id``, a coarse-grained timestamp, etc.) so
        # joint-action alignment is meaningful.
        per_agent_bucket: dict[str, dict[Any, str]] = defaultdict(dict)
        for i, ev in enumerate(events):
            actor = ev.get("actor_entity_id")
            action = ev.get(self._action_field)
            if not actor or action is None:
                continue
            bucket = ev.get(self._bucket_field, i)
            # Last-write-wins within a bucket per agent — the practical
            # shape of "agent X's action this round". For higher-fidelity
            # joint-distribution estimation, callers can use finer
            # bucketing.
            per_agent_bucket[str(actor)][bucket] = str(action)

        high_mi_pairs: list[tuple[str, str, float]] = []
        sorted_agents = sorted(active_agents)
        for i, a in enumerate(sorted_agents):
            for b in sorted_agents[i + 1 :]:
                a_buckets = per_agent_bucket[a]
                b_buckets = per_agent_bucket[b]
                # Joint action sequence on the intersection of buckets.
                shared_buckets = set(a_buckets) & set(b_buckets)
                if len(shared_buckets) < 2:
                    continue
                joint = [
                    (a_buckets[bk], b_buckets[bk])
                    for bk in sorted(shared_buckets, key=lambda x: (str(type(x)), x))
                ]
                mi = _mutual_information_nats(joint)
                if mi >= self._mi_threshold:
                    high_mi_pairs.append((a, b, mi))

        if not high_mi_pairs:
            return []

        # --- 3. union-find clusters from high-MI edges ----------------
        clusters = _connected_components(
            nodes=active_agents,
            edges=[(a, b) for (a, b, _mi) in high_mi_pairs],
        )

        patterns: list[EmergentPattern] = []
        # Pre-index pair MIs by frozenset for O(1) lookup during severity calc.
        pair_mi: dict[frozenset[str], float] = {
            frozenset({a, b}): mi for (a, b, mi) in high_mi_pairs
        }
        n_total = max(len(active_agents), 1)
        for cluster in clusters:
            if len(cluster) < self._min_cluster_size:
                continue
            # Severity = mean within-cluster MI × cluster_size / n_total.
            # Cluster_size / n_total upweights large coordinated coalitions
            # relative to small dyads.
            sorted_cluster = tuple(sorted(cluster))
            within = [
                pair_mi[frozenset({a, b})]
                for i, a in enumerate(sorted_cluster)
                for b in sorted_cluster[i + 1 :]
                if frozenset({a, b}) in pair_mi
            ]
            if not within:
                continue
            mean_mi = sum(within) / len(within)
            severity = mean_mi * (len(sorted_cluster) / n_total)
            patterns.append(
                EmergentPattern(
                    pattern_id=f"emp_{uuid4().hex[:12]}",
                    kind=PATTERN_ACTION_LOCKSTEP,
                    agent_ids=sorted_cluster,
                    target_entity_id=None,
                    severity=severity,
                    detected_at=detected_at,
                    evidence={
                        "mean_pairwise_mi_nats": mean_mi,
                        "n_pairs_in_cluster": len(within),
                        "n_total_active_agents": n_total,
                        "mi_threshold_nats": self._mi_threshold,
                    },
                )
            )
        return patterns

    # ------------------------------------------------------------------
    # Internals — pattern 2: shared-target convergence
    # ------------------------------------------------------------------

    def _detect_shared_target_convergence(
        self,
        *,
        events: tuple[Mapping[str, Any], ...],
        detected_at: datetime,
    ) -> list[EmergentPattern]:
        """
        Flag targets being acted on by ≥ ``min_cluster_size`` distinct
        agents at a per-target volume disproportionate to the per-target
        mean (Z-score > ``target_convergence_threshold``).
        """
        # target_entity_id → (agents acting on it, hit count)
        target_hits: dict[str, Counter[str]] = defaultdict(Counter)
        for ev in events:
            target = ev.get("target_entity_id")
            actor = ev.get("actor_entity_id")
            if not target or not actor:
                continue
            target_hits[str(target)][str(actor)] += 1

        if not target_hits:
            return []

        # Per-target hit counts (sum across actors).
        per_target_volume = {
            t: sum(actors.values()) for t, actors in target_hits.items()
        }
        if not per_target_volume:
            return []

        volumes = list(per_target_volume.values())
        mean_v = sum(volumes) / len(volumes)
        # Population stddev — guard against zero variance when all targets
        # received the same volume.
        var = sum((v - mean_v) ** 2 for v in volumes) / len(volumes)
        sigma = math.sqrt(var) if var > 0 else 0.0

        patterns: list[EmergentPattern] = []
        for target, volume in per_target_volume.items():
            actors = target_hits[target]
            distinct_actors = len(actors)
            if distinct_actors < self._min_cluster_size:
                continue
            if sigma == 0.0:
                # All targets hit at the same rate — no convergence signal
                # available. We only flag when at least min_cluster_size
                # agents converged AND there's variance in the population.
                continue
            z = (volume - mean_v) / sigma
            if z < self._target_z_threshold:
                continue
            severity = z * (distinct_actors / max(len(per_target_volume), 1))
            patterns.append(
                EmergentPattern(
                    pattern_id=f"emp_{uuid4().hex[:12]}",
                    kind=PATTERN_SHARED_TARGET_CONVERGENCE,
                    agent_ids=tuple(sorted(actors.keys())),
                    target_entity_id=target,
                    severity=severity,
                    detected_at=detected_at,
                    evidence={
                        "target_volume": volume,
                        "population_mean_volume": mean_v,
                        "population_stddev_volume": sigma,
                        "z_score": z,
                        "distinct_agents": distinct_actors,
                    },
                )
            )
        return patterns


# ----------------------------------------------------------------------
# Pure helpers — no class state, no side effects, easy to unit-test.
# ----------------------------------------------------------------------


def _mutual_information_nats(
    joint_samples: list[tuple[str, str]],
) -> float:
    """
    Empirical mutual information in nats from joint samples (X_i, Y_i).

    MI(X; Y) = Σ p(x, y) log [ p(x, y) / (p(x) p(y)) ]

    Uses plug-in (max-likelihood) probability estimates. For collusion
    detection on action streams the bias is acceptable; the
    Miller-Madow correction (Roulston 1999, Physica D 125) is left as a
    P2 upgrade — TODO(P2) below — since for the alarm-vs-no-alarm decision
    the threshold-relative ranking is what matters.

    TODO(P2): apply Miller-Madow bias correction:
        MI_MM = MI_plug_in + (|S(X,Y)| - |S(X)| - |S(Y)| + 1) / (2N).
        This sharpens detection on small windows where the plug-in
        estimator is biased upward.
    """
    n = len(joint_samples)
    if n < 2:
        return 0.0
    p_xy: Counter[tuple[str, str]] = Counter(joint_samples)
    p_x: Counter[str] = Counter(s[0] for s in joint_samples)
    p_y: Counter[str] = Counter(s[1] for s in joint_samples)
    mi = 0.0
    for (x, y), c_xy in p_xy.items():
        p_joint = c_xy / n
        p_marg = (p_x[x] / n) * (p_y[y] / n)
        if p_marg == 0.0 or p_joint == 0.0:
            continue
        mi += p_joint * math.log(p_joint / p_marg)
    # Plug-in MI is non-negative analytically; clamp to defend against
    # floating-point drift on near-zero estimates.
    return max(mi, 0.0)


def _connected_components(
    *, nodes: list[str], edges: list[tuple[str, str]]
) -> list[set[str]]:
    """
    Plain union-find for small agent populations.

    Used by ``_detect_action_lockstep`` to lift pairwise high-MI edges
    into agent clusters. Returns components as sets, in arbitrary order.
    """
    parent: dict[str, str] = {n: n for n in nodes}

    def find(x: str) -> str:
        # Path compression.
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for a, b in edges:
        if a in parent and b in parent:
            union(a, b)
    components: dict[str, set[str]] = defaultdict(set)
    for n in nodes:
        components[find(n)].add(n)
    return list(components.values())
