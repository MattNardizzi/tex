"""
Autonomous-attack action-cadence circuit-breaker.

[Architecture: Layer 1 (deterministic recognizers) → Layer 4 (structural FORBID floor)]

Why this exists
---------------
Anthropic's November 2025 disclosure of a largely-autonomous, AI-orchestrated
espionage campaign (GTG-1002) made one operational fact concrete: an agent under
adversary control does not act at human speed. It fans out — many requests, many
recipients, many tools — in seconds, far faster than any human-in-the-loop review
can keep up with. The defensive lesson Tex takes from that disclosure is NOT
"detect the attacker's content faster" (an arms race a probabilistic classifier
loses, per Nasr et al. arXiv:2510.09023 — a stronger optimiser routes around any
detector). It is the structural one: **the gate does not need to outpace the
attacker, it only needs to be unavoidable and structural.** Every outbound action
already passes through ``PolicyDecisionPoint.evaluate``; if a single agent's
*cadence* — its action rate and its branching fan-out — crosses a budget, that is
a deterministic, paraphrase-proof fact about the agent's behaviour, not an
inference about its content. A burst cannot be reworded to look slow.

So this module measures cadence over a sliding window keyed by (tenant, agent
identity) and exposes it on two of Tex's existing rails, both monotone-lowering:

  * **soft budget → ABSTAIN.** Above a soft rate/fan-out budget, a PERMIT is
    demoted to ABSTAIN (human review) by ``apply_cadence_hold`` — the same
    post-router, PERMIT→ABSTAIN-only shape as ``systemic.probguard``'s predictive
    holds. It never raises a verdict.
  * **hard threshold → FORBID.** Above a hard threshold, ``assess_for_floor``
    feeds the deterministic structural FORBID floor (``specialists.structural_floor``)
    — the same authority a PCAS deny or an IFC type violation has. A high cadence
    is a *proof over structure* (we counted the actions), never a probabilistic
    score, so it is allowed to fire the floor.

The structural floor result is sealed into the verdict's reasons + a counterfactual
("had the agent stayed within the soft budget, no hold would have fired") and the
window stats ride in the finding metadata, so the decision record explains itself.

Invariant discipline (CLAUDE.md rule 2 — sacred)
------------------------------------------------
A cadence signal can only ever move a verdict toward caution
(PERMIT → ABSTAIN → FORBID). ``apply_cadence_hold`` acts only on a routed PERMIT
and only ever yields ABSTAIN; the FORBID authority lives exclusively in the
deterministic floor and fires only on the HARD level (a counted threshold, never
a score). Neither path can relax a FORBID/ABSTAIN or manufacture a PERMIT.

Design note — two approaches considered (CORE change)
-----------------------------------------------------
The action must be observed exactly once per evaluation, yet its assessment is
read at three points in the pipeline (the recognizer for evidence, the structural
floor for HARD→FORBID, the post-router hold for SOFT→ABSTAIN).

  * **Approach A (CHOSEN): one stateful singleton tracker with request_id-idempotent
    observation + memoization.** All window state lives in one lock-guarded object.
    The first call for a request_id observes (mutates the window); every later call
    for the same request_id returns the identical memoized assessment. Observation
    is idempotent at the *window* level (a request_id already in the window is never
    re-counted), so it stays correct even if the memo evicts under load or the calls
    interleave across threads.
  * **Approach B (REJECTED): a consume-once request_id cache (mirroring the IFC
    labels cache), populated by the recognizer and popped by the floor.** Rejected
    because two distinct readers need the assessment (floor for HARD, hold for
    SOFT); a consume-once handoff starves the second reader, and a non-consuming
    cache needs the same bounded-eviction machinery as memoization anyway while
    splitting state across two modules and making correctness depend on the
    recognizer having run first. Approach A is one object, idempotent by
    construction, and robust to the recognizer being disabled by policy.

Time source & determinism
--------------------------
The window clock is ``request.requested_at`` (the edge-assigned, timezone-aware
timestamp already on every request), NOT wall-clock — so a window is a pure
function of the request stream and is reproducible in tests by setting
``requested_at``. Like any rate limiter, this signal is *deliberately* stateful:
the Nth identical action is treated differently from the 1st. That is the whole
point of a circuit-breaker and is consistent with Tex's other stateful signals
(session-scoped behavioural contracts). The PDP determinism fingerprint is
computed over content/policy/results, not over this overlay, so it is unaffected.

Maturity
--------
The *mechanism* (deterministic counting + monotone-lowering wiring) is
production-shaped. The default thresholds are ``research-early``: project-chosen
sane defaults, NOT lifted from any published calibration. Operators tune them via
the ``TEX_CADENCE_*`` environment variables; a real per-tenant calibration study
is owed.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, MutableMapping


# ── configuration ──────────────────────────────────────────────────────────


class CadenceLevel(Enum):
    """How far over budget one agent's cadence is. Strictly ordered, ascending."""

    CLEAR = "clear"
    SOFT = "soft"
    HARD = "hard"


@dataclass(frozen=True, slots=True)
class CadenceConfig:
    """
    Env-tunable thresholds for the action-cadence circuit-breaker.

    Defaults are deliberately high enough that ordinary human-paced agent traffic
    (a handful of actions in a window) never trips, and only an autonomous burst
    does. They are ``research-early`` — sane, not calibrated.

    Both dimensions are measured every window:
      * ``*_actions`` — action *rate*: number of distinct actions in the window.
      * ``*_fanout``  — *branching*: distinct targets (recipients / tools / MCP
        servers / declared targets) the agent touched in the window.

    Crossing EITHER soft budget → SOFT; crossing EITHER hard threshold → HARD.
    ``hard_* >= soft_*`` is enforced by ``from_env`` so the breaker can never be
    configured to FORBID before it would ABSTAIN.
    """

    enabled: bool = True
    window_seconds: float = 10.0
    soft_actions: int = 8
    hard_actions: int = 20
    soft_fanout: int = 6
    hard_fanout: int = 15
    # Per-key window hard cap (memory bound; far above any real hard threshold so
    # it never changes a verdict — it only stops a pathological key from growing
    # without limit).
    max_window_entries: int = 1024
    # LRU caps so the in-memory state is bounded regardless of cardinality.
    max_tracked_keys: int = 8192
    max_memo_entries: int = 4096

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None
    ) -> "CadenceConfig":
        """
        Build a config from ``TEX_CADENCE_*`` env vars, falling back to a sane
        default for any var that is missing or malformed (fail-safe: a bad env
        value never crashes the gate and never makes the breaker more aggressive
        than its defaults in a way that could over-block).
        """
        e = os.environ if env is None else env
        d = cls()

        enabled = _env_bool(e, "TEX_CADENCE_ENABLED", d.enabled)
        window_seconds = _env_float(e, "TEX_CADENCE_WINDOW_SECONDS", d.window_seconds)
        soft_actions = _env_int(e, "TEX_CADENCE_SOFT_ACTIONS", d.soft_actions)
        hard_actions = _env_int(e, "TEX_CADENCE_HARD_ACTIONS", d.hard_actions)
        soft_fanout = _env_int(e, "TEX_CADENCE_SOFT_FANOUT", d.soft_fanout)
        hard_fanout = _env_int(e, "TEX_CADENCE_HARD_FANOUT", d.hard_fanout)

        # Enforce hard >= soft on each axis. A misconfigured env that inverts them
        # would otherwise FORBID before it ABSTAINs (over-blocking); clamp the hard
        # threshold up to the soft budget instead of trusting the inversion.
        hard_actions = max(hard_actions, soft_actions)
        hard_fanout = max(hard_fanout, soft_fanout)

        return cls(
            enabled=enabled,
            window_seconds=window_seconds,
            soft_actions=soft_actions,
            hard_actions=hard_actions,
            soft_fanout=soft_fanout,
            hard_fanout=hard_fanout,
            max_window_entries=d.max_window_entries,
            max_tracked_keys=d.max_tracked_keys,
            max_memo_entries=d.max_memo_entries,
        )

    def classify(self, *, action_count: int, distinct_targets: int) -> CadenceLevel:
        """Pure classification of one window's stats. HARD is checked first so a
        burst that clears both thresholds reports HARD, never SOFT."""
        if action_count >= self.hard_actions or distinct_targets >= self.hard_fanout:
            return CadenceLevel.HARD
        if action_count >= self.soft_actions or distinct_targets >= self.soft_fanout:
            return CadenceLevel.SOFT
        return CadenceLevel.CLEAR


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _env_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0.0 else default


# ── assessment ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CadenceAssessment:
    """The cadence verdict-influence for one evaluated action.

    ``tracked`` is False when the request carries no agent identity to key on — in
    that case the breaker is a no-op (level is always CLEAR). ``reason`` and
    ``counterfactual`` are populated only when a budget is crossed; they are what
    gets sealed into the verdict.
    """

    level: CadenceLevel
    tracked: bool
    key: str
    action_count: int
    distinct_targets: int
    window_seconds: float
    soft_actions: int
    hard_actions: int
    soft_fanout: int
    hard_fanout: int
    reason: str
    counterfactual: str

    @property
    def fired(self) -> bool:
        return self.level is not CadenceLevel.CLEAR

    def metadata(self) -> dict[str, str | int | float | bool]:
        """Window stats flattened for a ``Finding.metadata`` block (typed values
        only, per the Finding schema)."""
        return {
            "cadence_level": self.level.value,
            "agent_key": self.key,
            "action_count": self.action_count,
            "distinct_targets": self.distinct_targets,
            "window_seconds": self.window_seconds,
            "soft_actions": self.soft_actions,
            "hard_actions": self.hard_actions,
            "soft_fanout": self.soft_fanout,
            "hard_fanout": self.hard_fanout,
            "counterfactual": self.counterfactual,
            "tier": "action_cadence",
        }


def _untracked_assessment(config: CadenceConfig) -> CadenceAssessment:
    return CadenceAssessment(
        level=CadenceLevel.CLEAR,
        tracked=False,
        key="",
        action_count=0,
        distinct_targets=0,
        window_seconds=config.window_seconds,
        soft_actions=config.soft_actions,
        hard_actions=config.hard_actions,
        soft_fanout=config.soft_fanout,
        hard_fanout=config.hard_fanout,
        reason="",
        counterfactual="",
    )


# ── the tracker ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _WindowEntry:
    ts: float
    request_id: str
    targets: frozenset[str]


class ActionCadenceTracker:
    """
    Sliding-window action-cadence tracker keyed by (tenant, agent identity).

    Thread-safe and request_id-idempotent. ``assess`` is the only entry point: the
    first call for a given request_id observes the action (prunes the window to
    ``window_seconds``, inserts this action once, classifies); subsequent calls for
    the same request_id return the identical memoized assessment without
    re-counting. State is bounded by LRU caps on tracked keys, per-key window
    length, and the memo.
    """

    __slots__ = ("_config", "_windows", "_memo", "_lock")

    def __init__(self, config: CadenceConfig | None = None) -> None:
        self._config = config or CadenceConfig()
        # key -> deque[_WindowEntry], LRU-ordered by most-recent access.
        self._windows: "OrderedDict[str, deque[_WindowEntry]]" = OrderedDict()
        # request_id -> CadenceAssessment, LRU-ordered, bounded.
        self._memo: "OrderedDict[str, CadenceAssessment]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def config(self) -> CadenceConfig:
        return self._config

    def assess(self, request: Any) -> CadenceAssessment:
        """Observe-once-and-classify the action carried by ``request``.

        Returns an untracked CLEAR assessment when the breaker is disabled or the
        request has no agent identity to attribute the action to (so anonymous /
        agentless traffic can never be bucketed together into a false burst).
        """
        config = self._config
        if not config.enabled:
            return _untracked_assessment(config)

        request_id = _request_id_str(request)
        key = _derive_key(request)
        if key is None:
            return _untracked_assessment(config)

        targets = _derive_targets(request)
        now = _request_timestamp(request)

        with self._lock:
            if request_id and request_id in self._memo:
                self._memo.move_to_end(request_id)
                return self._memo[request_id]

            window = self._windows.get(key)
            if window is None:
                window = deque()
                self._windows[key] = window
            self._windows.move_to_end(key)

            # Prune entries that have fallen out of the sliding window. The window
            # is anchored at this request's timestamp (the edge clock).
            horizon = now - config.window_seconds
            while window and window[0].ts <= horizon:
                window.popleft()

            # Idempotent insert: never count the same request_id twice, even if the
            # memo evicted and we re-entered for it.
            if not any(entry.request_id == request_id for entry in window):
                window.append(_WindowEntry(ts=now, request_id=request_id, targets=targets))
                while len(window) > config.max_window_entries:
                    window.popleft()

            action_count = len(window)
            distinct_targets = len({t for entry in window for t in entry.targets})

            level = config.classify(
                action_count=action_count, distinct_targets=distinct_targets
            )
            assessment = _build_assessment(
                config=config,
                key=key,
                level=level,
                action_count=action_count,
                distinct_targets=distinct_targets,
            )

            if request_id:
                self._memo[request_id] = assessment
                self._memo.move_to_end(request_id)
                while len(self._memo) > config.max_memo_entries:
                    self._memo.popitem(last=False)

            # Evict least-recently-used keys to bound cardinality.
            while len(self._windows) > config.max_tracked_keys:
                self._windows.popitem(last=False)

            return assessment


def _build_assessment(
    *,
    config: CadenceConfig,
    key: str,
    level: CadenceLevel,
    action_count: int,
    distinct_targets: int,
) -> CadenceAssessment:
    reason = ""
    counterfactual = ""
    if level is not CadenceLevel.CLEAR:
        if level is CadenceLevel.HARD:
            band = (
                f"hard threshold (>= {config.hard_actions} actions or "
                f">= {config.hard_fanout} distinct targets)"
            )
            effect = "structural FORBID"
        else:
            band = (
                f"soft budget (>= {config.soft_actions} actions or "
                f">= {config.soft_fanout} distinct targets)"
            )
            effect = "held for review (PERMIT->ABSTAIN)"
        reason = (
            f"Action-cadence circuit-breaker: agent '{key}' issued {action_count} "
            f"action(s) across {distinct_targets} distinct target(s) within the last "
            f"{config.window_seconds:g}s window, crossing the {band} — {effect}. "
            "Machine-speed action cadence is a deterministic, paraphrase-proof "
            "signal of autonomous-attack fan-out (Anthropic Nov-2025 disclosure)."
        )
        counterfactual = (
            f"Had this agent stayed within the soft budget "
            f"(< {config.soft_actions} actions and < {config.soft_fanout} distinct "
            f"targets per {config.window_seconds:g}s), no cadence hold would have fired."
        )
    return CadenceAssessment(
        level=level,
        tracked=True,
        key=key,
        action_count=action_count,
        distinct_targets=distinct_targets,
        window_seconds=config.window_seconds,
        soft_actions=config.soft_actions,
        hard_actions=config.hard_actions,
        soft_fanout=config.soft_fanout,
        hard_fanout=config.hard_fanout,
        reason=reason,
        counterfactual=counterfactual,
    )


# ── request projection helpers (pure) ──────────────────────────────────────


def _request_id_str(request: Any) -> str:
    rid = getattr(request, "request_id", None)
    return str(rid) if rid is not None else ""


def _request_timestamp(request: Any) -> float:
    """Epoch seconds from the edge-assigned ``requested_at``. Falls back to 0.0 so
    a malformed request can never crash the breaker (it simply lands in one
    degenerate window bucket)."""
    requested_at = getattr(request, "requested_at", None)
    ts = getattr(requested_at, "timestamp", None)
    if callable(ts):
        try:
            return float(ts())
        except (TypeError, ValueError, OverflowError, OSError):
            return 0.0
    return 0.0


def _derive_key(request: Any) -> str | None:
    """(tenant, agent identity) → a stable string key, or None when the request
    carries no agent identity (then the action is not attributable to an agent and
    the breaker stays a no-op rather than risk bucketing unrelated traffic).
    """
    tenant = "default"
    agent_part: str | None = None

    identity = getattr(request, "agent_identity", None)
    if identity is not None:
        tenant = getattr(identity, "tenant_id", None) or "default"
        if getattr(identity, "agent_id", None) is not None:
            agent_part = f"aid:{identity.agent_id}"
        elif getattr(identity, "external_agent_id", None):
            agent_part = f"ext:{identity.external_agent_id}"
        elif getattr(identity, "agent_name", None):
            agent_part = f"name:{identity.agent_name}"

    if agent_part is None:
        rid = getattr(request, "agent_id", None)
        if rid is not None:
            agent_part = f"aid:{rid}"

    if agent_part is None:
        return None
    return f"{tenant}|{agent_part}"


def _derive_targets(request: Any) -> frozenset[str]:
    """Distinct destinations/tools this one action touches — the fan-out atoms the
    window unions to measure branching: the recipient, any declared tools / MCP
    servers on the runtime identity, plus any explicit ``metadata['cadence_targets']``.
    """
    targets: set[str] = set()

    recipient = getattr(request, "recipient", None)
    if isinstance(recipient, str) and recipient.strip():
        targets.add(f"recipient:{recipient.strip().casefold()}")

    identity = getattr(request, "agent_identity", None)
    if identity is not None:
        for tool in getattr(identity, "tools", ()) or ():
            if isinstance(tool, str) and tool.strip():
                targets.add(f"tool:{tool.strip().casefold()}")
        for server in getattr(identity, "mcp_server_ids", ()) or ():
            if isinstance(server, str) and server.strip():
                targets.add(f"mcp:{server.strip().casefold()}")

    metadata = getattr(request, "metadata", None)
    if isinstance(metadata, Mapping):
        raw = metadata.get("cadence_targets")
        if isinstance(raw, (list, tuple, set, frozenset)):
            for item in raw:
                if isinstance(item, str) and item.strip():
                    targets.add(f"target:{item.strip().casefold()}")

    return frozenset(targets)


# ── module singleton (shared by recognizer, floor, and hold) ───────────────
#
# The recognizer (evidence + observation), the structural floor (HARD→FORBID),
# and the post-router hold (SOFT→ABSTAIN) must all read the SAME window state, so
# they share one process-level tracker. Operators wanting per-tenant isolation
# construct their own ActionCadenceTracker and inject it into the recognizer; the
# floor/hold read this singleton. Reset between tests via _reset_default_cadence_tracker.

_DEFAULT_TRACKER: ActionCadenceTracker | None = None
_DEFAULT_LOCK = threading.Lock()


def default_cadence_tracker() -> ActionCadenceTracker:
    """The process-wide tracker, lazily built from ``CadenceConfig.from_env`` on
    first use so env tuning at boot is honoured without a composition-root edit."""
    global _DEFAULT_TRACKER
    tracker = _DEFAULT_TRACKER
    if tracker is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_TRACKER is None:
                _DEFAULT_TRACKER = ActionCadenceTracker(CadenceConfig.from_env())
            tracker = _DEFAULT_TRACKER
    return tracker


def configure_default_cadence_tracker(config: CadenceConfig) -> ActionCadenceTracker:
    """Install a fresh singleton tracker with an explicit config. Used by the
    composition root and by integration tests that need known thresholds."""
    global _DEFAULT_TRACKER
    with _DEFAULT_LOCK:
        _DEFAULT_TRACKER = ActionCadenceTracker(config)
        return _DEFAULT_TRACKER


def _reset_default_cadence_tracker() -> None:
    """Drop the singleton so the next access rebuilds it from env. Test-only — the
    autouse conftest fixture calls this to isolate cadence state per test."""
    global _DEFAULT_TRACKER
    with _DEFAULT_LOCK:
        _DEFAULT_TRACKER = None


def assess_for_floor(request: Any) -> CadenceAssessment:
    """Assessment used by the structural floor. Reads the shared singleton so it
    sees the observation the recognizer already made for this request_id."""
    return default_cadence_tracker().assess(request)


# ── post-router soft hold (PERMIT → ABSTAIN), mirroring probguard ──────────


def apply_cadence_hold(*, base: Any, request: Any) -> Any:
    """Demote a routed PERMIT to ABSTAIN when the agent's cadence crosses the soft
    budget. The monotone-lowering guard below is the whole invariant: only a
    PERMIT is ever touched, and the only outcome is ABSTAIN.

    The HARD level is normally caught earlier by the structural floor (which
    short-circuits to FORBID before the router, so this hold never runs on it).
    Handling HARD here too is defense-in-depth: if the floor were ever bypassed,
    a HARD cadence still at least ABSTAINs from this soft rail — it can never be
    raised to FORBID from a hold (only the deterministic floor holds that
    authority), so the invariant is preserved either way.

    Returns the (possibly demoted) ``RoutingResult``, rebuilt immutably so the
    determinism fingerprint is preserved. Lazy engine imports avoid an import
    cycle through deterministic/ ← engine/router.
    """
    from tex.domain.verdict import Verdict

    # Monotone-lowering guard — only a PERMIT may be demoted. Everything else is
    # returned untouched: a cadence signal lowers, never raises.
    if base.verdict is not Verdict.PERMIT:
        return base

    assessment = default_cadence_tracker().assess(request)
    if not assessment.fired:
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reasons = list(base.reasons)
    reasons.append(assessment.reason)
    reasons.append(f"Counterfactual: {assessment.counterfactual}")

    flags = list(base.uncertainty_flags)
    flags.append(CADENCE_HOLD_FLAG)

    findings = list(base.findings)
    findings.append(
        Finding(
            source="deterministic.action_cadence",
            rule_name="action_cadence_soft_hold"
            if assessment.level is CadenceLevel.SOFT
            else "action_cadence_hard_hold",
            severity=Severity.WARNING
            if assessment.level is CadenceLevel.SOFT
            else Severity.CRITICAL,
            message=assessment.reason,
            metadata=assessment.metadata(),
        )
    )

    scores = dict(base.scores)
    scores["action_cadence"] = 1.0 if assessment.level is CadenceLevel.HARD else 0.5

    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=tuple(reasons),
        findings=tuple(findings),
        scores=scores,
        uncertainty_flags=tuple(flags),
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )


# Uncertainty flag the soft hold raises. Descriptive; engine.hold degrades
# gracefully on flags it has no tailored pivot for (the verdict is still ABSTAIN
# and a hold is still built).
CADENCE_HOLD_FLAG = "action_cadence_soft_budget_exceeded"


__all__ = [
    "CadenceLevel",
    "CadenceConfig",
    "CadenceAssessment",
    "ActionCadenceTracker",
    "default_cadence_tracker",
    "configure_default_cadence_tracker",
    "assess_for_floor",
    "apply_cadence_hold",
    "CADENCE_HOLD_FLAG",
]
