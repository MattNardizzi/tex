"""
Autonomous-attack action-cadence tracker + deterministic enforcement.

Why this exists (the rationale the task asks to be recorded inline)
-------------------------------------------------------------------
This answers the Anthropic November-2025 disclosure of the first publicly
documented large-scale AI-orchestrated cyber-attack: a frontier model was
driven to execute the great majority of an intrusion *autonomously* — issuing
requests at machine cadence, thousands of operations across a campaign, far
faster and wider than a human operator could.

The lesson Tex takes from that disclosure is **structural, not a detection
arms race.** We will not win by out-classifying the attacker's payloads with a
cleverer model — a stronger optimizer routes around any probabilistic detector
(Nasr et al., "The Attacker Moves Second," arXiv:2510.09023, 2025). What an
autonomous attack *cannot* hide — while remaining an autonomous attack — is its
**cadence**: the rate at which one identity emits actions, and how widely those
actions fan out (distinct recipients / tools / targets). Every agent action
already traverses this PDP, so the gate is *unavoidable*; we make it
*structural* by measuring cadence deterministically and letting a fixed budget,
never a model score, lower or floor the verdict. The gate need not outpace the
attacker — only be unavoidable and structural.

What this module is — and is NOT
--------------------------------
- It is a **deterministic** counter over a sliding time window keyed by
  ``(tenant, agent identity)``. Two budgets per window — an *action rate* and a
  *fan-out* (distinct targets) — each with a soft and a hard threshold.
  ``research-solid``: this is rate/fan-out accounting, not a claim of detecting
  intent.
- It is **NOT** a probabilistic risk score, and it must never be treated as one.
  A count crossing a fixed budget is a *fact about structure* (like a Datalog
  deny or an IFC type violation), which is precisely why it is allowed to fire
  the deterministic structural FORBID floor. The doctrine's bar — "a high
  *probabilistic* score must NOT fire the floor" — is respected: nothing here is
  probabilistic.

Trust invariants honored (CLAUDE.md):
  * **Signals only lower.** SOFT (over the soft budget) demotes a routed
    ``PERMIT`` → ``ABSTAIN`` and nothing else (``apply_attack_cadence_hold``).
    HARD (over the hard budget) forces ``FORBID`` via the structural floor.
    Neither path can raise a verdict toward PERMIT; HARD ⇒ FORBID only ever adds
    caution. Because ``hard >= soft`` is clamped at construction, HARD always
    implies SOFT — the ladder PERMIT→ABSTAIN→FORBID is monotone.
  * **Fail-safe / inert by default.** A request with no resolvable agent
    identity is never tracked (returns ``NORMAL``), so the entire content-only
    request path — every test and caller that sets no ``agent_id`` — is
    byte-for-byte unchanged.
  * **Determinism.** Cadence is genuinely *stateful and temporal* (that is the
    point — like a rate limiter). To keep "same request ⇒ same verdict" intact
    we (a) key the window clock off ``request.requested_at`` (never the wall
    clock) and (b) memoize the classification by ``request_id`` so a *replayed*
    request_id resolves to the identical tier it first produced. When a tier
    trips, the recognizer emits a finding that is folded into the determinism
    fingerprint, so a changed verdict always travels with a changed fingerprint.

State is in-memory (consistent with the default store model). The tracker is a
process-wide singleton; operators wanting per-tenant isolation construct their
own ``AttackCadenceTracker``. Reset for tests via ``reset_default_tracker()``.

This module imports nothing from ``tex.engine`` / ``tex.domain`` at module load
(it duck-types the request) so it can sit underneath the recognizer layer and
the structural floor without an import cycle; the routed-branch hold lazily
imports the engine types only when it actually demotes.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping


# Stable identifiers surfaced on the structural deny + findings so audit /
# replay can group by this defender without reparsing prose.
ATTACK_CADENCE_SPECIALIST = "attack_cadence"
ATTACK_CADENCE_CODE = "attack_cadence.autonomous_burst"

# Uncertainty flag the SOFT hold raises. Descriptive; engine.hold degrades
# gracefully on flags it has no tailored pivot for (verdict is still ABSTAIN).
ATTACK_CADENCE_FLAG = "autonomous_attack_cadence_soft_budget"


class CadenceTier(IntEnum):
    """Ordered cadence tiers. NORMAL < SOFT < HARD so ``max`` composes safely."""

    NORMAL = 0
    SOFT = 1
    HARD = 2


@dataclass(frozen=True, slots=True)
class CadenceConfig:
    """Env-configurable budgets. Sane defaults leave normal cadence untouched.

    Defaults (``research-early`` — chosen and verified in this repo, not lifted
    from a published calibration): a well-behaved agent rarely issues more than
    a handful of governed actions, to a handful of distinct targets, inside ten
    seconds; an autonomous attack loop blows past both. Tune per deployment via
    the ``TEX_CADENCE_*`` environment variables.

    The constructor clamps ``hard_*`` up to at least ``soft_*`` and the window
    to a positive value, so a fat-fingered env can never invert the ladder
    (which would break monotone tiering) — it can only widen or tighten it.
    """

    window_seconds: float = 10.0
    soft_actions: int = 8
    hard_actions: int = 20
    soft_fanout: int = 5
    hard_fanout: int = 12

    # Memory bounds (not safety thresholds): cap distinct tracked identities and
    # the events retained per identity, plus the per-request memo. All chosen so
    # the hard thresholds are reached long before any cap could mask a burst.
    max_tracked_keys: int = 4096
    max_events_per_key: int = 512
    request_memo_capacity: int = 4096

    def __post_init__(self) -> None:
        # Frozen dataclass: clamp via object.__setattr__ to keep the ladder sane.
        object.__setattr__(self, "window_seconds", max(1e-3, float(self.window_seconds)))
        object.__setattr__(self, "soft_actions", max(1, int(self.soft_actions)))
        object.__setattr__(self, "hard_actions", max(self.soft_actions, int(self.hard_actions)))
        object.__setattr__(self, "soft_fanout", max(1, int(self.soft_fanout)))
        object.__setattr__(self, "hard_fanout", max(self.soft_fanout, int(self.hard_fanout)))
        object.__setattr__(self, "max_tracked_keys", max(1, int(self.max_tracked_keys)))
        object.__setattr__(self, "max_events_per_key", max(1, int(self.max_events_per_key)))
        object.__setattr__(self, "request_memo_capacity", max(1, int(self.request_memo_capacity)))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "CadenceConfig":
        """Build from ``TEX_CADENCE_*`` env vars, falling back to the defaults."""
        e = env if env is not None else os.environ

        def _flt(name: str, default: float) -> float:
            try:
                return float(e[name])
            except (KeyError, TypeError, ValueError):
                return default

        def _int(name: str, default: int) -> int:
            try:
                return int(e[name])
            except (KeyError, TypeError, ValueError):
                return default

        return cls(
            window_seconds=_flt("TEX_CADENCE_WINDOW_SECONDS", 10.0),
            soft_actions=_int("TEX_CADENCE_SOFT_ACTIONS", 8),
            hard_actions=_int("TEX_CADENCE_HARD_ACTIONS", 20),
            soft_fanout=_int("TEX_CADENCE_SOFT_FANOUT", 5),
            hard_fanout=_int("TEX_CADENCE_HARD_FANOUT", 12),
        )


@dataclass(frozen=True, slots=True)
class CadenceObservation:
    """The deterministic result of recording one action into the window."""

    tier: CadenceTier
    tenant: str
    action_count: int
    fanout: int
    window_seconds: float
    soft_actions: int
    hard_actions: int
    soft_fanout: int
    hard_fanout: int
    triggered_by: tuple[str, ...]
    reason: str
    counterfactual: str

    @property
    def fired(self) -> bool:
        return self.tier is not CadenceTier.NORMAL


# A NORMAL observation for requests we do not track (no agent identity). Shared
# so the inert path allocates nothing.
_INERT = CadenceObservation(
    tier=CadenceTier.NORMAL,
    tenant="",
    action_count=0,
    fanout=0,
    window_seconds=0.0,
    soft_actions=0,
    hard_actions=0,
    soft_fanout=0,
    hard_fanout=0,
    triggered_by=(),
    reason="",
    counterfactual="",
)


def _identity_key(request: Any) -> tuple[str, str] | None:
    """Resolve ``(tenant, agent)`` for the request, or ``None`` if untrackable.

    Cadence is per-agent by definition. We require a concrete agent identity —
    a stable ``agent_id`` (preferred) or an ``agent_identity`` fingerprint.
    A bare ``session_id`` is intentionally NOT enough: it is too weak/common a
    handle to safely bucket distinct callers under one rate budget.
    """
    agent_id = getattr(request, "agent_id", None)
    identity = getattr(request, "agent_identity", None)

    tenant = "default"
    agent: str | None = None

    if identity is not None:
        tenant_val = getattr(identity, "tenant_id", None)
        if isinstance(tenant_val, str) and tenant_val.strip():
            tenant = tenant_val.strip().casefold()
        fingerprint = getattr(identity, "fingerprint_hash", None)
        if isinstance(fingerprint, str) and fingerprint:
            agent = fingerprint

    if agent_id is not None:
        # A stable agent_id is the strongest handle; let it own the bucket while
        # keeping the identity-derived tenant when one was supplied.
        agent = str(agent_id)

    if agent is None:
        return None
    return (tenant, agent)


def _request_ts(request: Any) -> float | None:
    """Window clock = ``request.requested_at`` (deterministic), as epoch seconds."""
    requested_at = getattr(request, "requested_at", None)
    if requested_at is None:
        return None
    try:
        return float(requested_at.timestamp())
    except (AttributeError, TypeError, ValueError, OSError):
        return None


def _request_id(request: Any) -> str | None:
    rid = getattr(request, "request_id", None)
    return str(rid) if rid is not None else None


def _fanout_tokens(request: Any) -> frozenset[str]:
    """Distinct fan-out tokens this single action touches.

    Union across the window measures branching/fan-out. We count distinct
    recipients, tools, MCP servers, and explicit target hints. An attack that
    hammers ONE endpoint trips the *rate* budget; one that sprays MANY trips the
    *fan-out* budget — the two budgets cover the two shapes of the same loop.
    """
    tokens: set[str] = set()

    recipient = getattr(request, "recipient", None)
    if isinstance(recipient, str) and recipient.strip():
        tokens.add(f"recipient:{recipient.strip().casefold()}")

    identity = getattr(request, "agent_identity", None)
    if identity is not None:
        for tool in getattr(identity, "tools", ()) or ():
            if isinstance(tool, str) and tool.strip():
                tokens.add(f"tool:{tool.strip().casefold()}")
        for mcp in getattr(identity, "mcp_server_ids", ()) or ():
            if isinstance(mcp, str) and mcp.strip():
                tokens.add(f"mcp:{mcp.strip().casefold()}")

    metadata = getattr(request, "metadata", None)
    if isinstance(metadata, Mapping):
        raw_targets = metadata.get("cadence_targets")
        candidates: list[Any] = []
        if isinstance(raw_targets, str):
            candidates = [raw_targets]
        elif isinstance(raw_targets, (list, tuple, set, frozenset)):
            candidates = list(raw_targets)
        for target in candidates:
            if isinstance(target, str) and target.strip():
                tokens.add(f"target:{target.strip().casefold()}")

    return frozenset(tokens)


class AttackCadenceTracker:
    """In-memory sliding-window cadence tracker keyed by ``(tenant, agent)``.

    Thread-safe. ``observe`` is idempotent per ``request_id`` (records the action
    exactly once however many surfaces — recognizer, structural floor, soft hold
    — consult it within one evaluation, and yields a stable result on replay).
    """

    __slots__ = ("_config", "_events", "_memo", "_lock")

    def __init__(self, config: CadenceConfig | None = None) -> None:
        self._config = config or CadenceConfig.from_env()
        # key -> deque of (timestamp_seconds, fanout_tokens)
        self._events: "OrderedDict[str, deque[tuple[float, frozenset[str]]]]" = OrderedDict()
        # request_id -> memoized observation (idempotency + stable replay)
        self._memo: "OrderedDict[str, CadenceObservation]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def config(self) -> CadenceConfig:
        return self._config

    def observe(self, request: Any) -> CadenceObservation:
        """Record ``request``'s action into its window and classify the cadence.

        Idempotent per ``request_id``: the first call records + classifies and
        caches; later calls (and replays) return the cached observation without
        advancing the window. Requests with no resolvable agent identity are
        inert (``NORMAL``, never recorded).
        """
        rid = _request_id(request)
        with self._lock:
            if rid is not None:
                cached = self._memo.get(rid)
                if cached is not None:
                    self._memo.move_to_end(rid)
                    return cached

            observation = self._record_locked(request)

            if rid is not None:
                self._memo[rid] = observation
                while len(self._memo) > self._config.request_memo_capacity:
                    self._memo.popitem(last=False)
            return observation

    def _record_locked(self, request: Any) -> CadenceObservation:
        key_parts = _identity_key(request)
        now = _request_ts(request)
        if key_parts is None or now is None:
            return _INERT

        tenant, agent = key_parts
        key = f"{tenant}\x1f{agent}"
        cfg = self._config

        events = self._events.get(key)
        if events is None:
            events = deque()
            self._events[key] = events
        self._events.move_to_end(key)

        events.append((now, _fanout_tokens(request)))

        # Drop events that fell out of the trailing window. ``now`` is this
        # request's own timestamp, so the action counts toward its own window.
        cutoff = now - cfg.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()
        # Hard memory bound (never reached before the hard threshold fires).
        while len(events) > cfg.max_events_per_key:
            events.popleft()

        # Count rate + distinct fan-out over [now - window, now].
        action_count = 0
        distinct: set[str] = set()
        for ts, tokens in events:
            if ts > now:
                # A future-dated event (clock skew / out-of-order replay) is
                # retained but not counted for THIS now.
                continue
            action_count += 1
            distinct.update(tokens)
        fanout = len(distinct)

        # Evict least-recently-used identities to bound memory.
        while len(self._events) > cfg.max_tracked_keys:
            self._events.popitem(last=False)

        tier, triggered_by = _classify(action_count, fanout, cfg)
        reason, counterfactual = _describe(
            tier=tier,
            triggered_by=triggered_by,
            action_count=action_count,
            fanout=fanout,
            cfg=cfg,
        )
        return CadenceObservation(
            tier=tier,
            tenant=tenant,
            action_count=action_count,
            fanout=fanout,
            window_seconds=cfg.window_seconds,
            soft_actions=cfg.soft_actions,
            hard_actions=cfg.hard_actions,
            soft_fanout=cfg.soft_fanout,
            hard_fanout=cfg.hard_fanout,
            triggered_by=triggered_by,
            reason=reason,
            counterfactual=counterfactual,
        )


def _classify(
    action_count: int, fanout: int, cfg: CadenceConfig
) -> tuple[CadenceTier, tuple[str, ...]]:
    """Map (rate, fan-out) to a tier. HARD implies SOFT because hard >= soft."""
    hard_axes: list[str] = []
    if action_count >= cfg.hard_actions:
        hard_axes.append("action_rate")
    if fanout >= cfg.hard_fanout:
        hard_axes.append("fanout")
    if hard_axes:
        return CadenceTier.HARD, tuple(hard_axes)

    soft_axes: list[str] = []
    if action_count >= cfg.soft_actions:
        soft_axes.append("action_rate")
    if fanout >= cfg.soft_fanout:
        soft_axes.append("fanout")
    if soft_axes:
        return CadenceTier.SOFT, tuple(soft_axes)

    return CadenceTier.NORMAL, ()


def _describe(
    *,
    tier: CadenceTier,
    triggered_by: tuple[str, ...],
    action_count: int,
    fanout: int,
    cfg: CadenceConfig,
) -> tuple[str, str]:
    """Build the human-readable trigger reason + counterfactual to seal."""
    if tier is CadenceTier.NORMAL:
        return "", ""

    label = "hard" if tier is CadenceTier.HARD else "soft"
    soft_a, hard_a = cfg.soft_actions, cfg.hard_actions
    soft_f, hard_f = cfg.soft_fanout, cfg.hard_fanout
    rate_budget = hard_a if tier is CadenceTier.HARD else soft_a
    fan_budget = hard_f if tier is CadenceTier.HARD else soft_f

    axes = " + ".join(triggered_by)
    reason = (
        f"Autonomous-attack cadence {label} budget exceeded ({axes}): "
        f"{action_count} action(s) and fan-out {fanout} distinct target(s) "
        f"within a {cfg.window_seconds:g}s window for one (tenant, agent) "
        f"[rate budget {rate_budget}, fan-out budget {fan_budget}]. "
        + (
            "Deterministic structural FORBID — cadence is a structural fact, "
            "not a model score."
            if tier is CadenceTier.HARD
            else "Holding for review (PERMIT→ABSTAIN)."
        )
    )
    # The counterfactual: the smallest change that would clear THIS tier.
    needs: list[str] = []
    if "action_rate" in triggered_by:
        needs.append(f"action rate below {rate_budget}/{cfg.window_seconds:g}s")
    if "fanout" in triggered_by:
        needs.append(f"fan-out below {fan_budget} distinct targets")
    counterfactual = (
        "Verdict would not have been "
        + ("FORBID" if tier is CadenceTier.HARD else "ABSTAIN")
        + " for this agent had its windowed "
        + " and ".join(needs)
        + "."
    )
    return reason, counterfactual


# ── process-wide singleton + test hooks ────────────────────────────────────

_DEFAULT_TRACKER: AttackCadenceTracker | None = None
_DEFAULT_LOCK = threading.Lock()


def default_tracker() -> AttackCadenceTracker:
    """Return the process-wide cadence tracker (lazily built from env)."""
    global _DEFAULT_TRACKER
    tracker = _DEFAULT_TRACKER
    if tracker is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_TRACKER is None:
                _DEFAULT_TRACKER = AttackCadenceTracker()
            tracker = _DEFAULT_TRACKER
    return tracker


def observe(request: Any) -> CadenceObservation:
    """Record + classify ``request`` against the process-wide tracker."""
    return default_tracker().observe(request)


def set_default_tracker(tracker: AttackCadenceTracker) -> None:
    """Install a specific tracker as the process-wide singleton. Test/ops hook."""
    global _DEFAULT_TRACKER
    with _DEFAULT_LOCK:
        _DEFAULT_TRACKER = tracker


def reset_default_tracker(config: CadenceConfig | None = None) -> AttackCadenceTracker:
    """Replace the singleton with a fresh tracker. Test hook (clears all state)."""
    tracker = AttackCadenceTracker(config=config)
    set_default_tracker(tracker)
    return tracker


def attack_cadence_deny_reason(request: Any) -> CadenceObservation | None:
    """Return the observation iff this request is a HARD structural deny, else None.

    Consumed by the structural FORBID floor. Recording happens here too (via
    ``observe``); the per-request_id memo guarantees it is counted only once
    across the recognizer / floor / hold surfaces.
    """
    obs = observe(request)
    return obs if obs.tier is CadenceTier.HARD else None


def apply_attack_cadence_hold(*, base: Any, request: Any) -> Any:
    """Soft, monotone-lowering hold: a SOFT (or higher) cadence demotes PERMIT→ABSTAIN.

    Mirrors ``systemic.probguard.apply_predictive_holds`` /
    ``engine.risk_spine.apply_risk_spine``: it acts ONLY when the routed verdict
    is ``PERMIT`` and only ever produces ``ABSTAIN`` — never raises a verdict,
    never relaxes one, never fires the deterministic floor. On the live path a
    HARD cadence has already FORBidden pre-router, so this hold normally sees
    only SOFT; it still demotes a HARD-on-PERMIT defensively (e.g. if the floor
    were disabled), because ABSTAIN is strictly more cautious than PERMIT.

    Returns the (possibly demoted) ``RoutingResult``, rebuilt immutably so the
    determinism fingerprint is preserved.
    """
    from tex.domain.verdict import Verdict

    # The whole monotone-lowering invariant in one guard: only a PERMIT moves.
    if base.verdict is not Verdict.PERMIT:
        return base

    obs = observe(request)
    if obs.tier is CadenceTier.NORMAL:
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reasons = list(base.reasons) + [obs.reason, obs.counterfactual]
    flags = list(base.uncertainty_flags) + [ATTACK_CADENCE_FLAG]
    scores = dict(base.scores)
    # Surface a bounded telemetry axis (NOT a probability): how far into the
    # soft band this agent's windowed rate sits. Never consumed by fusion.
    denom = max(1, obs.hard_actions)
    scores["attack_cadence"] = max(0.0, min(1.0, obs.action_count / denom))

    findings = list(base.findings) + [
        Finding(
            source="deterministic.attack_cadence",
            rule_name="autonomous_attack_cadence",
            severity=Severity.WARNING,
            message=obs.reason,
            metadata=cadence_finding_metadata(obs, stage="soft_hold"),
        )
    ]

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


def cadence_finding_metadata(obs: CadenceObservation, *, stage: str) -> dict[str, str | int | float | bool]:
    """Structured, audit-grade window stats for a finding (sealed into the verdict)."""
    return {
        "tier": obs.tier.name.casefold(),
        "stage": stage,
        "action_count": obs.action_count,
        "fanout": obs.fanout,
        "window_seconds": obs.window_seconds,
        "soft_actions": obs.soft_actions,
        "hard_actions": obs.hard_actions,
        "soft_fanout": obs.soft_fanout,
        "hard_fanout": obs.hard_fanout,
        "triggered_by": ",".join(obs.triggered_by),
        "tenant": obs.tenant,
        "counterfactual": obs.counterfactual,
        "code": ATTACK_CADENCE_CODE,
    }


__all__ = [
    "ATTACK_CADENCE_SPECIALIST",
    "ATTACK_CADENCE_CODE",
    "ATTACK_CADENCE_FLAG",
    "CadenceTier",
    "CadenceConfig",
    "CadenceObservation",
    "AttackCadenceTracker",
    "default_tracker",
    "observe",
    "set_default_tracker",
    "reset_default_tracker",
    "attack_cadence_deny_reason",
    "apply_attack_cadence_hold",
    "cadence_finding_metadata",
]
