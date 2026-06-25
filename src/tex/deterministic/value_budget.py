"""
Ledgered value-class confidentiality budget — a stateful, cross-session,
class-metered structural-floor accumulator.

[Architecture: Layer 1 (deterministic recognizers) → Layer 4 (structural FORBID floor)]

Why this exists
---------------
``deterministic/cadence.py`` proved one structural idea: the gate does not need
to out-think an adversary's *content*, only to count a deterministic, paraphrase-
proof fact about its *behaviour* (action rate / fan-out) over a sliding window,
and fire the structural floor when a counted threshold is crossed. A cadence
window is, however, deliberately FORGETFUL — it slides, and it lives only in
process memory, so a restart resets it and an attacker who paces below the rate
limit pays nothing for *what* each action exfiltrates.

This module is cadence's twin for the orthogonal, *cumulative* question: not "how
fast is this agent acting" but "how much sensitive value has this lineage already
moved, summed across its whole life — including before the last restart." It is a
**confidentiality-class budget**:

  * The metered quantity is a **calibrated FIDES confidentiality-class weight**
    (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED → 0 / 1 / 4 / 8 by default).
    This is **class-aware, NOT byte-accurate**: it prices the *sensitivity class*
    of a value, not its information content. It is emphatically NOT "bits" or
    "min-entropy" — a RESTRICTED one-byte secret and a RESTRICTED megabyte both
    debit the same class weight. The weights are a deliberately coarse, ordered
    proxy chosen so a sequence of high-class releases trips the budget far sooner
    than an equal-count sequence of PUBLIC ones. Operators tune them.
  * The accumulator is **additive per (tenant, agent, lineage)** and the
    authoritative running total is anchored in the **sealed
    ``SealedFactLedger``** (``provenance/ledger.py``) via ``append_sequenced``,
    keyed on the lineage. That is what makes the budget **non-resettable**: a
    restart reloads the running total by replaying the sealed ledger, and a
    fork / replay of the lineage's receipts is detectable as a chain break or a
    sequence gap. In-process state is a fast cache; the ledger is the truth.
  * Above the configured budget ``B`` (``TEX_BUDGET_CONFIDENTIAL_MAX``), the
    over-budget condition feeds the deterministic structural FORBID floor
    (``specialists.structural_floor._budget_deny``) — the same authority a PCAS
    deny or an IFC type violation has. "Cumulative class-weight over budget" is a
    *proof over the sealed history* (we summed the sealed debits), never a
    probabilistic score, so it is allowed to fire the floor.

Two rails, both monotone-lowering (consistent with cadence):

  * **over budget → FORBID.** ``BudgetLevel.OVER`` feeds the structural floor.
  * **ledger load/verify failure → ABSTAIN.** If the authoritative state cannot
    be reloaded or its chain does not verify, the budget is *unknown*, and an
    unknown budget must never silently allow. ``apply_budget_hold`` demotes a
    routed PERMIT to ABSTAIN (the same PERMIT→ABSTAIN-only shape as
    ``apply_cadence_hold``). It is fail-closed: doubt resolves to caution.

Invariant discipline (CLAUDE.md rule 2 — sacred)
------------------------------------------------
A budget signal can only ever move a verdict toward caution. The FORBID authority
lives exclusively in the structural floor and fires only on a counted cumulative
total crossing ``B`` (a proof over sealed structure, never a score). The
verify-failure ABSTAIN acts only on a routed PERMIT and only yields ABSTAIN.
Neither path can relax a FORBID/ABSTAIN or manufacture a PERMIT.

Default-OFF
-----------
The whole mechanism is gated behind ``TEX_BUDGET_ENABLED``. With it unset the
tracker reports an untracked CLEAR assessment and the debit seam in
``commands/evaluate_action.py`` is skipped, so behaviour is bit-for-bit unchanged.

Maturity
--------
The *mechanism* (sealed cumulative accounting + monotone-lowering wiring) is
production-shaped. The class weights and the budget ``B`` are ``research-early``:
project-chosen, NOT lifted from a published calibration; a real per-tenant /
per-class study is owed, and the honest "class-aware, not byte-aware" edge above
bounds what the number means.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from tex.governance.private_data_exec.ifc.capability_compat import ConfidentialityLevel


# ── configuration ──────────────────────────────────────────────────────────


class BudgetLevel(Enum):
    """How the cumulative confidentiality-class total stands against the budget.

    Strictly ordered, ascending. ``DEGRADED`` is the unknown-state rail (the
    authoritative ledger could not be reloaded/verified) — it is NOT "over
    budget" but it must not silently allow, so it drives a PERMIT→ABSTAIN hold.
    """

    CLEAR = "clear"
    DEGRADED = "degraded"  # ledger load/verify failed → state unknown → ABSTAIN
    OVER = "over"          # cumulative class-weight crossed B → FORBID


# Default per-class debit weights. CLASS-AWARE, NOT byte-accurate (see module
# docstring): a coarse ordered proxy for the sensitivity *class* moved, never a
# count of bits or an entropy estimate. The super-linear step at CONFIDENTIAL is
# deliberate — a handful of high-class releases should trip the budget while a
# long run of PUBLIC actions never does (the "value-not-count" property).
_DEFAULT_CLASS_WEIGHTS: dict[ConfidentialityLevel, int] = {
    ConfidentialityLevel.PUBLIC: 0,
    ConfidentialityLevel.INTERNAL: 1,
    ConfidentialityLevel.CONFIDENTIAL: 4,
    ConfidentialityLevel.RESTRICTED: 8,
}


@dataclass(frozen=True, slots=True)
class BudgetConfig:
    """Env-tunable config for the ledgered confidentiality-class budget.

    ``max_confidential`` is the budget ``B`` — the maximum cumulative class
    weight one (tenant, agent, lineage) may move before the structural floor
    FORBIDs. The default is deliberately high enough that ordinary PUBLIC/INTERNAL
    traffic never trips, and only sustained high-class movement does.
    """

    enabled: bool = False
    max_confidential: int = 32
    # LRU caps so the in-memory cache is bounded regardless of cardinality.
    max_tracked_keys: int = 8192
    max_memo_entries: int = 4096

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "BudgetConfig":
        """Build a config from ``TEX_BUDGET_*`` env vars, falling back to a sane
        default for any var that is missing or malformed (fail-safe: a bad env
        value never crashes the gate)."""
        e = os.environ if env is None else env
        d = cls()
        return cls(
            enabled=_env_bool(e, "TEX_BUDGET_ENABLED", d.enabled),
            max_confidential=_env_int(
                e, "TEX_BUDGET_CONFIDENTIAL_MAX", d.max_confidential
            ),
            max_tracked_keys=d.max_tracked_keys,
            max_memo_entries=d.max_memo_entries,
        )

    def class_weight(self, level: ConfidentialityLevel) -> int:
        """The calibrated debit for one confidentiality class. Class-aware, not
        byte-aware (see module docstring)."""
        return _DEFAULT_CLASS_WEIGHTS.get(level, 0)


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


# ── assessment ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BudgetAssessment:
    """The budget verdict-influence for one evaluated action.

    ``tracked`` is False when the budget is disabled or the request carries no
    lineage to key on — then the budget is a no-op (CLEAR). ``debit`` is the
    class weight this action contributed; ``total`` is the cumulative class
    weight for the lineage *including* this action (or the reloaded total, on a
    pure read). ``reason``/``counterfactual`` are populated only when a rail
    fires; they are what gets sealed into the verdict.
    """

    level: BudgetLevel
    tracked: bool
    key: str
    debit: int
    total: int
    budget: int
    confidentiality_class: str
    reason: str
    counterfactual: str

    @property
    def fired(self) -> bool:
        return self.level is not BudgetLevel.CLEAR

    @property
    def over_budget(self) -> bool:
        return self.level is BudgetLevel.OVER

    @property
    def degraded(self) -> bool:
        return self.level is BudgetLevel.DEGRADED

    def metadata(self) -> dict[str, str | int | float | bool]:
        """Flattened for a ``Finding.metadata`` block (typed values only)."""
        return {
            "budget_level": self.level.value,
            "lineage_key": self.key,
            "class_debit": self.debit,
            "cumulative_total": self.total,
            "budget": self.budget,
            "confidentiality_class": self.confidentiality_class,
            "counterfactual": self.counterfactual,
            "tier": "value_class_budget",
        }


def _untracked_assessment(config: BudgetConfig) -> BudgetAssessment:
    return BudgetAssessment(
        level=BudgetLevel.CLEAR,
        tracked=False,
        key="",
        debit=0,
        total=0,
        budget=config.max_confidential,
        confidentiality_class=ConfidentialityLevel.PUBLIC.name,
        reason="",
        counterfactual="",
    )


# ── the lineage key + class derivation (pure) ───────────────────────────────


_BUDGET_METADATA_KEY = "value_budget"


def derive_lineage_key(request: Any) -> str | None:
    """(tenant, agent, lineage) → a stable string key, or None when the request
    carries no agent identity to attribute the cumulative movement to.

    The lineage component lets a caller scope the budget to a sub-stream (a task,
    a session, a data-flow lineage) via ``metadata['value_budget']['lineage']``;
    absent that, the agent itself is the lineage. Mirrors cadence's keying so the
    two share the same (tenant, agent) attribution rules.
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

    lineage = "default"
    block = _budget_block(request)
    if block is not None:
        raw = block.get("lineage")
        if isinstance(raw, str) and raw.strip():
            lineage = raw.strip().casefold()

    return f"{tenant}|{agent_part}|lin:{lineage}"


def _budget_block(request: Any) -> Mapping[str, Any] | None:
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    raw = metadata.get(_BUDGET_METADATA_KEY)
    if isinstance(raw, Mapping):
        return raw
    return None


def derive_confidentiality_class(request: Any) -> ConfidentialityLevel:
    """The confidentiality class this action moves, from
    ``metadata['value_budget']['confidentiality']``.

    Accepts a level *name* (``"RESTRICTED"``) or its ordinal (``3``). Defaults to
    ``PUBLIC`` (a zero-weight debit) when absent or unparseable — so an action
    that declares no value class costs nothing and can never trip the budget.
    """
    block = _budget_block(request)
    if block is None:
        return ConfidentialityLevel.PUBLIC
    raw = block.get("confidentiality")
    if isinstance(raw, ConfidentialityLevel):
        return raw
    if isinstance(raw, bool):
        return ConfidentialityLevel.PUBLIC
    if isinstance(raw, int):
        try:
            return ConfidentialityLevel(raw)
        except ValueError:
            return ConfidentialityLevel.PUBLIC
    if isinstance(raw, str):
        token = raw.strip().upper()
        try:
            return ConfidentialityLevel[token]
        except KeyError:
            return ConfidentialityLevel.PUBLIC
    return ConfidentialityLevel.PUBLIC


def _request_id_str(request: Any) -> str:
    rid = getattr(request, "request_id", None)
    return str(rid) if rid is not None else ""


# ── the tracker ────────────────────────────────────────────────────────────


class ValueClassBudgetTracker:
    """
    Cumulative confidentiality-class budget keyed by (tenant, agent, lineage).

    Twin of ``ActionCadenceTracker``: thread-safe and request_id-idempotent, with
    LRU-bounded in-memory state. The DIFFERENCE from cadence is the source of
    truth. Cadence's window IS the state; here the in-memory total is only a
    cache — the authoritative cumulative total lives in the sealed
    ``SealedFactLedger`` (one ``append_sequenced`` per debit, keyed on the
    lineage). ``ledger`` is injected; when present, ``observe`` seals each debit
    and the running total reloads from the ledger on a cold key (so a process
    restart cannot reset the budget). When ``ledger is None`` the tracker still
    accumulates in memory (used by the pure-mechanism tests), but offers no
    cross-restart guarantee.

    Two entry points:
      * ``observe`` — the per-action debit seam (called once from
        ``evaluate_action``): derive the class weight, reload-or-read the
        lineage's sealed total, add this debit, seal the new total, classify.
      * ``peek`` — a pure READ for the structural floor / hold: returns the last
        observed assessment for this request_id, or reads the current sealed
        total without debiting. The floor must not double-count.
    """

    __slots__ = ("_config", "_totals", "_memo", "_ledger", "_lock")

    def __init__(
        self,
        config: BudgetConfig | None = None,
        *,
        ledger: Any | None = None,
    ) -> None:
        self._config = config or BudgetConfig()
        # lineage key -> cumulative class weight (the in-memory cache).
        self._totals: "OrderedDict[str, int]" = OrderedDict()
        # request_id -> BudgetAssessment, LRU-ordered, bounded.
        self._memo: "OrderedDict[str, BudgetAssessment]" = OrderedDict()
        self._ledger = ledger
        self._lock = threading.RLock()

    @property
    def config(self) -> BudgetConfig:
        return self._config

    # -------------------------------------------------------------- read
    def _reload_total(self, key: str) -> int | None:
        """Authoritative cumulative total for ``key`` from the sealed ledger.

        Replays the lineage's sealed BUDGET receipts and returns the highest
        sealed ``running_total``. Returns ``None`` (→ DEGRADED) if the chain does
        not verify or a sequence gap is detected — an unknown budget, never a
        silent zero. With no ledger wired, returns the in-memory cache.
        """
        ledger = self._ledger
        if ledger is None:
            return self._totals.get(key, 0)

        try:
            chain = ledger.verify_chain()
            if not chain.get("intact", False):
                return None
            gaps = ledger.verify_no_gaps()
            # A gap/duplicate specifically for THIS lineage is a fork/replay.
            if key in gaps.get("gaps", {}) or key in gaps.get("duplicates", {}):
                return None
            records = ledger.list_for_identity(key)
        except Exception:  # noqa: BLE001 — any ledger failure → unknown → ABSTAIN
            return None

        total = 0
        for rec in records:
            detail = getattr(rec.fact, "detail", None)
            if not isinstance(detail, Mapping):
                continue
            running = detail.get("running_total")
            if isinstance(running, int) and running > total:
                total = running
        return total

    def peek(self, request: Any) -> BudgetAssessment:
        """Pure read for the floor/hold — never debits. Returns the memoized
        assessment for this request_id if ``observe`` already ran for it;
        otherwise reads the current sealed total and classifies without adding."""
        config = self._config
        if not config.enabled:
            return _untracked_assessment(config)

        request_id = _request_id_str(request)
        key = derive_lineage_key(request)
        if key is None:
            return _untracked_assessment(config)

        with self._lock:
            if request_id and request_id in self._memo:
                self._memo.move_to_end(request_id)
                return self._memo[request_id]

            reloaded = self._reload_total(key)
            level_class = derive_confidentiality_class(request)
            if reloaded is None:
                return _build_degraded(config=config, key=key, level_class=level_class)
            return _build_assessment(
                config=config,
                key=key,
                debit=0,
                total=reloaded,
                level_class=level_class,
            )

    # -------------------------------------------------------------- write
    def observe(self, request: Any) -> BudgetAssessment:
        """The per-action debit seam. Idempotent per request_id: the first call
        derives the class weight, reloads the lineage's sealed total, adds this
        debit, seals the new total as a ``SealedFact(BUDGET)`` via
        ``append_sequenced(identity_key=lineage)``, classifies, and memoizes;
        subsequent calls for the same request_id return the memoized assessment
        without re-debiting (so the action is metered exactly once)."""
        config = self._config
        if not config.enabled:
            return _untracked_assessment(config)

        request_id = _request_id_str(request)
        key = derive_lineage_key(request)
        if key is None:
            return _untracked_assessment(config)

        level_class = derive_confidentiality_class(request)
        debit = config.class_weight(level_class)

        with self._lock:
            if request_id and request_id in self._memo:
                self._memo.move_to_end(request_id)
                return self._memo[request_id]

            reloaded = self._reload_total(key)
            if reloaded is None:
                # Authoritative state unknown — fail closed to DEGRADED (ABSTAIN).
                # Do NOT seal a debit on top of an unverifiable chain.
                assessment = _build_degraded(
                    config=config, key=key, level_class=level_class
                )
                self._memoize(request_id, assessment)
                return assessment

            new_total = reloaded + debit
            self._seal_debit(
                key=key,
                request_id=request_id,
                debit=debit,
                running_total=new_total,
                level_class=level_class,
            )
            self._totals[key] = new_total
            self._totals.move_to_end(key)
            while len(self._totals) > config.max_tracked_keys:
                self._totals.popitem(last=False)

            assessment = _build_assessment(
                config=config,
                key=key,
                debit=debit,
                total=new_total,
                level_class=level_class,
            )
            self._memoize(request_id, assessment)
            return assessment

    def _memoize(self, request_id: str, assessment: BudgetAssessment) -> None:
        if not request_id:
            return
        self._memo[request_id] = assessment
        self._memo.move_to_end(request_id)
        while len(self._memo) > self._config.max_memo_entries:
            self._memo.popitem(last=False)

    def _seal_debit(
        self,
        *,
        key: str,
        request_id: str,
        debit: int,
        running_total: int,
        level_class: ConfidentialityLevel,
    ) -> None:
        """Persist the authoritative new total as a sealed BUDGET fact, sequenced
        per lineage so a deletion/fork is detectable. No-op when no ledger is
        wired (the pure-mechanism path)."""
        ledger = self._ledger
        if ledger is None:
            return
        from tex.domain.evidence import EvidenceMaturity
        from tex.provenance.models import SealedFact, SealedFactKind

        fact = SealedFact(
            kind=SealedFactKind.BUDGET,
            subject_id=request_id or None,
            claim=(
                f"Value-class budget debit: lineage '{key}' moved a "
                f"{level_class.name} value (class weight {debit}); cumulative "
                f"confidentiality-class total now {running_total} "
                f"(budget {self._config.max_confidential})."
            ),
            maturity=EvidenceMaturity.RESEARCH_EARLY,
            detail={
                "lineage_key": key,
                "class_debit": debit,
                "running_total": running_total,
                "confidentiality_class": level_class.name,
                "budget": self._config.max_confidential,
            },
        )
        ledger.append_sequenced(fact, identity_key=key)


def _build_degraded(
    *, config: BudgetConfig, key: str, level_class: ConfidentialityLevel
) -> BudgetAssessment:
    reason = (
        f"Value-class budget: authoritative cumulative total for lineage '{key}' "
        "could not be reloaded/verified from the sealed ledger (chain break, "
        "sequence gap, or read failure). The budget is UNKNOWN — fail-closed to "
        "ABSTAIN (an unknown budget must never silently allow)."
    )
    counterfactual = (
        "Had the sealed budget chain verified, the action would have been "
        "metered against the cumulative confidentiality-class total."
    )
    return BudgetAssessment(
        level=BudgetLevel.DEGRADED,
        tracked=True,
        key=key,
        debit=0,
        total=0,
        budget=config.max_confidential,
        confidentiality_class=level_class.name,
        reason=reason,
        counterfactual=counterfactual,
    )


def _build_assessment(
    *,
    config: BudgetConfig,
    key: str,
    debit: int,
    total: int,
    level_class: ConfidentialityLevel,
) -> BudgetAssessment:
    over = total > config.max_confidential
    level = BudgetLevel.OVER if over else BudgetLevel.CLEAR
    reason = ""
    counterfactual = ""
    if over:
        reason = (
            f"Ledgered value-class budget: lineage '{key}' has moved a cumulative "
            f"confidentiality-class weight of {total}, exceeding the budget "
            f"{config.max_confidential} (this action's {level_class.name} debit "
            f"was {debit}). The total is summed over the lineage's SEALED history "
            "(reloads across restarts), so this is a proof over structure — a "
            "structural FORBID, never a probabilistic score."
        )
        counterfactual = (
            f"Had this lineage's cumulative confidentiality-class total stayed at "
            f"or below {config.max_confidential}, no budget FORBID would have fired."
        )
    return BudgetAssessment(
        level=level,
        tracked=True,
        key=key,
        debit=debit,
        total=total,
        budget=config.max_confidential,
        confidentiality_class=level_class.name,
        reason=reason,
        counterfactual=counterfactual,
    )


# ── module singleton (shared by the debit seam, the floor, and the hold) ────
#
# The debit seam (``evaluate_action``), the structural floor (OVER→FORBID), and
# the post-router hold (DEGRADED→ABSTAIN) must read the SAME cumulative state, so
# they share one process-level tracker. The ledger is injected once at boot (the
# composition root) so the tracker seals into the same sealed-fact ledger the
# rest of Tex writes. Reset between tests via _reset_default_budget_tracker.

_DEFAULT_TRACKER: ValueClassBudgetTracker | None = None
_DEFAULT_LOCK = threading.Lock()


def default_budget_tracker() -> ValueClassBudgetTracker:
    """The process-wide tracker, lazily built from ``BudgetConfig.from_env`` on
    first use. Built WITHOUT a ledger by default; the composition root installs a
    ledger-backed tracker via ``configure_default_budget_tracker`` when sealing is
    desired. With no ledger the cross-restart guarantee is absent (documented)."""
    global _DEFAULT_TRACKER
    tracker = _DEFAULT_TRACKER
    if tracker is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_TRACKER is None:
                _DEFAULT_TRACKER = ValueClassBudgetTracker(BudgetConfig.from_env())
            tracker = _DEFAULT_TRACKER
    return tracker


def configure_default_budget_tracker(
    config: BudgetConfig, *, ledger: Any | None = None
) -> ValueClassBudgetTracker:
    """Install a fresh singleton tracker with an explicit config + ledger. Used by
    the composition root and by integration tests that need known thresholds and a
    real sealed ledger."""
    global _DEFAULT_TRACKER
    with _DEFAULT_LOCK:
        _DEFAULT_TRACKER = ValueClassBudgetTracker(config, ledger=ledger)
        return _DEFAULT_TRACKER


def _reset_default_budget_tracker() -> None:
    """Drop the singleton so the next access rebuilds it from env. Test-only — the
    autouse conftest fixture calls this to isolate budget state per test."""
    global _DEFAULT_TRACKER
    with _DEFAULT_LOCK:
        _DEFAULT_TRACKER = None


def observe_for_debit(request: Any) -> BudgetAssessment:
    """The per-action debit entry point used by ``evaluate_action``. Observes
    (seals) exactly once per request_id on the shared singleton."""
    return default_budget_tracker().observe(request)


def assess_for_floor(request: Any) -> BudgetAssessment:
    """Pure read used by the structural floor — never debits (the debit already
    happened at the ``evaluate_action`` seam). Reads the shared singleton so it
    sees the total ``observe`` already sealed for this request_id."""
    return default_budget_tracker().peek(request)


# ── post-router degraded hold (PERMIT → ABSTAIN), mirroring cadence ─────────


BUDGET_HOLD_FLAG = "value_budget_state_unverifiable"


def apply_budget_hold(*, base: Any, request: Any) -> Any:
    """Demote a routed PERMIT to ABSTAIN when the budget state is DEGRADED (the
    sealed authoritative total could not be reloaded/verified). Fail-closed: an
    unknown budget resolves to caution, never a silent allow.

    Monotone-lowering guard: only a PERMIT is ever touched, and the only outcome
    is ABSTAIN. The OVER level is handled earlier by the structural floor (FORBID,
    short-circuiting the router), so this hold only ever acts on DEGRADED here —
    but if the floor were ever bypassed, OVER would also ABSTAIN from this rail
    (it can never be raised to FORBID from a hold). Lazy engine imports avoid an
    import cycle.
    """
    from tex.domain.verdict import Verdict

    if base.verdict is not Verdict.PERMIT:
        return base

    assessment = default_budget_tracker().peek(request)
    if not assessment.fired:
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reasons = list(base.reasons)
    reasons.append(assessment.reason)
    reasons.append(f"Counterfactual: {assessment.counterfactual}")

    flags = list(base.uncertainty_flags)
    flags.append(BUDGET_HOLD_FLAG)

    findings = list(base.findings)
    findings.append(
        Finding(
            source="deterministic.value_budget",
            rule_name="value_budget_degraded_hold",
            severity=Severity.WARNING,
            message=assessment.reason,
            metadata=assessment.metadata(),
        )
    )

    scores = dict(base.scores)
    scores["value_budget"] = 0.5

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


__all__ = [
    "BudgetLevel",
    "BudgetConfig",
    "BudgetAssessment",
    "ValueClassBudgetTracker",
    "derive_lineage_key",
    "derive_confidentiality_class",
    "default_budget_tracker",
    "configure_default_budget_tracker",
    "observe_for_debit",
    "assess_for_floor",
    "apply_budget_hold",
    "BUDGET_HOLD_FLAG",
]
