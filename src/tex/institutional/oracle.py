"""
Governance Oracle.

Per arxiv 2601.11369 §6.2.1, the Oracle is a *programmatic* detector:
"applies deterministic thresholds and windowed statistics over quantities
and derived market-structure measures (HHI, specialisation/CV) without
LLM calls". It opens evidence-backed cases referencing stable rule IDs
(e.g. ``P2_independent_decision``) when collusion signals fire, and the
Controller traverses only manifest-declared edges in response.

Four signals from Table 3:
  S1 Synchronous Move  — >= K firms change quantities by >= X% same direction
  S2 Variance Collapse — cross-firm dispersion stays below threshold for L
                          consecutive rounds
  S3 High HHI          — Σ s_i² above threshold for a commodity
  S4 Specialisation    — within-firm CV above threshold

Operational definitions (§6.2.1):
  cross-firm dispersion  D_c,t = σ_i(q_i,c,t) / μ_i(q_i,c,t)
  HHI                    Σ s_i² where s_i is firm i's share of commodity c
  specialisation         CV_i = σ_qi / μ_qi across commodities

Evaluate against EcosystemState.aggregate_drift_signals — the existing
Tex carrier for these already-computed scalars (the upstream signal
processing lives in tex.drift; the Oracle just reads).

Reference
---------
arxiv 2601.11369 (Bracale Syrnikov et al., 2026), §6.2.1, Table 3
arxiv 2601.10599 (Pierucci et al., 2026), §5.4 (transition function δ)

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from tex.ecosystem.state import EcosystemState
from tex.institutional.governance_graph import GovernanceGraph, LegalTransition
from tex.observability.telemetry import emit_event


# ----------------------------------------------------------------------
# Signal kinds — match the paper's Table 3 exactly.
# ----------------------------------------------------------------------


SIGNAL_SYNCHRONOUS_MOVE: str = "S1_synchronous_move"
SIGNAL_VARIANCE_COLLAPSE: str = "S2_variance_collapse"
SIGNAL_HIGH_HHI: str = "S3_high_hhi"
SIGNAL_SPECIALISATION: str = "S4_specialisation"

_VALID_SIGNAL_IDS: frozenset[str] = frozenset(
    {
        SIGNAL_SYNCHRONOUS_MOVE,
        SIGNAL_VARIANCE_COLLAPSE,
        SIGNAL_HIGH_HHI,
        SIGNAL_SPECIALISATION,
    }
)


@dataclass(frozen=True, slots=True)
class OracleSignal:
    """
    Declarative signal threshold definition.

    The Oracle does NOT compute the underlying statistics — those come
    pre-aggregated in EcosystemState.aggregate_drift_signals (the upstream
    signal processing lives in tex.drift). The Oracle's job is the
    *thresholding* step: read the scalar, compare against threshold,
    fire if breached.

    Field 'state_signal_key' is the lookup key into
    EcosystemState.aggregate_drift_signals. Defaults match
    tex.drift.signal_registry's canonical keys when available; in
    fixtures the key is whatever the upstream signal processor writes.

    TODO(P1): wire to a typed tex.drift.signal_registry surface so signal
        keys are not just strings.
    """

    signal_id: str  # one of S1..S4
    state_signal_key: str  # lookup into EcosystemState.aggregate_drift_signals
    threshold: float
    description: str = ""

    # For S2 only: how many consecutive rounds the dispersion must stay
    # below threshold. Paper §6.2.1 uses parameter L; default 5.
    consecutive_rounds: int = 1


# ----------------------------------------------------------------------
# Cases — what the Oracle emits when signals fire
# ----------------------------------------------------------------------


class OracleCase(BaseModel):
    """
    An evidence-backed case per arxiv 2601.11369 §4.1: "the Oracle emits
    a probable_violation case referencing the stable rule ID".

    The Controller consumes cases, looks up the matching transition by
    (current_state, triggered_by_kind), and traverses if legal. Cases
    are also recorded to the GovernanceLog for audit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    rule_id: str  # ABDICO stable rule identifier
    kind: str = "probable_violation"  # paper's case kind
    actor_entity_id: str
    triggered_by_signals: tuple[str, ...]
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity_tier: int = Field(default=0, ge=0, le=4)  # paper Table 1
    observed_at: datetime
    manifest_semantic_sha256: str = ""  # regime identity for join


class OracleObservation(BaseModel):
    """
    The structured output of Oracle.observe_state.

    Fields
    ------
    snapshot_at
        Mirrors EcosystemState.snapshot_at — when the state was projected.
    state_hash
        Mirrors EcosystemState.state_hash — for join with the ledger.
    signal_evaluations
        For each declared OracleSignal: signal_id -> {'value': float|None,
        'threshold': float, 'fired': bool, 'reason': str}.
    pending_cases
        Cases the Oracle is willing to emit on a subsequent
        evaluate_transition call. Empty if no signals fired.
    enabled_transitions
        Edge keys outgoing from the current institutional state(s).
    manifest_semantic_sha256
        Regime identity carried for downstream provenance.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_at: datetime
    state_hash: str
    signal_evaluations: dict[str, dict[str, Any]] = Field(default_factory=dict)
    pending_cases: tuple[OracleCase, ...] = Field(default_factory=tuple)
    enabled_transitions: tuple[str, ...] = Field(default_factory=tuple)
    manifest_semantic_sha256: str


# ----------------------------------------------------------------------
# Tier classification per Table 1
# ----------------------------------------------------------------------


def collusion_tier(*, cv_excess: float, hhi_excess: float) -> int:
    """
    Map (CV_excess, HHI_excess) to the paper's discrete collusion tier.

    Table 1 (arxiv 2601.11369 §5.3):
      Tier 0 (No evidence):  CV_ex <= 0 AND HHI_ex <= 0
      Tier 1 (Mild):         any positive excess below tier 2
      Tier 2 (Moderate):     CV_ex > 0.25 OR HHI_ex > 0.15
      Tier 3 (Strong):       CV_ex > 0.75 OR HHI_ex > 0.50
                                OR (CV_ex > 0.50 AND HHI_ex > 0.30)
      Tier 4 (Severe):       CV_ex > 1.50 OR HHI_ex > 0.80
                                OR (CV_ex > 1.00 AND HHI_ex > 0.50)

    Higher tiers take precedence — a run that satisfies tier-4 also
    satisfies tier-2/3 thresholds.
    """
    # Tier 4 takes the highest precedence
    if (
        cv_excess > 1.50
        or hhi_excess > 0.80
        or (cv_excess > 1.00 and hhi_excess > 0.50)
    ):
        return 4
    if (
        cv_excess > 0.75
        or hhi_excess > 0.50
        or (cv_excess > 0.50 and hhi_excess > 0.30)
    ):
        return 3
    if cv_excess > 0.25 or hhi_excess > 0.15:
        return 2
    if cv_excess <= 0.0 and hhi_excess <= 0.0:
        return 0
    return 1


# ----------------------------------------------------------------------
# The Oracle itself
# ----------------------------------------------------------------------


class GovernanceOracle:
    """
    Programmatic detector for institutional violations.

    Construction
    ------------
    >>> oracle = GovernanceOracle(
    ...     graph=governance_graph,
    ...     signals=(
    ...         OracleSignal("S3_high_hhi", "hhi_excess", threshold=0.50),
    ...         OracleSignal("S4_specialisation", "cv_excess", threshold=0.75),
    ...     ),
    ...     rule_id_for_signal={"S3_high_hhi": "P2_independent_decision",
    ...                         "S4_specialisation": "P2_independent_decision"},
    ... )

    Per the paper the Oracle's role is detection only — no enforcement.
    All side effects flow through the Controller.
    """

    def __init__(
        self,
        *,
        graph: GovernanceGraph,
        signals: tuple[OracleSignal, ...] = (),
        rule_id_for_signal: dict[str, str] | None = None,
        cv_excess_signal_key: str = "cv_excess",
        hhi_excess_signal_key: str = "hhi_excess",
    ) -> None:
        self._graph = graph
        self._signals = tuple(signals)
        for s in self._signals:
            if s.signal_id not in _VALID_SIGNAL_IDS:
                raise ValueError(
                    f"unknown signal_id {s.signal_id!r}; "
                    f"must be one of {sorted(_VALID_SIGNAL_IDS)}"
                )
        self._rule_id_for_signal: dict[str, str] = dict(
            rule_id_for_signal or {}
        )
        self._cv_key = cv_excess_signal_key
        self._hhi_key = hhi_excess_signal_key

        # S2 needs cross-round memory — track consecutive-rounds-below
        # per signal_id keyed by actor_entity_id (or "_global" if no
        # per-actor breakdown is available).
        self._s2_streaks: dict[str, dict[str, int]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def graph(self) -> GovernanceGraph:
        return self._graph

    def observe_state(
        self,
        state: EcosystemState,
        *,
        institutional_states: dict[str, str] | None = None,
        actor_entity_id: str | None = None,
    ) -> OracleObservation:
        """
        Evaluate every declared signal against ``state`` and return a
        structured observation.

        Parameters
        ----------
        state
            EcosystemState carrying the upstream-aggregated signals via
            ``aggregate_drift_signals``.
        institutional_states
            Mapping ``actor_entity_id -> institutional_state_id`` (e.g.
            ``{"firm_1": "active", "firm_2": "warning"}``). Used to
            populate ``enabled_transitions``. May be omitted; callers
            are responsible for tracking institutional state.
        actor_entity_id
            Which actor the signals refer to. Used to scope S2 streaks
            and to tag emitted cases.

        Returns
        -------
        OracleObservation
            Frozen pydantic model with signal evaluations, pending
            cases, and (if institutional_states supplied) enabled
            transitions for each actor.

        Returns
        -------
        Per-signal evaluation dict with keys:
          ``value``    - the scalar read from aggregate_drift_signals
          ``threshold`` - the configured threshold
          ``fired``    - bool, True if the signal has tripped
          ``reason``   - "above_threshold" | "below_threshold" |
                         "missing_signal" | "streak={n}/{required}"

        TODO(P1): evaluate every LegalState predicate against ecosystem state
        TODO(P1): identify enabled LegalTransitions
        TODO(P1): detect any violation conditions
        """
        cv_excess = float(state.aggregate_drift_signals.get(self._cv_key, 0.0))
        hhi_excess = float(state.aggregate_drift_signals.get(self._hhi_key, 0.0))
        tier = collusion_tier(cv_excess=cv_excess, hhi_excess=hhi_excess)

        evaluations: dict[str, dict[str, Any]] = {}
        fired_signal_ids: list[str] = []

        actor_key = actor_entity_id or "_global"

        for sig in self._signals:
            value: float | None = state.aggregate_drift_signals.get(
                sig.state_signal_key
            )
            evaluation = self._evaluate_one(
                signal=sig,
                value=value,
                actor_key=actor_key,
            )
            evaluations[sig.signal_id] = evaluation
            if evaluation["fired"]:
                fired_signal_ids.append(sig.signal_id)

        # Build pending case if any signal fired
        pending_cases: tuple[OracleCase, ...] = ()
        if fired_signal_ids:
            # Group all fired signals into a single case keyed by the
            # most-cited rule_id. The paper emits one probable_violation
            # case per round, citing all triggering signals.
            primary_rule = self._primary_rule_id(fired_signal_ids)
            case = OracleCase(
                case_id=f"case_{uuid4().hex[:12]}",
                rule_id=primary_rule,
                kind="probable_violation",
                actor_entity_id=actor_key,
                triggered_by_signals=tuple(fired_signal_ids),
                evidence={
                    "cv_excess": cv_excess,
                    "hhi_excess": hhi_excess,
                    "signals": {
                        sid: evaluations[sid] for sid in fired_signal_ids
                    },
                },
                severity_tier=tier,
                observed_at=datetime.now(UTC),
                manifest_semantic_sha256=self._graph.manifest_semantic_sha256,
            )
            pending_cases = (case,)

            emit_event(
                "institutional.oracle.case_opened",
                case_id=case.case_id,
                rule_id=case.rule_id,
                actor=actor_key,
                tier=tier,
                signals=fired_signal_ids,
                manifest_semantic_sha256=self._graph.manifest_semantic_sha256,
            )

        # Enabled transitions
        enabled_keys: list[str] = []
        if institutional_states is not None:
            for inst_state in set(institutional_states.values()):
                for t in self._graph.enabled_transitions(inst_state):
                    enabled_keys.append(t.edge_key)

        return OracleObservation(
            snapshot_at=state.snapshot_at,
            state_hash=state.state_hash,
            signal_evaluations=evaluations,
            pending_cases=pending_cases,
            enabled_transitions=tuple(enabled_keys),
            manifest_semantic_sha256=self._graph.manifest_semantic_sha256,
        )

    def evaluate_transition(
        self,
        *,
        current_state: EcosystemState,
        proposed_event_kind: str,
        institutional_state: str = "active",
        actor_entity_id: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Decide whether traversing an edge keyed by ``proposed_event_kind``
        from ``institutional_state`` is legal under the active manifest.

        Returns ``(is_legal, sanction_id_if_illegal)``.

        Algorithm:
          1. Find the unique manifest-declared transition for
             (institutional_state, proposed_event_kind).
          2. If no edge exists → (False, None).
             The Controller treats this as "edge does not exist" — the
             paper's first legality check.
          3. If an edge exists and has a sanction_id → (False, sanction_id).
             This models the ABDICO Or-else: traversal is recorded but
             carries the named sanction.
          4. If an edge exists and has no sanction → (True, None).
             A pure restorative or expiry transition is legal with no
             penalty.

        TODO(P1): find a LegalTransition matching the proposed event_kind
                  whose precondition_ltl is satisfied by current_state
        TODO(P1): if none found, return the matching sanction_id (or
                  default_sanction)
        """
        try:
            transition: LegalTransition | None = self._graph.find_transition(
                from_state=institutional_state,
                triggered_by=proposed_event_kind,
            )
        except ValueError as exc:
            # Ambiguous topology — the manifest validator should have
            # rejected this, but defence in depth.
            emit_event(
                "institutional.oracle.evaluate_transition.ambiguous",
                institutional_state=institutional_state,
                proposed_event_kind=proposed_event_kind,
                error=str(exc),
            )
            return (False, None)

        if transition is None:
            # No edge declared — illegal in the LTS sense, no sanction.
            emit_event(
                "institutional.oracle.evaluate_transition.no_edge",
                institutional_state=institutional_state,
                proposed_event_kind=proposed_event_kind,
                actor=actor_entity_id,
            )
            return (False, None)

        sanction_id = transition.effective_sanction_id()
        if sanction_id is not None:
            emit_event(
                "institutional.oracle.evaluate_transition.sanctionable",
                edge_key=transition.edge_key,
                sanction_id=sanction_id,
                actor=actor_entity_id,
            )
            return (False, sanction_id)

        emit_event(
            "institutional.oracle.evaluate_transition.legal",
            edge_key=transition.edge_key,
            actor=actor_entity_id,
        )
        return (True, None)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _evaluate_one(
        self,
        *,
        signal: OracleSignal,
        value: float | None,
        actor_key: str,
    ) -> dict[str, Any]:
        if value is None:
            return {
                "value": None,
                "threshold": signal.threshold,
                "fired": False,
                "reason": "missing_signal",
            }

        if signal.signal_id == SIGNAL_VARIANCE_COLLAPSE:
            # S2 fires only after L consecutive rounds below threshold.
            below = float(value) < signal.threshold
            streak_map = self._s2_streaks.setdefault(signal.signal_id, {})
            current_streak = streak_map.get(actor_key, 0)
            new_streak = current_streak + 1 if below else 0
            streak_map[actor_key] = new_streak
            fired = new_streak >= max(signal.consecutive_rounds, 1)
            return {
                "value": float(value),
                "threshold": signal.threshold,
                "fired": fired,
                "reason": (
                    f"streak={new_streak}/{signal.consecutive_rounds}"
                    if below
                    else "above_threshold"
                ),
            }

        # S1 / S3 / S4: simple threshold check.
        # S1 (synchronous move) and S4 (specialisation) compare a value
        # AGAINST a threshold for "fired = above". S3 (high HHI) is also
        # "fired = above". Conventionally we don't ship signals where
        # "below" fires; that's S2's job.
        fired = float(value) >= signal.threshold
        return {
            "value": float(value),
            "threshold": signal.threshold,
            "fired": fired,
            "reason": "above_threshold" if fired else "below_threshold",
        }

    def _primary_rule_id(self, fired_signal_ids: list[str]) -> str:
        """
        Pick a canonical rule_id for a multi-signal case. Prefer an
        explicit mapping; fall back to the first fired signal's mapping;
        fall back to a generic rule_id derived from the signal name.
        """
        for sid in fired_signal_ids:
            if sid in self._rule_id_for_signal:
                return self._rule_id_for_signal[sid]
        # Fallback: derive a stable rule_id from the first fired signal.
        first = fired_signal_ids[0]
        return self._rule_id_for_signal.get(first, f"rule_for_{first}")
