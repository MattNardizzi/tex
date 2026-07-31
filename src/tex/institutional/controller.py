"""
Governance Controller.

Per arxiv 2601.11369 §6.2.2 the Controller is the *manifest interpreter*:
"Given traversal requests selected by the policy program, it checks
legality (edge existence, state compatibility, cooldown gates), executes
the transition with manifest-declared temporal metadata (duration,
cooldown, jitter), and records each applied or blocked traversal with
full provenance (edge key, from/to states, case ID, effective timing)
in the immutable, append-only governance log."

The paper explicitly logs *blocked* traversals too — Section 7 reports
"244 suspension requests were denied because the required coordination
streak was not met". Tex preserves this discipline: every legality check
that fails produces a BLOCKED decision and a governance-log entry.

The Controller is the only component permitted to mutate trust scores
or revoke capabilities; in Thread 12 we model the *decision*, with
mechanical application deferred to tex.intervention.engine (P2).

Reference
---------
arxiv 2601.11369 (Bracale Syrnikov et al., 2026), §6.2.2, §7
arxiv 2601.10599 (Pierucci et al., 2026), §5.4 (Governance Engine)

Priority: P1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from tex.institutional.governance_graph import LegalTransition
from tex.institutional.oracle import GovernanceOracle, OracleCase
from tex.institutional.sanctions import RestorativePath, Sanction
from tex.observability.telemetry import emit_event


class ControllerOutcome(str, Enum):
    """The four possible outcomes per §6.2.2 + Tex's BLOCKED extension."""

    ALLOW = "ALLOW"
    SANCTION = "SANCTION"
    REMEDIATE = "REMEDIATE"
    BLOCKED = "BLOCKED"


class ControllerDecision(BaseModel):
    """
    A frozen, log-bound decision record.

    Every Controller.enforce() call produces exactly one
    ControllerDecision, regardless of outcome (including BLOCKED edges).
    The decision record is what the GovernanceLog signs and appends.

    Fields
    ------
    decision
        ALLOW | SANCTION | REMEDIATE | BLOCKED.
    edge_key
        The matched manifest edge_key. May be empty for "no edge"
        scenarios — the Controller still records the attempted traversal.
    rule_id
        ABDICO rule_id parsed from edge_key. May be empty if no edge
        matched.
    from_state, to_state
        The states the edge traverses. For BLOCKED with no matching
        edge, ``to_state`` is the empty string.
    triggered_by
        The proposed event kind that requested traversal.
    sanction_id, restorative_path_id
        Resolved IDs from the matched edge (if any).
    case_id
        The OracleCase that triggered this decision (if applicable).
    actor_entity_id
        Which actor the decision applies to.
    effective_round
        The round in which the decision takes effect (paper's "effective
        round + jitter" contract).
    cooldown_until_round
        Round number after which this edge can fire again for this
        actor. None if the edge has no cooldown.
    rationale
        Short human-legible reason rendered into Institutional notices.
    manifest_semantic_sha256
        Regime identity for the join with manifest digests.
    decided_at
        UTC timestamp of decision emission.
    decision_id
        Stable UUID4-derived identifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    decision: ControllerOutcome
    edge_key: str = ""
    rule_id: str = ""
    from_state: str
    to_state: str = ""
    triggered_by: str
    sanction_id: str | None = None
    restorative_path_id: str | None = None
    case_id: str | None = None
    actor_entity_id: str
    effective_round: int
    cooldown_until_round: int | None = None
    rationale: str = ""
    manifest_semantic_sha256: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GovernanceController:
    """
    Manifest interpreter.

    The Controller holds:
      - a reference to the Oracle (which holds the GovernanceGraph)
      - an optional intervention_engine (Thread 12 doesn't use it; P2
        will)
      - a GovernanceLog (separately keyed; required for production)
      - a per-(actor, edge) cooldown registry (in-memory for Thread 12)

    Cooldown semantics (§6.2.2):
      - When a transition fires with timing.cooldown_rounds > 0, the same
        edge cannot fire again for the same actor until current_round +
        cooldown_rounds has elapsed.
      - During cooldown, requests for that edge produce BLOCKED decisions
        which are still logged. Per §7 this is critical to deterrence
        legibility.
    """

    def __init__(
        self,
        *,
        oracle: GovernanceOracle,
        intervention_engine: Any = None,
        ledger: Any = None,
    ) -> None:
        self._oracle = oracle
        self._interventions = intervention_engine
        self._ledger = ledger  # GovernanceLog

        # cooldowns[(actor_id, edge_key)] = round_number_until_which_blocked
        self._cooldowns: dict[tuple[str, str], int] = {}

        # Per-actor current institutional state. The paper treats each
        # actor as having an independent institutional state (Active,
        # Warning, Fined, ...). Default is "active".
        self._actor_states: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def actor_state(self, actor_entity_id: str) -> str:
        """The institutional state currently assigned to ``actor``."""
        return self._actor_states.get(actor_entity_id, "active")

    def set_actor_state(self, actor_entity_id: str, state_id: str) -> None:
        """Externally seed an actor's state (test fixtures use this)."""
        self._actor_states[actor_entity_id] = state_id

    def in_cooldown(
        self,
        *,
        actor_entity_id: str,
        edge_key: str,
        current_round: int,
    ) -> bool:
        """True iff ``edge_key`` is on cooldown for ``actor`` right now."""
        until = self._cooldowns.get((actor_entity_id, edge_key))
        return until is not None and current_round < until

    def enforce(
        self,
        *,
        observation: dict | Any = None,
        proposed_event_kind: str = "",
        actor_entity_id: str = "",
        current_round: int = 0,
        case: OracleCase | None = None,
    ) -> dict:
        """
        Process a single traversal request and emit a ControllerDecision.

        Parameters
        ----------
        observation
            The Oracle observation (dict-like or pydantic OracleObservation).
            Carried through for log enrichment but the Controller's own
            decision logic dispatches via ``oracle.evaluate_transition``.
        proposed_event_kind
            The EventKind / case kind requesting traversal. Examples:
            "probable_violation" (Oracle-emitted), "expiry_tick"
            (time-driven restoration), or any EventKind from the manifest.
        actor_entity_id
            Which actor is requesting traversal.
        current_round
            Current simulation round (used for cooldown gating).
        case
            Optional OracleCase to bind into the decision record.

        Returns
        -------
        dict
            Serialised ControllerDecision (model_dump output).

        TODO(P1): consult Oracle.evaluate_transition
        TODO(P1): if sanction needed, request intervention selection
        TODO(P1): emit SANCTION_APPLIED or RESTORATIVE_PATH_TRIGGERED event
        TODO(P1): record decision in cryptographically-keyed governance log
        """
        if not actor_entity_id:
            raise ValueError("enforce() requires actor_entity_id")
        if not proposed_event_kind:
            raise ValueError("enforce() requires proposed_event_kind")

        graph = self._oracle.graph
        from_state = self.actor_state(actor_entity_id)

        # ------------------------------------------------------------------
        # Edge existence — the paper's first legality check.
        # ------------------------------------------------------------------
        try:
            transition: LegalTransition | None = graph.find_transition(
                from_state=from_state, triggered_by=proposed_event_kind
            )
        except ValueError as exc:
            decision = self._make_decision(
                outcome=ControllerOutcome.BLOCKED,
                from_state=from_state,
                triggered_by=proposed_event_kind,
                actor_entity_id=actor_entity_id,
                effective_round=current_round,
                rationale=f"manifest topology ambiguous: {exc}",
                case=case,
            )
            return self._record_and_return(decision)

        if transition is None:
            decision = self._make_decision(
                outcome=ControllerOutcome.BLOCKED,
                from_state=from_state,
                triggered_by=proposed_event_kind,
                actor_entity_id=actor_entity_id,
                effective_round=current_round,
                rationale=(
                    f"no manifest-declared edge from state={from_state!r} "
                    f"for triggered_by={proposed_event_kind!r}"
                ),
                case=case,
            )
            return self._record_and_return(decision)

        # ------------------------------------------------------------------
        # Cooldown gate — paper §7 records 244 blocked requests for this.
        # ------------------------------------------------------------------
        if self.in_cooldown(
            actor_entity_id=actor_entity_id,
            edge_key=transition.edge_key,
            current_round=current_round,
        ):
            until = self._cooldowns[(actor_entity_id, transition.edge_key)]
            decision = self._make_decision(
                outcome=ControllerOutcome.BLOCKED,
                edge_key=transition.edge_key,
                rule_id=transition.rule_id,
                from_state=from_state,
                to_state=transition.to_state,
                triggered_by=proposed_event_kind,
                sanction_id=transition.effective_sanction_id(),
                restorative_path_id=transition.restorative_path_id,
                actor_entity_id=actor_entity_id,
                effective_round=current_round,
                cooldown_until_round=until,
                rationale=(
                    f"edge {transition.edge_key!r} on cooldown until "
                    f"round {until} for actor {actor_entity_id!r}"
                ),
                case=case,
            )
            return self._record_and_return(decision)

        # ------------------------------------------------------------------
        # Outcome selection.
        # ------------------------------------------------------------------
        sanction_id = transition.effective_sanction_id()
        rest_id = transition.restorative_path_id

        outcome: ControllerOutcome
        rationale: str
        if rest_id is not None:
            outcome = ControllerOutcome.REMEDIATE
            try:
                path = graph.lookup_restorative_path(rest_id)
                rationale = (
                    f"traversed {transition.edge_key!r}: restorative_path="
                    f"{rest_id!r} (kind={path.restoration_kind})"
                )
            except KeyError:
                # Validation should have caught this; defence in depth.
                rationale = (
                    f"traversed {transition.edge_key!r}: restorative_path="
                    f"{rest_id!r} (lookup failed)"
                )
        elif sanction_id is not None:
            outcome = ControllerOutcome.SANCTION
            try:
                sanction = graph.lookup_sanction(sanction_id)
                rationale = (
                    f"traversed {transition.edge_key!r}: sanction="
                    f"{sanction_id!r} (action={sanction.enforcement_action})"
                )
            except KeyError:
                rationale = (
                    f"traversed {transition.edge_key!r}: sanction="
                    f"{sanction_id!r} (lookup failed)"
                )
        else:
            outcome = ControllerOutcome.ALLOW
            rationale = (
                f"traversed {transition.edge_key!r}: legal restorative/expiry"
            )

        # Apply state transition
        self._actor_states[actor_entity_id] = transition.to_state

        # Schedule cooldown if declared.
        cooldown_rounds = self._cooldown_for(transition)
        cooldown_until = (
            current_round + cooldown_rounds if cooldown_rounds > 0 else None
        )
        if cooldown_until is not None:
            self._cooldowns[(actor_entity_id, transition.edge_key)] = (
                cooldown_until
            )

        decision = self._make_decision(
            outcome=outcome,
            edge_key=transition.edge_key,
            rule_id=transition.rule_id,
            from_state=from_state,
            to_state=transition.to_state,
            triggered_by=proposed_event_kind,
            sanction_id=sanction_id,
            restorative_path_id=rest_id,
            actor_entity_id=actor_entity_id,
            effective_round=current_round,
            cooldown_until_round=cooldown_until,
            rationale=rationale,
            case=case,
        )
        return self._record_and_return(decision)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _make_decision(
        self,
        *,
        outcome: ControllerOutcome,
        from_state: str,
        triggered_by: str,
        actor_entity_id: str,
        effective_round: int,
        edge_key: str = "",
        rule_id: str = "",
        to_state: str = "",
        sanction_id: str | None = None,
        restorative_path_id: str | None = None,
        cooldown_until_round: int | None = None,
        rationale: str = "",
        case: OracleCase | None = None,
    ) -> ControllerDecision:
        return ControllerDecision(
            decision_id=f"dec_{uuid4().hex[:12]}",
            decision=outcome,
            edge_key=edge_key,
            rule_id=rule_id,
            from_state=from_state,
            to_state=to_state,
            triggered_by=triggered_by,
            sanction_id=sanction_id,
            restorative_path_id=restorative_path_id,
            case_id=case.case_id if case is not None else None,
            actor_entity_id=actor_entity_id,
            effective_round=effective_round,
            cooldown_until_round=cooldown_until_round,
            rationale=rationale,
            manifest_semantic_sha256=(
                self._oracle.graph.manifest_semantic_sha256
            ),
        )

    def _record_and_return(self, decision: ControllerDecision) -> dict:
        emit_event(
            "institutional.controller.decision",
            decision_id=decision.decision_id,
            outcome=decision.decision.value,
            edge_key=decision.edge_key,
            actor=decision.actor_entity_id,
            effective_round=decision.effective_round,
            sanction_id=decision.sanction_id,
            restorative_path_id=decision.restorative_path_id,
            cooldown_until_round=decision.cooldown_until_round,
            manifest_semantic_sha256=decision.manifest_semantic_sha256,
        )
        if self._ledger is not None:
            try:
                self._ledger.record_decision(controller_decision=decision)
            except Exception as exc:  # pragma: no cover - defensive
                emit_event(
                    "institutional.controller.ledger_record_failed",
                    decision_id=decision.decision_id,
                    error=str(exc),
                )
        return decision.model_dump(mode="json")

    @staticmethod
    def _cooldown_for(transition: LegalTransition) -> int:
        if transition.timing is None:
            return 0
        v = transition.timing.get("cooldown_rounds", 0)
        try:
            return max(0, int(v))
        except (TypeError, ValueError):
            return 0
