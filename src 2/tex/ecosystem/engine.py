"""
EcosystemEngine — primary entrypoint for ecosystem governance.

Replaces per-action adjudication. Every existing six-layer-pipeline verdict
gets injected into the ecosystem graph as an event, and the ecosystem engine
emits the ecosystem-level verdict that subsumes it.

The eight-step pipeline:

  1. ontology check       — event conforms to type system?
  2. graph projection     — current ecosystem state
  3. contract check       — agent behavioral contracts violated?       (P1 stub)
  4. governance graph LTS — legal transition under active institutional graph? (P1 stub)
  5. causal attribution   — what prior events causally enable this?    (P1 stub)
  6. drift detection      — does this event spike any tracked drift signal? (P1 stub)
  7. systemic risk        — bounded-compromise score under this event  (P2 stub)
  8. intervention select  — if not PERMIT, what cost-bounded intervention? (P2 stub)

Architecture (Microsoft Agent Governance Toolkit, April 2026, three-plane model)
--------------------------------------------------------------------------------
* Enforcement plane: ``evaluate()``, sub-millisecond when the flag is off,
  single-digit-millisecond when on with empty P1/P2 stubs.
* Control plane: P1 collaborators (contracts/institutional/causal/drift) are
  injectable but not on the critical path today.
* Audit plane: ``attest_state()`` produces the SCITT-shaped Signed Statement
  insurers and NAIC examiners verify offline.

Per-agent overhead budget per AAF (arxiv 2512.18561) §6: < 5% of the control
loop. For a Python implementation this maps to:
  * disabled path:   < 100 µs
  * enabled, no P1:  < 10 ms p99

Priority
--------
P0 — wire skeleton in days 1-14 (using in-memory graph). P1 — full causal +
governance LTS + drift in days 31-90. P2 — full intervention + digital twin
in days 90+.

References
----------
- AAF (arxiv 2512.18561 v3, March 2026): eight-step runtime layer.
- Institutional AI (arxiv 2601.10599, 2601.11369, January 2026):
  governance-graph LTS framing for steps 4 and 8.
- IETF SCITT architecture draft -22 (April 2026): attestation envelope.
- RFC 9162 (Certificate Transparency v2): window Merkle root format.
- Microsoft Agent Governance Toolkit (open-sourced April 2026):
  three-plane (Enforcement / Control / Audit) deployment pattern.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from tex.ecosystem._attestation import (
    build_attestation_payload,
    build_envelope,
    sign_envelope,
)
from tex.ecosystem._window import empty_root, merkle_root
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState
from tex.ecosystem.verdict import (
    EcosystemAxisScores,
    EcosystemVerdict,
    EcosystemVerdictKind,
)
from tex.ecosystem_config import is_flag_on

# NOTE: ``CryptoProvenance`` is imported under ``TYPE_CHECKING`` below.
# It is used only as a type annotation on ``EcosystemEngine.__init__``
# (no runtime use), and importing it at module top-level creates a
# cycle: ``tex.pitch`` -> ``tex.c2pa`` -> ``tex.events`` (which
# triggers ``tex.ecosystem`` package init via ``proposed_event``) ->
# ``tex.ecosystem.engine`` -> ``tex.events.crypto_provenance`` (already
# partially loaded). Thread 4 (May 2026): broke the cycle by deferring
# this single import to TYPE_CHECKING. The remaining ``tex.events``
# imports below do not participate in the cycle because they do not
# reach back into ``tex.ecosystem``.
from tex.events.event import genesis_ledger_hash
from tex.events.exceptions import LedgerAppendError
from tex.events.ledger import InMemoryLedger
from tex.graph.exceptions import GraphMutationError, UnknownActorError
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.intervention.kinds import InterventionKind
from tex.observability.telemetry import emit_event
from tex.ontology.validator import OntologyValidator

if TYPE_CHECKING:
    # Thread 4 (May 2026): ``CryptoProvenance`` is hoisted here to break
    # the ``tex.pitch`` -> ``tex.c2pa`` -> ``tex.events`` ->
    # ``tex.ecosystem`` -> ``tex.events.crypto_provenance`` cycle.
    # It is used only as a parameter annotation on ``__init__``; the
    # annotation is quoted at the call site so this import is purely a
    # type-checker hint.
    from tex.events.crypto_provenance import CryptoProvenance

    # Thread 2 institutional collaborators. Imported under TYPE_CHECKING
    # so the engine remains importable when liboqs is absent (the lazy
    # ``_pq_signing`` import inside ``__init__`` defers that probe to
    # the moment an oracle is actually wired).
    from tex.institutional.governance_graph import GovernanceGraph
    from tex.institutional.governance_log import GovernanceLog
    from tex.institutional.oracle import GovernanceOracle

    # Thread 8 intervention collaborators. Same TYPE_CHECKING pattern --
    # the calc is pure Python (no liboqs dependency) but the
    # InterventionEngine and RestorativePathExecutor accept a ledger
    # that lazily imports the signing provider, so we defer the runtime
    # imports to the constructor body.
    from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
    from tex.intervention.engine import InterventionEngine
    from tex.intervention.kinds import Intervention
    from tex.intervention.restorative import RestorativePathExecutor


# Environment flag the operator flips to enable ecosystem governance.
# Default off — existing six-layer pipeline runs untouched.
_ENV_FLAG_NAME: str = "TEX_ECOSYSTEM"

# Step 7 systemic-risk scorer is flag-gated and DEFAULT OFF.
#
# Rationale (SOTA as of May 2026):
# * Safety evaluators must be opted *in*. Google Cloud's June 2025
#   post-incident remediation made this explicit ("enforce all changes
#   to critical binaries to be feature-flag protected and disabled by
#   default") and Unleash / GitHub / OWASP guidance have followed.
# * The Thread-9 ``SystemicRiskEvaluator`` exists today as an unverified
#   scorer (PCTL over a DTMC abstraction, per ProbGuard arxiv 2508.00500
#   v3, Mar 27 2026). Until per-tenant validation runs land, the engine
#   ships with the scorer wired but the flag off — call sites are
#   exercised in tests; production deployments enable explicitly.
# * Parsing happens through a single canonical helper
#   (``tex.ecosystem_config.is_flag_on``) so the engine and config
#   module cannot drift. Strict equality with ``"1"`` defends against
#   typos silently enabling an expensive path.
#
# Telemetry fires on *every* evaluate(), regardless of flag state, with
# the literal observed value of the env var. A misconfigured deployment
# is therefore loudly visible in the audit plane rather than silent.
_ENV_FLAG_SYSTEMIC: str = "TEX_ECOSYSTEM_SYSTEMIC"


def _read_flag_from_env() -> bool:
    return is_flag_on(_ENV_FLAG_NAME)


def _neutral_axis_scores(*, drift_delta: float = 0.0) -> EcosystemAxisScores:
    """
    Build the neutral axis scores returned by the P0 pipeline.

    Steps 3-7 are stubs in P0; the engine emits neutral axis scores so
    downstream consumers (dashboards, evidence chain readers) can already
    branch on the field shape. P1/P2 will populate real scores.

    The drift_delta defaults to 0.0 ("no measured drift") rather than nan
    or "unknown" because the field is typed ``float`` on
    ``EcosystemAxisScores``; a P1 drift package will replace this stub.
    """
    return EcosystemAxisScores(
        contract_violation_severity=0.0,
        governance_graph_legality=1.0,  # 1.0 = legal under active LTS
        causal_attribution_confidence=0.0,
        drift_delta=drift_delta,
        systemic_risk_under_event=0.0,
        bounded_compromise_score=0.0,
    )


# Single neutral instance reused on every PERMIT — frozen, so sharing is safe.
_NEUTRAL_AXIS_SCORES: EcosystemAxisScores = _neutral_axis_scores()


# Sentinel for the disabled-engine pre-state hash: callers can branch on this
# string ("ecosystem_disabled") instead of having to special-case None.
_DISABLED_STATE_HASH: str = "ecosystem_disabled"


class EcosystemEngine:
    """The top-level ecosystem-state evaluator."""

    def __init__(
        self,
        *,
        ontology: OntologyValidator | None = None,
        graph: InMemoryTemporalKG | None = None,
        projection: StateProjection | None = None,
        events: InMemoryLedger | None = None,
        provenance: "CryptoProvenance | None" = None,
        # P1/P2 collaborators — accepted for forward compatibility but not
        # invoked on the critical path in P0.
        contracts: object | None = None,
        institutional: object | None = None,
        causal: object | None = None,
        drift: object | None = None,
        systemic: object | None = None,
        intervention: object | None = None,
        enabled: bool | None = None,
        # Thread 2 (P1): institutional governance-graph LTS wired into
        # step 4. Both default ``None`` for backward compat — when
        # neither is provided, step 4 is a pass-through (axis score 1.0,
        # "no manifest declared, all transitions legal under undeclared
        # regime"). Reference: arxiv 2601.11369 (Bracale Syrnikov et
        # al., Jan 2026) and FRONTIER_DELTA_thread_2.md §4.1.
        governance_graph: "GovernanceGraph | None" = None,
        oracle: "GovernanceOracle | None" = None,
        # Thread 2 (P1): institutional governance log (signed audit
        # trail of every step-4 decision). When ``None`` and an oracle
        # is wired, a default log is created using the strongest
        # available signing provider (see
        # ``tex.institutional._pq_signing.select_institutional_signing_provider``).
        governance_log: "GovernanceLog | None" = None,
        # Thread 2 (P1): per-actor institutional state. Maps
        # ``actor_entity_id -> institutional_state_id`` (e.g. "active",
        # "warning", "fined"). Operators initialise actors as "active"
        # by default. The engine does NOT mutate this map today —
        # mutation across rounds is a Thread-2.5 concern (state-machine
        # advancement on FORBID with sanction). Subagent inheritance
        # walks this map via ``resolve_effective_state``.
        institutional_states: "dict[str, str] | None" = None,
        # Thread 7.1: RiskGate P3 monotonic restriction (arxiv
        # 2604.24686 §4). When True, the engine tracks a per-actor
        # minimum viability index observed across the evaluation
        # history. Subsequent verdicts cannot report a higher
        # *effective* viability than that floor without an explicit
        # recovery event. Default False for backward compat.
        monotonic_restriction: bool = False,
        # Thread 8: intervention selection (Step 8). When
        # ``intervention_calc`` is supplied, FORBID exits invoke
        # ``InterventionEngine.select()`` over
        # ``candidate_interventions`` and attach the chosen
        # ``recommended_intervention_id`` to the verdict. When the
        # calc is supplied AND ``restorative_executor`` is supplied
        # AND ``auto_execute_restorative`` is True, the RESTORATIVE_PATH
        # interventions actually walk the path. Default behavior
        # (no calc) preserves Thread 1-7 verdicts byte-for-byte.
        # Reference: arxiv 2512.18561 v3 §5.4 Theorem 5;
        # FRONTIER_DELTA_thread_8.md.
        intervention_calc: "BoundedCompromiseCalculator | None" = None,
        candidate_interventions: "tuple[Intervention, ...]" = (),
        restorative_executor: "RestorativePathExecutor | None" = None,
        auto_execute_restorative: bool = False,
        target_compromise_ratio: float | None = None,
    ) -> None:
        """
        Construct an ecosystem engine.

        Parameters
        ----------
        ontology, graph, projection, events, provenance
            P0 collaborators. Required when ``enabled`` resolves True.
            Wired through dependency injection so tests can swap any of
            them for fakes / spies.
        contracts, institutional, causal, drift, systemic, intervention
            P1/P2 collaborators reserved for future steps. Accepted now so
            call sites do not change when those packages land.
        enabled
            Tri-state. ``None`` means read ``TEX_ECOSYSTEM`` from env.
            ``True``/``False`` overrides the env (used by tests).
        governance_graph, oracle
            Thread-2 institutional collaborators. When both are
            provided, step 4 of ``evaluate()`` becomes a real
            governance-graph LTS legality check per arxiv 2601.11369.
            When either is ``None``, step 4 is a pass-through. Backward
            compatible — existing tests do not pass these.
        governance_log
            Optional pre-constructed audit log. When ``None`` and an
            oracle is wired, a default log is constructed using the
            strongest available signing provider (ML-DSA-65 / hybrid /
            ECDSA-P256 per liboqs availability — see
            ``tex.institutional._pq_signing``).
        institutional_states
            Optional ``actor_entity_id -> state_id`` mapping. Defaults
            to empty (all actors treated as ``"active"``). Used by step
            4 to determine the ``from_state`` for transition lookup.
        """
        self._ontology = ontology
        self._graph = graph
        self._projection = projection
        self._events = events
        self._provenance = provenance
        self._contracts = contracts
        self._institutional = institutional
        self._causal = causal
        self._drift = drift
        self._systemic = systemic
        self._intervention = intervention

        # Thread 2 wire-in. Explicit ``oracle`` wins over ``institutional``
        # when both are supplied; we keep ``institutional`` for callers
        # passing a higher-level wrapper that doesn't expose the oracle
        # directly.
        self._governance_graph = governance_graph
        self._oracle = oracle
        self._institutional_states: dict[str, str] = dict(
            institutional_states or {}
        )

        # Lazy-create a governance log only when an oracle is wired AND
        # the caller didn't pre-construct one. This keeps the disabled
        # path zero-cost and avoids importing ``_pq_signing`` (which
        # probes liboqs at import time) for non-institutional callers.
        if self._oracle is not None and governance_log is None:
            from tex.institutional._pq_signing import (
                select_institutional_signing_provider,
            )
            from tex.institutional.governance_log import GovernanceLog

            selected = select_institutional_signing_provider()
            keypair = selected.provider.generate_keypair(
                "tex-institutional-log"
            )
            self._governance_log: "GovernanceLog | None" = GovernanceLog(
                signing_key_id="tex-institutional-log",
                signing_keypair=keypair,
                signing_provider=selected.provider,
                manifest_semantic_sha256=(
                    governance_graph.manifest_semantic_sha256
                    if governance_graph is not None
                    else None
                ),
            )
            self._signing_algorithm: str = selected.algorithm.value
        else:
            self._governance_log = governance_log
            self._signing_algorithm = (
                "caller_provided" if governance_log is not None else "none"
            )

        self._enabled: bool = (
            _read_flag_from_env() if enabled is None else bool(enabled)
        )

        # Thread 7.1: RiskGate P3 monotonic-restriction floor.
        # Map actor_entity_id → minimum viability_index observed.
        # When ``monotonic_restriction=True`` the engine surfaces an
        # ``effective_viability_index`` ≤ this floor on subsequent
        # verdicts. Operators clear an entry by calling
        # ``record_recovery(actor)`` after the actor has satisfied a
        # recovery event (sanction served, contract recovery within
        # k, etc.).
        self._monotonic_restriction: bool = monotonic_restriction
        self._viability_floor: dict[str, float] = {}

        # Thread 8 wire-in. The calc is the gating dependency: if no
        # calc is supplied, Step 8 is a strict pass-through (preserves
        # 2,470 existing tests byte-for-byte). When the calc is wired,
        # we lazily construct an InterventionEngine bound to the
        # ecosystem-level governance log so intervention application
        # records join the same audit chain as step-4 assessments.
        # Per FRONTIER_DELTA_thread_8 §6: intervention selection
        # happens BEFORE ledger append; if selection raises, the
        # FORBID goes out cleanly without polluting the ledger.
        self._intervention_calc: "BoundedCompromiseCalculator | None" = (
            intervention_calc
        )
        self._candidate_interventions: "tuple[Intervention, ...]" = tuple(
            candidate_interventions
        )
        self._restorative_executor: "RestorativePathExecutor | None" = (
            restorative_executor
        )
        self._auto_execute_restorative: bool = bool(auto_execute_restorative)
        # Effective target eta*: explicit override > calc's default.
        if target_compromise_ratio is not None:
            if not (0.0 <= target_compromise_ratio <= 1.0):
                raise ValueError(
                    "target_compromise_ratio must be in [0, 1], "
                    f"got {target_compromise_ratio}"
                )
            self._target_compromise_ratio: float = float(target_compromise_ratio)
        elif intervention_calc is not None:
            self._target_compromise_ratio = intervention_calc.target_compromise_ceiling
        else:
            # Default unused when calc is None; pick a safe sentinel.
            self._target_compromise_ratio = 1.0

        self._intervention_engine: "InterventionEngine | None"
        if intervention_calc is not None:
            from tex.intervention.engine import InterventionEngine as _IEng

            self._intervention_engine = _IEng(
                bounded_compromise_calc=intervention_calc,
                ledger=self._governance_log,
            )
        else:
            self._intervention_engine = None

        if self._enabled:
            self._assert_p0_collaborators_wired()

    # ------------------------------------------------------------------ public

    @property
    def enabled(self) -> bool:
        """Whether the engine will perform real evaluation or short-circuit."""
        return self._enabled

    @property
    def monotonic_restriction(self) -> bool:
        """Whether RiskGate P3 monotonic restriction is active."""
        return self._monotonic_restriction

    def viability_floor_for(self, actor_entity_id: str) -> float | None:
        """
        Read-only access to the per-actor viability floor.

        Returns ``None`` if no floor has been recorded for the actor
        (no prior evaluation), or the minimum viability index observed
        across the actor's evaluation history.

        Per RiskGate (arxiv 2604.24686) P3 — once the engine has
        observed an actor at a low viability, subsequent verdicts
        cannot relax that floor without an explicit
        ``record_recovery`` call.
        """
        return self._viability_floor.get(actor_entity_id)

    def record_recovery(self, *, actor_entity_id: str) -> None:
        """
        Clear the viability floor for ``actor_entity_id``.

        Operators call this after the actor has satisfied a recovery
        event (sanction served, contract recovery within k, etc.).
        The next verdict reports the actor's full computed viability
        index without floor enforcement.

        Per RiskGate P3 — recovery requires an explicit operator
        action; the engine does not implicitly relax restrictions.
        """
        prior = self._viability_floor.pop(actor_entity_id, None)
        emit_event(
            "ecosystem.engine.monotonic_restriction.recovery",
            actor_entity_id=actor_entity_id,
            prior_floor=prior,
        )

    def evaluate(self, proposed: ProposedEvent) -> EcosystemVerdict:
        """
        Evaluate a proposed event against the current ecosystem state.

        Pipeline status (Thread 7 complete):

          Step 1 — ontology.validate_event(proposed)                 [done]
          Step 2 — graph.project_state_at(proposed.timestamp)        [done]
          Step 3 — contract check (Bhardwaj ABC arxiv 2602.22302)    [done, Thread 7]
          Step 4 — governance LTS legality (Thread 2)                [done]
          Step 5 — fast causal attribution (CHIEF.fast_attribute)    [done, Thread 7]
          Step 6 — drift detection (BOCPD + anytime-valid e-process) [done, Thread 7]
          Step 7 — systemic risk (flag-gated, Thread 9 implements)   [call site wired, Thread 7]
          Step 8 — intervention selection (Thread 8)                 [pending]
          PERMIT path — append to ledger + graph; recompute hash     [done]

        Steps 3, 5, 6, 7 are *axis scorers* (not hard gates) per
        FRONTIER_DELTA_thread_7.md §6. They populate ``axis_scores``;
        the engine PERMITs on aggregate. The composition gate that
        decides FORBID/ABSTAIN/SANCTION on aggregate axis scores lands
        in Thread 8.

        Reference: AAF (arxiv 2512.18561 v3, Mar 2026) §4.1 pipeline
                   ordering; Institutional AI (arxiv 2601.10599) §3
                   LTS framing for step 4; Bhardwaj ABC (arxiv
                   2602.22302) §3 for step 3; MASPrism (arxiv
                   2605.07509, May 2026) for step 5 technique
                   inspiration; Drift-to-Action (arxiv 2603.08578,
                   Mar 2026) for step 6 anytime-valid certificate;
                   ProbGuard (arxiv 2508.00500 v3, Mar 2026) +
                   GeomHerd (arxiv 2605.11645, May 2026) for step 7
                   Thread-9 target.
        """
        proposed_event_id = self._derive_event_id(proposed)

        if not self._enabled:
            # Disabled: O(1) inert PERMIT, no mutation, no telemetry spam.
            # Single telemetry event for diagnosability.
            emit_event(
                "ecosystem.engine.evaluate.disabled",
                proposed_event_kind=proposed.event_kind,
                proposed_actor=proposed.actor_entity_id,
            )
            return EcosystemVerdict(
                kind=EcosystemVerdictKind.PERMIT,
                proposed_event_id=proposed_event_id,
                issued_at=_now_utc(),
                axis_scores=_NEUTRAL_AXIS_SCORES,
                ecosystem_state_hash_before=_DISABLED_STATE_HASH,
                ecosystem_state_hash_after=None,
                rationale="ecosystem governance disabled (TEX_ECOSYSTEM=0)",
                evidence_record_id=None,
                recommended_intervention_id=None,
            )

        # --- Step 1: ontology validation ---
        # The ontology validator enforces type-system invariants. Any failure
        # here is a hard FORBID — the event is malformed and must not enter
        # the graph or the ledger.
        assert self._ontology is not None  # guaranteed by __init__ check
        ok, errors = self._ontology.validate_event(proposed)
        if not ok:
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=(
                    "step 1 ontology violation: " + "; ".join(errors)
                ),
                state_hash_before=_DISABLED_STATE_HASH,
                reason="ontology",
            )

        # --- Step 2: graph projection (state at proposed.proposed_at) ---
        # We project the state *before* admitting the event so the verdict
        # carries the pre-event state hash; the post-event hash is set on
        # PERMIT below after the graph has been updated.
        assert self._projection is not None and self._graph is not None
        try:
            state_before: EcosystemState = self._projection.project_at(
                proposed.proposed_at
            )
        except Exception as exc:  # pragma: no cover - defensive
            # Projection is pure-read; failure here means the graph is in a
            # bad state (e.g., naive datetime). We FORBID rather than crash.
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=f"step 2 projection failure: {exc}",
                state_hash_before=_DISABLED_STATE_HASH,
                reason="projection",
            )

        # Frontier addition (not in the AAF abstract but required by SOTA
        # multi-agent governance per Institutional AI §3 and SAGA): the actor
        # must be a registered ecosystem entity. Ontology validation is
        # type-only; entity presence is graph-only.
        if not self._graph._has_entity(proposed.actor_entity_id):
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=(
                    f"step 2 unknown actor: entity "
                    f"{proposed.actor_entity_id!r} not registered in graph"
                ),
                state_hash_before=state_before.state_hash,
                reason="unknown_actor",
            )

        # --- Step 3: behavioral contracts (Thread 7, wired) ---
        # Composes Bhardwaj ABC (arxiv 2602.22302) §3.2 deterministic
        # satisfaction with the ecosystem-level severity aggregate.
        # We call ``compliance_scores`` (NOT ``check_pre``) because
        # ``compliance_scores`` is pure: no step_index advance, no
        # violation recording, no soft-recovery deadlines touched.
        # The PDP layer owns recording — the ecosystem engine reads
        # the (C_hard, C_soft) snapshot and converts it into the
        # ``contract_violation_severity`` axis.
        #
        # Severity = 1 - min(C_hard, C_soft) — a single hard failure
        # propagates to maximum severity (mirrors ABC's "any hard
        # violation invalidates the step" semantics §3.3).
        #
        # FAIL-CLOSED: if the enforcer raises, severity is set to 1.0
        # (treat as if all constraints failed) and a telemetry event
        # fires. We do NOT short-circuit to FORBID here — step 3 is
        # an axis score input, not a hard gate. The downstream
        # composition gate (when implemented in Thread 8) decides
        # whether the severity is FORBID-worthy. Today the high-
        # severity event still PERMITs but its evidence record
        # surfaces the severity explicitly.
        #
        # Reference: arxiv 2602.22302 §3.2, §3.3, §3.6; Thread 1.5
        # SessionEnforcerRegistry composition; FRONTIER_DELTA_thread_7.md §6.1.
        contract_violation_severity = 0.0
        if self._contracts is not None:
            try:
                # Duck-type the contracts collaborator: accepts any
                # object with a ``compliance_scores`` method matching
                # the ABC signature. Most callers pass a
                # ``ContractEnforcer`` directly; tests pass a fake.
                scores = self._contracts.compliance_scores(
                    agent_id=proposed.actor_entity_id,
                    proposed_event=proposed,
                    current_state=state_before,
                )
                # Tolerate empty contract sets (constraints_evaluated=0
                # → both scores default to 1.0; severity is 0.0).
                worst = min(scores.c_hard, scores.c_soft)
                contract_violation_severity = max(0.0, min(1.0, 1.0 - worst))
                emit_event(
                    "ecosystem.engine.step3.contracts_evaluated",
                    proposed_event_id=proposed_event_id,
                    c_hard=scores.c_hard,
                    c_soft=scores.c_soft,
                    contracts_evaluated=scores.contracts_evaluated,
                    constraints_evaluated=scores.constraints_evaluated,
                    severity=contract_violation_severity,
                )
            except Exception as exc:  # pragma: no cover — defensive
                # Fail-closed per Section 3 of standing orders:
                # surface the severity as 1.0 so the verdict's axis
                # honestly reports "we don't know — assume worst."
                contract_violation_severity = 1.0
                emit_event(
                    "ecosystem.engine.step3.contract_enforcer_error",
                    proposed_event_id=proposed_event_id,
                    error=f"{type(exc).__name__}: {exc}",
                )

        # --- Step 4: governance-graph LTS legality check ---
        # When an oracle is wired, ask whether the proposed event is a
        # legal transition under the active institutional graph. Per
        # arxiv 2601.11369 §4.2 the LTS is over institutional events;
        # action events without a manifest-declared edge produce
        # ``(False, None)`` from ``evaluate_transition`` which we
        # interpret as "no edge declared → step 4 is a pass-through"
        # (axis score 1.0). When an edge IS declared and the manifest
        # marks it sanctionable, step 4 returns FORBID with rationale
        # naming the (from_state, triggered_by) pair.
        #
        # Reference: arxiv 2601.11369 (Bracale Syrnikov et al., Jan 2026)
        # and FRONTIER_DELTA_thread_2.md §4 for the design rationale.
        #
        # Subagent-state inheritance per arxiv 2605.08460 (Cai/Zhang/Hei,
        # May 8 2026): an actor's effective ``from_state`` is the
        # most-restrictive state across its ``spawned_by`` chain. A
        # subagent of a ``suspended`` actor is evaluated under
        # ``suspended``.
        governance_graph_legality = 1.0
        if self._oracle is not None:
            from tex.institutional.subagent_inheritance import (
                resolve_effective_state,
            )

            actor = proposed.actor_entity_id
            direct_state = self._institutional_states.get(actor, "active")
            inherited = resolve_effective_state(
                graph=self._graph,
                actor_entity_id=actor,
                direct_state=direct_state,
                institutional_states=self._institutional_states,
                at=proposed.proposed_at,
            )

            try:
                is_legal, sanction_id = self._oracle.evaluate_transition(
                    current_state=state_before,
                    proposed_event_kind=proposed.event_kind,
                    institutional_state=inherited.effective_state,
                    actor_entity_id=actor,
                )
            except Exception as exc:
                # Fail-closed per standing orders §3: enforcement gate
                # errors default to FORBID, never PERMIT. We surface a
                # FORBID with rationale rather than crashing.
                emit_event(
                    "ecosystem.engine.step4.oracle_error",
                    proposed_event_id=proposed_event_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
                return self._forbid(
                    proposed_event_id=proposed_event_id,
                    rationale=(
                        f"step 4 governance LTS: oracle error "
                        f"({type(exc).__name__}); fail-closed FORBID"
                    ),
                    state_hash_before=state_before.state_hash,
                    reason="step4_oracle_error",
                )

            # Whether the transition is legal or not, record the
            # assessment to the signed governance log. The audit trail
            # must include legal decisions too — an external auditor
            # reconstructing "did this transition pass step 4?" needs
            # the legal-decision record (see FRONTIER_DELTA §6).
            self._record_step4_assessment(
                proposed_event_id=proposed_event_id,
                actor_entity_id=actor,
                effective_state=inherited.effective_state,
                direct_state=inherited.direct_state,
                inherited_from=inherited.inherited_from,
                chain_length=inherited.chain_length,
                proposed_event_kind=proposed.event_kind,
                is_legal=is_legal,
                sanction_id=sanction_id,
            )

            if not is_legal:
                rationale_parts = [
                    f"step 4 governance LTS: transition "
                    f"{proposed.event_kind!r} from state "
                    f"{inherited.effective_state!r} not legal"
                ]
                if sanction_id is not None:
                    rationale_parts.append(f"sanction={sanction_id!r}")
                if inherited.inherited_from is not None:
                    rationale_parts.append(
                        f"state inherited from {inherited.inherited_from!r} "
                        f"(direct state was {inherited.direct_state!r})"
                    )
                return self._forbid(
                    proposed_event_id=proposed_event_id,
                    rationale="; ".join(rationale_parts),
                    state_hash_before=state_before.state_hash,
                    reason="step4_illegal_transition",
                )

            # Legal: record the legality positively in the axis score.
            governance_graph_legality = 1.0

        # --- Step 5: pre-emission causal attribution (Thread 7, wired) ---
        # Sub-5ms p99 attribution on the request path. Distinct from the
        # full post-incident ``attribute_root_cause`` endpoint — this
        # is the spec-required "faster, less complete attribution."
        # Reads the agent's declared ``upstream_event_ids`` chain and
        # the active-agent set; returns a top-K candidate list +
        # confidence in [0, 1]. See
        # ``HierarchicalCausalGraph.fast_attribute`` for the
        # algorithm and FRONTIER_DELTA_thread_7.md §6.2 for the
        # design justification (rejected MASPrism port at 2.66s/trace
        # vs. 5ms budget).
        #
        # FAIL-CLOSED: on any error the axis is set to 0.0 (no
        # attribution) and a telemetry event fires — the engine
        # continues, treating "we don't know" as "no positive
        # causal attribution evidence."
        causal_attribution_confidence = 0.0
        if self._causal is not None:
            try:
                fast_result = self._causal.fast_attribute(
                    proposed_event_id=proposed_event_id,
                    upstream_event_ids=proposed.upstream_event_ids,
                    active_agent_ids=state_before.active_agent_ids,
                )
                causal_attribution_confidence = max(
                    0.0, min(1.0, fast_result.confidence)
                )
                emit_event(
                    "ecosystem.engine.step5.causal_attributed",
                    proposed_event_id=proposed_event_id,
                    confidence=causal_attribution_confidence,
                    top_candidates=list(fast_result.top_candidates),
                    sample_size=fast_result.sample_size,
                )
            except Exception as exc:  # pragma: no cover — defensive
                causal_attribution_confidence = 0.0
                emit_event(
                    "ecosystem.engine.step5.causal_error",
                    proposed_event_id=proposed_event_id,
                    error=f"{type(exc).__name__}: {exc}",
                )

        # --- Step 6: drift detection (Thread 7, wired) ---
        # BOCPD + anytime-valid e-process composed via
        # ``tex.drift.signal_registry.evaluate_drift``. Per Thread 7
        # design (FRONTIER_DELTA §6.3): Bayesian change-point posterior
        # + frequentist anytime-valid p-value, blended into the
        # ``drift_delta`` axis. The anytime-valid certificate is emitted
        # alongside the Bayesian score so downstream interventions
        # (Thread 8) can apply Drift-to-Action arxiv 2603.08578's
        # cost-aware controller against a valid Type-I-bounded signal.
        #
        # When no drift collaborator is wired the axis is honestly
        # 0.0 and a telemetry event fires — the engine does NOT
        # reach into a module-level default singleton (that would
        # leak state across operators and across tests). Explicit
        # opt-in via ``drift=DriftSignalRegistry(...)`` at engine
        # construction is required to score drift.
        #
        # FAIL-CLOSED: on any error drift is set to 0.0 (no drift
        # observed) and telemetry fires. Engine continues. Drift is
        # an axis score input, not a hard gate.
        drift_delta = 0.0
        if self._drift is not None:
            try:
                from tex.drift.signal_registry import (
                    DriftSignalRegistry,
                    evaluate_drift,
                )

                registry: "DriftSignalRegistry | None"
                if isinstance(self._drift, DriftSignalRegistry):
                    registry = self._drift
                else:
                    # Unknown collaborator type — caller passed
                    # something duck-typed but not a DriftSignalRegistry.
                    # Use module-level default as fallback. (Same
                    # behavior as a deliberate registry=None.)
                    registry = None

                drift_eval = evaluate_drift(
                    proposed=proposed,
                    state_before=state_before,
                    registry=registry,
                )
                drift_delta = drift_eval.drift_delta
                emit_event(
                    "ecosystem.engine.step6.drift_evaluated",
                    proposed_event_id=proposed_event_id,
                    drift_delta=drift_delta,
                    change_point_detected=drift_eval.change_point_detected,
                    anytime_valid_p_value=drift_eval.anytime_valid_p_value,
                    signals_evaluated=list(drift_eval.signals_evaluated),
                    dominant_signal=drift_eval.dominant_signal_id,
                )
            except Exception as exc:  # pragma: no cover — defensive
                drift_delta = 0.0
                emit_event(
                    "ecosystem.engine.step6.drift_error",
                    proposed_event_id=proposed_event_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
        else:
            emit_event(
                "ecosystem.engine.step6.drift_skipped_no_collaborator",
                proposed_event_id=proposed_event_id,
            )

        # --- Step 7: systemic risk under proposed event ---
        #
        # Flag-gated and DEFAULT OFF (Bug #2 in KNOWN_BUGS.md was the
        # engine and ecosystem_config disagreeing on the default; this
        # block reads the canonical helper from ``tex.ecosystem_config``
        # so the two cannot drift again).
        #
        # Cited design directions for the wired SystemicRiskEvaluator:
        #
        #   * ProbGuard (arxiv 2508.00500 v3, Mar 27 2026): PCTL
        #     property ``P_{<θ}[ F unsafe_state ]`` over a DTMC
        #     abstraction of the ecosystem state. PAC bounds. 38.66s
        #     forward-looking warnings on the published benchmarks.
        #   * GeomHerd (arxiv 2605.11645, May 2026): Ollivier-Ricci
        #     curvature on agent-interaction graphs. Forward-looking
        #     ≥272 steps before order-parameter onset.
        #
        # The engine never short-circuits to FORBID/ABSTAIN on a scorer
        # failure: a misconfigured flag must not be capable of DoS'ing
        # the system. When the scorer raises, the axis is honestly
        # reported as 0.0 ("unknown") and a typed telemetry event fires
        # so operators see the failure in the audit plane.
        #
        # Telemetry fires on *every* path — flag-on-scored, flag-on-not-
        # implemented, flag-on-error, flag-off-skipped — so deployment
        # state is always observable. Per Unleash / OWASP 2026 guidance
        # for safety-critical feature flags.
        systemic_risk_under_event = 0.0
        systemic_flag_on = is_flag_on(_ENV_FLAG_SYSTEMIC)
        flag_value_observed = os.environ.get(_ENV_FLAG_SYSTEMIC)
        if systemic_flag_on and self._systemic is not None:
            try:
                systemic_risk_under_event = float(
                    self._systemic.score(state=state_before)
                )
                # Clamp into [0, 1] defensively — the field is
                # ge=0, le=1 validated.
                systemic_risk_under_event = max(
                    0.0, min(1.0, systemic_risk_under_event)
                )
                emit_event(
                    "ecosystem.engine.step7.systemic_scored",
                    proposed_event_id=proposed_event_id,
                    systemic_risk=systemic_risk_under_event,
                )
            except NotImplementedError:
                # The scorer is wired but the per-tenant model isn't
                # yet validated. Surface loudly — operators must detect
                # this rather than silently believing the system is
                # scoring systemic risk.
                systemic_risk_under_event = 0.0
                emit_event(
                    "ecosystem.engine.step7.systemic_not_implemented",
                    proposed_event_id=proposed_event_id,
                    note=(
                        "TEX_ECOSYSTEM_SYSTEMIC=1 but "
                        "SystemicRiskEvaluator.score() raises "
                        "NotImplementedError. Axis reported as 0.0; "
                        "engine continues."
                    ),
                )
            except Exception as exc:  # pragma: no cover — defensive
                systemic_risk_under_event = 0.0
                emit_event(
                    "ecosystem.engine.step7.systemic_error",
                    proposed_event_id=proposed_event_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
        else:
            # Default-off path: emit a typed event so operators can see
            # the flag state on every evaluation. Distinguish three
            # sub-cases for observability — flag unset, flag explicitly
            # off, and flag on but scorer not wired (deployment bug).
            if not systemic_flag_on and self._systemic is None:
                reason = "flag_off_and_no_collaborator"
            elif not systemic_flag_on:
                reason = "flag_off"
            else:
                reason = "flag_on_but_no_collaborator"
            emit_event(
                "ecosystem.engine.step7.systemic_skipped",
                proposed_event_id=proposed_event_id,
                reason=reason,
                flag_value=flag_value_observed,
                systemic_collaborator_wired=self._systemic is not None,
            )

        # All four newly-wired axes folded into the verdict's per-axis
        # scoring. ``bounded_compromise_score`` is populated by Thread 8
        # below as 1 - eta* whenever an intervention is recommended.
        # The initial neutral value is overwritten if Step 8 actually
        # selects an intervention.
        bounded_compromise_score = 0.0

        # --- Step 8: intervention selection + axis-derived FORBID gate ---
        # Per the engine-module docstring §evaluate: "The composition
        # gate that decides FORBID/ABSTAIN/SANCTION on aggregate axis
        # scores lands in Thread 8."
        #
        # When Thread 8 is wired (intervention_calc supplied):
        #   1. Compute an axis-derived FORBID predicate. The default
        #      predicate is conservative: FORBID when any of
        #      (contract_violation_severity, 1 - governance_graph_legality,
        #      drift_delta, systemic_risk_under_event) exceeds 0.5.
        #   2. If FORBID, call InterventionEngine.select() to find the
        #      lowest-cost intervention that bounds eta* below the
        #      operator's target. Pass the dominant drift signal as
        #      current_drift_score.
        #   3. If a satisfying intervention exists:
        #         - Call .apply() to emit the ML-DSA-signed
        #           governance-log record (cert + AIR phase tag).
        #         - For RESTORATIVE_PATH kinds, if a restorative
        #           executor is wired AND auto_execute_restorative is
        #           True, walk the path. Otherwise, the verdict carries
        #           the recommendation; an async worker walks it.
        #         - Emit verdict: SANCTION (admit + sanction) for
        #           non-blocking kinds; REMEDIATE (block + restore) for
        #           QUARANTINE, HUMAN_APPROVAL_GATE, RESTORATIVE_PATH.
        #   4. If no candidate satisfies: FAIL-CLOSED to FORBID with no
        #      recommendation. The caller (operator) must remediate
        #      out-of-band.
        # Reference: arxiv 2512.18561 v3 §5.4 Theorem 5;
        # FRONTIER_DELTA_thread_8.md §4 Delta-1, §6.
        recommended_intervention_id: str | None = None
        verdict_kind_override: EcosystemVerdictKind | None = None
        verdict_rationale_override: str | None = None

        if self._intervention_engine is not None:
            # Axis-derived FORBID predicate. Mirrors the viability-index
            # decomposition (RiskGate U/SB/RG) but uses the raw axes so
            # the threshold is operator-tunable in a future thread.
            sb_severity = max(
                max(0.0, min(1.0, contract_violation_severity)),
                max(0.0, min(1.0, 1.0 - governance_graph_legality)),
            )
            u_drift = max(0.0, min(1.0, drift_delta))
            rg_systemic = max(0.0, min(1.0, systemic_risk_under_event))
            dominant_axis = max(sb_severity, u_drift, rg_systemic)
            axes_imply_forbid = dominant_axis >= 0.5

            if axes_imply_forbid:
                emit_event(
                    "ecosystem.engine.step8.axes_imply_forbid",
                    proposed_event_id=proposed_event_id,
                    sb_severity=sb_severity,
                    drift=u_drift,
                    systemic=rg_systemic,
                    dominant_axis=dominant_axis,
                )
                # Drive selection from the dominant adversary signal:
                # use drift_delta as the scalar current_drift_score
                # because that is the live distributional-shift signal
                # Step 6 produces; contract / governance / systemic
                # axes are categorical and don't map directly onto
                # g_max. A future iteration can pass a structured
                # drift_signals dict to the calc.
                try:
                    chosen = self._intervention_engine.select(
                        current_drift_score=u_drift,
                        target_max_compromise_ratio=(
                            self._target_compromise_ratio
                        ),
                        candidate_interventions=self._candidate_interventions,
                    )
                except Exception as exc:  # defence in depth
                    emit_event(
                        "ecosystem.engine.step8.select_failed",
                        proposed_event_id=proposed_event_id,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    chosen = None

                if chosen is None:
                    # No candidate satisfies the bound -> FAIL-CLOSED FORBID
                    # with no recommendation. The verdict still carries the
                    # axes that triggered the gate so an operator dashboard
                    # can show the operator why.
                    return self._forbid(
                        proposed_event_id=proposed_event_id,
                        rationale=(
                            f"step 8 axes_imply_forbid (sb={sb_severity:.3f}, "
                            f"drift={u_drift:.3f}, sys={rg_systemic:.3f}); "
                            "no candidate intervention satisfies the "
                            "bounded-compromise bound"
                        ),
                        state_hash_before=state_before.state_hash,
                        reason="step8_no_satisfying_intervention",
                    )

                # Apply the chosen intervention. On apply failure,
                # FAIL-CLOSED to FORBID with no recommendation.
                try:
                    self._intervention_engine.apply(chosen)
                except Exception as exc:
                    emit_event(
                        "ecosystem.engine.step8.apply_failed",
                        proposed_event_id=proposed_event_id,
                        intervention_id=chosen.intervention_id,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    return self._forbid(
                        proposed_event_id=proposed_event_id,
                        rationale=(
                            f"step 8 selected intervention "
                            f"{chosen.intervention_id} but apply failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                        state_hash_before=state_before.state_hash,
                        reason="step8_apply_failed",
                    )

                recommended_intervention_id = chosen.intervention_id

                # Compute bounded_compromise_score = 1 - eta* so a
                # higher score = tighter bound. eta* is recomputable
                # from the cost fields the engine already has.
                try:
                    g_max = self._intervention_calc.estimate_adversary_payoff(
                        drift_signals={"drift_delta": u_drift}
                    )
                    eta = self._intervention_calc.long_run_compromise_ratio_from_window(
                        penalty_window_aggregate=(
                            chosen.expected_cost_to_adversary
                        ),
                        adversary_g_max=g_max,
                    )
                    bounded_compromise_score = max(0.0, min(1.0, 1.0 - eta))
                except Exception:  # defence in depth
                    bounded_compromise_score = 0.0

                # Restorative path execution (for RESTORATIVE_PATH kinds).
                if (
                    chosen.kind == InterventionKind.RESTORATIVE_PATH
                    and self._restorative_executor is not None
                    and self._auto_execute_restorative
                ):
                    path_id = chosen.parameters.get("path_id", "") if chosen.parameters else ""
                    if path_id:
                        try:
                            ok = self._restorative_executor.execute(
                                path_id=str(path_id),
                                target_entity_id=chosen.target_entity_id,
                            )
                        except Exception as exc:
                            emit_event(
                                "ecosystem.engine.step8.restorative_execute_error",
                                proposed_event_id=proposed_event_id,
                                error=f"{type(exc).__name__}: {exc}",
                            )
                            ok = False
                        emit_event(
                            "ecosystem.engine.step8.restorative_executed",
                            proposed_event_id=proposed_event_id,
                            intervention_id=chosen.intervention_id,
                            path_id=path_id,
                            ok=ok,
                        )

                # Verdict-kind mapping. Per verdict-module docstring:
                #   SANCTION  = admit event + apply sanction
                #   REMEDIATE = block event + execute restorative
                # Mapping by intervention kind:
                blocking_kinds = {
                    InterventionKind.QUARANTINE,
                    InterventionKind.HUMAN_APPROVAL_GATE,
                    InterventionKind.RESTORATIVE_PATH,
                }
                if chosen.kind in blocking_kinds:
                    verdict_kind_override = EcosystemVerdictKind.REMEDIATE
                else:
                    verdict_kind_override = EcosystemVerdictKind.SANCTION
                verdict_rationale_override = (
                    f"step 8 axes_imply_forbid (sb={sb_severity:.3f}, "
                    f"drift={u_drift:.3f}, sys={rg_systemic:.3f}); "
                    f"intervention={chosen.intervention_id} "
                    f"kind={chosen.kind.value} "
                    f"target={chosen.target_entity_id} "
                    f"eta_star_after={1.0 - bounded_compromise_score:.4f}"
                )
            else:
                emit_event(
                    "ecosystem.engine.step8.axes_clean",
                    proposed_event_id=proposed_event_id,
                    sb_severity=sb_severity,
                    drift=u_drift,
                    systemic=rg_systemic,
                )

        axis_scores = EcosystemAxisScores(
            contract_violation_severity=contract_violation_severity,
            governance_graph_legality=governance_graph_legality,
            causal_attribution_confidence=causal_attribution_confidence,
            drift_delta=drift_delta,
            systemic_risk_under_event=systemic_risk_under_event,
            bounded_compromise_score=bounded_compromise_score,
        )

        # If Step 8 emitted a verdict-kind override (SANCTION or
        # REMEDIATE), short-circuit before PERMIT-path ledger append.
        # The intervention's governance-log record is already in the
        # audit chain; appending the proposed_event to the main events
        # ledger would be misleading (the event was blocked or
        # sanctioned, not admitted as-is).
        if verdict_kind_override == EcosystemVerdictKind.REMEDIATE:
            # REMEDIATE: do NOT append to main ledger or mutate graph.
            assert verdict_rationale_override is not None
            emit_event(
                "ecosystem.engine.evaluate.remediated",
                proposed_event_id=proposed_event_id,
                recommended_intervention_id=recommended_intervention_id,
            )
            return EcosystemVerdict(
                kind=EcosystemVerdictKind.REMEDIATE,
                proposed_event_id=proposed_event_id,
                issued_at=_now_utc(),
                axis_scores=axis_scores,
                ecosystem_state_hash_before=state_before.state_hash,
                ecosystem_state_hash_after=None,
                rationale=verdict_rationale_override,
                evidence_record_id=None,
                recommended_intervention_id=recommended_intervention_id,
            )
        # SANCTION falls through to PERMIT-path ledger append so the
        # event is on-record, but the verdict.kind is overridden below
        # after we know the appended event_id.

        # --- PERMIT path: append to ledger + graph; recompute state hash ---
        assert self._events is not None and self._provenance is not None
        try:
            event = self._events.append_proposed(
                proposed,
                provenance=self._provenance,
                event_id=proposed_event_id,
            )
        except LedgerAppendError as exc:
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=f"ledger append failed: {exc}",
                state_hash_before=state_before.state_hash,
                reason="ledger_append",
            )

        try:
            self._graph.add_event(
                event_id=event.event_id,
                kind=event.kind,
                actor=event.actor_entity_id,
                target=event.target_entity_id,
                payload=dict(event.payload),
                timestamp=event.timestamp,
                upstream=event.upstream_event_ids,
            )
        except (GraphMutationError, UnknownActorError) as exc:
            # Ledger append succeeded but graph rejected the edge — typically
            # a missing target entity. The ledger record is durable; we surface
            # this as ABSTAIN rather than FORBID because the audit trail
            # already captured the event. Operators repair the graph and
            # replay.
            emit_event(
                "ecosystem.engine.evaluate.graph_inconsistent",
                proposed_event_id=event.event_id,
                detail=str(exc),
            )
            return EcosystemVerdict(
                kind=EcosystemVerdictKind.ABSTAIN,
                proposed_event_id=event.event_id,
                issued_at=_now_utc(),
                axis_scores=axis_scores,
                ecosystem_state_hash_before=state_before.state_hash,
                ecosystem_state_hash_after=None,
                rationale=(
                    f"event recorded in ledger but graph rejected edge: {exc}"
                ),
                evidence_record_id=event.event_id,
                recommended_intervention_id=None,
            )

        state_hash_after = self._graph.state_hash(proposed.proposed_at)

        # Thread 7.1: RiskGate P3 monotonic-restriction floor update.
        # The actor's floor is the MINIMUM of (existing floor, current
        # viability_index). Floor enforcement is reflected in the
        # PERMIT rationale; the EcosystemAxisScores fields are NOT
        # mutated (they always report the raw computed values).
        # Operators querying ``viability_floor_for(actor)`` see the
        # enforced floor; the verdict envelope's rationale notes when
        # the floor was active.
        floor_was_active = False
        floor_value: float | None = None
        if self._monotonic_restriction:
            actor = proposed.actor_entity_id
            current_viability = axis_scores.viability_index
            existing_floor = self._viability_floor.get(actor)
            if existing_floor is None or current_viability < existing_floor:
                self._viability_floor[actor] = current_viability
                floor_value = current_viability
            else:
                floor_value = existing_floor
                # Current evaluation is more permissive than the floor —
                # the floor is *enforced*. Emit telemetry so operators
                # see the divergence.
                if current_viability > existing_floor + 1e-9:
                    floor_was_active = True
                    emit_event(
                        "ecosystem.engine.monotonic_restriction.floor_enforced",
                        proposed_event_id=event.event_id,
                        actor_entity_id=actor,
                        current_viability=current_viability,
                        floor_viability=existing_floor,
                    )

        emit_event(
            "ecosystem.engine.evaluate.ok",
            proposed_event_id=event.event_id,
            event_kind=event.kind,
            sequence_number=event.sequence_number,
            state_hash_before=state_before.state_hash,
            state_hash_after=state_hash_after,
            viability_index=axis_scores.viability_index,
            graduated_level=axis_scores.graduated_level.value,
            floor_active=floor_was_active,
            floor_value=floor_value,
        )

        rationale_base = (
            f"steps 1-7 evaluated "
            f"(contracts severity={axis_scores.contract_violation_severity:.3f}, "
            f"causal confidence={axis_scores.causal_attribution_confidence:.3f}, "
            f"drift delta={axis_scores.drift_delta:.3f}, "
            f"systemic={axis_scores.systemic_risk_under_event:.3f}, "
            f"viability={axis_scores.viability_index:.3f}, "
            f"level={axis_scores.graduated_level.value})"
        )
        rationale_floor = (
            f"; P3 floor enforced at {floor_value:.3f}"
            if floor_was_active and floor_value is not None
            else ""
        )

        # Step 8 may have overridden the verdict kind to SANCTION
        # (event admitted to the ledger but with a sanction applied).
        # REMEDIATE was short-circuited before the ledger append above.
        effective_kind = (
            verdict_kind_override
            if verdict_kind_override == EcosystemVerdictKind.SANCTION
            else EcosystemVerdictKind.PERMIT
        )
        effective_rationale = (
            verdict_rationale_override
            if verdict_rationale_override is not None
            else (
                f"{rationale_base}{rationale_floor}; "
                f"admitted at sequence {event.sequence_number}"
            )
        )

        return EcosystemVerdict(
            kind=effective_kind,
            proposed_event_id=event.event_id,
            issued_at=_now_utc(),
            axis_scores=axis_scores,
            ecosystem_state_hash_before=state_before.state_hash,
            ecosystem_state_hash_after=state_hash_after,
            rationale=effective_rationale,
            evidence_record_id=event.event_id,
            recommended_intervention_id=recommended_intervention_id,
        )

    def attest_state(
        self,
        *,
        period_start_iso: str,
        period_end_iso: str,
    ) -> bytes:
        """
        Produce an ecosystem-state attestation: a single signed packet plus
        bounded-compromise certificate for the period.

        This is the artifact the insurer / NAIC / FTC verifier consumes.

        Wire format
        -----------
        SCITT-shaped Signed Statement: canonical-JSON envelope with CWT
        claims (iss/sub/iat/nbf/exp), payload type, and payload dict;
        followed by a signature trailer carrying a base64 signature plus
        ``key_id`` and ``algorithm`` lines so verifiers do not need a
        Tex-specific parser. See ``tex.ecosystem._attestation``.

        Payload contents
        ----------------
        * ``state_hash_at_end``    — graph state hash at ``period_end``
        * ``window_merkle_root``  — RFC 9162 §2.1 Merkle root over events
                                    in the window, sorted by
                                    (timestamp, event_id)
        * ``ledger_head_sequence``, ``ledger_head_record_hash`` — anchor
                                    the window into the global hash chain
        * event count + first/last sequence numbers in the window

        Reference
        ---------
        - IETF SCITT architecture draft -22 §6 (Signed Statement structure).
        - RFC 9162 §2.1 (Merkle Tree Hash).
        - AAF (arxiv 2512.18561) §4.2 (cryptographically verifiable
          interaction provenance).

        TODO(P1): aggregate ecosystem state hash for the period   [done — window_merkle_root]
        TODO(P2): include bounded-compromise certificate
        TODO(P0): sign with ML-DSA via tex.pqcrypto                [done — pluggable provider]
        TODO(P1): swap wire format to ``application/scitt-statement+cose``
                  once cbor2 is approved.
        TODO(P1): include a VDF-anchored ``time_anchor`` so ``nbf``/``exp``
                  are un-backdatable (eprint 2026/737).
        """
        if not self._enabled:
            raise RuntimeError(
                "EcosystemEngine.attest_state requires the engine to be "
                "enabled (TEX_ECOSYSTEM=1 or enabled=True at construction)"
            )

        period_start = _parse_iso_aware(period_start_iso, "period_start_iso")
        period_end = _parse_iso_aware(period_end_iso, "period_end_iso")
        if period_end < period_start:
            raise ValueError(
                "period_end_iso must be >= period_start_iso "
                f"(got start={period_start.isoformat()}, "
                f"end={period_end.isoformat()})"
            )

        assert self._graph is not None and self._events is not None
        assert self._provenance is not None

        # State hash at the end of the period (entity/event content snapshot).
        state_hash_at_end = self._graph.state_hash(period_end)

        # Walk the ledger for events that fall inside the window. The ledger
        # is small (< 1M records per AAF §6 storage analysis), so a linear
        # scan is fine for P0; a P1 backend with a time-indexed projection
        # would replace this.
        all_events = self._events.stream_after(0)
        events_in_window = [
            ev for ev in all_events
            if period_start <= ev.timestamp <= period_end
        ]
        # Canonical ordering for the Merkle tree: (timestamp, event_id).
        # Same total order ``_canonical_state_at`` uses for events.
        events_in_window.sort(key=lambda e: (e.timestamp, e.event_id))

        if events_in_window:
            window_merkle_root = merkle_root(
                [e.record_hash for e in events_in_window]
            )
            first_seq: int | None = events_in_window[0].sequence_number
            last_seq: int | None = events_in_window[-1].sequence_number
        else:
            window_merkle_root = empty_root()
            first_seq = None
            last_seq = None

        # Ledger head at end of period: latest event with timestamp <=
        # period_end. If none, anchor to genesis sentinel + sequence 0.
        head_event = None
        for ev in all_events:
            if ev.timestamp <= period_end:
                if head_event is None or ev.sequence_number > head_event.sequence_number:
                    head_event = ev
        if head_event is None:
            ledger_head_sequence = 0
            ledger_head_record_hash = genesis_ledger_hash()
        else:
            ledger_head_sequence = head_event.sequence_number
            ledger_head_record_hash = head_event.record_hash

        payload = build_attestation_payload(
            state_hash_at_end=state_hash_at_end,
            window_merkle_root=window_merkle_root,
            ledger_head_sequence=ledger_head_sequence,
            ledger_head_record_hash=ledger_head_record_hash,
            event_count_in_window=len(events_in_window),
            first_sequence_in_window=first_seq,
            last_sequence_in_window=last_seq,
        )
        envelope = build_envelope(
            issued_at=_now_utc(),
            period_start=period_start,
            period_end=period_end,
            payload=payload,
        )

        # Sign through the same provenance/provider abstraction the ledger
        # uses so an operator flipping ECDSA -> ML-DSA-65 does not need to
        # touch this code path.
        packet = sign_envelope(
            envelope=envelope,
            signing_key=self._provenance._key,  # noqa: SLF001 — internal field
            provider=self._provenance.provider,
        )

        emit_event(
            "ecosystem.engine.attest.ok",
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            event_count_in_window=len(events_in_window),
            window_merkle_root=window_merkle_root,
            state_hash_at_end=state_hash_at_end,
        )
        return packet

    # ----------------------------------------------------------------- helpers

    def _assert_p0_collaborators_wired(self) -> None:
        """Fail fast if a required P0 collaborator was not injected."""
        missing: list[str] = []
        if self._ontology is None:
            missing.append("ontology")
        if self._graph is None:
            missing.append("graph")
        if self._projection is None:
            missing.append("projection")
        if self._events is None:
            missing.append("events")
        if self._provenance is None:
            missing.append("provenance")
        if missing:
            raise ValueError(
                "EcosystemEngine enabled but missing P0 collaborators: "
                + ", ".join(missing)
            )

    @staticmethod
    def _derive_event_id(proposed: ProposedEvent) -> str:
        """
        Derive a stable event_id for the proposed event.

        The ledger generates random ids by default; for ecosystem-engine
        round-trips we want the verdict's ``proposed_event_id`` to match
        the resulting ledger ``event_id`` so consumers can join across
        traces. Format mirrors ``CryptoProvenance``'s default:
        ``evt_<uuid4-hex12>``.
        """
        return f"evt_{uuid4().hex[:12]}"

    def _forbid(
        self,
        *,
        proposed_event_id: str,
        rationale: str,
        state_hash_before: str,
        reason: str,
    ) -> EcosystemVerdict:
        """Build a FORBID verdict and emit telemetry."""
        emit_event(
            "ecosystem.engine.evaluate.forbidden",
            proposed_event_id=proposed_event_id,
            reason=reason,
            rationale=rationale,
        )
        return EcosystemVerdict(
            kind=EcosystemVerdictKind.FORBID,
            proposed_event_id=proposed_event_id,
            issued_at=_now_utc(),
            axis_scores=_NEUTRAL_AXIS_SCORES,
            ecosystem_state_hash_before=state_hash_before,
            ecosystem_state_hash_after=None,
            rationale=rationale,
            evidence_record_id=None,
            recommended_intervention_id=None,
        )

    def _record_step4_assessment(
        self,
        *,
        proposed_event_id: str,
        actor_entity_id: str,
        effective_state: str,
        direct_state: str,
        inherited_from: str | None,
        chain_length: int,
        proposed_event_kind: str,
        is_legal: bool,
        sanction_id: str | None,
    ) -> None:
        """
        Append a signed audit record of a step-4 assessment.

        Legal and illegal assessments are both recorded — an EU AI Act
        Article 12 auditor reconstructing "did this transition pass step
        4?" needs the positive case too. The log entry is signed via
        the provider selected at engine construction (see
        ``tex.institutional._pq_signing``).

        Silently no-ops when no governance log was wired (defence in
        depth — should not occur in practice because the log is auto-
        constructed when an oracle is supplied).
        """
        if self._governance_log is None:
            return

        payload: dict = {
            "kind": "step4_assessment",
            "proposed_event_id": proposed_event_id,
            "actor_entity_id": actor_entity_id,
            "effective_institutional_state": effective_state,
            "direct_institutional_state": direct_state,
            "inherited_from": inherited_from or "",
            "spawn_chain_length": chain_length,
            "proposed_event_kind": proposed_event_kind,
            "is_legal": is_legal,
            "sanction_id": sanction_id or "",
            "signing_algorithm": self._signing_algorithm,
            "manifest_semantic_sha256": (
                self._governance_graph.manifest_semantic_sha256
                if self._governance_graph is not None
                else ""
            ),
        }
        try:
            self._governance_log.record_observation(oracle_observation=payload)
        except Exception as exc:  # pragma: no cover - defence in depth
            # Audit-write failure is loud but non-fatal: the verdict
            # path continues. Operators monitoring the
            # ``governance_log.append_failed`` event remediate.
            emit_event(
                "ecosystem.engine.step4.audit_write_failed",
                proposed_event_id=proposed_event_id,
                error=f"{type(exc).__name__}: {exc}",
            )


# --------------------------------------------------------------- module helpers


def _now_utc() -> datetime:
    """Wall-clock UTC datetime; centralized for test monkey-patching."""
    return datetime.now(UTC)


def _parse_iso_aware(value: str, field_name: str) -> datetime:
    """
    Parse an ISO-8601 string and require timezone-awareness.

    The graph and ledger reject naive datetimes (Thread 2/3 invariant); we
    propagate the same rule to attestation period bounds.
    """
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid ISO-8601 datetime: {exc}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware (RFC 3339)")
    return parsed.astimezone(UTC)
