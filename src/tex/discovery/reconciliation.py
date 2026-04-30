"""
Reconciliation engine.

The reconciliation engine is the part of the discovery layer that
makes Tex structurally different from Zenity and Noma's discovery
products. Their output is a dashboard. Tex's output is a registry
action: every CandidateAgent that crosses a confidence threshold is
either promoted to a real AgentIdentity, used to update an existing
agent's capability surface, or used to trigger a lifecycle transition
into QUARANTINED. The next action the agent takes lands in fusion
with the discovery provenance already attached.

Decision matrix the engine implements:

  reconciliation_key not in registry
    └─ confidence >= AUTO_REGISTER_THRESHOLD
       └─ surface_unbounded == False           → REGISTER (NEW_AGENT)
       └─ surface_unbounded == True            → HOLD AS AMBIGUOUS
    └─ confidence <  AUTO_REGISTER_THRESHOLD   → NO_OP_BELOW_THRESHOLD

  reconciliation_key in registry, agent ACTIVE
    └─ no drift                                → NO_OP_KNOWN_UNCHANGED
    └─ drift below QUARANTINE threshold         → UPDATE (UPDATED_DRIFT)
    └─ drift above QUARANTINE threshold         → QUARANTINE (QUARANTINED_FOR_DRIFT)

  reconciliation_key in registry, agent REVOKED
    └─                                          → SKIP (SKIPPED_REVOKED)

  reconciliation_key in registry, agent QUARANTINED or PENDING
    └─ keep updating capability surface drift
       so the operator has fresh information
       when they decide to clear quarantine    → UPDATE (UPDATED_DRIFT)

The engine is pure: it returns a ReconciliationOutcome and any
side-effects it wants applied. The DiscoveryService below is the
thing that actually mutates the registry and writes the ledger. This
keeps the core decision logic unit-testable without hitting any
stores.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    CapabilitySurface,
)
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryFindingKind,
    ReconciliationAction,
    ReconciliationOutcome,
)


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Confidence at which we will auto-register a candidate as a new agent.
# Below this we hold and mark NO_OP_BELOW_THRESHOLD; the operator can
# review held candidates via the API.
AUTO_REGISTER_THRESHOLD: float = 0.80

# Drift score above which we transition a known agent to QUARANTINED
# instead of just updating its capability surface. Drift is defined
# below in `_capability_drift`.
QUARANTINE_DRIFT_THRESHOLD: float = 0.60


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    """
    Pure decision returned by the engine.

    The DiscoveryService converts this into actual mutations.
    Splitting these allows reconciliation to be tested with no stores
    and lets the service own all I/O concerns.
    """

    outcome: ReconciliationOutcome
    new_agent: AgentIdentity | None = None
    update_capability_surface_for: AgentIdentity | None = None
    new_capability_surface: CapabilitySurface | None = None
    quarantine_agent_id: AgentIdentity | None = None


class ReconciliationEngine:
    """
    Stateless engine that turns one candidate into one decision.

    The engine takes the candidate and the existing AgentIdentity (if
    any) and produces a ReconciliationDecision. It does not touch any
    store. That makes it deterministic and trivial to unit-test.
    """

    def __init__(
        self,
        *,
        auto_register_threshold: float = AUTO_REGISTER_THRESHOLD,
        quarantine_drift_threshold: float = QUARANTINE_DRIFT_THRESHOLD,
    ) -> None:
        if not 0.0 <= auto_register_threshold <= 1.0:
            raise ValueError("auto_register_threshold must be in [0, 1]")
        if not 0.0 <= quarantine_drift_threshold <= 1.0:
            raise ValueError("quarantine_drift_threshold must be in [0, 1]")
        self._auto_register_threshold = auto_register_threshold
        self._quarantine_drift_threshold = quarantine_drift_threshold

    def decide(
        self,
        *,
        candidate: CandidateAgent,
        existing: AgentIdentity | None,
    ) -> ReconciliationDecision:
        """
        Decide what to do with one candidate.

        Branches are exclusive; exactly one outcome is produced. The
        outcome's `findings` carry the human-readable reasons so the
        ledger entry tells the audit story.
        """

        if existing is None:
            return self._handle_new(candidate)

        if existing.lifecycle_status is AgentLifecycleStatus.REVOKED:
            return _decision(
                _outcome(
                    candidate=candidate,
                    finding_kind=DiscoveryFindingKind.DUPLICATE,
                    action=ReconciliationAction.SKIPPED_REVOKED,
                    confidence=candidate.confidence,
                    findings=(
                        f"Candidate matches revoked agent {existing.agent_id}; "
                        "skipped to keep revoke terminal.",
                    ),
                )
            )

        return self._handle_known(candidate, existing)

    # ------------------------------------------------------------------ helpers

    def _handle_new(self, candidate: CandidateAgent) -> ReconciliationDecision:
        if candidate.confidence < self._auto_register_threshold:
            return _decision(
                _outcome(
                    candidate=candidate,
                    finding_kind=DiscoveryFindingKind.NEW_AGENT,
                    action=ReconciliationAction.NO_OP_BELOW_THRESHOLD,
                    confidence=candidate.confidence,
                    findings=(
                        f"Confidence {candidate.confidence:.2f} below auto-register "
                        f"threshold {self._auto_register_threshold:.2f}; held for "
                        "operator review.",
                    ),
                )
            )

        if candidate.capability_hints.surface_unbounded:
            return _decision(
                _outcome(
                    candidate=candidate,
                    finding_kind=DiscoveryFindingKind.AMBIGUOUS,
                    action=ReconciliationAction.HELD_AMBIGUOUS,
                    confidence=candidate.confidence,
                    findings=(
                        "Connector reports an unbounded capability surface; "
                        "auto-registration disabled. Operator must review "
                        "before this agent is allowed to operate.",
                    ),
                )
            )

        # Build the new AgentIdentity with the proposed surface.
        proposed_surface = _surface_from_hints(candidate)
        proposed_trust_tier = candidate.risk_band.suggested_trust_tier
        proposed_environment = candidate.environment_hint
        if not isinstance(proposed_environment, AgentEnvironment):
            proposed_environment = AgentEnvironment.PRODUCTION

        owner = candidate.owner_hint or "discovery@tex"
        new_agent = AgentIdentity(
            name=candidate.name,
            owner=owner,
            description=candidate.description,
            tenant_id=candidate.tenant_id,
            model_provider=candidate.model_provider_hint,
            model_name=candidate.model_name_hint,
            framework=candidate.framework_hint,
            environment=proposed_environment,
            trust_tier=proposed_trust_tier,
            lifecycle_status=AgentLifecycleStatus.PENDING,
            capability_surface=proposed_surface,
            tags=tuple(sorted({*candidate.tags, "discovered"})),
            metadata={
                "discovery_source": str(candidate.source),
                "discovery_external_id": candidate.external_id,
                "discovery_risk_band": str(candidate.risk_band),
            },
        )

        outcome = _outcome(
            candidate=candidate,
            finding_kind=DiscoveryFindingKind.NEW_AGENT,
            action=ReconciliationAction.REGISTERED,
            confidence=candidate.confidence,
            resulting_agent_id=new_agent.agent_id,
            findings=(
                f"Auto-registered new agent {new_agent.agent_id} from "
                f"{candidate.source}.",
                f"Proposed capability surface: action_types="
                f"{list(proposed_surface.allowed_action_types)}, "
                f"channels={list(proposed_surface.allowed_channels)}.",
            ),
        )

        return _decision(outcome=outcome, new_agent=new_agent)

    def _handle_known(
        self,
        candidate: CandidateAgent,
        existing: AgentIdentity,
    ) -> ReconciliationDecision:
        proposed_surface = _surface_from_hints(candidate)
        drift_score, drift_findings = _capability_drift(
            existing.capability_surface, proposed_surface
        )

        if drift_score == 0.0:
            return _decision(
                _outcome(
                    candidate=candidate,
                    finding_kind=DiscoveryFindingKind.KNOWN_AGENT_UNCHANGED,
                    action=ReconciliationAction.NO_OP_KNOWN_UNCHANGED,
                    confidence=candidate.confidence,
                    resulting_agent_id=existing.agent_id,
                    findings=(
                        f"Candidate matches known agent {existing.agent_id}; "
                        "no capability surface drift.",
                    ),
                )
            )

        if drift_score >= self._quarantine_drift_threshold:
            return _decision(
                _outcome(
                    candidate=candidate,
                    finding_kind=DiscoveryFindingKind.KNOWN_AGENT_DRIFT,
                    action=ReconciliationAction.QUARANTINED_FOR_DRIFT,
                    confidence=candidate.confidence,
                    resulting_agent_id=existing.agent_id,
                    findings=(
                        f"Drift score {drift_score:.2f} >= quarantine threshold "
                        f"{self._quarantine_drift_threshold:.2f}; agent quarantined.",
                        *drift_findings,
                    ),
                ),
                quarantine_agent_id=existing,
            )

        return _decision(
            _outcome(
                candidate=candidate,
                finding_kind=DiscoveryFindingKind.KNOWN_AGENT_DRIFT,
                action=ReconciliationAction.UPDATED_DRIFT,
                confidence=candidate.confidence,
                resulting_agent_id=existing.agent_id,
                findings=(
                    f"Drift score {drift_score:.2f}; capability surface widened.",
                    *drift_findings,
                ),
            ),
            update_capability_surface_for=existing,
            new_capability_surface=proposed_surface,
        )


# ---------------------------------------------------------------------------
# Pure helpers — used by the engine and exported for tests
# ---------------------------------------------------------------------------


def _surface_from_hints(candidate: CandidateAgent) -> CapabilitySurface:
    """Translate connector hints into a Tex CapabilitySurface."""
    hints = candidate.capability_hints
    return CapabilitySurface(
        allowed_action_types=hints.inferred_action_types,
        allowed_channels=hints.inferred_channels,
        allowed_environments=(str(candidate.environment_hint).casefold(),),
        allowed_recipient_domains=hints.inferred_recipient_domains,
        allowed_tools=hints.inferred_tools,
        allowed_mcp_servers=hints.inferred_mcp_servers,
        data_scopes=hints.inferred_data_scopes,
    )


def _capability_drift(
    existing: CapabilitySurface,
    proposed: CapabilitySurface,
) -> tuple[float, tuple[str, ...]]:
    """
    Compute a drift score in [0, 1] between two capability surfaces.

    Drift = fraction of dimensions where the proposed surface adds
    new entries that the existing surface did not have. Entries that
    were removed from existing → proposed are not penalized; that is
    "narrowing," not drift. We only flag widening, because widening
    is the dangerous direction: an agent suddenly gaining new
    permissions on the platform side is a signal of compromise or
    operator misconfiguration.

    Returns the score plus a tuple of human-readable findings naming
    which dimensions drifted.
    """

    findings: list[str] = []
    drift_signals: list[float] = []

    pairs = (
        ("action_types", existing.allowed_action_types, proposed.allowed_action_types),
        ("channels", existing.allowed_channels, proposed.allowed_channels),
        (
            "recipient_domains",
            existing.allowed_recipient_domains,
            proposed.allowed_recipient_domains,
        ),
        ("tools", existing.allowed_tools, proposed.allowed_tools),
        ("mcp_servers", existing.allowed_mcp_servers, proposed.allowed_mcp_servers),
        ("data_scopes", existing.data_scopes, proposed.data_scopes),
    )

    for dimension, existing_set, proposed_set in pairs:
        new_entries = sorted(set(proposed_set) - set(existing_set))
        if not new_entries:
            drift_signals.append(0.0)
            continue
        # Drift on this dimension scales with how many new entries
        # appeared, capped at 1.0. A single new tool is a small
        # signal; ten new tools is a strong one.
        signal = min(1.0, len(new_entries) / 4.0)
        drift_signals.append(signal)
        findings.append(
            f"{dimension}: discovered new entries {new_entries} "
            f"not present in existing surface."
        )

    if not drift_signals:
        return 0.0, tuple()

    drift_score = sum(drift_signals) / len(drift_signals)
    return drift_score, tuple(findings)


def _outcome(
    *,
    candidate: CandidateAgent,
    finding_kind: DiscoveryFindingKind,
    action: ReconciliationAction,
    confidence: float,
    resulting_agent_id=None,
    findings: tuple[str, ...] = tuple(),
) -> ReconciliationOutcome:
    """Compact constructor for ReconciliationOutcome."""
    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=candidate.reconciliation_key,
        finding_kind=finding_kind,
        action=action,
        confidence=confidence,
        resulting_agent_id=resulting_agent_id,
        findings=findings,
    )


def _decision(
    outcome: ReconciliationOutcome,
    *,
    new_agent: AgentIdentity | None = None,
    update_capability_surface_for: AgentIdentity | None = None,
    new_capability_surface: CapabilitySurface | None = None,
    quarantine_agent_id: AgentIdentity | None = None,
) -> ReconciliationDecision:
    return ReconciliationDecision(
        outcome=outcome,
        new_agent=new_agent,
        update_capability_surface_for=update_capability_surface_for,
        new_capability_surface=new_capability_surface,
        quarantine_agent_id=quarantine_agent_id,
    )
