"""
OCSF audit connector — the agentless, tamper-resistant catch.

The IdP consent graph (the seamless one-grant core) sees every agent that
authenticates through the directory. It cannot see the one that does not —
the headless script on a laptop with a personal key, the container agent
that never registered. Those still leave a trace the moment they *act*,
because their action lands in a control-plane audit log the workload cannot
suppress. Reading that log is how the shadow agent the directory missed is
caught — as actions, agentlessly, at ``AUDIT_LOG`` admissibility.

This connector consumes OCSF-normalized audit events (see ``ocsf``), groups
them by the acting agent's stable handle (a resource ARN or principal id),
and emits one ``CandidateAgent`` per distinct agent, carrying the operations
it was seen performing as capability hints. It is live-capable through an
injected ``source``: a deployment points it at a Security Lake OCSF feed, a
CloudTrail Lake query, or any OCSF-speaking SIEM. Tests inject a fixture
source. The grouping and emission logic is identical in both.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Iterable

from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.discovery.ocsf import OcsfEvent, normalize
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)

# A source is any callable that, given the run context, returns an iterable
# of raw audit records. The connector normalizes them through OCSF.
AuditSource = Callable[[ConnectorContext], Iterable[dict[str, Any]]]


class OcsfAuditConnector(BaseConnector):
    """
    Agentless audit-plane connector over OCSF events.

    Construct with a ``source`` (the records reader) and a ``source_format``
    (``"ocsf"`` for Security Lake, ``"cloudtrail"`` for a raw trail). ``scan``
    normalizes, groups by acting agent, and emits candidates at AUDIT_LOG
    admissibility.
    """

    def __init__(
        self,
        *,
        source: AuditSource,
        source_format: str = "ocsf",
    ) -> None:
        super().__init__(source=DiscoverySource.CLOUD_AUDIT, name="ocsf_audit")
        self._source = source
        self._source_format = source_format

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        raw = self._source(context)
        events = list(normalize(raw, source_format=self._source_format))

        # Group by the agent's stable handle.
        by_agent: dict[str, list[OcsfEvent]] = defaultdict(list)
        for ev in events:
            by_agent[ev.actor_id].append(ev)

        for handle, agent_events in by_agent.items():
            yield self._candidate(handle, agent_events, context)

    def _candidate(
        self, handle: str, events: list[OcsfEvent], context: ConnectorContext
    ) -> CandidateAgent:
        events.sort(key=lambda e: e.occurred_at)
        last = events[-1]
        operations = sorted({e.activity for e in events})
        vendor = last.product_vendor
        product = last.product_name

        # Audit volume is a weak risk signal on its own; lean conservative.
        # A high count of distinct privileged-looking operations nudges up.
        privileged = sum(
            1 for op in operations
            if any(k in op.lower() for k in ("delete", "create", "put", "write", "invoke"))
        )
        if privileged >= 4:
            risk = DiscoveryRiskBand.HIGH
        elif privileged >= 1:
            risk = DiscoveryRiskBand.MEDIUM
        else:
            risk = DiscoveryRiskBand.LOW

        hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(operations),
        )

        return CandidateAgent(
            source=DiscoverySource.CLOUD_AUDIT,
            tenant_id=context.tenant_id,
            external_id=handle,
            name=last.actor_name or handle,
            description=f"Observed acting via {product} ({len(events)} events).",
            model_provider_hint=vendor.lower() if vendor != "unknown" else None,
            framework_hint=product.lower() if product != "unknown" else None,
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk,
            confidence=0.92,  # the workload cannot suppress that it acted
            capability_hints=hints,
            last_seen_active_at=last.occurred_at,
            evidence={
                "event_count": len(events),
                "operations": operations,
                "resource_arn": last.resource_arn,
                "log_vendor": vendor,
                "log_product": product,
                "discovered_via": "audit_plane_ocsf",
            },
            tags=("audit", "agentless", vendor.lower()) if vendor != "unknown" else ("audit", "agentless"),
        )
