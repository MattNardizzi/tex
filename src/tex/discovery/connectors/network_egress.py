"""
Network-egress connector — the headless agent nothing else lists.

A directory shows agents that authenticate through it. A cloud-audit log
shows agents on that cloud. Neither sees the CLI script on a laptop, the
cron job on a forgotten VM, or the server-side daemon holding a personal
API key — agents with no card, no OAuth consent, no directory entry. The
one thing every one of them must do to be an agent is *talk to a model
endpoint over the network.* That egress is the signal.

This plane reads DNS / proxy / VPC-flow metadata and TLS handshake
fingerprints — never payload. Two facets matter:

  * **TLS SNI / the client-provided host header** names the destination
    even on an encrypted connection (the SNI is sent in the clear), so a
    connection to ``api.openai.com`` or ``bedrock-runtime.us-east-1.
    amazonaws.com`` is visible without decryption.
  * **JA3 / JA4 fingerprints** hash the TLS ClientHello (and, for JA4, the
    later handshake), so the *client stack* — the SDK / runtime making the
    call — has a stable fingerprint even as IPs and certs rotate. JA4 is
    the current generation; JA3 is kept for backward correlation.

The signal is ``NETWORK_OBSERVED``: out-of-process, at a chokepoint the
workload cannot bypass while still reaching a model. The workload cannot
suppress that it connected. Metadata only — the privacy line the gate
holds, this plane holds too.

Real connector replacement: implement ``_run_scan`` against a Zeek/Suricata
feed, a forward-proxy access log, or VPC flow logs joined to a JA4
fingerprint store, grouping flows by (workload source, JA4, SNI). The
fields below map directly.

DELEGATION (the SIEVE network-egress collector is the single source of truth):
this connector now delegates its flow parsing + grouping to the engine sensor's
collector (``engine.sensors.network_egress``) so the flow-feature extractor —
including the behavioral ``token_waveform_sig`` / ``cadence_sig`` axis the old
inline grouper lacked — lives in exactly one place. This connector remains the
``DiscoverySource``-shaped output adapter (it still emits ``CandidateAgent``);
its class name, constructor signature, and the ``(workload, ja4, sni)`` grouping
behavior the witness-layer tests assert are preserved (flows with no behavioral
facets collapse to one group per workload/ja4/sni exactly as before).
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.discovery.engine.sensors.network_egress import (
    EgressGroup,
    group_flows,
    parse_ocsf_flow_records,
    provider_for_host as _provider_for_host,
)
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)


class NetworkEgressConnector(BaseConnector):
    """
    Mock network-egress connector.

    Accepts flow records shaped like proxy/VPC-flow + TLS metadata:

        {
          "source_workload": "vm-build-07" | "laptop-mnardizzi",
          "sni": "api.openai.com",
          "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
          "ja3": "769,47-53-5-10-...,0-11-10,29-23-24,0",
          "first_seen": "2026-...Z",
          "last_seen": "2026-...Z",
          "bytes_out": 184320,
          "connection_count": 42
        }

    Flows are grouped by (source_workload, ja4, sni) into one CandidateAgent
    each, only when the SNI resolves to a known model endpoint — an egress
    to a non-model host is not evidence of an agent.
    """

    def __init__(self, *, flows: list[dict[str, Any]] | None = None) -> None:
        super().__init__(source=DiscoverySource.NETWORK_EGRESS, name="network_egress_mock")
        self._flows = list(flows or [])

    def replace_flows(self, flows: list[dict[str, Any]]) -> None:
        self._flows = list(flows)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        # Delegate parsing + behavioral grouping to the SIEVE collector. It
        # drops non-model egress, groups on the behavioral key (workload/ja4/sni
        # + token_waveform_sig/cadence_sig), and returns aggregated EgressGroups.
        groups = group_flows(parse_ocsf_flow_records(self._flows))
        for group in groups:
            # A connector candidate needs the legacy ``(workload, ja4, sni)``
            # tuple to form a stable external id; a group missing any of them is
            # not connector-emittable (the engine SENSOR still emits it as an
            # Incidence on whatever facets it has).
            if not (group.source_workload and group.ja4 and group.sni):
                continue
            yield self._build_candidate(group, context)

    def _build_candidate(
        self,
        group: EgressGroup,
        context: ConnectorContext,
    ) -> CandidateAgent:
        workload = group.source_workload or ""
        ja4 = group.ja4 or ""
        sni = group.sni or ""
        provider = group.provider or "unknown"
        connections = group.connection_count

        # A stable, content-free external id: the workload + client
        # fingerprint + destination. Survives IP and cert rotation, which
        # is the whole point of fingerprinting the client stack.
        external_id = hashlib.sha256(
            f"{workload}|{ja4}|{sni}".encode("utf-8")
        ).hexdigest()[:32]

        # An egress-only agent is unmanaged by definition — nothing else
        # listed it — so the risk floor is elevated.
        risk = DiscoveryRiskBand.HIGH if connections >= 50 else DiscoveryRiskBand.MEDIUM

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=("model_inference",),
            inferred_recipient_domains=(sni.casefold(),),
        )

        evidence: dict[str, Any] = {
            "source_workload": workload,
            "ja4": ja4,
            "sni": sni,
            "model_provider": provider,
            "connection_count": connections,
            "signal": "tls_egress_observation",
            "metadata_only": True,
            "catches": "headless/CLI/server agents with no card or directory entry",
        }
        # Surface the behavioral axis the collector now derives (the old grouper
        # had none) so the connector evidence carries the agent-vs-human /
        # two-agents-behind-one-egress tells too.
        if group.token_waveform_sig:
            evidence["token_waveform_sig"] = group.token_waveform_sig
        if group.cadence_sig:
            evidence["cadence_sig"] = group.cadence_sig
        if group.packetization_mode:
            evidence["packetization_mode"] = group.packetization_mode

        return CandidateAgent(
            source=DiscoverySource.NETWORK_EGRESS,
            tenant_id=context.tenant_id,
            external_id=external_id,
            name=f"egress:{workload}→{provider}",
            model_provider_hint=provider,
            framework_hint="unknown_egress",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk,
            confidence=0.82,
            capability_hints=capability_hints,
            last_seen_active_at=group.last_seen or group.first_seen,
            evidence=evidence,
            tags=("network_egress", "shadow", "metadata_only"),
        )
