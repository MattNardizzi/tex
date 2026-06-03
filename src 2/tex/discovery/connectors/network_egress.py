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
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Iterable

from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)

# Current LLM / agent API egress destinations (SNI / host header → provider).
# Kept conservative and updatable; matched as a suffix so regional
# subdomains (bedrock-runtime.us-east-1.amazonaws.com) resolve too.
_MODEL_ENDPOINTS: dict[str, str] = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
    "aiplatform.googleapis.com": "google_vertex",
    "bedrock-runtime.amazonaws.com": "aws_bedrock",
    "bedrock-agentcore.amazonaws.com": "aws_bedrock_agentcore",
    "api.cohere.ai": "cohere",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "openai.azure.com": "azure_openai",
}


def _provider_for_host(host: str) -> str | None:
    low = host.casefold()
    for suffix, provider in _MODEL_ENDPOINTS.items():
        if low == suffix or low.endswith("." + suffix) or suffix in low:
            return provider
    return None


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
        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for flow in self._flows:
            sni = str(flow.get("sni", "")).strip()
            if not sni or _provider_for_host(sni) is None:
                continue  # only model-endpoint egress is agent evidence
            workload = str(flow.get("source_workload", "")).strip()
            ja4 = str(flow.get("ja4") or flow.get("ja3") or "").strip()
            if not workload or not ja4:
                continue
            grouped[(workload, ja4, sni)].append(flow)

        for (workload, ja4, sni), flows in grouped.items():
            yield self._build_candidate(workload, ja4, sni, flows, context)

    def _build_candidate(
        self,
        workload: str,
        ja4: str,
        sni: str,
        flows: list[dict[str, Any]],
        context: ConnectorContext,
    ) -> CandidateAgent:
        provider = _provider_for_host(sni) or "unknown"
        first = min(
            (_parse_iso(f.get("first_seen")) for f in flows if f.get("first_seen")),
            default=None,
        )
        last = max(
            (_parse_iso(f.get("last_seen")) for f in flows if f.get("last_seen")),
            default=first,
        )
        connections = sum(int(f.get("connection_count", 1)) for f in flows)

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

        evidence = {
            "source_workload": workload,
            "ja4": ja4,
            "sni": sni,
            "model_provider": provider,
            "connection_count": connections,
            "signal": "tls_egress_observation",
            "metadata_only": True,
            "catches": "headless/CLI/server agents with no card or directory entry",
        }

        return CandidateAgent(
            source=DiscoverySource.NETWORK_EGRESS,
            tenant_id=context.tenant_id,
            external_id=external_id,
            name=f"egress:{workload}\u2192{provider}",
            model_provider_hint=provider,
            framework_hint="unknown_egress",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk,
            confidence=0.82,
            capability_hints=capability_hints,
            last_seen_active_at=last,
            evidence=evidence,
            tags=("network_egress", "shadow", "metadata_only"),
        )


def _parse_iso(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None
