"""
Kernel-eBPF connector — the signal the workload cannot reach.

The top of the admissibility hierarchy. Every other plane observes the
agent through something the agent talks to: a directory it authenticates
against, an API whose audit log it triggers, a network it egresses over.
A kernel observation is different in kind — an eBPF program attached to a
kernel hook sees the process *from underneath*. The workload cannot forge
it, cannot suppress it, and cannot even tell it is there. Paired with a
hardware/TEE measurement of the running code, this is identity anchored to
*what is actually executing*, not to anything the agent asserts.

Modelled on Cilium Tetragon's event shape (verified June 2026):
``process_exec`` / ``process_exit`` events from kprobes on ``execve``,
each enriched with the binary path, arguments, process lineage, the
container/pod identity, and — where measured boot / TEE attestation is
present — the measured code hash. Tetragon filters and aggregates in the
kernel (<1% overhead) and exports JSON to user space.

A measured-code hash is the strongest behavioural anchor Tex can carry:
it survives credential rotation and rename completely, because it is the
hash of the code itself. The admissibility grade stays *revisable* — if a
TEE-shielding method is later broken, the sealed ``attestation_method``
lets every certificate that relied on it be found and re-graded (§4).

Real connector replacement: implement ``_run_scan`` against the Tetragon
gRPC event stream (or a JSON export), correlating ``process_exec`` events
that load a known agent runtime/binary into one CandidateAgent per
(measured_code_hash, pod). The fields below map directly.
"""

from __future__ import annotations

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

# Binaries / interpreters that, when observed executing an agent entry
# point, indicate an AI agent runtime. A real deployment matches on the
# measured code hash against a known-runtime catalogue; the mock matches
# on the binary basename for shape.
_AGENT_RUNTIME_HINTS = (
    "python",
    "node",
    "uv",
    "agent",
    "langgraph",
    "crewai",
    "autogen",
    "ollama",
)


class KernelEbpfConnector(BaseConnector):
    """
    Mock kernel-eBPF connector.

    Accepts ``process_exec``-shaped events:

        {
          "binary": "/usr/bin/python3.12",
          "args": "-m agent.main --serve",
          "pod": "ns/agents/pod/order-bot-7c9",
          "container_image": "registry/order-bot@sha256:...",
          "measured_code_hash": "sha256:...",     # from measured boot / TEE
          "attestation_method": "intel_tdx" | "amd_sev_snp" | "measured_boot" | None,
          "parent_binary": "/sbin/init",
          "exec_time": "2026-...Z",
          "syscall_profile": ["connect", "openat", "execve"]
        }

    Events are grouped by (measured_code_hash or pod) into one
    CandidateAgent each, with ``KERNEL_ATTESTED`` admissibility.
    """

    def __init__(self, *, events: list[dict[str, Any]] | None = None) -> None:
        super().__init__(source=DiscoverySource.KERNEL_EBPF, name="kernel_ebpf_mock")
        self._events = list(events or [])

    def replace_events(self, events: list[dict[str, Any]]) -> None:
        self._events = list(events)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self._events:
            if not _looks_like_agent_runtime(event):
                continue
            key = str(
                event.get("measured_code_hash")
                or event.get("pod")
                or event.get("binary")
                or ""
            ).strip()
            if not key:
                continue
            grouped[key].append(event)

        for key, events in grouped.items():
            yield self._build_candidate(key, events, context)

    def _build_candidate(
        self,
        key: str,
        events: list[dict[str, Any]],
        context: ConnectorContext,
    ) -> CandidateAgent:
        sample = events[0]
        measured = sample.get("measured_code_hash")
        attestation_method = sample.get("attestation_method")
        pod = str(sample.get("pod", "")).strip()
        binary = str(sample.get("binary", "")).strip()
        latest = max(
            (_parse_iso(e.get("exec_time")) for e in events if e.get("exec_time")),
            default=None,
        )
        syscalls = sorted(
            {
                s.casefold()
                for e in events
                for s in (e.get("syscall_profile") or [])
                if isinstance(s, str)
            }
        )

        # An attested, measured agent is the highest-confidence discovery
        # Tex can make. Without a measurement (kprobe only, no TEE) it is
        # still kernel-observed, just slightly less.
        attested = bool(measured)
        confidence = 0.98 if attested else 0.9

        name = pod.rsplit("/", 1)[-1] if pod else (binary.rsplit("/", 1)[-1] or key[:16])

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(syscalls[:8]),
            inferred_tools=tuple(),
        )

        evidence = {
            "measured_code_hash": measured,
            "attestation_method": attestation_method,  # sealed so the grade is revisable
            "pod": pod or None,
            "container_image": sample.get("container_image"),
            "binary": binary or None,
            "parent_binary": sample.get("parent_binary"),
            "exec_count": len(events),
            "signal": "kernel_ebpf_observation",
            "workload_can_reach_signal": False,
        }

        return CandidateAgent(
            source=DiscoverySource.KERNEL_EBPF,
            tenant_id=context.tenant_id,
            external_id=key,
            name=name,
            framework_hint=_framework_from_args(sample.get("args")),
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=DiscoveryRiskBand.MEDIUM,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=latest,
            evidence=evidence,
            tags=("kernel_ebpf", "attested" if attested else "kernel_observed"),
        )


def _looks_like_agent_runtime(event: dict[str, Any]) -> bool:
    blob = " ".join(
        str(event.get(k, "")) for k in ("binary", "args", "container_image")
    ).casefold()
    return any(hint in blob for hint in _AGENT_RUNTIME_HINTS)


def _framework_from_args(args: Any) -> str | None:
    if not isinstance(args, str):
        return None
    low = args.casefold()
    for fw in ("langgraph", "crewai", "autogen", "ollama"):
        if fw in low:
            return fw
    return None


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
