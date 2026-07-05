"""
SIEVE sensor REGISTRY — the flag-gated activation seam for the plane roster.

This is the single place that maps every breadth plane (ARCHITECTURE.md §8
P0..P14) to (a) its activation env flag and (b) a factory that constructs the
plane's ``EngineSensor``. ``build_active_sensors(env)`` returns ONLY the sensors
whose flag is enabled in ``env`` — so nothing activates without its
``TEX_SIEVE_P*_*`` flag, and the default (no flags set) yields an empty list.

Why this exists (the contracts-pass deliverable):

- It fixes the EXACT factory signature the ten parallel sensor builders register
  against, so their work coheres without touching each other or ``fuse.py``.
- It enforces the two HARD RULES at the activation boundary:
  1. **Flag-gated OFF by default** — a plane is only built when ``env`` carries a
     truthy value for its flag (ARCHITECTURE.md §8 default-safe table). A merge
     to main auto-deploys prod; an absent flag MUST leave the plane inert.
  2. **Degrade to EMPTY, never raise** — a factory that cannot construct its
     sensor (missing creds / unreachable source / unavailable kernel tap)
     returns an empty sensor instead of raising, exactly like
     ``ConduitConnectionsConnector`` returning inert when unconnected. The
     registry wraps every factory so even a raising factory degrades to the
     ``_EmptySensor`` rather than crashing boot or a scan.

The registry imports NO connector eagerly at module load — the slice sensors are
the only hard imports (they are pure-stdlib file readers). Roster factories
import their source connector lazily INSIDE the factory, so a missing optional
dependency degrades that one plane to empty rather than breaking the import of
the whole registry. Until a builder lands a real factory, its slot is the
``_empty_factory`` (returns an inert sensor) so ``build_active_sensors`` is total
over the whole roster and the flag-gating contract is testable today.

Factory signature (the contract the ten builders register against)::

    SensorFactory = Callable[[Mapping[str, str]], EngineSensor]

A factory receives the same ``env`` mapping ``build_active_sensors`` was given
(so it can read its source path / endpoint / credential env vars) and returns an
``EngineSensor``. It MUST NOT raise; on any missing input it returns a sensor
whose ``sense`` yields nothing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from tex.discovery.engine.models import Incidence, PlaneId
from tex.discovery.engine.sensors.actions_trail import ActionsTrailSensor
from tex.discovery.engine.sensors.base import EngineSensor, SenseContext
from tex.discovery.engine.sensors.fs_write_scan import FsWriteScanSensor
from tex.discovery.engine.sensors.governance_stream import (
    build_governance_stream_sensor,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The factory contract the ten plane builders register against
# ---------------------------------------------------------------------------

#: Every roster sensor is built by a factory of this exact shape. It is handed
#: the process ``env`` mapping (so it can read its own source path / endpoint /
#: credential vars) and returns a constructed ``EngineSensor``. It MUST degrade
#: to an empty sensor (never raise) when its source/creds are absent.
SensorFactory = Callable[[Mapping[str, str]], EngineSensor]


@dataclass(frozen=True)
class _EmptySensor:
    """A faithful inert sensor: declares its plane, senses nothing.

    Used (a) as the default-safe degrade when a real factory cannot construct
    its sensor, and (b) as the placeholder a not-yet-built plane slot returns so
    the registry is total over the whole roster. It satisfies ``EngineSensor``
    (``plane_id`` + ``sense``) and always yields an empty iterable — the literal
    "degrade to EMPTY, never raise" rule.
    """

    plane_id: PlaneId

    def sense(self, context: SenseContext) -> Iterable[Incidence]:
        return ()


def _empty_factory_for(plane_id: PlaneId) -> SensorFactory:
    """A factory that always returns the inert sensor for ``plane_id``.

    The default slot for any roster plane whose real builder has not landed yet,
    and the value a flag-enabled-but-unbuilt plane resolves to (so enabling a
    flag for an unbuilt plane is safe — it simply senses nothing).
    """

    def _factory(env: Mapping[str, str]) -> EngineSensor:  # noqa: ARG001
        return _EmptySensor(plane_id=plane_id)

    return _factory


def _safe(plane_id: PlaneId, factory: SensorFactory) -> SensorFactory:
    """Wrap a factory so a raise degrades to the inert sensor (never crashes).

    This is the registry-level enforcement of "never raise": even a buggy or
    dependency-missing factory cannot break boot or a scan — it falls back to
    ``_EmptySensor`` for its plane and logs at INFO (coverage was partial), the
    same posture as a connector degrading when unconnected.
    """

    def _wrapped(env: Mapping[str, str]) -> EngineSensor:
        try:
            sensor = factory(env)
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info(
                "sieve: plane %s factory degraded to empty: %s", plane_id.value, exc
            )
            return _EmptySensor(plane_id=plane_id)
        if sensor is None:  # a factory that returned nothing also degrades safe
            return _EmptySensor(plane_id=plane_id)
        return sensor

    return _wrapped


# ---------------------------------------------------------------------------
# Slice-sensor factories (the two REAL planes already built + green)
# ---------------------------------------------------------------------------


def _actions_trail_factory(env: Mapping[str, str]) -> EngineSensor:  # noqa: ARG001
    """Occasion A — the actions-trail plane. Pure file reader; never raises.

    The source directory is supplied at sense-time via ``SenseContext.actions_dir``
    (configurable so a verifier can point it at a planted directory), so the
    factory needs no env to construct; a missing/empty directory degrades the
    sensor's ``sense`` to empty.
    """
    return ActionsTrailSensor()


def _fs_write_factory(env: Mapping[str, str]) -> EngineSensor:  # noqa: ARG001
    """Occasion B — the fs-write-scan plane. Pure file reader; never raises."""
    return FsWriteScanSensor()


def _network_egress_factory(env: Mapping[str, str]) -> EngineSensor:
    """P1–P4 network-egress plane (the universal passive net).

    Imported lazily so the network-egress module loads only when its flag is
    enabled. The factory reads the labeled local fixture-shim path from
    ``TEX_SIEVE_P1_FLOW_FIXTURE`` and degrades to an empty sensor when no
    source/fixture is present (a live deployment re-registers with its real
    Zeek/OCSF feed wrapped as a ``FlowSource``). Never raises.
    """
    from tex.discovery.engine.sensors.network_egress import (
        build_network_egress_sensor,
    )

    return build_network_egress_sensor(env)


def _saas_automation_factory(env: Mapping[str, str]) -> EngineSensor:
    """P5/P10 — the SaaS/automation plane (Slack/SF/GitHub bots + OAuth + RPA).

    Wraps the existing discovery connectors as SaaS signal SOURCES. Builds a LIVE
    source only when its credential env var is present (e.g. ``SLACK_TOKEN``) and
    NO sources otherwise, so a flag-enabled-but-uncredentialed env senses empty
    (the §8 default-safe degrade). Imports its builder LAZILY inside the factory
    so a missing optional dependency degrades this one plane to empty rather than
    breaking the registry import.
    """
    from tex.discovery.engine.sensors.saas_automation import (
        build_saas_automation_sensor,
    )

    return build_saas_automation_sensor(env)


def _signed_id_factory(env: Mapping[str, str]) -> EngineSensor:
    """P13/P5 — wrap a connected directory's read seam as the signed-id source.

    Builds a live Microsoft-Graph-shaped transport (the Entra/Okta read seam)
    ONLY when the deployment has supplied all three IdP client-credential env
    vars (the no-directory-connected default leaves them unset). With any
    missing, the sensor is constructed inert (``transport=None``) so it senses
    nothing — the common case the brief calls out. Imports the transport + sensor
    LAZILY inside the factory so a missing optional dependency degrades this one
    plane to empty rather than breaking the registry import.

    Env contract (all optional; absence = no directory connected, plane degrades):
    - ``TEX_SIEVE_P13_TENANT_ID``     — directory tenant id.
    - ``TEX_SIEVE_P13_CLIENT_ID``     — read-only client id (Application.Read.All).
    - ``TEX_SIEVE_P13_CLIENT_SECRET`` — opaque client secret (deployment-provided).
    - ``TEX_SIEVE_P13_GRAPH_BASE``    — optional API base override (Okta / sovereign).
    - ``TEX_SIEVE_P13_LABEL``         — optional receipt label (e.g. "entra"/"okta").
    With no creds set, returns an inert sensor (senses nothing), satisfying the
    default-safe rule even when ``TEX_SIEVE_P13_SIGNED`` is enabled.
    """
    from tex.discovery.engine.sensors.identity_idp import IdentityIdpSensor

    tenant_id = (env.get("TEX_SIEVE_P13_TENANT_ID") or "").strip()
    client_id = (env.get("TEX_SIEVE_P13_CLIENT_ID") or "").strip()
    client_secret = (env.get("TEX_SIEVE_P13_CLIENT_SECRET") or "").strip()
    if not (tenant_id and client_id and client_secret):
        # No directory connected (or partial creds) → inert, senses nothing.
        return IdentityIdpSensor(transport=None)

    from tex.discovery.graph_transport import GraphCredentials, LiveGraphTransport

    creds_kwargs: dict[str, str] = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    graph_base = (env.get("TEX_SIEVE_P13_GRAPH_BASE") or "").strip()
    if graph_base:
        creds_kwargs["graph_base"] = graph_base
    transport = LiveGraphTransport(GraphCredentials(**creds_kwargs))
    label = (env.get("TEX_SIEVE_P13_LABEL") or "directory").strip() or "directory"
    return IdentityIdpSensor(transport=transport, evidence_label=label)


def _mcp_toolgraph_factory(env: Mapping[str, str]) -> EngineSensor:
    """P10 — the MCP / A2A tool-graph plane (the tool-call graph IS a census).

    Wraps a configurable MCP server-record source as a SIGNAL SOURCE behind the
    sensor; the env-built sensor has no passive source and no network fetcher, so
    it senses NOTHING (the s8 default-safe degrade) even when ``TEX_SIEVE_P10_MCP``
    is enabled. Active AgentCard crawling / MCP ``tools/list`` probing are
    additionally gated behind ``TEX_SIEVE_P10_ACTIVE`` / ``TEX_SIEVE_P10_PROBE``
    and still require a host-wired fetcher, so the network-touching paths stay OFF
    unless explicitly opted in. Imports its builder LAZILY inside the factory so a
    missing optional dependency degrades this one plane to empty rather than
    breaking the registry import.
    """
    from tex.discovery.engine.sensors.mcp_toolgraph import (
        build_mcp_toolgraph_sensor,
    )

    return build_mcp_toolgraph_sensor(env)


def _managed_control_factory(env: Mapping[str, str]) -> EngineSensor:
    """P6/P7 — the managed-control plane (Bedrock / OpenAI / OCSF / vault-CI-OIDC).

    Builds the plane's control-plane SOURCES from ``env`` and wraps the existing
    discovery connectors as signal sources. EVERY construction path degrades to
    an EMPTY-sensing sensor when its creds are absent: an unset/blank env var
    contributes no source, and a sensor with zero sources senses nothing. Imports
    its connectors LAZILY inside the factory so a missing optional dependency
    degrades this one plane to empty rather than breaking the registry import.

    Env contract (all optional; absence = that source is omitted, plane degrades):
    - ``TEX_SIEVE_P6_TENANT``         — tenant id passed to the connector context
                                        (defaults to ``"default"``).
    - ``OPENAI_API_KEY``              — live OpenAI Assistants source (P6).
    - ``OPENAI_ORG`` / ``OPENAI_PROJECT`` — optional OpenAI scope headers.
    With no creds set, returns an inert sensor (senses nothing), satisfying the
    default-safe rule even when ``TEX_SIEVE_P6_AUDIT`` is enabled.
    """
    from tex.discovery.engine.sensors.managed_control import (
        ManagedControlSensor,
        connector_source,
    )

    tenant_id = (env.get("TEX_SIEVE_P6_TENANT") or "default").strip() or "default"
    sources = []

    api_key = (env.get("OPENAI_API_KEY") or "").strip()
    if api_key:
        try:
            from tex.discovery.connectors.openai_live import (
                OpenAIAssistantsLiveConnector,
            )

            connector = OpenAIAssistantsLiveConnector(
                api_key=api_key,
                organization=(env.get("OPENAI_ORG") or None),
                project=(env.get("OPENAI_PROJECT") or None),
            )
            sources.append(connector_source(connector, "openai_assistants"))
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: managed_control openai source omitted: %s", exc)

    # No source configured → an inert sensor (senses nothing). This is the
    # default-safe path: a flag-enabled-but-uncredentialed environment degrades
    # to empty, never raises.
    return ManagedControlSensor(sources, tenant_id=tenant_id)


def _static_supplychain_factory(env: Mapping[str, str]) -> EngineSensor:
    """P8 — the static supply-chain / provenance plane (parse-only, no network).

    Imported lazily so the module loads only when its flag is enabled. The
    factory reads the scan root(s) from ``TEX_SIEVE_P8_REPO`` and degrades to an
    empty-sensing sensor when no root is configured (the §8 default-safe degrade —
    a flag-enabled-but-unrooted env senses nothing). Pure parsing; never raises.
    """
    from tex.discovery.engine.sensors.static_supplychain import (
        build_static_supplychain_sensor,
    )

    return build_static_supplychain_sensor(env)


# ---------------------------------------------------------------------------
# The roster: PlaneId -> (env flag, factory)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlaneRegistration:
    """One plane's activation contract: its env flag + its sensor factory."""

    plane_id: PlaneId
    env_flag: str
    factory: SensorFactory


#: The activation roster. KEY INVARIANTS:
#:  - Every entry is FLAG-GATED: ``build_active_sensors`` includes a plane only
#:    when ``env[flag]`` is truthy. The default (no flags) yields nothing.
#:  - Every factory is ``_safe``-wrapped: a raising/None factory degrades to the
#:    inert sensor for that plane.
#:  - The two slice planes (ACTIONS_TRAIL / FS_WRITE) carry real factories and
#:    their own flags so they too are opt-in under the registry path (the direct
#:    ``pipeline.run_slice`` path is unaffected — it constructs them directly).
#:  - The ten roster planes default to ``_empty_factory_for`` until their builder
#:    REPLACES the factory here via ``register_sensor`` (or by editing this map).
#:    Enabling a flag for an unbuilt plane is therefore safe (senses nothing).
_ROSTER: dict[PlaneId, PlaneRegistration] = {
    # --- the two REAL slice planes (built + green) ------------------------
    PlaneId.ACTIONS_TRAIL: PlaneRegistration(
        PlaneId.ACTIONS_TRAIL, "TEX_SIEVE_ACTIONS_TRAIL", _safe(PlaneId.ACTIONS_TRAIL, _actions_trail_factory)
    ),
    PlaneId.FS_WRITE: PlaneRegistration(
        PlaneId.FS_WRITE, "TEX_SIEVE_FS_WRITE", _safe(PlaneId.FS_WRITE, _fs_write_factory)
    ),
    # --- the ten flag-gated breadth planes (ARCHITECTURE.md §8) -----------
    # Each builder REPLACES its factory below (via ``register_sensor``) with a
    # real source-backed sensor. Until then the slot is inert + flag-gated OFF.
    PlaneId.SIGNED_ID: PlaneRegistration(
        PlaneId.SIGNED_ID, "TEX_SIEVE_P13_SIGNED", _safe(PlaneId.SIGNED_ID, _signed_id_factory)
    ),
    PlaneId.NETWORK_EGRESS: PlaneRegistration(
        PlaneId.NETWORK_EGRESS, "TEX_SIEVE_P1_JA4", _safe(PlaneId.NETWORK_EGRESS, _network_egress_factory)
    ),
    PlaneId.KERNEL_EBPF: PlaneRegistration(
        PlaneId.KERNEL_EBPF, "TEX_SIEVE_P9_EBPF", _safe(PlaneId.KERNEL_EBPF, _empty_factory_for(PlaneId.KERNEL_EBPF))
    ),
    PlaneId.MANAGED_CONTROL: PlaneRegistration(
        PlaneId.MANAGED_CONTROL, "TEX_SIEVE_P6_AUDIT", _safe(PlaneId.MANAGED_CONTROL, _managed_control_factory)
    ),
    PlaneId.SAAS_AUTOMATION: PlaneRegistration(
        PlaneId.SAAS_AUTOMATION, "TEX_SIEVE_P5_OAUTH", _safe(PlaneId.SAAS_AUTOMATION, _saas_automation_factory)
    ),
    PlaneId.GOVERNANCE_STREAM: PlaneRegistration(
        PlaneId.GOVERNANCE_STREAM, "TEX_SIEVE_P11_OTEL", _safe(PlaneId.GOVERNANCE_STREAM, build_governance_stream_sensor)
    ),
    PlaneId.STATIC_SUPPLYCHAIN: PlaneRegistration(
        PlaneId.STATIC_SUPPLYCHAIN, "TEX_SIEVE_P8_SUPPLY", _safe(PlaneId.STATIC_SUPPLYCHAIN, _static_supplychain_factory)
    ),
    PlaneId.MCP_TOOLGRAPH: PlaneRegistration(
        PlaneId.MCP_TOOLGRAPH, "TEX_SIEVE_P10_MCP", _safe(PlaneId.MCP_TOOLGRAPH, _mcp_toolgraph_factory)
    ),
    PlaneId.ENDPOINT_EDR: PlaneRegistration(
        PlaneId.ENDPOINT_EDR, "TEX_SIEVE_P9_EDR", _safe(PlaneId.ENDPOINT_EDR, _empty_factory_for(PlaneId.ENDPOINT_EDR))
    ),
    PlaneId.HONEYTOKEN: PlaneRegistration(
        PlaneId.HONEYTOKEN, "TEX_SIEVE_P14_DECOY", _safe(PlaneId.HONEYTOKEN, _empty_factory_for(PlaneId.HONEYTOKEN))
    ),
    # --- the coverage-health meta-plane (P0) ------------------------------
    PlaneId.COVERAGE_HEALTH: PlaneRegistration(
        PlaneId.COVERAGE_HEALTH, "TEX_SIEVE_P0_COVERAGE", _safe(PlaneId.COVERAGE_HEALTH, _empty_factory_for(PlaneId.COVERAGE_HEALTH))
    ),
}


_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})


def _is_enabled(env: Mapping[str, str], flag: str) -> bool:
    """A flag is enabled iff present with a recognized truthy value."""
    val = env.get(flag)
    return isinstance(val, str) and val.strip().casefold() in _TRUTHY


def _is_disabled(env: Mapping[str, str], flag: str) -> bool:
    """An EXPLICIT per-plane opt-out — the only thing that darkens a plane
    under the full sweep (``TEX_SIEVE_ALL``). Absence is not an opt-out."""
    val = env.get(flag)
    return isinstance(val, str) and val.strip().casefold() in _FALSEY


#: The full-sweep master switch. When truthy, EVERY roster plane is built (each
#: still degrades to empty without its own source), so a single press of Begin
#: lights up the entire layer. Kept SEPARATE from ``TEX_SIEVE_ENABLED`` so the
#: default-safe contract holds: enabling SIEVE without ``TEX_SIEVE_ALL`` still
#: requires explicit per-plane opt-in, and a bare merge-to-main / prod deploy
#: never activates a plane. Genuinely-intrusive sub-actions (decoy planting,
#: active MCP probing) stay behind their OWN sub-flags, which the sweep never
#: sets — full sweep means passive sensing on every plane, nothing intrusive.
_ALL_FLAG = "TEX_SIEVE_ALL"


def _run_all(env: Mapping[str, str]) -> bool:
    """Whether the full-sweep switch lights up every roster plane."""
    return _is_enabled(env, _ALL_FLAG)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def register_sensor(plane_id: PlaneId, factory: SensorFactory, *, env_flag: str | None = None) -> None:
    """Register (or REPLACE) the factory for a plane.

    The ten plane builders call this to wire their real source-backed factory
    into the roster slot the contracts pass reserved for them, e.g.::

        from tex.discovery.engine.sensors.registry import register_sensor
        register_sensor(PlaneId.KERNEL_EBPF, _build_kernel_ebpf_sensor)

    The supplied factory is ``_safe``-wrapped here so a builder cannot break the
    never-raise contract. ``env_flag`` defaults to the roster's existing flag for
    the plane (the §8 table value); pass it only to override. A plane not already
    in the roster requires ``env_flag`` (there is no §8 default to inherit).
    """
    existing = _ROSTER.get(plane_id)
    flag = env_flag or (existing.env_flag if existing else None)
    if flag is None:
        raise ValueError(
            f"register_sensor({plane_id.value}) needs env_flag — no roster default"
        )
    _ROSTER[plane_id] = PlaneRegistration(plane_id, flag, _safe(plane_id, factory))


def active_plane_flags(env: Mapping[str, str]) -> tuple[str, ...]:
    """The env flags that are enabled in ``env`` (sorted, for receipts/tests).

    With the full-sweep switch (``TEX_SIEVE_ALL``) on, every roster plane is
    active — except planes the operator EXPLICITLY opted out with a falsey
    per-plane value — so the reported flags mirror what actually armed.
    """
    if _run_all(env):
        return tuple(
            sorted(
                reg.env_flag
                for reg in _ROSTER.values()
                if not _is_disabled(env, reg.env_flag)
            )
        )
    return tuple(
        sorted(reg.env_flag for reg in _ROSTER.values() if _is_enabled(env, reg.env_flag))
    )


def build_active_sensors(env: Mapping[str, str]) -> list[EngineSensor]:
    """Build ONLY the sensors whose activation flag is enabled in ``env``.

    Default-safe: with no ``TEX_SIEVE_*`` flags set this returns ``[]`` (nothing
    activates on a merge-to-main / prod deploy). For every flag-enabled plane the
    plane's ``_safe``-wrapped factory is invoked with ``env`` and its sensor is
    appended; a factory that cannot construct its sensor yields the inert sensor
    for that plane rather than raising, so a partially-credentialed environment
    degrades to fewer live planes, never a crash.

    The returned order is the roster declaration order (stable, deterministic).
    """
    sensors: list[EngineSensor] = []
    run_all = _run_all(env)
    for reg in _ROSTER.values():
        if run_all:
            # Full sweep: every plane arms unless EXPLICITLY opted out.
            if not _is_disabled(env, reg.env_flag):
                sensors.append(reg.factory(env))
        elif _is_enabled(env, reg.env_flag):
            sensors.append(reg.factory(env))
    return sensors


def roster_plane_ids() -> tuple[PlaneId, ...]:
    """All plane ids the registry knows (for tests / introspection)."""
    return tuple(_ROSTER.keys())


__all__ = [
    "SensorFactory",
    "PlaneRegistration",
    "register_sensor",
    "build_active_sensors",
    "active_plane_flags",
    "roster_plane_ids",
]


# ---------------------------------------------------------------------------
# Builder wiring — REAL source-backed factories that REPLACE their inert slot.
# ---------------------------------------------------------------------------
# Each call below swaps a roster slot's ``_empty_factory_for`` placeholder for
# the plane builder's real factory, keeping the §8 env flag. ``register_sensor``
# ``_safe``-wraps every factory, so a missing source/dependency still degrades to
# empty rather than raising. Flag-gating is unchanged: the plane stays OFF until
# its ``TEX_SIEVE_P*`` flag is set.


def _build_kernel_ebpf_sensor(env: Mapping[str, str]) -> EngineSensor:
    """P9 — the kernel/eBPF plane (PROVEN ground truth; identity-less processes).

    Reads a Tetragon-shaped kernel event stream and resolves the two-axis
    identity (``code_hash`` MERGES exec_ids of one binary; ``syscall_graph_sig``
    SPLITS distinct agents under one binary). Imports its sensor LAZILY (registry
    rule: no plane imported eagerly at module load). The event-source path comes
    from ``TEX_SIEVE_P9_EBPF_EVENTS`` (a Tetragon JSONL export — a live
    ``tetra getevents -o json`` stream on Linux, or a recorded same-shape fixture
    read by the clearly-labeled local shim on macOS/tests). With no path set — or
    a missing file — the sensor senses nothing, even when ``TEX_SIEVE_P9_EBPF``
    is enabled. Never raises.
    """
    from tex.discovery.engine.sensors.kernel_ebpf import build_kernel_ebpf_sensor

    return build_kernel_ebpf_sensor(env)


register_sensor(PlaneId.KERNEL_EBPF, _build_kernel_ebpf_sensor)


def _build_endpoint_edr_sensor(env: Mapping[str, str]) -> EngineSensor:
    """P9 (endpoint) — the endpoint/EDR plane (OBSERVED host process inventory).

    The coarser, more deployable cousin of the kernel/eBPF plane: a user-space
    EDR / osquery sensor snapshots a host's process inventory (running processes,
    hosting runtime, on-disk code hash, persistence mechanism) and emits one
    OBSERVED incidence per distinct host-agent, carrying the IDENTITY-grade
    ``code_hash`` cross-plane merge anchor (shared with the eBPF plane) + the
    BRIDGING-grade ``host_id``. Imports its sensor LAZILY (registry rule: no plane
    imported eagerly at module load). The telemetry-source path comes from
    ``TEX_SIEVE_P9_EDR_TELEMETRY`` (an osquery-shaped JSONL export — a live
    ``osqueryi --json`` / EDR process-inventory export, or a recorded same-shape
    fixture read by the clearly-labeled local shim). With no path set — or a
    missing file — the sensor senses nothing, even when ``TEX_SIEVE_P9_EDR`` is
    enabled. Never raises.
    """
    from tex.discovery.engine.sensors.endpoint_edr import build_endpoint_edr_sensor

    return build_endpoint_edr_sensor(env)


register_sensor(PlaneId.ENDPOINT_EDR, _build_endpoint_edr_sensor)


def _build_honeytoken_decoy_sensor(env: Mapping[str, str]) -> EngineSensor:
    """P14 — the ACTIVE honeytoken / decoy-lattice plane (PROVEN on a bite).

    The only ACTIVE plane: it plants decoys/canaries/markers whose only caller is
    an undiscovered agent and emits one PROVEN incidence per HONORED trip
    (``{decoy_id, canary_cred_id, injected_marker, caller_fingerprint}``), where
    ``injected_marker`` is the N3 cross-plane JOIN KEY that fuses an agent's read-
    and act-footprints. Imports its sensor LAZILY (registry rule: no plane imported
    eagerly at module load). INERT BY DEFAULT (the §8 "inert (no decoys planted)"
    posture): with no ``TEX_SIEVE_P14_REGISTRY`` decoy ledger configured, NO decoy
    is planted, so the plane senses nothing even when ``TEX_SIEVE_P14_DECOY`` is on
    and a trip source (``TEX_SIEVE_P14_TRIPS``) is wired. Never raises.
    """
    from tex.discovery.engine.sensors.honeytoken_decoy import (
        build_honeytoken_decoy_sensor,
    )

    return build_honeytoken_decoy_sensor(env)


register_sensor(PlaneId.HONEYTOKEN, _build_honeytoken_decoy_sensor)
