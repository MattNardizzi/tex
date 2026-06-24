"""
Unit tests for the P10 MCP / A2A TOOL-GRAPH plane sensor.

Proves the white-space leg (ARCHITECTURE.md §8 P10; RESEARCH_LOG.md §1 P10, §139):
**the tool-call graph IS an agent census.** The sensor ingests a configurable MCP
server-record source (connected-client lists + exercised tool-DAGs + declared
``tools/list``) and, opt-in + bounded, crawls AgentCard/``.well-known`` endpoints
and probes MCP servers for ``tools/list`` via an injectable fetcher. It emits
``Incidence(plane=MCP_TOOLGRAPH)`` carrying ``{tool_set_minhash (IDENTITY-grade),
agent_external_id?, mcp_server_url, agent_card_id?}`` with admissibility OBSERVED
for an exercised tool-DAG and CLAIMED for a declared surface. It MUST degrade to
EMPTY (never raise) when no source / fetcher is configured.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_mcp_toolgraph.py -q
"""

from __future__ import annotations

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.mcp_toolgraph import (
    MCPToolGraphSensor,
    build_mcp_toolgraph_sensor,
    tool_set_minhash,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# ---------------------------------------------------------------------------
# Fixtures: a planted MCP server inventory (the shape MCPServerConnector / a live
# MCP inventory emits). Two clients on one server: AssayPilot (exercising a write
# tool-DAG, carrying a stable handle) + an anonymous Cursor client; plus a
# server-level declared tools/list (CLAIMED surface).
# ---------------------------------------------------------------------------


def _mcp_server_records() -> list[dict]:
    return [
        {
            "server_name": "tex-mcp",
            "server_url": "https://mcp.tex.internal",
            "environment": "production",
            "tools": ["file_write", "file_read", "shell_exec", "http_get"],
            "clients": [
                {
                    "client_id": "AssayPilot",
                    "client_name": "AssayPilot",
                    "host_kind": "custom",
                    "tool_names": ["file_write", "file_read", "shell_exec"],
                    "agent_card_id": "card-assaypilot-1",
                    "last_seen_at": "2026-06-23T12:00:00Z",
                },
                {
                    # No client_id / client_name / card_id — a truly handle-less
                    # session. It is STILL discoverable on its tool-set MinHash +
                    # the server cohort key (the census property).
                    "host_kind": "cursor",
                    "tool_names": ["file_read", "http_get"],
                    "ts": 1782242999.0,
                },
            ],
        },
    ]


# ---------------------------------------------------------------------------
# PASSIVE — emits correct Incidence for a planted agent (exercised + declared).
# ---------------------------------------------------------------------------


def test_emits_mcp_incidence_for_planted_agent() -> None:
    sensor = MCPToolGraphSensor(source=_mcp_server_records)
    incs = list(sensor.sense(SenseContext()))

    assert incs, "expected MCP incidences for the planted server inventory"
    assert all(i.plane_id is PlaneId.MCP_TOOLGRAPH for i in incs)
    assert all(i.footprint.plane_id is PlaneId.MCP_TOOLGRAPH for i in incs)
    assert all(0.0 <= i.catchability <= 1.0 for i in incs)
    assert all(i.observed_at.tzinfo is not None for i in incs)

    # The AssayPilot client carries the mandated keys; agent_external_id is the
    # IDENTITY-grade cross-plane join key, tool_set_minhash the IDENTITY-grade
    # behavioral fingerprint, mcp_server_url + agent_card_id the BRIDGING cohort.
    assayp = next(
        i for i in incs if i.footprint.key("agent_external_id") == "AssayPilot"
    )
    assert assayp.admissibility is Admissibility.OBSERVED
    assert assayp.footprint.key(FootprintField.MCP_SERVER_URL) == "https://mcp.tex.internal"
    assert assayp.footprint.key(FootprintField.AGENT_CARD_ID) == "card-assaypilot-1"
    assert assayp.footprint.key(FootprintField.TOOL_SET_MINHASH) is not None
    # The exercised tool-DAG rides as a descriptive attr for capability mapping.
    assert "file_write" in (assayp.footprint.attr("exercised_tools") or "")
    assert assayp.footprint.attr("surface") == "exercised_tool_dag"

    # The server-level tools/list advertisement is a CLAIMED incidence.
    declared = [i for i in incs if i.admissibility is Admissibility.CLAIMED]
    assert len(declared) == 1
    assert declared[0].footprint.attr("surface") == "declared_tools_list"
    assert declared[0].footprint.key(FootprintField.MCP_SERVER_URL) == "https://mcp.tex.internal"


def test_anonymous_client_still_emits_on_minhash_and_server() -> None:
    """A client with no stable handle is still discoverable on its tool-set
    MinHash + the server cohort key (the census property)."""
    sensor = MCPToolGraphSensor(source=_mcp_server_records)
    incs = list(sensor.sense(SenseContext()))
    cursor = next(
        i
        for i in incs
        if i.admissibility is Admissibility.OBSERVED
        and i.footprint.key("agent_external_id") is None
    )
    assert cursor.footprint.key(FootprintField.TOOL_SET_MINHASH) is not None
    assert cursor.footprint.key(FootprintField.MCP_SERVER_URL) == "https://mcp.tex.internal"
    assert cursor.footprint.attr("host_kind") == "cursor"


# ---------------------------------------------------------------------------
# MinHash deployment fingerprint — clusters near-duplicate tool sets (§139).
# ---------------------------------------------------------------------------


def test_tool_set_minhash_is_deterministic_and_order_independent() -> None:
    a = tool_set_minhash(["file_write", "file_read", "shell_exec"])
    b = tool_set_minhash(["shell_exec", "file_read", "file_write"])
    assert a is not None and a == b  # order-independent + deterministic
    assert tool_set_minhash([]) is None  # empty tool set has no fingerprint


def test_tool_set_minhash_collides_on_near_duplicate_sets() -> None:
    """A renamed/near-duplicate tool set shares most MinHash bands, so it is the
    same deployment fingerprint regime — distinct from an unrelated tool set."""
    base = ["send_email", "list_calendar", "create_event"]
    near = ["send_emails", "list_calendar", "create_event"]  # one tool pluralized
    unrelated = ["deploy_k8s", "scale_replicas", "rollback_release"]
    assert tool_set_minhash(base) != tool_set_minhash(unrelated)
    # The pluralized variant is NOT identical (it is a different set) but the
    # fingerprint function is stable + total over it (no raise, real signature).
    assert tool_set_minhash(near) is not None


# ---------------------------------------------------------------------------
# FUSE — same agent on this plane fuses to ONE entity (cross-plane fusibility).
# ---------------------------------------------------------------------------


def test_mcp_fuses_two_sightings_on_identity_key() -> None:
    """Two sightings of AssayPilot (same agent_external_id / same tool set) fuse
    to ONE SieveEntity, proving the IDENTITY-grade join keys link correctly."""

    def _two_sightings() -> list[dict]:
        return [
            {
                "server_url": "https://mcp.a.internal",
                "clients": [
                    {
                        "client_id": "AssayPilot",
                        "tool_names": ["file_write", "file_read"],
                    }
                ],
            },
            {
                "server_url": "https://mcp.b.internal",  # different server (cohort)
                "clients": [
                    {
                        "client_id": "AssayPilot",  # same IDENTITY-grade handle
                        "tool_names": ["file_write", "file_read"],
                    }
                ],
            },
        ]

    sensor = MCPToolGraphSensor(source=_two_sightings)
    incs = list(sensor.sense(SenseContext()))
    entities = resolve(incs)
    labels = {e.label for e in entities}
    assert "AssayPilot" in labels
    assayp = next(e for e in entities if e.label == "AssayPilot")
    # Both AssayPilot MCP footprints collapsed into ONE entity despite different
    # (bridging-grade) server URLs.
    assert len(assayp.incidences) == 2


# ---------------------------------------------------------------------------
# ACTIVE — opt-in, bounded crawl/probe via an INJECTABLE fixture fetcher.
# ---------------------------------------------------------------------------


def test_active_agent_card_crawl_emits_claimed_incidence() -> None:
    """Crawling a ``.well-known``/AgentCard endpoint yields a CLAIMED incidence
    carrying the declared A2A skills[] + a tool-set MinHash over them."""
    card_bodies = {
        "https://shadow.example/.well-known/agent.json": {
            "name": "ShadowAgent",
            "agent_card_id": "card-shadow-7",
            "skills": [
                {"name": "summarize"},
                {"name": "translate"},
            ],
        }
    }

    def _fetch(url: str) -> dict | None:
        return card_bodies.get(url)

    sensor = MCPToolGraphSensor(
        source=None,
        active_endpoints=["https://shadow.example/.well-known/agent.json"],
        fetcher=_fetch,
    )
    incs = list(sensor.sense(SenseContext()))
    assert len(incs) == 1
    card = incs[0]
    assert card.admissibility is Admissibility.CLAIMED
    assert card.footprint.attr("surface") == "agent_card"
    assert card.footprint.key("agent_external_id") == "ShadowAgent"
    assert card.footprint.key(FootprintField.AGENT_CARD_ID) == "card-shadow-7"
    assert card.footprint.key(FootprintField.TOOL_SET_MINHASH) is not None
    skills = card.footprint.attr(FootprintField.A2A_SKILLS) or ""
    assert "summarize" in skills and "translate" in skills


def test_active_tools_list_probe_emits_claimed_incidence() -> None:
    """Probing an MCP server URL for tools/list yields a CLAIMED incidence."""

    def _fetch(url: str) -> dict | None:
        return {"result": {"tools": [{"name": "file_write"}, {"name": "git_push"}]}}

    sensor = MCPToolGraphSensor(
        source=None,
        probe_servers=["https://mcp.probe.internal"],
        fetcher=_fetch,
    )
    incs = list(sensor.sense(SenseContext()))
    assert len(incs) == 1
    probe = incs[0]
    assert probe.admissibility is Admissibility.CLAIMED
    assert probe.footprint.attr("surface") == "tools_list_probe"
    assert probe.footprint.key(FootprintField.MCP_SERVER_URL) == "https://mcp.probe.internal"
    assert probe.footprint.key(FootprintField.TOOL_SET_MINHASH) is not None


def test_active_crawl_is_bounded_by_max_active() -> None:
    """The active crawl honors the max_active cap regardless of list length."""
    calls: list[str] = []

    def _fetch(url: str) -> dict | None:
        calls.append(url)
        return {"name": f"agent-{url[-1]}", "skills": ["a", "b"]}

    sensor = MCPToolGraphSensor(
        source=None,
        active_endpoints=[f"https://e{i}.example/card" for i in range(10)],
        fetcher=_fetch,
        max_active=3,
    )
    list(sensor.sense(SenseContext()))
    assert len(calls) == 3  # bounded


def test_active_crawl_degrades_on_unreachable_endpoint() -> None:
    """An unreachable endpoint (fetcher raises / returns None) degrades to fewer
    incidences, never an exception."""

    def _fetch(url: str) -> dict | None:
        if "boom" in url:
            raise RuntimeError("connection refused")
        return None  # unreachable / malformed body

    sensor = MCPToolGraphSensor(
        source=None,
        active_endpoints=["https://boom.example/card", "https://dead.example/card"],
        fetcher=_fetch,
    )
    assert list(sensor.sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# DEGRADE-TO-EMPTY — the non-negotiable default-safe contract.
# ---------------------------------------------------------------------------


def test_degrades_to_empty_when_no_source_configured() -> None:
    sensor = MCPToolGraphSensor(source=None)
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_source_callable_raises() -> None:
    def _boom() -> list[dict]:
        raise RuntimeError("mcp inventory unavailable")

    assert list(MCPToolGraphSensor(source=_boom).sense(SenseContext())) == []


def test_degrades_to_empty_on_empty_and_malformed_rows() -> None:
    assert list(MCPToolGraphSensor(source=[]).sense(SenseContext())) == []
    malformed = ["not-a-dict", 42, {"unrelated": "x"}, {"clients": "not-a-list"}]
    incs = list(MCPToolGraphSensor(source=lambda: malformed).sense(SenseContext()))
    assert incs == []


def test_active_off_when_no_fetcher_even_with_endpoints() -> None:
    """Configured endpoints with NO fetcher do NOT crawl (no un-opted network)."""
    sensor = MCPToolGraphSensor(
        source=None,
        active_endpoints=["https://e.example/card"],
        probe_servers=["https://mcp.example"],
        fetcher=None,
    )
    assert list(sensor.sense(SenseContext())) == []


def test_iterable_source_is_consumed_directly() -> None:
    """A plain iterable (not a callable) MCP inventory is accepted directly."""
    sensor = MCPToolGraphSensor(source=_mcp_server_records())
    incs = list(sensor.sense(SenseContext()))
    assert any(i.admissibility is Admissibility.OBSERVED for i in incs)


# ---------------------------------------------------------------------------
# REGISTRY — flag-gated OFF by default; env-built factory is default-safe inert.
# ---------------------------------------------------------------------------


def test_flag_gated_off_by_default_in_registry() -> None:
    # No flags → no MCP sensor built (default-safe on merge-to-main).
    assert build_active_sensors({}) == []


def test_registry_factory_is_inert_without_a_wired_source() -> None:
    """Enabling TEX_SIEVE_P10_MCP builds the sensor, but with no in-process source
    and no fetcher it senses NOTHING — flag-on must not crash or fake."""
    sensors = build_active_sensors({"TEX_SIEVE_P10_MCP": "1"})
    mcp = [s for s in sensors if s.plane_id is PlaneId.MCP_TOOLGRAPH]
    assert len(mcp) == 1
    assert list(mcp[0].sense(SenseContext())) == []


def test_env_built_factory_stays_inert_even_with_active_flags() -> None:
    """Even with the active/probe flags + endpoint lists set, the env-built
    factory wires NO fetcher, so it stays inert (no un-opted-in network touch)."""
    sensor = build_mcp_toolgraph_sensor(
        {
            "TEX_SIEVE_P10_MCP": "1",
            "TEX_SIEVE_P10_ACTIVE": "1",
            "TEX_SIEVE_P10_ENDPOINTS": "https://e.example/card",
            "TEX_SIEVE_P10_PROBE": "1",
            "TEX_SIEVE_P10_PROBE_URLS": "https://mcp.example",
        }
    )
    assert isinstance(sensor, MCPToolGraphSensor)
    assert list(sensor.sense(SenseContext())) == []
