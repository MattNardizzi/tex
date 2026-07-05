"""
Unit tests for the P8 STATIC SUPPLY-CHAIN / PROVENANCE plane sensor.

Proves the LEADING-INDICATOR leg (ARCHITECTURE.md §8 P8; RESEARCH_LOG.md §1 P8,
§6 P8): an agent exists in code BEFORE it egresses a packet. The sensor scans a
repo/dir (PURE PARSING, no network) for agent DEFINITIONS — LangGraph/CrewAI/
AutoGen/LangChain graph constructs, MCP server manifests, IaC (Terraform/
serverless) agent resources + attached IAM, and lockfile/SBOM framework tells —
and emits one ``Incidence(plane=STATIC_SUPPLYCHAIN)`` per declaration whose
footprint is ``{repo_path, agent_def_symbol, framework, manifest_path,
declared_tools, iam_role}`` plus the IDENTITY-grade ``agent_external_id`` join
key. ``admissibility=claimed`` for declared defs/manifests, ``platform_attested``
for an IaC resource with an attached IAM role. It MUST degrade to EMPTY (never
raise) on a missing source.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_static_supplychain.py -q
"""

from __future__ import annotations

from pathlib import Path

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.registry import build_active_sensors
from tex.discovery.engine.sensors.static_supplychain import (
    ENV_REPO_ROOTS,
    StaticSupplyChainSensor,
    build_static_supplychain_sensor,
)


# ---------------------------------------------------------------------------
# Fixture: a planted repo with one of each declaration kind.
# ---------------------------------------------------------------------------


def _plant_repo(root: Path) -> None:
    """Write a small repo with a LangGraph agent, an MCP manifest, a Terraform
    Lambda + attached IAM role, and a requirements lockfile naming an SDK."""
    # (1) A LangGraph agent definition in Python source.
    (root / "agents").mkdir(parents=True, exist_ok=True)
    (root / "agents" / "assay_pilot.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "\n"
        "AssayPilot = StateGraph(dict)\n"
        "AssayPilot.add_node('plan', plan_fn)\n"
        "graph = AssayPilot.compile()\n",
        encoding="utf-8",
    )

    # (2) An MCP server manifest declaring a tool surface.
    (root / "mcp.json").write_text(
        '{\n'
        '  "name": "ledger-mcp",\n'
        '  "tools": [\n'
        '    {"name": "post_journal_entry"},\n'
        '    {"name": "read_balance"}\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )

    # (3) A Terraform agent resource (Lambda) with an attached IAM role.
    (root / "infra").mkdir(parents=True, exist_ok=True)
    (root / "infra" / "main.tf").write_text(
        'resource "aws_lambda_function" "treasury_agent" {\n'
        '  function_name = "treasury-agent"\n'
        '  role          = "arn:aws:iam::123456789012:role/treasury-agent-exec"\n'
        '  runtime       = "python3.12"\n'
        '}\n',
        encoding="utf-8",
    )

    # (4) A lockfile naming an agent SDK (leading-indicator cohort tell).
    (root / "requirements.txt").write_text(
        "crewai==0.51.0\nrequests==2.32.0\n", encoding="utf-8"
    )

    # A vendored dep that MUST be skipped (proves the skip-list).
    (root / "node_modules" / "langgraph-js").mkdir(parents=True, exist_ok=True)
    (root / "node_modules" / "langgraph-js" / "decoy.py").write_text(
        "Decoy = StateGraph(dict)\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# (1) emits correct Incidence for a planted agent definition
# ---------------------------------------------------------------------------


def test_emits_incidence_for_each_planted_declaration(tmp_path: Path) -> None:
    _plant_repo(tmp_path)
    sensor = StaticSupplyChainSensor(roots=[tmp_path])
    incidences = list(sensor.sense(SenseContext()))

    # Every incidence is on the P8 plane and is a real Incidence.
    assert incidences, "expected at least one planted declaration"
    for inc in incidences:
        assert isinstance(inc, Incidence)
        assert inc.plane_id is PlaneId.STATIC_SUPPLYCHAIN
        assert inc.footprint.plane_id is PlaneId.STATIC_SUPPLYCHAIN
        assert 0.0 <= inc.catchability <= 1.0
        assert inc.footprint.attr("pre_runtime") == "true"

    by_symbol = {inc.footprint.key(FootprintField.AGENT_DEF_SYMBOL): inc for inc in incidences}

    # --- the LangGraph agent definition ----------------------------------
    assert "AssayPilot" in by_symbol
    lg = by_symbol["AssayPilot"]
    assert lg.footprint.key(FootprintField.FRAMEWORK) == "langgraph"
    # IDENTITY-grade cross-plane join key carries the declared agent handle.
    assert lg.footprint.key("agent_external_id") == "AssayPilot"
    assert lg.footprint.key(FootprintField.REPO_PATH) == "agents/assay_pilot.py"
    assert lg.admissibility is Admissibility.CLAIMED

    # --- the MCP server manifest -----------------------------------------
    assert "ledger-mcp" in by_symbol
    mcp = by_symbol["ledger-mcp"]
    assert mcp.footprint.key(FootprintField.FRAMEWORK) == "mcp"
    assert mcp.footprint.key(FootprintField.MANIFEST_PATH) == "mcp.json"
    # Declared tools are canonicalized to a sorted CSV.
    assert mcp.footprint.key(FootprintField.DECLARED_TOOLS) == "post_journal_entry,read_balance"
    assert mcp.admissibility is Admissibility.CLAIMED

    # --- the Terraform Lambda + attached IAM role ------------------------
    assert "treasury_agent" in by_symbol
    tf = by_symbol["treasury_agent"]
    assert tf.footprint.key(FootprintField.FRAMEWORK) == "terraform"
    assert (
        tf.footprint.key(FootprintField.IAM_ROLE)
        == "arn:aws:iam::123456789012:role/treasury-agent-exec"
    )
    # An attached IAM role is a PLATFORM-ATTESTED pre-runtime blast-radius grant.
    assert tf.admissibility is Admissibility.PLATFORM_ATTESTED

    # --- the lockfile SDK tell (leading-indicator cohort) ----------------
    assert "crewai" in by_symbol
    dep = by_symbol["crewai"]
    assert dep.footprint.key(FootprintField.FRAMEWORK) == "crewai"
    assert dep.footprint.attr("sbom_tell") == "true"
    # A pure cohort tell carries NO specific agent_external_id (so it does not
    # spuriously fuse with a runtime agent merely sharing the framework).
    assert dep.footprint.key("agent_external_id") is None

    # --- the skip-list held: the vendored decoy was NOT discovered -------
    assert "Decoy" not in by_symbol


def test_declared_symbol_fuses_with_a_runtime_sighting(tmp_path: Path) -> None:
    """The IDENTITY-grade ``agent_external_id`` makes a code-declared agent fuse
    with the same agent's runtime footprint into ONE SieveEntity (cross-plane)."""
    (tmp_path / "a.py").write_text("AssayPilot = StateGraph(dict)\n", encoding="utf-8")
    static_incs = list(StaticSupplyChainSensor(roots=[tmp_path]).sense(SenseContext()))
    assert static_incs

    # A runtime ACTIONS_TRAIL footprint of the SAME agent handle.
    from tex.discovery.engine.models import FootprintVector

    runtime = Incidence(
        plane_id=PlaneId.ACTIONS_TRAIL,
        footprint=FootprintVector.of(
            plane_id=PlaneId.ACTIONS_TRAIL,
            keys={"agent_external_id": "AssayPilot"},
            attrs={"action_type": "file_write"},
        ),
        catchability=1.0,
        admissibility=Admissibility.OBSERVED,
        raw_evidence_ref="runtime:1",
    )

    entities = resolve([*static_incs, runtime])
    # The declared symbol + the runtime sighting fuse to ONE entity seen on BOTH
    # the pre-runtime static plane and the runtime trail plane.
    fused = [e for e in entities if PlaneId.STATIC_SUPPLYCHAIN in e.planes_seen]
    assert len(fused) == 1
    assert fused[0].planes_seen >= {PlaneId.STATIC_SUPPLYCHAIN, PlaneId.ACTIONS_TRAIL}


# ---------------------------------------------------------------------------
# (2) degrade-to-empty on a missing source
# ---------------------------------------------------------------------------


def test_degrades_to_empty_with_no_roots() -> None:
    """No scan root → emits nothing, never raises (the unconfigured case)."""
    assert list(StaticSupplyChainSensor(roots=None).sense(SenseContext())) == []
    assert list(StaticSupplyChainSensor(roots=[]).sense(SenseContext())) == []


def test_degrades_to_empty_when_root_missing(tmp_path: Path) -> None:
    """A configured-but-nonexistent root degrades to empty, never raises."""
    missing = tmp_path / "does-not-exist"
    sensor = StaticSupplyChainSensor(roots=[missing])
    assert list(sensor.sense(SenseContext())) == []


def test_empty_repo_emits_nothing(tmp_path: Path) -> None:
    """A real but agent-free repo yields no synthetic placeholder."""
    (tmp_path / "readme.md").write_text("# just docs\n", encoding="utf-8")
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert list(StaticSupplyChainSensor(roots=[tmp_path]).sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# (3) flag-gating + factory default-safety (the §8 activation contract)
# ---------------------------------------------------------------------------


def test_factory_degrades_empty_without_repo_env(tmp_path: Path) -> None:
    """The registry factory with NO ``TEX_SIEVE_P8_REPO`` set senses nothing."""
    sensor = build_static_supplychain_sensor(env={})
    assert list(sensor.sense(SenseContext())) == []


def test_factory_reads_repo_env(tmp_path: Path) -> None:
    """The factory honors ``TEX_SIEVE_P8_REPO`` as its scan root."""
    (tmp_path / "a.py").write_text("Crew = Crew(agents=[])\n", encoding="utf-8")
    sensor = build_static_supplychain_sensor(env={ENV_REPO_ROOTS: str(tmp_path)})
    incs = list(sensor.sense(SenseContext()))
    assert any(i.footprint.key(FootprintField.FRAMEWORK) == "crewai" for i in incs)


def test_plane_is_flag_gated_off_by_default() -> None:
    """Default (no flags) builds NO P8 sensor — the merge-to-main safe posture."""
    built = build_active_sensors(env={})
    assert all(s.plane_id is not PlaneId.STATIC_SUPPLYCHAIN for s in built)


def test_plane_activates_only_under_its_flag(tmp_path: Path) -> None:
    """``TEX_SIEVE_P8_SUPPLY`` truthy activates the plane; the factory still
    degrades-empty when no repo root is configured (default-safe)."""
    built = build_active_sensors(env={"TEX_SIEVE_P8_SUPPLY": "1"})
    p8 = [s for s in built if s.plane_id is PlaneId.STATIC_SUPPLYCHAIN]
    assert len(p8) == 1
    # Flag on but no TEX_SIEVE_P8_REPO → still senses nothing (never raises).
    assert list(p8[0].sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# Manifest fallback handle — never a dotfile stem (the ".mcp" junk-name bug).
# ---------------------------------------------------------------------------


def test_nameless_dotfile_manifest_falls_back_to_owning_dir(tmp_path: Path) -> None:
    """Regression (2026-07-05): a ``.mcp.json`` whose server name cannot be
    parsed landed as an agent literally named ``".mcp"`` (the dotfile stem).
    The fallback handle is the manifest's OWNING directory."""
    plugin = tmp_path / "plugins" / "example-plugin"
    plugin.mkdir(parents=True)
    (plugin / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")

    sensor = StaticSupplyChainSensor(roots=[tmp_path])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    inc = incidences[0]
    assert inc.footprint.key(FootprintField.AGENT_DEF_SYMBOL) == "example-plugin"
    assert inc.footprint.key("agent_external_id") == "example-plugin"
    assert inc.raw_evidence_ref.endswith("#example-plugin")


def test_nameless_manifest_at_root_never_yields_a_dot_name(tmp_path: Path) -> None:
    """A nameless manifest with NO owning directory inside the root falls back
    to the root's own name (or the de-dotted stem) — never a leading-dot
    handle."""
    root = tmp_path / "myrepo"
    root.mkdir()
    (root / ".mcp.json").write_text("{}", encoding="utf-8")

    sensor = StaticSupplyChainSensor(roots=[root])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    symbol = incidences[0].footprint.key(FootprintField.AGENT_DEF_SYMBOL)
    assert symbol == "myrepo"
    assert not symbol.startswith(".")


def test_named_manifest_handles_are_unchanged(tmp_path: Path) -> None:
    """The fallback NEVER overrides a declared name: ``mcpServers`` keys and
    single-server ``name`` fields keep winning exactly as before."""
    keyed = tmp_path / "bridges"
    keyed.mkdir()
    (keyed / ".mcp.json").write_text(
        '{"mcpServers": {"telegram": {"command": "run"}}}', encoding="utf-8"
    )
    (tmp_path / "mcp.json").write_text('{"name": "ledger-mcp"}', encoding="utf-8")

    sensor = StaticSupplyChainSensor(roots=[tmp_path])
    symbols = {
        i.footprint.key(FootprintField.AGENT_DEF_SYMBOL)
        for i in sensor.sense(SenseContext())
    }
    assert symbols == {"telegram", "ledger-mcp"}
