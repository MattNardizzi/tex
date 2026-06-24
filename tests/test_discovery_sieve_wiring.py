"""
SIEVE → discovery-surface WIRING tests (ARCHITECTURE.md §8 default-safe contract).

These prove the ADDITIVE, default-safe wiring of the SIEVE engine into the live
discovery surface — NOT the engine internals (those are covered by
``test_discovery_sieve_slice.py`` and the per-plane tests). The three load-
bearing obligations from the wiring brief:

(a) DORMANT BY DEFAULT — with NO ``TEX_SIEVE_*`` flags set, ``build_sieve_driver``
    returns ``None`` (legacy path only), ``_build_discovery_connectors`` is
    unchanged, and an ignite call neither activates SIEVE nor crashes. The
    boot/ignite behavior is byte-for-byte today's.

(b) ACTIVE WHEN FLAGGED — with ``TEX_SIEVE_ENABLED`` + ONE plane flag + a fixture
    source, the driver runs the SIEVE engine and surfaces a resolved entity
    THROUGH the existing registry + ledger governance boundary.

(c) NEVER RAISES ON MISSING CREDS — building the driver and running it with the
    master flag on but no sources / no plane flags degrades to an empty, honest
    result, never an exception.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_sieve_wiring.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

from tex.discovery.engine import adapter  # noqa: F401 — binds SieveEntity output stubs
from tex.discovery.engine.sensors.registry import build_active_sensors
from tex.discovery.sieve_driver import SieveDriver, build_sieve_driver
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

# The per-plane env flag + source-context env names the wiring reads (the slice
# planes, which take their source from the SenseContext roots the driver sets).
_MASTER = "TEX_SIEVE_ENABLED"
_ACTIONS_FLAG = "TEX_SIEVE_ACTIONS_TRAIL"
_FS_FLAG = "TEX_SIEVE_FS_WRITE"
_ACTIONS_DIR_ENV = "TEX_SIEVE_ACTIONS_DIR"
_WORKSPACE_DIR_ENV = "TEX_SIEVE_WORKSPACE_DIR"


def _plant_two_occasion_estate(root: Path) -> tuple[Path, Path]:
    """Plant a tiny two-occasion fixture: one trail row + the file it wrote.

    Returns ``(actions_dir, workspace_dir)`` ready for the SenseContext roots.
    The ACTIONS_TRAIL row claims ``report/study-52.md``; a real file at
    ``<workspace>/report/study-52.md`` is the FS_WRITE occasion. They fuse to
    ONE entity (the cross-plane join key is the workspace-relative path).
    """
    actions_dir = root / "logs"
    workspace_dir = root / "workspace"
    actions_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "report").mkdir(parents=True, exist_ok=True)

    row = {
        "ts": 1782242461.21,
        "agent": "AssayPilot",
        "action_type": "file_write",
        "summary": "Write internal report 'report/study-52.md'",
        "verdict": "PERMIT",
        "released": True,
        "executed": True,
        "result": {"wrote": "report/study-52.md", "bytes": 114},
    }
    (actions_dir / "AssayPilot.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    (workspace_dir / "report" / "study-52.md").write_text("x" * 114, encoding="utf-8")
    return actions_dir, workspace_dir


# ---------------------------------------------------------------------------
# (a) DORMANT BY DEFAULT — no flags → no driver, legacy path unchanged.
# ---------------------------------------------------------------------------


def test_no_flags_yields_no_driver():
    """With no env flags, ``build_sieve_driver`` is a pure no-op (returns None)."""
    assert build_sieve_driver({}) is None
    # Also robust to unrelated env present but the master flag absent / falsey.
    assert build_sieve_driver({"TEX_APP_ENV": "development"}) is None
    assert build_sieve_driver({_MASTER: "0"}) is None
    assert build_sieve_driver({_MASTER: "false"}) is None


def test_no_flags_build_active_sensors_is_empty():
    """The registry the driver delegates to is itself empty with no plane flags.

    This is the engine-side guarantee that an absent flag set means SIEVE
    senses nothing — the default-safe posture a merge-to-main relies on.
    """
    assert build_active_sensors({}) == []


def test_build_discovery_connectors_unchanged_without_flags(monkeypatch):
    """``_build_discovery_connectors`` is byte-for-byte identical with/without
    the master flag UNSET — the SIEVE wiring never touches the legacy list."""
    from tex.main import _build_discovery_connectors

    # Force a deterministic, synthetic-free baseline (no demo seed / sandbox)
    # so the comparison is about SIEVE only, not unrelated env.
    for var in ("TEX_SANDBOX", _MASTER, _ACTIONS_FLAG, _FS_FLAG):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TEX_DISCOVERY_DEMO_SEED", "0")

    before = [type(c).__name__ for c in _build_discovery_connectors()]
    # Even if the operator had set the master flag, the legacy connector list is
    # unaffected (SIEVE is a SIBLING, never a replacement).
    monkeypatch.setenv(_MASTER, "1")
    after = [type(c).__name__ for c in _build_discovery_connectors()]
    assert before == after
    # And the driver the flag would build is a no-op against the registry/ledger.
    assert build_sieve_driver({}) is None


def test_dormant_driver_run_is_inert_when_master_off():
    """No driver → no projection. Simulate the ignite guard's None-check."""
    driver = build_sieve_driver({_ACTIONS_FLAG: "1"})  # plane flag but NO master
    assert driver is None  # ignite would skip SIEVE entirely


# ---------------------------------------------------------------------------
# (b) ACTIVE WHEN FLAGGED — master + plane flag + fixture → entity surfaces.
# ---------------------------------------------------------------------------


def test_flagged_driver_surfaces_entity_through_registry_and_ledger(tmp_path, monkeypatch):
    """With the master flag + the two slice-plane flags + a fixture estate, the
    driver runs SIEVE and lands a resolved entity in the registry + ledger."""
    # ``is_production_env()`` reads the real process env; pin non-production so
    # the synthetic slice roots are honored (a prod deploy forces them off).
    monkeypatch.setenv("TEX_APP_ENV", "development")
    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)

    env = {
        _MASTER: "1",
        _ACTIONS_FLAG: "1",
        _FS_FLAG: "1",
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }

    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    # Both slice-plane flags are reported active (receipt surface).
    assert _ACTIONS_FLAG in driver.active_plane_flags()
    assert _FS_FLAG in driver.active_plane_flags()

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    assert len(registry.list_all()) == 0

    result = driver.run(registry, ledger)

    # The engine surfaced at least one entity and projected it through the
    # governance boundary (registry write + ledger append).
    assert result is not None
    assert result.projected >= 1
    landed = registry.list_all()
    assert len(landed) >= 1
    # It is a SIEVE-projected, generic cross-plane entity (not a native object).
    assert any("sieve" in (a.metadata or {}).get("discovery_external_id", "") for a in landed)
    # The ledger recorded the discovery (durable hash-chained record).
    assert len(ledger.list_all()) >= 1


def test_flagged_but_no_source_degrades_to_empty():
    """Master + plane flag ON but NO fixture source → an honest EMPTY result,
    never a crash and never a fabricated entity."""
    env = {_MASTER: "1", _ACTIONS_FLAG: "1", "TEX_APP_ENV": "development"}
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    result = driver.run(registry, ledger)

    assert result is not None
    assert result.projected == 0
    assert len(registry.list_all()) == 0
    # The honest output is still a (wide, degenerate) unseen estimate, not None.
    assert result.unseen is not None


def test_production_forces_synthetic_estate_off(tmp_path, monkeypatch):
    """In production the synthetic slice roots are forced OFF, so even with the
    slice flags + fixture present SIEVE surfaces nothing from them.

    ``is_production_env()`` is the genuine deploy signal — it reads the real
    process ``TEX_APP_ENV`` (not the injected env), so the test sets it on the
    real environment via monkeypatch, exactly as a prod deploy would.
    """
    monkeypatch.setenv("TEX_APP_ENV", "production")
    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    env = {
        _MASTER: "1",
        _ACTIONS_FLAG: "1",
        _FS_FLAG: "1",
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    # The synthetic roots were dropped in production.
    assert driver.actions_dir is None
    assert driver.workspace_dir is None

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    result = driver.run(registry, ledger)
    assert result is not None
    assert result.projected == 0
    assert len(registry.list_all()) == 0


# ---------------------------------------------------------------------------
# (c) NEVER RAISES ON MISSING CREDS / SOURCES.
# ---------------------------------------------------------------------------


def test_construction_never_raises_with_missing_creds():
    """Building the driver with the master flag on but every plane that needs a
    credential flag-enabled and UNCREDENTIALED must not raise, and the run must
    degrade to empty rather than crashing."""
    env = {
        _MASTER: "1",
        # Enable credentialed planes WITHOUT supplying any creds/sources.
        "TEX_SIEVE_P13_SIGNED": "1",   # identity/IdP — no tenant/client/secret
        "TEX_SIEVE_P6_AUDIT": "1",     # managed control — no OPENAI_API_KEY
        "TEX_SIEVE_P1_JA4": "1",       # network egress — no flow fixture
        "TEX_SIEVE_P10_MCP": "1",      # MCP tool-graph — no source
        "TEX_SIEVE_P8_SUPPLY": "1",    # supply-chain — no repo root
        "TEX_APP_ENV": "development",
    }
    # Must not raise.
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    # Must not raise; degrades to empty (no creds → every plane senses nothing).
    result = driver.run(registry, ledger)
    assert result is not None
    assert result.projected == 0
    assert len(registry.list_all()) == 0


def test_build_active_sensors_with_uncredentialed_planes_never_raises():
    """The registry-level guarantee the driver leans on: building every
    flag-enabled plane with no creds returns sensors that all degrade to empty."""
    env = {
        "TEX_SIEVE_P13_SIGNED": "1",
        "TEX_SIEVE_P6_AUDIT": "1",
        "TEX_SIEVE_P1_JA4": "1",
        "TEX_SIEVE_P10_MCP": "1",
        "TEX_SIEVE_P8_SUPPLY": "1",
        "TEX_SIEVE_P9_EBPF": "1",
        "TEX_SIEVE_P9_EDR": "1",
        "TEX_SIEVE_P14_DECOY": "1",
    }
    sensors = build_active_sensors(env)  # must not raise
    assert len(sensors) >= 1
    # Every sensor senses nothing on an empty context (no creds/sources).
    from tex.discovery.engine.sensors import SenseContext

    ctx = SenseContext()
    for sensor in sensors:
        assert list(sensor.sense(ctx)) == []


# ---------------------------------------------------------------------------
# Defense-in-depth: a live-Entra construction failure must NEVER seed synthetic
# agents on a real deploy (the except-branch mirrors the no-creds _demo_seed gate).
# ---------------------------------------------------------------------------


def test_entra_live_failure_fallback_is_empty_in_production(monkeypatch):
    """If the live Entra connector raises during construction in production, the
    fallback transport must be EMPTY — never plant the 33-agent demo seed — even
    when TEX_DISCOVERY_DEMO_SEED=1 is forced on (production gates it off)."""
    from tex.main import _build_discovery_connectors

    monkeypatch.setenv("TEX_APP_ENV", "production")
    monkeypatch.setenv("TEX_DISCOVERY_ENTRA_TENANT_ID", "t")
    monkeypatch.setenv("TEX_DISCOVERY_ENTRA_CLIENT_ID", "c")
    monkeypatch.setenv("TEX_DISCOVERY_ENTRA_CLIENT_SECRET", "s")
    monkeypatch.setenv("TEX_DISCOVERY_DEMO_SEED", "1")  # forced on, yet prod gates it off

    # Force live-transport construction to raise (the only trigger for the
    # except-branch), and spy every FixtureGraphTransport the builder constructs.
    import tex.discovery.graph_transport as gt

    def _boom(*_a, **_k):
        raise RuntimeError("live transport unavailable")

    captured: list[dict] = []
    real_fixture = gt.FixtureGraphTransport

    def _spy(pages):
        captured.append(pages)
        return real_fixture(pages)

    monkeypatch.setattr("tex.discovery.graph_transport.LiveGraphTransport", _boom)
    monkeypatch.setattr("tex.discovery.graph_transport.FixtureGraphTransport", _spy)

    conns = _build_discovery_connectors()  # must NOT raise

    # The Entra fallback ran (the except-branch built a FixtureGraphTransport),
    # and in production every fixture transport is handed an EMPTY page set —
    # no synthetic agents, even with the demo seed flag forced on.
    assert captured, "expected the except-branch to build a FixtureGraphTransport"
    assert all(pages == {} for pages in captured)
    assert conns  # the connector list is still assembled, just synthetic-free
