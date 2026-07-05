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

(d) ROOTS LIGHT THE SLICE PLANES — pointing ``TEX_SIEVE_ACTIONS_DIR`` /
    ``TEX_SIEVE_WORKSPACE_DIR`` at an estate (dev only) lights ACTIONS_TRAIL /
    FS_WRITE without a second flag; an explicit flag value wins; production
    injects nothing. Regression for the 2026-07-05 live gap where the roots
    alone left both planes out of ignite's coverage object entirely.

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
from tex.discovery.engine.sensors.registry import build_active_sensors, roster_plane_ids
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
# (a) LIVE BY DEFAULT — Begin ignites the entire discovery layer; only an
#     EXPLICIT operator opt-out (master or per-plane) turns anything off.
# ---------------------------------------------------------------------------


def test_default_is_live_full_sweep():
    """With no env flags, ``build_sieve_driver`` returns a LIVE driver with the
    full-sweep switch lit — every roster plane arms; a plane is dark only when
    its vantage is genuinely missing, never because a flag was unset."""
    driver = build_sieve_driver({})
    assert isinstance(driver, SieveDriver)
    assert driver.env.get("TEX_SIEVE_ALL") == "1"
    # The full roster arms (flags reported for receipts).
    assert len(driver.active_plane_flags()) == len(roster_plane_ids())
    # An EXPLICIT full-sweep value is honored as-is, never overridden.
    explicit = build_sieve_driver({"TEX_SIEVE_ALL": "0"})
    assert isinstance(explicit, SieveDriver)
    assert explicit.env.get("TEX_SIEVE_ALL") == "0"


def test_explicit_master_opt_out_yields_no_driver():
    """Only a DELIBERATE falsey master flag removes the driver — the legacy
    path, byte-for-byte. Unset is not an opt-out."""
    assert build_sieve_driver({_MASTER: "0"}) is None
    assert build_sieve_driver({_MASTER: "false"}) is None
    assert build_sieve_driver({_MASTER: "off"}) is None
    assert isinstance(build_sieve_driver({"TEX_APP_ENV": "development"}), SieveDriver)


def test_explicit_per_plane_opt_out_darkens_that_plane_only():
    """Under the full sweep an explicitly-falsey per-plane flag opts that ONE
    plane out; every other plane stays armed."""
    driver = build_sieve_driver({_ACTIONS_FLAG: "0"})
    assert isinstance(driver, SieveDriver)
    flags = driver.active_plane_flags()
    assert _ACTIONS_FLAG not in flags
    assert len(flags) == len(roster_plane_ids()) - 1


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
    # The live-by-default driver is a SIBLING too — its existence never touches
    # the legacy connector list.
    assert isinstance(build_sieve_driver({}), SieveDriver)


def test_dormant_driver_run_is_inert_when_master_off():
    """No driver → no projection. Simulate the ignite guard's None-check.

    An EXPLICIT master opt-out wins over everything else — even an explicit
    plane flag — and ignite skips SIEVE entirely."""
    driver = build_sieve_driver({_ACTIONS_FLAG: "1", _MASTER: "0"})
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
# (d) ROOTS LIGHT THE SLICE PLANES — pointing SIEVE at an estate is the intent
#     to sense it. Regression for the 2026-07-05 live gap: TEX_SIEVE_ENABLED +
#     the two DIR roots (and NO per-plane flags) ran ignite with NEITHER
#     ACTIONS_TRAIL nor FS_WRITE active, so the coverage object omitted both.
# ---------------------------------------------------------------------------


def test_flags_plus_roots_run_planes_senses_both_slice_planes(tmp_path):
    """The roster path itself: with the two slice-plane flags set and the roots
    threaded via the SenseContext (exactly what ``SieveDriver.run`` builds),
    ``run_planes`` SENSES both planes — each appears in ``active_planes`` AND in
    ``occasions`` (emitted >=1 incidence from the planted estate) and the two
    occasions fuse to entities.

    Pins the roster MEMBERSHIP of ACTIONS_TRAIL / FS_WRITE: removing either
    from the registry (a capability subtraction) fails here first.
    """
    from tex.discovery.engine.models import PlaneId
    from tex.discovery.engine.pipeline import run_planes
    from tex.discovery.engine.sensors import SenseContext

    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    result = run_planes(
        env={_ACTIONS_FLAG: "1", _FS_FLAG: "1"},
        context=SenseContext(actions_dir=actions_dir, workspace_dir=workspace_dir),
    )
    assert PlaneId.ACTIONS_TRAIL in result.active_planes
    assert PlaneId.FS_WRITE in result.active_planes
    assert PlaneId.ACTIONS_TRAIL in result.occasions
    assert PlaneId.FS_WRITE in result.occasions
    assert len(result.entities) >= 1


def test_roots_alone_light_both_slice_planes(tmp_path, monkeypatch):
    """The live gap, exactly: master + the two DIR roots, NO per-plane flags.
    The driver lights both slice planes from the roots, actually senses the
    estate, and projects through the governance boundary."""
    monkeypatch.setenv("TEX_APP_ENV", "development")
    from tex.discovery.engine.models import PlaneId

    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    env = {
        _MASTER: "1",
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    # The roots implied the flags — the receipt surface reports both active.
    assert _ACTIONS_FLAG in driver.active_plane_flags()
    assert _FS_FLAG in driver.active_plane_flags()

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    result = driver.run(registry, ledger)
    assert result is not None
    assert PlaneId.ACTIONS_TRAIL in result.occasions
    assert PlaneId.FS_WRITE in result.occasions
    assert result.projected >= 1
    assert len(registry.list_all()) >= 1


def test_roots_alone_ignite_coverage_names_both_planes(tmp_path, monkeypatch):
    """The exact observable from the live repro: ignite's coverage object must
    list both slice planes as FIRED (it previously omitted them entirely).
    Drives the same seam ignite drives: ``driver.run`` → ``coverage.summarize``
    (what ``_run_sieve`` → ``_sieve_coverage`` compose on the route)."""
    monkeypatch.setenv("TEX_APP_ENV", "development")
    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    env = {
        _MASTER: "1",
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }
    driver = build_sieve_driver(env)
    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    result = driver.run(registry, ledger)
    assert result is not None

    from tex.discovery.engine.coverage import summarize

    cov = summarize(result, headline_count=len(registry.list_all()))
    obj = cov.as_object()
    fired = set(obj["fired"])
    assert "activity logs" in fired
    assert "file writes" in fired
    blind = {b["plane"] for b in obj["blind"]}
    assert "activity logs" not in blind
    assert "file writes" not in blind


def test_explicit_flag_value_beats_root_injection(tmp_path, monkeypatch):
    """An operator's deliberate ``TEX_SIEVE_ACTIONS_TRAIL=0`` keeps that plane
    OFF even with its root set; the other root still lights its own plane."""
    monkeypatch.setenv("TEX_APP_ENV", "development")
    from tex.discovery.engine.models import PlaneId

    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    env = {
        _MASTER: "1",
        _ACTIONS_FLAG: "0",  # deliberate OFF
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    assert _ACTIONS_FLAG not in driver.active_plane_flags()
    assert _FS_FLAG in driver.active_plane_flags()

    result = driver.run(InMemoryAgentRegistry(), InMemoryDiscoveryLedger())
    assert result is not None
    assert PlaneId.ACTIONS_TRAIL not in result.active_planes
    assert PlaneId.FS_WRITE in result.occasions


def test_production_roots_never_sense_synthetic_estate(tmp_path, monkeypatch):
    """Production posture: the synthetic roots are forced off, so even under the
    full sweep (slice planes ARMED) their sensors have no vantage and a stray
    dev DIR var on a prod deploy surfaces NOTHING — no minted entities, no
    projection from the planted estate."""
    monkeypatch.setenv("TEX_APP_ENV", "production")
    actions_dir, workspace_dir = _plant_two_occasion_estate(tmp_path)
    env = {
        _MASTER: "1",
        _ACTIONS_DIR_ENV: str(actions_dir),
        _WORKSPACE_DIR_ENV: str(workspace_dir),
    }
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    assert driver.actions_dir is None
    assert driver.workspace_dir is None

    registry = InMemoryAgentRegistry()
    result = driver.run(registry, InMemoryDiscoveryLedger())
    assert result is not None
    assert result.projected == 0
    assert len(registry.list_all()) == 0


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


# ---------------------------------------------------------------------------
# Re-sweep idempotency — N declared entities → N registry rows, forever.
# Regression for the 2026-07-05 live double-count: ignite minted 5 declared
# MCP-manifest entities and the standing watch's next SIEVE cycle minted the
# SAME 5 again (10 rows for 5 entities).
# ---------------------------------------------------------------------------


def test_standing_resweep_is_idempotent_n_entities_n_rows(tmp_path, monkeypatch):
    """A re-sweep over an UNCHANGED source reconciles every entity to the row
    it minted last time — same rows, no re-mint — while a genuinely-NEW
    declaration still lands as a new row (the capability mandate, never
    removed)."""
    monkeypatch.setenv("TEX_APP_ENV", "development")
    repo = tmp_path / "estate"
    plugin = repo / "plugins" / "example-plugin"
    plugin.mkdir(parents=True)
    # A nameless dotfile manifest (the ".mcp" junk-name repro) + a named one.
    (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
    (repo / "mcp.json").write_text(
        json.dumps({"name": "discord", "tools": [{"name": "send_message"}]})
    )

    env = {_MASTER: "1", "TEX_SIEVE_P8_SUPPLY": "1", "TEX_SIEVE_P8_REPO": str(repo)}
    driver = build_sieve_driver(env)
    assert isinstance(driver, SieveDriver)
    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()

    first = driver.run(registry, ledger, tenant="tex-enterprise")
    assert first is not None and first.projected >= 2
    rows_after_first = {a.agent_id for a in registry.list_all()}
    assert len(rows_after_first) >= 2
    # The junk-name fallback is gone: the nameless manifest lands under its
    # owning directory, never the dotfile stem.
    names = {a.name for a in registry.list_all()}
    assert "example-plugin" in names
    assert ".mcp" not in names

    # The standing watch's next cycle over the SAME source: no new rows.
    second = driver.run(registry, ledger, tenant="tex-enterprise")
    assert second is not None
    assert {a.agent_id for a in registry.list_all()} == rows_after_first

    # A genuinely-new declaration appears → exactly it mints, nothing else.
    other = repo / "services" / "telegram-bridge"
    other.mkdir(parents=True)
    (other / "mcp.json").write_text(json.dumps({"name": "telegram"}))
    third = driver.run(registry, ledger, tenant="tex-enterprise")
    assert third is not None
    rows_after_third = {a.agent_id for a in registry.list_all()}
    assert rows_after_first < rows_after_third
    assert len(rows_after_third) == len(rows_after_first) + 1


def test_standing_watch_reruns_sieve_under_each_enrolled_tenant():
    """THE live 2026-07-05 re-mint mechanism: ignite projected SIEVE under the
    watched tenant (``tex-enterprise``) but the standing tick re-ran the
    driver with NO tenant — the hardcoded ``default`` — where neither the
    tenant-scoped reconciliation key nor the tenant-scoped bind could see
    ignite's rows, so every cycle re-minted the same entities. The standing
    re-run must project under the ENROLLED tenant(s); with nothing enrolled it
    keeps the pre-enrollment default-estate behavior."""
    from tex.discovery.scheduler import BackgroundScanScheduler

    calls: list[str] = []

    class _RecordingDriver:
        def run(self, registry, ledger, *, index=None, tenant="default"):  # noqa: ANN001
            calls.append(tenant)
            return None

    class _StubService:
        def scan(self, **kwargs):  # noqa: ANN003 — legacy loop not under test
            raise RuntimeError("stub: legacy connector scan not under test")

    sched = BackgroundScanScheduler(
        service=_StubService(), tenants=["tex-enterprise"]
    )
    sched.attach_sieve(
        sieve_driver=_RecordingDriver(),
        agent_registry=InMemoryAgentRegistry(),
        discovery_ledger=InMemoryDiscoveryLedger(),
    )
    sched._run_one_cycle()
    assert calls == ["tex-enterprise"]

    # Capability preserved: an un-ignited estate (no enrolled tenants) still
    # gets its standing re-run, under the default estate exactly as before.
    calls.clear()
    sched_default = BackgroundScanScheduler(service=_StubService(), tenants=[])
    sched_default.attach_sieve(
        sieve_driver=_RecordingDriver(),
        agent_registry=InMemoryAgentRegistry(),
        discovery_ledger=InMemoryDiscoveryLedger(),
    )
    sched_default._run_one_cycle()
    assert calls == ["default"]
