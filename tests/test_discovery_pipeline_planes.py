"""
SIEVE pipeline — the MULTI-PLANE registry-driven path (``pipeline.run_planes``).

``run_slice`` proves the thin two-plane vertical slice. ``run_planes`` is its
full-roster sibling: it SENSEs across EVERY flag-enabled plane built by the
registry (``build_active_sensors``), then FUSEs cross-plane, ESTIMATEs over the
genuinely-live capture occasions, and ADAPTs each resolved entity through the
governance boundary. This module proves the four load-bearing properties of that
path:

1. **Default-safe.** With NO ``TEX_SIEVE_P*`` flags set, the active roster is
   empty, so ``run_planes`` returns an honest empty result — never raises, never
   fabricates an entity, never touches the registry. This is the posture a
   merge-to-main / prod deploy must keep (ARCHITECTURE.md §8).

2. **Multi-plane SENSE → FUSE → ESTIMATE → ADAPT.** Two flag-enabled real planes
   (P9 kernel/eBPF + P9 endpoint/EDR), each fed a planted same-shape fixture,
   both emit incidences; the pipeline resolves them, the estimator counts BOTH
   live planes as capture occasions, and the adapter lands every entity in the
   registry + ledger so ``StandingGovernance`` can now govern them.

3. **Cross-plane fusion to ONE entity.** Two EDR sightings of the SAME on-disk
   agent (same ``code_hash``, an IDENTITY-grade join key) seen on two distinct
   hosts fuse to ONE entity across the host bridge — the same-agent-on-N-planes
   join the multi-plane path exists to perform.

4. **Configurable + degrade-to-empty.** A flag-enabled-but-unsourced plane
   contributes no incidences (the §8 default-safe degrade) rather than raising,
   so a partially-credentialed env yields fewer live planes, never a crash.

These run against REAL sensors built by the REAL registry — no mocks of the
engine — exactly as a live deployment would activate them.
"""

from __future__ import annotations

import json
from pathlib import Path

# Importing the adapter binds the SieveEntity output-boundary methods used by
# ``run_planes``' ADAPT stage, so it must be importable for the projection path.
from tex.discovery.engine import adapter  # noqa: F401
from tex.discovery.engine.models import PlaneId
from tex.discovery.engine.pipeline import PlanesResult, run_planes
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.endpoint_edr import ENDPOINT_EDR_TELEMETRY_ENV
from tex.discovery.engine.sensors.kernel_ebpf import KERNEL_EBPF_EVENTS_ENV
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

_EBPF_FLAG = "TEX_SIEVE_P9_EBPF"
_EDR_FLAG = "TEX_SIEVE_P9_EDR"

# A sha256-shaped on-disk code hash — the IDENTITY-grade anchor the EDR plane
# joins on, shared by an agent that shows up on TWO hosts.
_CODE = "ab12cd34ef56" * 5 + "ab12"  # 64 hex chars


# ---------------------------------------------------------------------------
# Faithful same-shape fixtures (the SAME shapes the live exports emit).
# ---------------------------------------------------------------------------


def _ebpf_fixture(path: Path) -> Path:
    """A Tetragon JSONL export (``tetra getevents -o json`` shape)."""
    events = [
        {
            "time": "2026-05-01T12:00:00.000Z",
            "process_exec": {
                "process": {
                    "exec_id": "E:1782242461000000000:101",
                    "pid": 101,
                    "binary": "/usr/bin/python3.12",
                    "arguments": "-m assaypilot.main --serve",
                    "parent_exec_id": "/sbin/init",
                    "binary_properties": {"file": {"hash": {"sha256": _CODE}}},
                }
            },
        },
        {
            "time": "2026-05-01T12:00:01.000Z",
            "process_kprobe": {
                "function_name": "tcp_connect",
                "process": {
                    "exec_id": "E:1782242461000000000:101",
                    "binary": "/usr/bin/python3.12",
                    "binary_properties": {"file": {"hash": {"sha256": _CODE}}},
                },
                "args": [{"sock_arg": {"daddr": "10.0.0.5", "dport": 443}}],
            },
        },
        {
            "time": "2026-05-01T12:00:02.000Z",
            "process_kprobe": {
                "function_name": "security_file_permission",
                "process": {
                    "exec_id": "E:1782242461000000000:101",
                    "binary": "/usr/bin/python3.12",
                    "binary_properties": {"file": {"hash": {"sha256": _CODE}}},
                },
                "args": [{"file_arg": {"path": "/ws/preclinical/readout-52.md"}}],
            },
        },
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def _edr_fixture(path: Path) -> Path:
    """An osquery ``processes`` JSONL export — the SAME agent on TWO hosts.

    Both rows carry the SAME on-disk ``sha256`` (the IDENTITY-grade ``code_hash``
    join), differing only on ``host_identifier`` (a BRIDGING-grade cohort key).
    A correct resolver fuses them to ONE entity across the host bridge.
    """
    records = [
        {
            "host_identifier": "host-7a2b",
            "name": "python3.12",
            "path": "/usr/bin/python3.12",
            "cmdline": "python3 -m assaypilot.main --serve",
            "pid": 101,
            "parent": 1,
            "sha256": _CODE,
            "persistence": "systemd:assaypilot.service",
            "unixTime": 1782242461,
        },
        {
            "host_identifier": "host-9c4d",
            "name": "python3.12",
            "path": "/usr/bin/python3.12",
            "cmdline": "python3 -m assaypilot.main --serve",
            "pid": 202,
            "parent": 1,
            "sha256": _CODE,
            "persistence": "systemd:assaypilot.service",
            "unixTime": 1782242470,
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Default-safe: no flags → empty roster → honest empty result, no registry hit.
# ---------------------------------------------------------------------------


def test_run_planes_default_safe_no_flags():
    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()

    result = run_planes(env={}, registry=registry, ledger=ledger)

    assert isinstance(result, PlanesResult)
    assert result.entities == ()
    assert result.active_planes == ()
    assert result.occasions == ()
    assert result.projected == 0
    # Honest empty estimate: degenerate band + a named blind spot per withheld.
    assert result.unseen is not None
    assert result.unseen.coverage_health in ("degenerate", "wide", "unknown")
    assert [b.missing_plane for b in result.unseen.named_blind_spots] == [
        PlaneId.WITHHELD_THIRD
    ]
    # The registry was never touched.
    assert list(registry.list_all()) == []


# ---------------------------------------------------------------------------
# 2 + 3. Two flag-enabled real planes → SENSE → FUSE → ESTIMATE → ADAPT.
# ---------------------------------------------------------------------------


def test_run_planes_two_live_planes_sense_fuse_estimate_adapt(tmp_path: Path):
    ebpf = _ebpf_fixture(tmp_path / "tetra.jsonl")
    edr = _edr_fixture(tmp_path / "edr.jsonl")

    env = {
        _EBPF_FLAG: "1",
        KERNEL_EBPF_EVENTS_ENV: str(ebpf),
        _EDR_FLAG: "1",
        ENDPOINT_EDR_TELEMETRY_ENV: str(edr),
    }

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()

    result = run_planes(
        env=env,
        context=SenseContext(),
        registry=registry,
        ledger=ledger,
    )

    # Both flag-enabled planes built a sensor (active roster).
    assert PlaneId.KERNEL_EBPF in result.active_planes
    assert PlaneId.ENDPOINT_EDR in result.active_planes

    # Both planes genuinely CAPTURED (each emitted >=1 incidence) → both are
    # counted as capture occasions by the estimator.
    assert PlaneId.KERNEL_EBPF in result.occasions
    assert PlaneId.ENDPOINT_EDR in result.occasions

    # FUSE: the eBPF sighting resolves to its own entity (its identity join is
    # the syscall-graph signature, NOT bare code_hash — the two-axis design that
    # refuses to over-merge it with the EDR rows); the TWO EDR sightings of the
    # SAME on-disk agent on two hosts fuse to ONE entity across the host bridge
    # via the IDENTITY-grade code_hash edge. So 2 entities total.
    assert len(result.entities) == 2

    # Key on planes_CAPTURED (where members were genuinely sighted), NOT
    # planes_seen — planes_seen unions the bridging-edge planes (the shared
    # binary_path links the two planes with a weak bridging edge that does NOT
    # merge them), so it is not the membership oracle here.
    edr_entities = [
        e
        for e in result.entities
        if e.planes_captured == frozenset({PlaneId.ENDPOINT_EDR})
    ]
    assert len(edr_entities) == 1
    # The EDR entity fused BOTH host sightings (cross-host, same code_hash) — the
    # same-agent-on-N-vantages join the multi-plane path exists to perform.
    assert len(edr_entities[0].incidences) == 2
    # And that fusion was carried by an IDENTITY-grade (code_hash) edge.
    assert any(
        ed.grade.value == "identity" and ed.plane_id is PlaneId.ENDPOINT_EDR
        for ed in edr_entities[0].edges
    )

    ebpf_entities = [
        e
        for e in result.entities
        if e.planes_captured == frozenset({PlaneId.KERNEL_EBPF})
    ]
    assert len(ebpf_entities) == 1

    # ESTIMATE: a real two-occasion estimate with the withheld blind spot named.
    assert result.unseen is not None
    assert result.unseen.ci_low <= result.unseen.lower <= result.unseen.ci_high
    assert PlaneId.WITHHELD_THIRD in {
        b.missing_plane for b in result.unseen.named_blind_spots
    }
    # The slice never asserts measured-catchability calibration.
    assert result.unseen.coverage_health != "calibrated"

    # ADAPT: every resolved entity landed in the registry (governable now) AND a
    # hash-chained ledger row was appended per entity.
    assert result.projected == len(result.entities)
    assert len(list(registry.list_all())) == len(result.entities)
    assert len(list(ledger.list_all())) >= len(result.entities)


# ---------------------------------------------------------------------------
# 4. A flag-enabled-but-unsourced plane degrades to empty (no crash, no occasion).
# ---------------------------------------------------------------------------


def test_run_planes_flag_enabled_but_unsourced_plane_degrades_empty(tmp_path: Path):
    edr = _edr_fixture(tmp_path / "edr.jsonl")

    # eBPF flag ON but NO events path → that plane builds a sensor that senses
    # nothing; EDR is fully sourced and captures.
    env = {
        _EBPF_FLAG: "1",  # enabled but unsourced → degrades to empty
        _EDR_FLAG: "1",
        ENDPOINT_EDR_TELEMETRY_ENV: str(edr),
    }

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()

    result = run_planes(env=env, registry=registry, ledger=ledger)

    # eBPF built a sensor (flag ON) but captured nothing (no source).
    assert PlaneId.KERNEL_EBPF in result.active_planes
    assert PlaneId.KERNEL_EBPF not in result.occasions
    # EDR captured the planted cross-host agent → exactly ONE fused entity.
    assert PlaneId.ENDPOINT_EDR in result.occasions
    assert len(result.entities) == 1
    assert result.projected == 1


# ---------------------------------------------------------------------------
# 5. No boundary supplied → pure SENSE→FUSE→ESTIMATE (no registry mutation).
# ---------------------------------------------------------------------------


def test_run_planes_without_boundary_is_a_pure_probe(tmp_path: Path):
    edr = _edr_fixture(tmp_path / "edr.jsonl")
    env = {_EDR_FLAG: "1", ENDPOINT_EDR_TELEMETRY_ENV: str(edr)}

    result = run_planes(env=env)  # no registry/ledger

    # Entities + estimate are produced, but nothing was projected (a coverage
    # probe that must not mutate the registry).
    assert len(result.entities) == 1
    assert result.projected == 0
    assert result.unseen is not None
