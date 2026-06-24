"""
P9 (endpoint) endpoint/EDR plane tests (``sensors.endpoint_edr``).

Proves the load-bearing properties the plane contract requires:

1. A PLANTED host-agent (an osquery ``processes``-shaped telemetry fixture, read
   by the clearly-labeled local shim) emits a correct ``OBSERVED`` ``Incidence``
   carrying the §8 endpoint-EDR footprint fields {host_id, process_name, runtime,
   code_hash, persistence}, with the IDENTITY-grade ``code_hash`` as a KEY and the
   descriptive fields as ATTRS.
2. The IDENTITY-grade ``code_hash`` this plane emits FUSES the same agent across
   the endpoint-EDR plane and the kernel/eBPF plane to ONE entity (the cross-plane
   join this coarser cousin exists to contribute).
3. Many process sightings (workers / re-execs) of ONE deployed agent on one host
   fold into ONE incidence; two genuinely-distinct agents on the same host stay
   SEPARATE (the N1 shared-host split surface preserved).
4. The plane DEGRADES TO EMPTY (never raises) when no source is configured, when
   the source file is missing, and through the registry factory built without a
   telemetry path.
5. FLAG-GATING: the registry builds the sensor ONLY when ``TEX_SIEVE_P9_EDR`` is
   set; the default (no flags) yields no endpoint-EDR sensor.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_endpoint_edr.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.endpoint_edr import (
    ENDPOINT_EDR_CATCHABILITY,
    ENDPOINT_EDR_TELEMETRY_ENV,
    EndpointEdrSensor,
    _FixtureTelemetrySource,
    build_endpoint_edr_sensor,
)
from tex.discovery.engine.sensors.registry import build_active_sensors

_FLAG = "TEX_SIEVE_P9_EDR"

# A planted, deployed agent: a python interpreter hosting agent code on one host,
# hashed on disk, persisted via a systemd unit — plus two worker re-execs of the
# SAME code (same sha256) on the same host. The osquery ``processes`` row shape.
_PLANTED_AGENT_RECORDS = [
    {
        "host_identifier": "host-7a2b",
        "name": "python3.12",
        "path": "/usr/bin/python3.12",
        "cmdline": "python3 -m assaypilot.main --serve",
        "pid": 12345,
        "parent": 1,
        "sha256": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
        "persistence": "systemd:assaypilot.service",
        "unixTime": 1782242461,
    },
    {
        "host_identifier": "host-7a2b",
        "name": "python3.12",
        "path": "/usr/bin/python3.12",
        "cmdline": "python3 -m assaypilot.main --worker 1",
        "pid": 12346,
        "sha256": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
        "unixTime": 1782242462,
    },
    {
        "host_identifier": "host-7a2b",
        "name": "python3.12",
        "path": "/usr/bin/python3.12",
        "cmdline": "python3 -m assaypilot.main --worker 2",
        "pid": 12347,
        "sha256": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
        "unixTime": 1782242463,
    },
]


def _write_fixture(tmp_path: Path, records: list[dict]) -> Path:
    """Write an osquery-shaped JSONL telemetry fixture (one record per line)."""
    fixture = tmp_path / "edr_telemetry.jsonl"
    fixture.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    return fixture


def _sense(fixture: Path) -> list[Incidence]:
    sensor = EndpointEdrSensor(_FixtureTelemetrySource(fixture))
    return list(sensor.sense(SenseContext()))


# ---------------------------------------------------------------------------
# 1. A planted host-agent emits a correct OBSERVED incidence with the §8 fields
# ---------------------------------------------------------------------------


def test_planted_agent_emits_correct_incidence(tmp_path):
    fixture = _write_fixture(tmp_path, _PLANTED_AGENT_RECORDS)
    incidences = _sense(fixture)

    # Three process sightings of ONE deployed agent fold into ONE incidence.
    assert len(incidences) == 1
    inc = incidences[0]

    assert inc.plane_id is PlaneId.ENDPOINT_EDR
    assert inc.admissibility is Admissibility.OBSERVED
    assert inc.catchability == ENDPOINT_EDR_CATCHABILITY
    # OBSERVED, not PROVEN — strictly the coarser cousin of the eBPF plane.
    assert inc.catchability < 1.0
    assert inc.observed_at.tzinfo is not None
    assert inc.raw_evidence_ref.startswith(str(fixture))

    fp = inc.footprint
    # KEYS (matched on by fuse): host_id (bridging) + code_hash (identity).
    assert fp.key(FootprintField.HOST_ID.value) == "host-7a2b"
    assert (
        fp.key(FootprintField.CODE_HASH.value)
        == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
    )
    # ATTRS (descriptive payload, not matched on).
    assert fp.attr(FootprintField.PROCESS_NAME.value) == "python3.12"
    assert fp.attr(FootprintField.RUNTIME.value) == "python"
    assert fp.attr(FootprintField.PERSISTENCE.value) == "systemd:assaypilot.service"
    # All three PIDs folded into the one host-agent footprint.
    assert fp.attr("process_count") == "3"
    assert "12345" in (fp.attr("pids") or "")


# ---------------------------------------------------------------------------
# 2. The IDENTITY-grade code_hash fuses across the endpoint-EDR + eBPF planes
# ---------------------------------------------------------------------------


def test_code_hash_fuses_across_endpoint_and_ebpf_planes(tmp_path):
    """The endpoint-EDR incidence and a kernel/eBPF incidence sharing the SAME
    ``code_hash`` resolve to ONE entity — the cross-plane join this plane adds."""
    fixture = _write_fixture(tmp_path, _PLANTED_AGENT_RECORDS)
    edr_incidences = _sense(fixture)
    assert len(edr_incidences) == 1
    code_hash = edr_incidences[0].footprint.key(FootprintField.CODE_HASH.value)

    # A kernel/eBPF sighting of the SAME binary (same code_hash) on its own plane.
    from tex.discovery.engine.models import FootprintVector

    ebpf_inc = Incidence(
        plane_id=PlaneId.KERNEL_EBPF,
        footprint=FootprintVector.of(
            plane_id=PlaneId.KERNEL_EBPF,
            keys={
                FootprintField.SYSCALL_GRAPH_SIG.value: "sgs:deadbeef",
                FootprintField.CODE_HASH.value: code_hash,
            },
        ),
        catchability=1.0,
        admissibility=Admissibility.PROVEN,
        raw_evidence_ref="kernel_ebpf:1",
    )

    entities = resolve([*edr_incidences, ebpf_inc])
    # The shared identity-grade code_hash fuses the two cross-plane sightings.
    assert len(entities) == 1
    entity = entities[0]
    assert PlaneId.ENDPOINT_EDR in entity.planes_seen
    assert PlaneId.KERNEL_EBPF in entity.planes_seen


# ---------------------------------------------------------------------------
# 3. Two distinct agents on one host stay SEPARATE (N1 shared-host split surface)
# ---------------------------------------------------------------------------


def test_two_distinct_agents_on_one_host_stay_separate(tmp_path):
    records = [
        {
            "host_identifier": "host-shared",
            "name": "python3.12",
            "path": "/usr/bin/python3.12",
            "cmdline": "python3 -m alpha.main",
            "pid": 100,
            "sha256": "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
            "unixTime": 1782242461,
        },
        {
            "host_identifier": "host-shared",
            "name": "node",
            "path": "/usr/bin/node",
            "cmdline": "node /srv/beta/server.js",
            "pid": 200,
            "sha256": "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
            "unixTime": 1782242462,
        },
    ]
    fixture = _write_fixture(tmp_path, records)
    incidences = _sense(fixture)

    # Two distinct code hashes on one host → two distinct incidences (not merged
    # by the shared bridging host_id).
    assert len(incidences) == 2
    hashes = {i.footprint.key(FootprintField.CODE_HASH.value) for i in incidences}
    assert len(hashes) == 2
    hosts = {i.footprint.key(FootprintField.HOST_ID.value) for i in incidences}
    assert hosts == {"host-shared"}
    runtimes = {i.footprint.attr(FootprintField.RUNTIME.value) for i in incidences}
    assert runtimes == {"python", "node"}


# ---------------------------------------------------------------------------
# 4. Degrade-to-empty (never raise) on every absent-source path
# ---------------------------------------------------------------------------


def test_degrades_to_empty_when_no_source():
    sensor = EndpointEdrSensor(telemetry_source=None)
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_on_missing_file(tmp_path):
    missing = tmp_path / "nope.jsonl"
    sensor = EndpointEdrSensor(_FixtureTelemetrySource(missing))
    assert list(sensor.sense(SenseContext())) == []


def test_factory_degrades_to_empty_without_telemetry_path():
    sensor = build_endpoint_edr_sensor({})
    assert sensor.plane_id is PlaneId.ENDPOINT_EDR
    assert list(sensor.sense(SenseContext())) == []


def test_malformed_lines_are_skipped_not_raised(tmp_path):
    fixture = tmp_path / "messy.jsonl"
    fixture.write_text(
        "\n".join(
            [
                "not json at all",
                json.dumps({"no_host": True}),  # unattributable → skipped
                json.dumps(_PLANTED_AGENT_RECORDS[0]),  # the one good record
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sensor = EndpointEdrSensor(_FixtureTelemetrySource(fixture))
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    assert incidences[0].footprint.key(FootprintField.HOST_ID.value) == "host-7a2b"


# ---------------------------------------------------------------------------
# 5. Flag-gating through the registry — OFF by default, ON only with the flag
# ---------------------------------------------------------------------------


def test_registry_off_by_default():
    sensors = build_active_sensors({})
    assert not any(s.plane_id is PlaneId.ENDPOINT_EDR for s in sensors)


def test_registry_builds_sensor_when_flag_enabled(tmp_path):
    fixture = _write_fixture(tmp_path, _PLANTED_AGENT_RECORDS)
    env = {_FLAG: "1", ENDPOINT_EDR_TELEMETRY_ENV: str(fixture)}
    sensors = build_active_sensors(env)
    edr = [s for s in sensors if s.plane_id is PlaneId.ENDPOINT_EDR]
    assert len(edr) == 1
    # And the flag-built sensor actually senses the planted agent.
    incidences = list(edr[0].sense(SenseContext()))
    assert len(incidences) == 1
    assert incidences[0].plane_id is PlaneId.ENDPOINT_EDR


def test_registry_flag_enabled_but_no_telemetry_degrades_empty():
    """Flag ON but no telemetry path → built, but senses nothing (default-safe)."""
    sensors = build_active_sensors({_FLAG: "1"})
    edr = [s for s in sensors if s.plane_id is PlaneId.ENDPOINT_EDR]
    assert len(edr) == 1
    assert list(edr[0].sense(SenseContext())) == []
