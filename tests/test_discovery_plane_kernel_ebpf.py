"""
P9 KERNEL / eBPF plane tests (``tex.discovery.engine.sensors.kernel_ebpf``).

Proves the kernel plane on the HARD case the SIEVE engine exists to solve:
**local, identity-less processes** (the tex-enterprise fleet are plain OS
processes — no OIDC sub, no SPIFFE id, no managed-control id). The only thing
that identifies them is what is actually executing — the measured code hash, the
exec lineage, and the syscall-graph shape.

What is proven here, each mapping to a HARD RULE / the mandate:

1. A planted agent in a Tetragon-shaped event log resolves to a PROVEN
   ``Incidence`` on ``PlaneId.KERNEL_EBPF`` with the contract footprint
   ``{code_hash, exec_id, proc_lineage, syscall_graph_sig, binary_path}`` and
   carries the identity-grade behavioral join key the cross-plane resolver fuses
   on.
2. The TWO-AXIS identity: ``code_hash`` MERGES many ``exec_id``s of ONE binary
   (re-execs collapse to one agent) while ``syscall_graph_sig`` SPLITS two
   DISTINCT agents that share the same binary/``code_hash``.
3. Degrade-to-EMPTY: a missing event source (no path / missing file) senses
   nothing and NEVER raises.
4. Flag-gating: built only behind ``TEX_SIEVE_P9_EBPF``; the registry yields
   nothing by default and the plane stays inert with no event source even when
   the flag is on.

The fixture is a faithful Tetragon JSONL (``process_exec`` / ``process_exit`` /
``process_kprobe`` for connect + file-write) — the SAME shape a real
``tetra getevents -o json`` export emits; the local shim only substitutes the
event SOURCE (a file for the kernel ring buffer).

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_kernel_ebpf.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import Admissibility, PlaneId
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.kernel_ebpf import (
    KERNEL_EBPF_EVENTS_ENV,
    KernelEbpfSensor,
    _FixtureEventSource,
    build_kernel_ebpf_sensor,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# ---------------------------------------------------------------------------
# Tetragon fixture builders (the SAME shape `tetra getevents -o json` emits).
# ---------------------------------------------------------------------------


def _exec_event(exec_id: str, binary: str, code_hash: str, parent: str, args: str) -> dict:
    return {
        "time": "2026-05-01T12:00:00.000Z",
        "process_exec": {
            "process": {
                "exec_id": exec_id,
                "pid": int(exec_id.split(":")[-1] or "0"),
                "binary": binary,
                "arguments": args,
                "parent_exec_id": parent,
                "binary_properties": {"file": {"hash": {"sha256": code_hash}}},
            }
        },
    }


def _kprobe_connect(exec_id: str, binary: str, code_hash: str, daddr: str, dport: int) -> dict:
    return {
        "time": "2026-05-01T12:00:01.000Z",
        "process_kprobe": {
            "function_name": "tcp_connect",
            "process": {
                "exec_id": exec_id,
                "binary": binary,
                "binary_properties": {"file": {"hash": {"sha256": code_hash}}},
            },
            "args": [{"sock_arg": {"daddr": daddr, "dport": dport}}],
        },
    }


def _kprobe_write(exec_id: str, binary: str, code_hash: str, path: str) -> dict:
    return {
        "time": "2026-05-01T12:00:02.000Z",
        "process_kprobe": {
            "function_name": "security_file_permission",
            "process": {
                "exec_id": exec_id,
                "binary": binary,
                "binary_properties": {"file": {"hash": {"sha256": code_hash}}},
            },
            "args": [{"file_arg": {"path": path}}],
        },
    }


def _exit_event(exec_id: str, binary: str, code_hash: str) -> dict:
    return {
        "time": "2026-05-01T12:00:03.000Z",
        "process_exit": {
            "process": {
                "exec_id": exec_id,
                "binary": binary,
                "binary_properties": {"file": {"hash": {"sha256": code_hash}}},
            }
        },
    }


def _write_fixture(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Proof 1 — a planted identity-less agent emits a correct PROVEN incidence.
# ---------------------------------------------------------------------------


def test_planted_agent_emits_proven_incidence_with_contract_footprint(tmp_path: Path) -> None:
    bina = "/usr/bin/python3.12"
    code = "ab12cd34" * 8  # a sha256-shaped code hash
    # One agent, two re-execs of the SAME binary (a restart / worker fork). The
    # two execs share code_hash AND behavioral shape → must MERGE to one agent.
    events = [
        _exec_event("E:1782242461000000000:101", bina, code, "/sbin/init", "-m assaypilot.main --serve"),
        _kprobe_connect("E:1782242461000000000:101", bina, code, "10.0.0.5", 443),
        _kprobe_write("E:1782242461000000000:101", bina, code, "/ws/preclinical/study-readouts/52.md"),
        _exit_event("E:1782242461000000000:101", bina, code),
        # re-exec (different exec_id, same binary, same behavior) — MERGE axis.
        _exec_event("E:1782242499000000000:222", bina, code, "/sbin/init", "-m assaypilot.main --serve"),
        _kprobe_connect("E:1782242499000000000:222", bina, code, "10.0.0.5", 443),
        _kprobe_write("E:1782242499000000000:222", bina, code, "/ws/preclinical/study-readouts/52.md"),
    ]
    fixture = tmp_path / "tetragon.jsonl"
    _write_fixture(fixture, events)

    sensor = build_kernel_ebpf_sensor({KERNEL_EBPF_EVENTS_ENV: str(fixture)})
    incidences = list(sensor.sense(SenseContext()))

    # The MERGE axis collapsed BOTH exec_ids into exactly ONE agent.
    assert len(incidences) == 1
    inc = incidences[0]

    # Ground truth: kernel observation is PROVEN and lives on the P9 plane.
    assert inc.plane_id is PlaneId.KERNEL_EBPF
    assert inc.admissibility is Admissibility.PROVEN
    assert inc.observed_at.tzinfo is not None

    fp = inc.footprint
    # The contract footprint fields are present. ``code_hash`` is the MERGE-axis
    # anchor carried as a receipt attr (NOT a cross-incidence join key — bare
    # code_hash would over-merge two agents sharing a binary); ``binary_path`` is
    # a weak bridging key; ``syscall_graph_sig`` is the identity-grade join key.
    assert fp.attr("code_hash") == code
    assert fp.key("binary_path") == bina
    sgs = fp.key("syscall_graph_sig")
    assert sgs is not None and sgs.startswith("sgs:")
    # exec_id folds BOTH re-execs; proc_lineage captures the parent.
    exec_ids = (fp.attr("exec_id") or "").split(",")
    assert set(exec_ids) == {
        "E:1782242461000000000:101",
        "E:1782242499000000000:222",
    }
    assert fp.attr("exec_count") == "2"
    assert "/sbin/init" in (fp.attr("proc_lineage") or "")
    # The connect + write side-effects are carried for receipts.
    assert "10.0.0.5:443" in (fp.attr("connect_targets") or "")
    assert "/ws/preclinical/study-readouts/52.md" in (fp.attr("write_targets") or "")


# ---------------------------------------------------------------------------
# Proof 2 — two-axis identity: same binary, DIFFERENT behavior → SPLIT.
# ---------------------------------------------------------------------------


def test_two_distinct_agents_under_one_binary_split_on_syscall_graph(tmp_path: Path) -> None:
    bina = "/usr/bin/python3.12"
    code = "ffeedd00" * 8  # the SAME code hash for both agents (one binary)

    # Agent A: a network-talking agent (connect-heavy syscall graph).
    a = "E:1782242461000000000:301"
    # Agent B: a file-writing agent (write-heavy syscall graph), SAME binary.
    b = "E:1782242462000000000:302"
    events = [
        _exec_event(a, bina, code, "/sbin/init", "-m netbot.main"),
        _kprobe_connect(a, bina, code, "203.0.113.9", 8443),
        _kprobe_connect(a, bina, code, "203.0.113.10", 8443),
        _exec_event(b, bina, code, "/sbin/init", "-m filebot.main"),
        _kprobe_write(b, bina, code, "/ws/reports/a.md"),
        _kprobe_write(b, bina, code, "/ws/reports/b.md"),
    ]
    fixture = tmp_path / "tetragon.jsonl"
    _write_fixture(fixture, events)

    sensor = KernelEbpfSensor(event_source=_FixtureEventSource(fixture))
    incidences = list(sensor.sense(SenseContext()))

    # code_hash alone is too COARSE — it would MERGE these to one. The
    # syscall_graph_sig SPLIT axis keeps the two distinct agents apart.
    assert len(incidences) == 2
    sgs = {i.footprint.key("syscall_graph_sig") for i in incidences}
    assert len(sgs) == 2  # the two behaviors produced two distinct signatures
    # Both still carry the shared binary code hash (the merge-axis context attr).
    assert {i.footprint.attr("code_hash") for i in incidences} == {code}

    # And the fuse stage does NOT collapse them: the identity-grade join key is
    # the per-agent syscall_graph_sig, not the shared code_hash.
    entities = resolve(incidences)
    assert len(entities) == 2


def test_re_execs_of_one_agent_merge_not_split(tmp_path: Path) -> None:
    """The MERGE axis: many exec_ids of one binary+behavior = ONE entity."""
    bina = "/usr/bin/python3.12"
    code = "11223344" * 8
    events = []
    for i, pid in enumerate(("401", "402", "403")):
        ex = f"E:178224250{i}000000000:{pid}"
        events += [
            _exec_event(ex, bina, code, "/sbin/init", "-m worker.main"),
            _kprobe_connect(ex, bina, code, "10.1.1.1", 80),
            _kprobe_write(ex, bina, code, "/ws/out/log.txt"),
        ]
    fixture = tmp_path / "tetragon.jsonl"
    _write_fixture(fixture, events)

    sensor = build_kernel_ebpf_sensor({KERNEL_EBPF_EVENTS_ENV: str(fixture)})
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    assert incidences[0].footprint.attr("exec_count") == "3"


# ---------------------------------------------------------------------------
# Proof 3 — degrade to EMPTY (never raise) on a missing/absent source.
# ---------------------------------------------------------------------------


def test_degrades_to_empty_when_no_event_source() -> None:
    # No path env at all → inert sensor, senses nothing, never raises.
    sensor = build_kernel_ebpf_sensor({})
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_event_file_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    sensor = build_kernel_ebpf_sensor({KERNEL_EBPF_EVENTS_ENV: str(missing)})
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_on_malformed_events(tmp_path: Path) -> None:
    fixture = tmp_path / "garbage.jsonl"
    fixture.write_text("not json\n{}\n[]\n", encoding="utf-8")
    sensor = build_kernel_ebpf_sensor({KERNEL_EBPF_EVENTS_ENV: str(fixture)})
    # Malformed / non-process lines degrade to fewer events, never an exception.
    assert list(sensor.sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# Proof 4 — flag-gating: OFF by default; inert source even when the flag is on.
# ---------------------------------------------------------------------------


def test_plane_is_flag_gated_off_by_default() -> None:
    # No TEX_SIEVE_* flag set → the registry builds NO sensors at all.
    assert build_active_sensors({}) == []


def test_flag_on_but_no_source_degrades_empty(tmp_path: Path) -> None:
    # Flag ENABLED but no event-source path → the plane is built but inert.
    sensors = build_active_sensors({"TEX_SIEVE_P9_EBPF": "1"})
    kernel = [s for s in sensors if s.plane_id is PlaneId.KERNEL_EBPF]
    assert len(kernel) == 1
    assert list(kernel[0].sense(SenseContext())) == []


def test_flag_on_with_source_emits_via_registry(tmp_path: Path) -> None:
    bina = "/usr/bin/python3.12"
    code = "abcabc12" * 8
    ex = "E:1782242461000000000:501"
    fixture = tmp_path / "tetragon.jsonl"
    _write_fixture(
        fixture,
        [
            _exec_event(ex, bina, code, "/sbin/init", "-m agent.main"),
            _kprobe_write(ex, bina, code, "/ws/x.md"),
        ],
    )
    sensors = build_active_sensors(
        {"TEX_SIEVE_P9_EBPF": "1", KERNEL_EBPF_EVENTS_ENV: str(fixture)}
    )
    kernel = [s for s in sensors if s.plane_id is PlaneId.KERNEL_EBPF]
    assert len(kernel) == 1
    incs = list(kernel[0].sense(SenseContext()))
    assert len(incs) == 1
    assert incs[0].admissibility is Admissibility.PROVEN
