"""
P9 — the KERNEL / eBPF plane (``PlaneId.KERNEL_EBPF``).

The PROVEN ground-truth vantage (ARCHITECTURE.md §8 P9; RESEARCH_LOG.md P9). An
eBPF program attached to a kernel hook sees a process *from underneath*: the
workload cannot forge it, suppress it, or even tell it is there. This is the
plane that finds the HARD case — **local, identity-less processes**: the
tex-enterprise fleet are plain OS processes with no OIDC sub, no SPIFFE id, no
managed-control id. The only thing that identifies them is *what is actually
executing* — the measured code hash, the exec lineage, and the syscall-graph
shape of their behavior.

What it ingests
---------------
A Tetragon-shaped kernel event stream (Cilium Tetragon JSON, verified June 2026):

    {"process_exec": {"process": {
        "exec_id": "a3f...:1782242461000000000:12345",
        "pid": 12345, "binary": "/usr/bin/python3.12",
        "arguments": "-m assaypilot.main --serve",
        "parent_exec_id": "...", "pod": {...},
        "binary_properties": {"file": {"hash": {"sha256": "ab12..."}}}}}}     # IMA / bpf_ima_inode_hash
    {"process_exit": {"process": {"exec_id": "...", ...}}}
    {"process_kprobe": {"function_name": "tcp_connect", "process": {...}, ...}}   # connect
    {"process_kprobe": {"function_name": "security_file_permission",            # file-write
                        "process": {...},
                        "args": [{"file_arg": {"path": "/ws/foo/bar.md"}}]}}

Each event carries the fields the P9 footprint needs: ``code_hash`` (the
measured-boot / IMA inode hash — the MERGE anchor that survives rotation/rename),
``exec_id`` (Tetragon's globally-unique re-exec id), ``binary_path``, the
``proc_lineage`` (parent → child exec chain), and — derived from the per-process
syscall/kprobe stream — a ``syscall_graph_sig`` (the behavioral SPLIT signature)
and an optional ``spiffe_id`` when a SPIFFE/SPIRE selector resolved the workload.

Two-axis identity (the load-bearing insight — ARCHITECTURE.md §1.2)
------------------------------------------------------------------
- **MERGE axis** — ``code_hash``: many ``exec_id``s of one binary (re-execs,
  restarts, worker forks) are the SAME code; they collapse to ONE agent.
- **SPLIT axis** — ``syscall_graph_sig``: two *distinct* agents sharing one
  binary (e.g. two configs of ``python3``) have different syscall-graph shapes
  and must NOT be merged just because their ``code_hash`` matches.

``code_hash`` alone is too COARSE (10k agents share one ``python3`` hash) and
``exec_id`` alone is too FINE (every re-exec = a new id). The entity is the
JOIN: code-hash MERGES, behavior SPLITS. This sensor performs the merge+split
WITHIN the plane — it groups the raw exec/exit/connect/write events by the
(``code_hash``, ``syscall_graph_sig``) pair and emits ONE incidence per distinct
agent, folding all of that agent's exec_ids into the footprint. The per-agent
identity key the cross-plane resolver fuses on is the behavioral
``syscall_graph_sig`` (identity-grade in ``fuse._IDENTITY_KEYS``, so it closes
transitively to the same entity across planes) — NOT bare ``code_hash``, which
would over-merge two distinct agents sharing a binary. ``code_hash`` is carried
as the coarse merge-axis context and ``binary_path`` as a weak bridging hint.

Real collector vs local shim
----------------------------
The capability is genuinely implemented for the Linux/Tetragon target: the event
PARSER (``_parse_tetragon_event`` / ``_iter_events``) reads exactly the Tetragon
JSON shape a real ``tetra getevents -o json`` stream (or the gRPC export) emits.
On a Linux host with Tetragon installed, point the sensor at the live JSONL
export and it ingests real kernel events unchanged.

eBPF/Tetragon CANNOT run on macOS, so for tests + local dev this module ships a
CLEARLY-LABELED shim (``_FixtureEventSource``) that reads a fixture event-log
file of the SAME Tetragon event shape. The shim substitutes only the event
SOURCE (a file instead of a kernel ring buffer); every downstream step — the
parser, the two-axis grouping, the footprint construction — is the real
implementation exercised against real-shaped events. It is never a fake that
pretends to be the kernel sensor; it is the real sensor reading recorded events.

Flag-gating + degrade-to-empty
------------------------------
Built only behind ``TEX_SIEVE_P9_EBPF`` (ARCHITECTURE.md §8 default-safe table).
The factory reads the event-source path from ``TEX_SIEVE_P9_EBPF_EVENTS`` (a
Tetragon JSONL export path). With no flag set, the registry never builds it; with
the flag set but no source path / a missing file, it degrades to EMPTY (senses
nothing) and never raises — the same posture as a connector returning inert when
unconnected.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED recall of the kernel/eBPF plane (a slice constant, NOT measured;
#: measurement deferred to Phase 5). A kernel-observed exec is ground truth
#: (near-1.0 where the sensor exists); ring-buffer drops / un-hookable kernels /
#: kTLS-blinded flows are NAMED blind spots reported by the estimator, not folded
#: into this recall. The count-based slice estimator carries-but-does-not-consume
#: this value.
KERNEL_EBPF_CATCHABILITY = 1.0

#: The env var the factory reads for the Tetragon event-source path (a JSONL
#: export, one JSON event per line). Absent / missing → degrade to empty.
KERNEL_EBPF_EVENTS_ENV = "TEX_SIEVE_P9_EBPF_EVENTS"

#: Tetragon kprobe ``function_name`` values that denote a network connect.
_CONNECT_FUNCS: frozenset[str] = frozenset(
    {"tcp_connect", "tcp_v4_connect", "tcp_v6_connect", "__sys_connect"}
)

#: Tetragon kprobe ``function_name`` values that denote a file write/open-for-write.
_FILE_WRITE_FUNCS: frozenset[str] = frozenset(
    {
        "security_file_permission",
        "security_inode_create",
        "vfs_write",
        "__x64_sys_write",
        "fd_install",
    }
)


# ---------------------------------------------------------------------------
# Normalized event — the shape the parser produces from any Tetragon event
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _KernelEvent:
    """One normalized kernel observation parsed from a Tetragon event.

    ``kind`` is ``exec`` | ``exit`` | ``connect`` | ``file_write``. The parser
    maps each Tetragon envelope onto this flat shape so the two-axis grouping
    never touches the raw JSON nesting again.
    """

    kind: str
    exec_id: str
    code_hash: str | None
    binary_path: str | None
    parent_exec_id: str | None
    spiffe_id: str | None
    syscall: str | None  # the kprobe function (for connect / file_write events)
    target: str | None  # the connect peer or written file path
    observed_at: datetime
    raw_ref: str


# ---------------------------------------------------------------------------
# Event sources — the REAL collector target + the CLEARLY-LABELED local shim
# ---------------------------------------------------------------------------


def _iter_events(raw_lines: Iterable[str], source_label: str) -> Iterator[_KernelEvent]:
    """Parse a Tetragon JSONL stream into normalized ``_KernelEvent`` records.

    This is the REAL collector logic — identical for a live Linux Tetragon
    export and for the local fixture shim; only the line SOURCE differs. A
    malformed line degrades to a skipped event, never an exception.
    """
    for lineno, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(envelope, dict):
            continue
        event = _parse_tetragon_event(envelope, f"{source_label}:{lineno}")
        if event is not None:
            yield event


@dataclass(frozen=True)
class _FixtureEventSource:
    """LOCAL SHIM (clearly labeled): reads a fixture file of Tetragon events.

    NOT a fake kernel sensor — it substitutes ONLY the event SOURCE (a recorded
    JSONL fixture instead of the kernel ring buffer) so the genuinely-implemented
    parser + two-axis grouping run on real-shaped events on macOS, where eBPF
    cannot run. On a Linux host the live Tetragon export replaces this file path
    with no code change. Degrades to an empty stream on a missing/unreadable file.
    """

    path: Path

    def stream(self) -> Iterator[_KernelEvent]:
        try:
            if not self.path.is_file():
                return iter(())
            handle = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            return iter(())
        return self._drain(handle)

    def _drain(self, handle) -> Iterator[_KernelEvent]:
        with handle:
            lines = list(handle)
        yield from _iter_events(lines, source_label=str(self.path))


# ---------------------------------------------------------------------------
# Tetragon envelope parser (the real Linux-target collector logic)
# ---------------------------------------------------------------------------


def _dig(d: object, *path: str) -> object:
    """Safely walk a nested-dict path, returning ``None`` on any miss."""
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _coerce_ts(value: object) -> datetime:
    """tz-aware timestamp from a Tetragon ``time`` (RFC3339) or epoch-ns int."""
    if isinstance(value, str) and value:
        v = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            dt = datetime.fromisoformat(v)
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    if isinstance(value, (int, float)):
        try:
            # Tetragon exec_id embeds epoch-ns; a bare number here is treated ns.
            return datetime.fromtimestamp(float(value) / 1e9, tz=UTC)
        except (OverflowError, ValueError, OSError):
            pass
    return datetime.now(UTC)


def _process_block(envelope: Mapping[str, object]) -> tuple[str, Mapping[str, object]] | None:
    """Return ``(kind, process_dict)`` for a Tetragon envelope, or ``None``.

    Recognizes ``process_exec`` / ``process_exit`` / ``process_kprobe`` (the
    connect + file-write probes). Other event types degrade to ``None`` (skipped).
    """
    if "process_exec" in envelope:
        proc = _dig(envelope, "process_exec", "process")
        return ("exec", proc) if isinstance(proc, dict) else None
    if "process_exit" in envelope:
        proc = _dig(envelope, "process_exit", "process")
        return ("exit", proc) if isinstance(proc, dict) else None
    if "process_kprobe" in envelope:
        proc = _dig(envelope, "process_kprobe", "process")
        return ("kprobe", proc) if isinstance(proc, dict) else None
    return None


def _parse_tetragon_event(
    envelope: Mapping[str, object], raw_ref: str
) -> _KernelEvent | None:
    """Map one Tetragon JSON envelope onto a normalized ``_KernelEvent``.

    Returns ``None`` for envelopes that carry no usable process identity (so the
    stream simply has fewer events — never a raise).
    """
    block = _process_block(envelope)
    if block is None:
        return None
    raw_kind, proc = block

    exec_id = proc.get("exec_id")
    if not isinstance(exec_id, str) or not exec_id.strip():
        return None
    exec_id = exec_id.strip()

    code_hash = _dig(proc, "binary_properties", "file", "hash", "sha256")
    if not isinstance(code_hash, str) or not code_hash.strip():
        # Some exporters surface the IMA hash flatter.
        alt = proc.get("code_hash") or proc.get("ima_hash")
        code_hash = alt.strip() if isinstance(alt, str) and alt.strip() else None
    else:
        code_hash = code_hash.strip()

    binary = proc.get("binary")
    binary_path = binary.strip() if isinstance(binary, str) and binary.strip() else None

    parent = proc.get("parent_exec_id") or _dig(envelope, "process_exec", "parent", "exec_id")
    parent_exec_id = parent.strip() if isinstance(parent, str) and parent.strip() else None

    # SPIFFE/SPIRE selector if the workload was attested (rare for the local fleet).
    spiffe = (
        proc.get("spiffe_id")
        or _dig(proc, "pod", "workload", "spiffe_id")
        or _dig(envelope, "process_exec", "spiffe_id")
    )
    spiffe_id = spiffe.strip() if isinstance(spiffe, str) and spiffe.strip() else None

    observed_at = _coerce_ts(envelope.get("time") or proc.get("start_time"))

    # Map the kprobe variants onto connect / file_write; exec/exit pass through.
    kind = raw_kind
    syscall: str | None = None
    target: str | None = None
    if raw_kind == "kprobe":
        fn = envelope.get("process_kprobe")
        func = fn.get("function_name") if isinstance(fn, dict) else None
        func = func.strip() if isinstance(func, str) else None
        syscall = func
        if func in _CONNECT_FUNCS:
            kind = "connect"
            target = _extract_connect_target(fn if isinstance(fn, dict) else {})
        elif func in _FILE_WRITE_FUNCS:
            kind = "file_write"
            target = _extract_file_target(fn if isinstance(fn, dict) else {})
        else:
            # An unrecognized kprobe still contributes to the syscall graph shape.
            kind = "syscall"

    return _KernelEvent(
        kind=kind,
        exec_id=exec_id,
        code_hash=code_hash,
        binary_path=binary_path,
        parent_exec_id=parent_exec_id,
        spiffe_id=spiffe_id,
        syscall=syscall,
        target=target,
        observed_at=observed_at,
        raw_ref=raw_ref,
    )


def _extract_connect_target(kprobe: Mapping[str, object]) -> str | None:
    """Best-effort connect peer (``ip:port`` / ``sni``) from a kprobe's args."""
    args = kprobe.get("args")
    if isinstance(args, list):
        for arg in args:
            sock = _dig(arg, "sock_arg")
            if isinstance(sock, dict):
                daddr = sock.get("daddr")
                dport = sock.get("dport")
                if daddr is not None:
                    return f"{daddr}:{dport}" if dport is not None else str(daddr)
    return None


def _extract_file_target(kprobe: Mapping[str, object]) -> str | None:
    """Best-effort written file path from a kprobe's file_arg."""
    args = kprobe.get("args")
    if isinstance(args, list):
        for arg in args:
            path = _dig(arg, "file_arg", "path")
            if isinstance(path, str) and path.strip():
                return path.strip()
    return None


# ---------------------------------------------------------------------------
# Two-axis identity — the merge (code_hash) + split (syscall_graph_sig)
# ---------------------------------------------------------------------------


@dataclass
class _AgentAccumulator:
    """Folds many exec_ids of ONE distinct agent into a single footprint.

    Keyed by (``code_hash``, ``syscall_graph_sig``): same code + same behavioral
    shape = same agent (MERGE many exec_ids); same code + DIFFERENT shape = two
    agents (SPLIT). Accumulates the lineage + targets across the agent's exec
    occasions so the emitted incidence summarizes the whole process group.
    """

    code_hash: str | None
    syscall_graph_sig: str
    binary_path: str | None = None
    spiffe_id: str | None = None
    exec_ids: set[str] = field(default_factory=set)
    parents: set[str] = field(default_factory=set)
    connect_targets: set[str] = field(default_factory=set)
    write_targets: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    first_ref: str | None = None

    def absorb(self, ev: _KernelEvent) -> None:
        self.exec_ids.add(ev.exec_id)
        if ev.binary_path and self.binary_path is None:
            self.binary_path = ev.binary_path
        if ev.spiffe_id and self.spiffe_id is None:
            self.spiffe_id = ev.spiffe_id
        if ev.parent_exec_id:
            self.parents.add(ev.parent_exec_id)
        if ev.kind == "connect" and ev.target:
            self.connect_targets.add(ev.target)
        if ev.kind == "file_write" and ev.target:
            self.write_targets.add(ev.target)
        if self.first_seen is None or ev.observed_at < self.first_seen:
            self.first_seen = ev.observed_at
            self.first_ref = ev.raw_ref
        if self.last_seen is None or ev.observed_at > self.last_seen:
            self.last_seen = ev.observed_at


def _syscall_graph_sig(syscall_sequence: Sequence[str]) -> str:
    """A stable behavioral SPLIT signature from a process's syscall/kprobe stream.

    The behavioral fingerprint that SEPARATES two distinct agents sharing one
    binary. We canonicalize the syscall graph as the sorted set of observed
    (prev→next) call BIGRAMS — order-sensitive enough to distinguish two configs
    of the same interpreter, stable across re-execs of one agent — then hash it.
    Two agents with the same code hash but different tool/IO behavior produce
    different signatures; the SAME agent re-exec'd produces the same signature.

    A real deployment would use a richer syscall-graph kernel (n-gram MinHash /
    graphlet sketch); the bigram-set hash is the faithful, deterministic slice
    realization of that SPLIT axis.
    """
    seq = [s for s in syscall_sequence if s]
    if not seq:
        return "sgs:empty"
    bigrams = sorted({f"{a}>{b}" for a, b in zip(seq, seq[1:])}) or sorted(set(seq))
    digest = hashlib.sha256("|".join(bigrams).encode("utf-8")).hexdigest()
    return f"sgs:{digest[:32]}"


def _group_into_agents(events: Sequence[_KernelEvent]) -> list[_AgentAccumulator]:
    """Collapse raw events into one accumulator per DISTINCT agent (two-axis).

    Step 1 — per ``exec_id`` collect the behavioral syscall sequence (the kprobe
    functions in observation order) and the code hash / binary.
    Step 2 — compute each exec's ``syscall_graph_sig`` (SPLIT axis).
    Step 3 — group execs by (``code_hash``, ``syscall_graph_sig``): the code hash
    MERGES re-execs/forks of one agent; the syscall-graph sig keeps two distinct
    agents sharing a binary apart. Emit one accumulator per group.
    """
    # exec_id -> ordered syscall functions + a representative code_hash/binary.
    per_exec_syscalls: dict[str, list[str]] = defaultdict(list)
    per_exec_code: dict[str, str | None] = {}
    per_exec_events: dict[str, list[_KernelEvent]] = defaultdict(list)
    exec_order: list[str] = []

    for ev in events:
        if ev.exec_id not in per_exec_events:
            exec_order.append(ev.exec_id)
        per_exec_events[ev.exec_id].append(ev)
        if ev.code_hash and per_exec_code.get(ev.exec_id) is None:
            per_exec_code[ev.exec_id] = ev.code_hash
        per_exec_code.setdefault(ev.exec_id, None)
        if ev.syscall:
            per_exec_syscalls[ev.exec_id].append(ev.syscall)
        elif ev.kind == "exec":
            # The exec itself anchors the graph with an execve marker.
            per_exec_syscalls[ev.exec_id].append("execve")

    # (code_hash, syscall_graph_sig) -> accumulator.
    groups: dict[tuple[str | None, str], _AgentAccumulator] = {}
    for exec_id in exec_order:
        sig = _syscall_graph_sig(per_exec_syscalls.get(exec_id, []))
        code = per_exec_code.get(exec_id)
        key = (code, sig)
        acc = groups.get(key)
        if acc is None:
            acc = _AgentAccumulator(code_hash=code, syscall_graph_sig=sig)
            groups[key] = acc
        for ev in per_exec_events[exec_id]:
            acc.absorb(ev)
    return list(groups.values())


# ---------------------------------------------------------------------------
# The sensor
# ---------------------------------------------------------------------------


class KernelEbpfSensor:
    """P9 instrument — emits one PROVEN ``Incidence`` per distinct kernel agent.

    Construct with an event-source callable returning a ``_KernelEvent`` stream
    (the live Tetragon export on Linux, or the ``_FixtureEventSource`` shim on
    macOS/tests). ``sense`` groups the raw events into distinct agents via the
    two-axis identity and emits one incidence per agent. Degrades to empty when
    the source yields nothing; NEVER raises.
    """

    plane_id: PlaneId = PlaneId.KERNEL_EBPF

    def __init__(
        self,
        event_source: "_FixtureEventSource | None" = None,
        *,
        catchability: float = KERNEL_EBPF_CATCHABILITY,
    ) -> None:
        self._source = event_source
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401, ARG002
        """Ingest the kernel event stream into ``Incidence`` records.

        - Pulls the Tetragon-shaped event stream from the configured source
          (live export or fixture shim).
        - Groups events into DISTINCT agents via the two-axis identity
          (``code_hash`` MERGES exec_ids; ``syscall_graph_sig`` SPLITS).
        - Emits one ``Incidence`` per agent, ``admissibility=PROVEN``, with a
          footprint keyed on the identity-grade ``syscall_graph_sig`` (+ optional
          ``spiffe_id`` / ``code_hash``) and carrying ``exec_id`` (folded set),
          ``proc_lineage``, ``binary_path``, and the connect/write targets as
          attrs for receipts.
        - Returns an empty iterable on a missing/empty source; NEVER raises.
        """
        return list(self._iter(context))

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:  # noqa: ARG002
        if self._source is None:
            return
        try:
            events = list(self._source.stream())
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: kernel_ebpf source degraded to empty: %s", exc)
            return
        if not events:
            return
        for acc in _group_into_agents(events):
            inc = self._agent_to_incidence(acc)
            if inc is not None:
                yield inc

    def _agent_to_incidence(self, acc: _AgentAccumulator) -> Incidence | None:
        # CROSS-INCIDENCE IDENTITY (two-axis). The per-agent strong JOIN KEY is
        # the behavioral SPLIT signature ``syscall_graph_sig`` (identity-grade in
        # fuse._IDENTITY_KEYS). It MERGES re-execs of one agent (same code + same
        # behavior → same signature) yet keeps two DISTINCT agents that share a
        # binary apart (same code_hash, different behavior → different signature).
        #
        # ``code_hash`` is deliberately NOT a cross-incidence key: bare code_hash
        # is identity-grade in fuse, so emitting it as a key would OVER-MERGE the
        # two distinct agents sharing one binary (the very failure the two-axis
        # model exists to prevent — 10k agents share one ``python3`` hash). The
        # MERGE it drives is performed WITHIN this plane by the grouping in
        # ``_group_into_agents``; here code_hash is carried as the merge-axis
        # CONTEXT attr (receipts / display), and ``binary_path`` is a weak
        # BRIDGING-grade key (links a cohort, never merges identities alone).
        keys: dict[str, str] = {
            FootprintField.SYSCALL_GRAPH_SIG.value: acc.syscall_graph_sig,
        }
        if acc.spiffe_id:
            keys[FootprintField.SPIFFE_ID.value] = acc.spiffe_id
        if acc.binary_path:
            keys[FootprintField.BINARY_PATH.value] = acc.binary_path

        exec_ids = sorted(acc.exec_ids)
        lineage = sorted(acc.parents)
        attrs: dict[str, str] = {
            FootprintField.EXEC_ID.value: ",".join(exec_ids),
            "exec_count": str(len(exec_ids)),
        }
        if acc.code_hash:
            # The MERGE-axis anchor, carried as receipt/context (not a join key).
            attrs[FootprintField.CODE_HASH.value] = acc.code_hash
        if lineage:
            attrs[FootprintField.PROC_LINEAGE.value] = ",".join(lineage)
        if acc.connect_targets:
            attrs["connect_targets"] = ",".join(sorted(acc.connect_targets))
        if acc.write_targets:
            attrs["write_targets"] = ",".join(sorted(acc.write_targets))
        if acc.last_seen is not None:
            attrs["last_seen"] = acc.last_seen.isoformat()

        footprint = FootprintVector.of(
            plane_id=PlaneId.KERNEL_EBPF, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.KERNEL_EBPF,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.PROVEN,
                raw_evidence_ref=acc.first_ref or "kernel_ebpf",
                observed_at=acc.last_seen or datetime.now(UTC),
            )
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Registry factory (flag-gated, degrade-to-empty)
# ---------------------------------------------------------------------------


def build_kernel_ebpf_sensor(env: Mapping[str, str]):
    """Factory the registry calls under the ``TEX_SIEVE_P9_EBPF`` flag.

    Reads the Tetragon event-source path from ``TEX_SIEVE_P9_EBPF_EVENTS``. On a
    Linux host this is a live ``tetra getevents -o json`` JSONL export; on macOS /
    in tests it is a recorded fixture of the SAME shape (read by the clearly
    labeled ``_FixtureEventSource`` shim). With no path set — or a missing file —
    the sensor degrades to EMPTY (senses nothing). Never raises.
    """
    raw_path = env.get(KERNEL_EBPF_EVENTS_ENV, "").strip()
    source = _FixtureEventSource(Path(raw_path)) if raw_path else None
    return KernelEbpfSensor(event_source=source)


__all__ = [
    "KernelEbpfSensor",
    "build_kernel_ebpf_sensor",
    "KERNEL_EBPF_CATCHABILITY",
    "KERNEL_EBPF_EVENTS_ENV",
]
