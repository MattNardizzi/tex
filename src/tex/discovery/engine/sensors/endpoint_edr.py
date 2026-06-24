"""
P9 (endpoint) — the ENDPOINT / EDR plane (``PlaneId.ENDPOINT_EDR``).

A COARSER, MORE DEPLOYABLE cousin of the kernel/eBPF plane (``kernel_ebpf.py``).
Where eBPF attaches a kernel hook and sees a process *from underneath* (the
PROVEN ground-truth vantage, Linux-only, hard to deploy), an EDR / endpoint agent
sits in USER space and periodically snapshots the **process inventory** of a host:
what is running right now, which interpreter is hosting it, the on-disk hash of
its binary, and whether it has wired itself into a persistence mechanism
(systemd unit, cron, LaunchAgent, Run key, ...). This is exactly the telemetry a
CrowdStrike / SentinelOne / Defender-for-Endpoint sensor — or the cross-platform
open-source ``osquery`` ``processes`` table — already emits on every managed
endpoint, so it is the cheapest plane to STAND UP across a real fleet even where
eBPF cannot run (macOS, Windows, locked-down kernels).

What it ingests
---------------
A host telemetry snapshot stream, modeled on the osquery ``processes`` /
``startup_items`` schema (the de-facto cross-platform EDR query shape, verified
June 2026). One JSON record per running process::

    {"host_identifier": "host-7a2b", "name": "python3.12",
     "path": "/usr/bin/python3.12", "cmdline": "python3 -m assaypilot.main --serve",
     "pid": 12345, "parent": 1,
     "sha256": "ab12...",                     # hashed binary on disk (osquery hash JOIN)
     "persistence": "systemd:assaypilot.service"}   # startup_items / crontab JOIN

The runtime hosting the agent (``python`` / ``node`` / ``deno`` / a bare binary)
is DERIVED from the executable name + cmdline, since the agent process is almost
always an interpreter hosting agent code rather than a named binary. Persistence
is the mechanism that re-launches the agent across reboots — a strong "this is a
deployed, surviving agent, not a one-shot" signal.

Footprint (ARCHITECTURE.md §8 endpoint EDR — fields {host_id, process_name,
runtime, code_hash, persistence})
------------------------------------------------------------------------------
- ``code_hash``     — IDENTITY-grade in ``fuse._IDENTITY_KEYS``: the on-disk
                      SHA-256 of the executing binary. This is the SAME merge
                      anchor the eBPF plane (IMA inode hash) carries, so an agent
                      seen on BOTH the endpoint-EDR plane and the kernel/eBPF
                      plane FUSES to one entity across the two vantages. It is the
                      load-bearing cross-plane join key this plane contributes.
- ``host_id``       — BRIDGING-grade in ``fuse._BRIDGING_KEYS``: a coarse cohort
                      (many distinct agents share one host), so it links but never
                      merges two distinct agents alone — and a single host hosting
                      k distinct agents is the N1 shared-host SPLIT surface.
- ``process_name``  — descriptive attr (the interpreter/binary name).
- ``runtime``       — descriptive attr (derived hosting runtime).
- ``persistence``   — descriptive attr (the survival mechanism, for receipts +
                      the agent-vs-ephemeral signal).

HONEST POSITIONING vs the eBPF plane
------------------------------------
This plane is OBSERVED, not PROVEN. A user-space EDR sensor can be blinded by a
sufficiently privileged process (it sees what the host agent is allowed to see),
its inventory is a periodic SNAPSHOT (it can miss a short-lived process between
polls), and its on-disk hash is the file at rest, not the kernel-measured exec
image. So its ``admissibility`` is ``OBSERVED`` and its catchability is an
asserted constant strictly BELOW the eBPF plane's — it is the broad, cheap,
deployable net, with eBPF as the narrow high-trust oracle. The two planes are
genuinely independent capture occasions (kernel-internal vs user-space agent),
which is what the capture-recapture math needs.

Real collector vs local shim
----------------------------
The capability is genuinely implemented for the real EDR target: the record
PARSER (``_parse_process_record``) reads exactly the osquery ``processes``-table
JSON shape a real ``osqueryi --json "SELECT ... FROM processes ..."`` export (or a
CrowdStrike/SentinelOne/Defender process-inventory export normalized to that
shape) emits. Point the sensor at a live snapshot export and it ingests real
endpoint telemetry unchanged.

For tests + local dev this module ships a CLEARLY-LABELED shim
(``_FixtureTelemetrySource``) that reads a fixture file of the SAME osquery
record shape. The shim substitutes ONLY the telemetry SOURCE (a recorded JSONL
file instead of a live EDR poll); every downstream step — the parser, the
host/runtime/persistence derivation, the per-agent grouping, the footprint
construction — is the real implementation exercised against real-shaped records.
It is never a fake that pretends to be the EDR sensor.

Flag-gating + degrade-to-empty
------------------------------
Built ONLY behind ``TEX_SIEVE_P9_EDR`` (ARCHITECTURE.md §8 default-safe table).
The factory reads the telemetry-source path from ``TEX_SIEVE_P9_EDR_TELEMETRY``
(an osquery-shaped JSONL export). With no flag set, the registry never builds it;
with the flag set but no source path / a missing file, it degrades to EMPTY
(senses nothing) and never raises — the same posture as a connector returning
inert when unconnected.
"""

from __future__ import annotations

import json
import logging
import re
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

#: ASSERTED recall of the endpoint/EDR plane (a slice constant, NOT measured;
#: measurement deferred to Phase 5). Deliberately BELOW the kernel/eBPF plane's
#: 1.0: a user-space EDR sensor sees a periodic SNAPSHOT (can miss a short-lived
#: process between polls) and can be blinded by a privileged process — it is the
#: broad, cheap, deployable net, not the kernel ground-truth oracle. The
#: count-based slice estimator carries-but-does-not-consume this value.
ENDPOINT_EDR_CATCHABILITY = 0.85

#: The env var the factory reads for the telemetry-source path (an osquery
#: ``processes``-shaped JSONL export, one JSON record per line). Absent /
#: missing → degrade to empty.
ENDPOINT_EDR_TELEMETRY_ENV = "TEX_SIEVE_P9_EDR_TELEMETRY"

#: Interpreter/runtime names that HOST agent code (the process is the runtime,
#: the agent is its argument). Matched against the executable name + cmdline so a
#: ``python3 -m assaypilot.main`` process is attributed to the ``python`` runtime.
#: Ordered most-specific-first within each family so the derived label is stable.
_RUNTIME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("python", re.compile(r"\bpython[0-9.]*\b", re.IGNORECASE)),
    ("node", re.compile(r"\bnode(?:js)?\b", re.IGNORECASE)),
    ("deno", re.compile(r"\bdeno\b", re.IGNORECASE)),
    ("bun", re.compile(r"\bbun\b", re.IGNORECASE)),
    ("ruby", re.compile(r"\bruby\b", re.IGNORECASE)),
    ("java", re.compile(r"\bjava\b", re.IGNORECASE)),
    ("dotnet", re.compile(r"\bdotnet\b", re.IGNORECASE)),
    ("go", re.compile(r"\bgo\b", re.IGNORECASE)),
)


# ---------------------------------------------------------------------------
# Normalized record — the shape the parser produces from any osquery row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProcessObservation:
    """One normalized endpoint process observation parsed from an osquery row.

    The flat shape the per-agent grouping operates on, so the raw osquery /
    EDR JSON nesting is never touched again after the parser.
    """

    host_id: str
    process_name: str
    runtime: str
    code_hash: str | None
    persistence: str | None
    binary_path: str | None
    cmdline: str | None
    pid: str | None
    observed_at: datetime
    raw_ref: str


# ---------------------------------------------------------------------------
# Runtime derivation — which interpreter is hosting the agent
# ---------------------------------------------------------------------------


def _derive_runtime(name: str, cmdline: str | None, binary_path: str | None) -> str:
    """Best-effort hosting runtime from the process name + cmdline + path.

    Agent processes are almost always an interpreter hosting agent code, so the
    runtime is what re-launches the same code: ``python`` / ``node`` / etc. Falls
    back to ``"native"`` for a bare compiled binary with no recognized runtime,
    so the field is always present for the footprint.
    """
    haystack = " ".join(p for p in (name, cmdline, binary_path) if p)
    for label, pattern in _RUNTIME_PATTERNS:
        if pattern.search(haystack):
            return label
    return "native"


# ---------------------------------------------------------------------------
# osquery record parser (the real, deployable EDR-target collector logic)
# ---------------------------------------------------------------------------


def _clean_str(value: object) -> str | None:
    """A stripped non-empty string, or ``None`` (osquery emits ``""`` for null)."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _coerce_ts(value: object) -> datetime:
    """tz-aware timestamp from an osquery ``unixTime`` / ``time`` field.

    osquery snapshot results carry a top-level ``unixTime`` (epoch seconds); a
    per-row ``start_time`` is also epoch seconds. Anything unparseable falls back
    to "now" (UTC) so one odd record never drops an otherwise-valid observation.
    """
    if isinstance(value, str) and value.strip():
        v = value.strip()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(v)
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, ValueError, OSError):
            pass
    return datetime.now(UTC)


def _parse_process_record(
    record: Mapping[str, object], raw_ref: str
) -> _ProcessObservation | None:
    """Map one osquery ``processes``-row onto a normalized ``_ProcessObservation``.

    Reads the canonical osquery column names with tolerant fallbacks for the
    common EDR-export aliases (``host_identifier``/``hostIdentifier``/``host``;
    ``sha256``/``code_hash``/``hash``). Returns ``None`` for a record carrying no
    usable host + process identity (so the stream simply has fewer observations —
    never a raise).
    """
    host_id = (
        _clean_str(record.get("host_identifier"))
        or _clean_str(record.get("hostIdentifier"))
        or _clean_str(record.get("host"))
        or _clean_str(record.get("host_id"))
    )
    name = _clean_str(record.get("name")) or _clean_str(record.get("process_name"))
    binary_path = _clean_str(record.get("path")) or _clean_str(record.get("binary_path"))
    # A process with neither a host nor any name is unattributable → skip.
    if not host_id or not (name or binary_path):
        return None
    if name is None:
        # Derive a name from the binary path leaf when osquery omitted ``name``.
        name = Path(binary_path).name if binary_path else "unknown"

    cmdline = _clean_str(record.get("cmdline")) or _clean_str(record.get("command_line"))
    code_hash = (
        _clean_str(record.get("sha256"))
        or _clean_str(record.get("code_hash"))
        or _clean_str(record.get("hash"))
    )
    persistence = (
        _clean_str(record.get("persistence"))
        or _clean_str(record.get("startup_item"))
        or _clean_str(record.get("autostart"))
    )
    pid = _clean_str(record.get("pid"))
    observed_at = _coerce_ts(
        record.get("unixTime") or record.get("time") or record.get("start_time")
    )
    runtime = _derive_runtime(name, cmdline, binary_path)

    return _ProcessObservation(
        host_id=host_id,
        process_name=name,
        runtime=runtime,
        code_hash=code_hash,
        persistence=persistence,
        binary_path=binary_path,
        cmdline=cmdline,
        pid=pid,
        observed_at=observed_at,
        raw_ref=raw_ref,
    )


def _iter_records(raw_lines: Iterable[str], source_label: str) -> Iterator[_ProcessObservation]:
    """Parse an osquery-shaped JSONL stream into ``_ProcessObservation`` records.

    This is the REAL collector logic — identical for a live EDR/osquery export and
    for the local fixture shim; only the line SOURCE differs. A malformed line
    degrades to a skipped record, never an exception. A line that is itself a JSON
    ARRAY (osquery ``--json`` snapshot mode emits one array) is flattened.
    """
    for lineno, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except (ValueError, TypeError):
            continue
        rows: Sequence[object]
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = [payload]
        else:
            continue
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            ref = f"{source_label}:{lineno}" if len(rows) == 1 else f"{source_label}:{lineno}.{idx}"
            obs = _parse_process_record(row, ref)
            if obs is not None:
                yield obs


# ---------------------------------------------------------------------------
# Telemetry source — the REAL collector target + the CLEARLY-LABELED local shim
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FixtureTelemetrySource:
    """LOCAL SHIM (clearly labeled): reads a fixture file of osquery records.

    NOT a fake EDR sensor — it substitutes ONLY the telemetry SOURCE (a recorded
    JSONL fixture instead of a live EDR / osquery poll) so the genuinely-
    implemented parser + per-agent grouping run on real-shaped records on any
    platform, including in CI. On a real fleet the live ``osqueryi --json`` /
    EDR-export path replaces this file path with no code change. Degrades to an
    empty stream on a missing/unreadable file.
    """

    path: Path

    def stream(self) -> Iterator[_ProcessObservation]:
        try:
            if not self.path.is_file():
                return iter(())
            handle = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            return iter(())
        return self._drain(handle)

    def _drain(self, handle) -> Iterator[_ProcessObservation]:
        with handle:
            lines = list(handle)
        yield from _iter_records(lines, source_label=str(self.path))


# ---------------------------------------------------------------------------
# Per-agent grouping — fold many process sightings into one host-agent footprint
# ---------------------------------------------------------------------------


@dataclass
class _HostAgentAccumulator:
    """Folds many process sightings of ONE host-agent into a single footprint.

    Keyed by (``host_id``, identity): a deployed agent shows up as many processes
    (workers, restarts, re-execs) of the SAME code on ONE host. We collapse them
    so the plane emits ONE incidence per distinct host-agent rather than one per
    transient PID. The grouping identity is the ``code_hash`` when the EDR sensor
    hashed the binary (the strong, cross-plane merge anchor); when no hash is
    available it falls back to the (runtime, process_name) shape so an
    un-hashed agent is still folded coherently within its host instead of
    fragmenting into one incidence per PID.
    """

    host_id: str
    identity: str
    process_name: str
    runtime: str
    code_hash: str | None = None
    persistence: str | None = None
    binary_path: str | None = None
    pids: set[str] = field(default_factory=set)
    cmdlines: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    first_ref: str | None = None

    def absorb(self, obs: _ProcessObservation) -> None:
        if obs.code_hash and self.code_hash is None:
            self.code_hash = obs.code_hash
        if obs.persistence and self.persistence is None:
            self.persistence = obs.persistence
        if obs.binary_path and self.binary_path is None:
            self.binary_path = obs.binary_path
        if obs.pid:
            self.pids.add(obs.pid)
        if obs.cmdline:
            self.cmdlines.add(obs.cmdline)
        if self.first_seen is None or obs.observed_at < self.first_seen:
            self.first_seen = obs.observed_at
            self.first_ref = obs.raw_ref
        if self.last_seen is None or obs.observed_at > self.last_seen:
            self.last_seen = obs.observed_at


def _group_into_host_agents(
    observations: Sequence[_ProcessObservation],
) -> list[_HostAgentAccumulator]:
    """Collapse raw process observations into one accumulator per host-agent.

    The grouping key is (``host_id``, identity) where identity is the
    ``code_hash`` if present (the strong merge anchor shared with the eBPF plane),
    else the (runtime, process_name) shape — so re-execs / workers of one deployed
    agent on one host fold into ONE footprint while two genuinely-distinct agents
    on the same host (different code hash) stay separate, preserving the N1
    shared-host split surface for ``fuse``/``disambiguate`` downstream.
    """
    groups: dict[tuple[str, str], _HostAgentAccumulator] = {}
    for obs in observations:
        identity = obs.code_hash or f"shape:{obs.runtime}:{obs.process_name}"
        key = (obs.host_id, identity)
        acc = groups.get(key)
        if acc is None:
            acc = _HostAgentAccumulator(
                host_id=obs.host_id,
                identity=identity,
                process_name=obs.process_name,
                runtime=obs.runtime,
            )
            groups[key] = acc
        acc.absorb(obs)
    return list(groups.values())


# ---------------------------------------------------------------------------
# The sensor
# ---------------------------------------------------------------------------


class EndpointEdrSensor:
    """Endpoint/EDR instrument — one OBSERVED ``Incidence`` per host-agent.

    Construct with a telemetry-source object exposing ``stream()`` returning a
    ``_ProcessObservation`` stream (the live osquery/EDR export on a real fleet,
    or the ``_FixtureTelemetrySource`` shim in tests). ``sense`` groups the raw
    process inventory into distinct host-agents and emits one incidence per
    agent. Degrades to empty when the source is absent or yields nothing; NEVER
    raises.
    """

    plane_id: PlaneId = PlaneId.ENDPOINT_EDR

    def __init__(
        self,
        telemetry_source: "_FixtureTelemetrySource | None" = None,
        *,
        catchability: float = ENDPOINT_EDR_CATCHABILITY,
    ) -> None:
        self._source = telemetry_source
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401, ARG002
        """Ingest the endpoint process-inventory stream into ``Incidence`` records.

        - Pulls the osquery-shaped process inventory from the configured source
          (live EDR export or the fixture shim).
        - Groups observations into distinct host-agents (``host_id`` + code-hash /
          runtime+name identity), folding re-execs/workers of one deployed agent.
        - Emits one ``Incidence`` per host-agent, ``admissibility=OBSERVED``, with a
          footprint keyed on the IDENTITY-grade ``code_hash`` (the cross-plane merge
          anchor shared with the eBPF plane) + the BRIDGING-grade ``host_id``, and
          carrying ``process_name`` / ``runtime`` / ``persistence`` as attrs.
        - Returns an empty iterable on a missing/empty source; NEVER raises.
        """
        return list(self._iter(context))

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:  # noqa: ARG002
        if self._source is None:
            return
        try:
            observations = list(self._source.stream())
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: endpoint_edr source degraded to empty: %s", exc)
            return
        if not observations:
            return
        for acc in _group_into_host_agents(observations):
            inc = self._agent_to_incidence(acc)
            if inc is not None:
                yield inc

    def _agent_to_incidence(self, acc: _HostAgentAccumulator) -> Incidence | None:
        # KEYS (matched on by fuse):
        #  - code_hash: IDENTITY-grade — the cross-plane merge anchor. An agent
        #    seen here AND on the kernel/eBPF plane fuses on this exact key.
        #  - host_id:   BRIDGING-grade — coarse cohort; links but never merges
        #    two distinct agents, and one host hosting k agents is the N1 split.
        keys: dict[str, str] = {
            FootprintField.HOST_ID.value: acc.host_id,
        }
        if acc.code_hash:
            keys[FootprintField.CODE_HASH.value] = acc.code_hash
        if acc.binary_path:
            keys[FootprintField.BINARY_PATH.value] = acc.binary_path

        # ATTRS (carried for receipts + capability/disambiguation, not matched on).
        attrs: dict[str, str] = {
            FootprintField.PROCESS_NAME.value: acc.process_name,
            FootprintField.RUNTIME.value: acc.runtime,
        }
        if acc.persistence:
            attrs[FootprintField.PERSISTENCE.value] = acc.persistence
        if acc.pids:
            attrs["pids"] = ",".join(sorted(acc.pids))
            attrs["process_count"] = str(len(acc.pids))
        if acc.cmdlines:
            attrs["cmdline"] = sorted(acc.cmdlines)[0]
        if acc.last_seen is not None:
            attrs["last_seen"] = acc.last_seen.isoformat()

        footprint = FootprintVector.of(
            plane_id=PlaneId.ENDPOINT_EDR, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.ENDPOINT_EDR,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.OBSERVED,
                raw_evidence_ref=acc.first_ref or "endpoint_edr",
                observed_at=acc.last_seen or datetime.now(UTC),
            )
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Registry factory (flag-gated, degrade-to-empty)
# ---------------------------------------------------------------------------


def build_endpoint_edr_sensor(env: Mapping[str, str]) -> EndpointEdrSensor:
    """Factory the registry calls under the ``TEX_SIEVE_P9_EDR`` flag.

    Reads the telemetry-source path from ``TEX_SIEVE_P9_EDR_TELEMETRY``. On a real
    fleet this is a live ``osqueryi --json "SELECT ... FROM processes ..."`` export
    (or a CrowdStrike/SentinelOne/Defender process-inventory export normalized to
    the osquery shape); in tests / local dev it is a recorded fixture of the SAME
    shape (read by the clearly labeled ``_FixtureTelemetrySource`` shim). With no
    path set — or a missing file — the sensor degrades to EMPTY (senses nothing).
    Never raises.
    """
    raw_path = (env.get(ENDPOINT_EDR_TELEMETRY_ENV) or "").strip()
    source = _FixtureTelemetrySource(Path(raw_path)) if raw_path else None
    return EndpointEdrSensor(telemetry_source=source)


__all__ = [
    "EndpointEdrSensor",
    "build_endpoint_edr_sensor",
    "ENDPOINT_EDR_CATCHABILITY",
    "ENDPOINT_EDR_TELEMETRY_ENV",
]
