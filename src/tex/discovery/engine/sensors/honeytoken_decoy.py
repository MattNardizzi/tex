"""
P14 — the ACTIVE honeytoken / decoy-lattice plane (``PlaneId.HONEYTOKEN``).

The only ACTIVE vantage in the roster (ARCHITECTURE.md §8 P14; RESEARCH_LOG.md
§1 P14, N3, WS-5). Every other plane PASSIVELY watches a vantage an agent
happens to cross; this plane MANUFACTURES the vantage. It plants decoys whose
ONLY plausible caller is an undiscovered agent — canary credentials, a decoy
MCP server / tool, a honey-URL, an agent-only DOM element, a prompt-injection
canary — and waits for a TRIP. A trip is, by construction, a near-zero-false-
positive sighting: a human or a governed agent has no reason to touch a credential
that was never issued to anything real (LLM Agent Honeypot, arXiv 2410.13919;
Parallel-Poisoned Web, arXiv 2509.00124; Decoy-MCP honeypot, Zeltser 2026).

Two distinct outputs, both PROVEN-grade (a trip is ground truth — the caller
DID exercise the decoy):

1. **The decoy TRIP (P14, the WS-5 active-flush leg).** A zero-passive-signal
   agent that bypasses every gate and writes no log still bites a planted decoy
   the moment it tries to use it. One trip → one
   ``Incidence(plane=HONEYTOKEN, admissibility=PROVEN)`` footprint
   ``{decoy_id, canary_cred_id, caller_fingerprint, tripped_at}``. ``decoy_id``
   and ``canary_cred_id`` are IDENTITY-grade in ``fuse._IDENTITY_KEYS`` (a planted
   secret is, by schema, "the same agent" — two trips of one canary fuse), while
   ``caller_fingerprint`` is BRIDGING (a shared egress/UA cohort that links but
   never merges alone).

2. **The injected-marker JOIN KEY (N3, the cross-plane fusion leg).** A unique
   marker is seeded per VANTAGE into the decoy surface (e.g. baked into a honey
   document the agent READS, then re-emitted into whatever the agent WRITES). When
   the SAME marker tripped on a READ surface reappears on an ACT surface, it
   provably fuses one agent's read-footprint to its act-footprint — manufacturing
   a common identifier for the no-common-key case (RESEARCH_LOG.md N3). The marker
   rides as the IDENTITY-grade ``injected_marker`` key so ``fuse.py`` closes it
   transitively into ONE entity across the two planes.

------------------------------------------------------------------------------
The decoy REGISTRY + trip-ingestion (configurable; degrade-empty)
------------------------------------------------------------------------------
The plane is INERT BY DEFAULT — NO decoys are planted unless the host configures
a decoy registry, and the sensor senses nothing until a trip is ingested. This is
the literal §8 default-safe posture for P14 ("inert (no decoys planted)") behind
``TEX_SIEVE_P14_DECOY``: enabling the flag without wiring a registry/trip source
yields an empty plane, never a crash.

Both inputs are CONFIGURABLE and supplied at construction (NOT hardcoded), exactly
like ``governance_stream`` / ``kernel_ebpf`` wrap a real source behind the sensor:

- ``registry`` — the planted-decoy ledger: a ``DecoyRegistry`` (or any iterable of
  ``PlantedDecoy``) describing which decoys/canaries/markers were planted on which
  vantage. With no registry, NO decoy is considered planted (inert).
- ``trip_source`` — the trip-event feed: a zero-argument callable returning an
  iterable of trip-event mappings, or such an iterable directly (an in-process
  honeytoken-alert hook, or a recorded trip-log file read by the labeled local
  shim). A trip is only honored when its ``decoy_id`` / ``canary_cred_id`` /
  marker matches a PLANTED decoy in the registry — an unplanted-decoy trip is
  ignored (it cannot be one of our manufactured vantages).

A ``None`` source, a raising callable, a malformed row, or a trip against an
unplanted decoy all degrade to *fewer incidences*, never an exception.

Real collector vs local shim
----------------------------
The trip INGESTOR (``_iter_trips`` / ``_trip_to_incidence``) reads exactly the
event shape a real honeytoken-alert webhook / decoy-MCP access log emits, so on a
live deployment the host wires the real alert hook as the ``trip_source`` with no
code change. For tests + local dev the ``_FixtureTripSource`` shim reads a recorded
trip-log file of the SAME shape — it substitutes only the trip SOURCE (a file for
the live alert stream); the registry match, the marker-join logic, and the
footprint construction are the real implementation. It is never a fake that
pretends a trip happened; it replays recorded trips against the real registry.

Catchability here is an ASSERTED plane recall (a slice constant): an agent that
BITES is seen with near-certainty, but the bite-RATE over a known-size lattice is
the Phase-5 recapture term that CALIBRATES per-plane catchability (N2) — the
count-based slice estimator carries-but-does-not-consume this value.

References: ARCHITECTURE.md §8 (P14 flag table), §11 (vantage independence — the
active-decoy plane is physically distinct from passive-network/endpoint-eBPF);
RESEARCH_LOG.md §1 P14, N2 (bite-rate calibration), N3 (injected-marker join key),
WS-5 (active flush + injected-identifier fusion).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED recall of the active honeytoken plane (a slice constant, NOT measured;
#: measurement deferred to Phase 5). An agent that BITES a planted decoy is seen
#: with near-certainty; agents that never touch a decoy are out-of-cohort and are
#: the estimator's job (the bite-rate over a known-size lattice is the N2 recapture
#: term that CALIBRATES this value in Phase 5). The count-based slice estimator
#: carries-but-does-not-consume this value.
HONEYTOKEN_CATCHABILITY = 1.0

#: The env var the factory reads for the recorded trip-log path (a JSONL file, one
#: JSON trip event per line — the SAME shape a live honeytoken-alert webhook
#: emits). Absent / missing → degrade to empty.
HONEYTOKEN_TRIPS_ENV = "TEX_SIEVE_P14_TRIPS"

#: Optional env var for a recorded decoy-registry path (a JSONL file, one planted
#: decoy per line). Absent → no decoys planted → the plane is inert even with the
#: flag on (the §8 default-safe "inert (no decoys planted)" posture).
HONEYTOKEN_REGISTRY_ENV = "TEX_SIEVE_P14_REGISTRY"


# ---------------------------------------------------------------------------
# The decoy REGISTRY — what was planted, and on which vantage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlantedDecoy:
    """One decoy/canary/marker planted into the estate (an active tripwire).

    A planted decoy is the ground truth of "this surface is a manufactured
    vantage" — only an undiscovered caller would touch it. The fields are the
    handles a trip event is matched against:

    - ``decoy_id``        — the stable id of the decoy surface (a decoy MCP server,
                            a honey-URL, an agent-only DOM element).
    - ``canary_cred_id``  — the unique canary credential / token this decoy issues
                            or guards (``None`` for a pure read-surface decoy).
    - ``injected_marker`` — the unique per-VANTAGE marker seeded into the decoy
                            surface (N3). When the agent re-emits it on another
                            plane, the marker fuses the two footprints. ``None``
                            for a decoy that carries no injected marker.
    - ``vantage``         — a free-text label of the surface kind ("read" / "act" /
                            "mcp" / "dom" / "credential"), carried for receipts.

    A decoy is "planted" iff it appears in the registry. At least one of
    ``decoy_id`` / ``canary_cred_id`` / ``injected_marker`` must be set so a trip
    has something to match against; a fully-empty decoy is rejected at construction.
    """

    decoy_id: str | None = None
    canary_cred_id: str | None = None
    injected_marker: str | None = None
    vantage: str | None = None

    def __post_init__(self) -> None:
        if not (self.decoy_id or self.canary_cred_id or self.injected_marker):
            raise ValueError(
                "a PlantedDecoy must carry at least one of "
                "decoy_id / canary_cred_id / injected_marker"
            )


@dataclass(frozen=True)
class DecoyRegistry:
    """The planted-decoy ledger a trip event is reconciled against.

    Inert by default: an EMPTY registry (no decoys planted) matches nothing, so the
    sensor senses nothing — the §8 default-safe "inert (no decoys planted)" posture
    for P14. A trip is honored ONLY when its decoy/canary/marker matches a decoy in
    here; an unplanted-decoy trip is ignored (it is not one of our manufactured
    vantages and so carries no discovery signal we can stand behind).
    """

    decoys: tuple[PlantedDecoy, ...] = ()

    @classmethod
    def of(cls, decoys: Iterable[PlantedDecoy]) -> "DecoyRegistry":
        """Build a registry from any iterable of planted decoys."""
        return cls(decoys=tuple(decoys))

    def is_empty(self) -> bool:
        return not self.decoys

    def match(
        self,
        decoy_id: str | None,
        canary_cred_id: str | None,
        injected_marker: str | None,
    ) -> PlantedDecoy | None:
        """Return the planted decoy a trip matches, or ``None`` if unplanted.

        A trip matches a planted decoy when ANY of its non-empty identifiers
        equals the corresponding planted identifier — a bite on the decoy id, on
        the canary credential, or a re-emission of the injected marker all confirm
        the SAME planted vantage. The first matching decoy wins (registries are
        small and authored, so order is stable + auditable).
        """
        for decoy in self.decoys:
            if decoy_id and decoy.decoy_id and decoy.decoy_id == decoy_id:
                return decoy
            if (
                canary_cred_id
                and decoy.canary_cred_id
                and decoy.canary_cred_id == canary_cred_id
            ):
                return decoy
            if (
                injected_marker
                and decoy.injected_marker
                and decoy.injected_marker == injected_marker
            ):
                return decoy
        return None


#: A source of trip events: an iterable of event mappings, or a zero-argument
#: callable returning one (an in-process honeytoken-alert hook / a recorded
#: trip-log iterator). ``None`` means "no trip source configured" → degrade empty.
TripSource = (
    Callable[[], Iterable[Mapping[str, object]]]
    | Iterable[Mapping[str, object]]
    | None
)

#: Trip-event field aliases → the canonical handle. The ingestor accepts the
#: vocabulary a real honeytoken-alert webhook / decoy-MCP access log emits.
_DECOY_ID_ALIASES: tuple[str, ...] = ("decoy_id", "decoy", "tripwire_id", "honey_id")
_CANARY_ALIASES: tuple[str, ...] = (
    "canary_cred_id",
    "canary_id",
    "canary_token",
    "token_id",
    "credential_id",
)
_MARKER_ALIASES: tuple[str, ...] = (
    "injected_marker",
    "marker",
    "canary_marker",
    "join_marker",
)
_FINGERPRINT_ALIASES: tuple[str, ...] = (
    "caller_fingerprint",
    "fingerprint",
    "caller",
    "src_ip",
    "source_ip",
    "user_agent",
)
_TRIPPED_AT_ALIASES: tuple[str, ...] = (
    "tripped_at",
    "ts",
    "timestamp",
    "time",
    "observed_at",
)
#: An optional agent handle a richer alert source may already know (e.g. a leaked
#: header). It is BRIDGING/descriptive only — a trip's identity-grade join is the
#: planted ``decoy_id`` / ``canary_cred_id`` / ``injected_marker``, never a
#: self-asserted caller name.
_PLANE_ALIASES: tuple[str, ...] = ("plane", "vantage", "surface")


def _first(row: Mapping[str, object], names: Sequence[str]) -> object | None:
    """First present, non-empty value among ``names`` (alias resolution)."""
    for name in names:
        if name in row:
            val = row[name]
            if val is not None and not (isinstance(val, str) and not val.strip()):
                return val
    return None


def _as_str(val: object | None) -> str | None:
    """Coerce a present value to a trimmed string, or ``None``."""
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _coerce_tripped_at(val: object | None) -> datetime:
    """tz-aware trip time from epoch seconds or an ISO string.

    Falls back to now(UTC) on anything unparseable so a single odd row never drops
    an otherwise-valid trip observation.
    """
    if val is None:
        return datetime.now(UTC)
    if isinstance(val, bool):
        return datetime.now(UTC)
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=UTC)
        except (ValueError, OverflowError, OSError):
            return datetime.now(UTC)
    if isinstance(val, str):
        s = val.strip()
        # Numeric string → epoch seconds.
        try:
            return datetime.fromtimestamp(float(s), tz=UTC)
        except (ValueError, OverflowError, OSError):
            pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Trip source — the REAL alert ingestor target + the CLEARLY-LABELED local shim
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FixtureTripSource:
    """LOCAL SHIM (clearly labeled): reads a recorded trip-log file of trip events.

    NOT a fake honeytoken sensor — it substitutes ONLY the trip SOURCE (a recorded
    JSONL file instead of the live honeytoken-alert webhook stream) so the
    genuinely-implemented registry-match + marker-join + footprint construction run
    on real-shaped trip events. On a live deployment the host wires the real alert
    hook as the ``trip_source`` with no code change. Degrades to an empty stream on
    a missing/unreadable file. Callable so it is itself a valid ``TripSource``.
    """

    path: Path

    def __call__(self) -> Iterator[Mapping[str, object]]:
        import json

        try:
            if not self.path.is_file():
                return
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(obj, Mapping):
                yield obj


@dataclass(frozen=True)
class _FixtureRegistrySource:
    """LOCAL SHIM (clearly labeled): reads a recorded decoy-registry JSONL file.

    One planted decoy per line (``{decoy_id?, canary_cred_id?, injected_marker?,
    vantage?}``). Substitutes only the registry SOURCE (a file for the host's
    in-process decoy ledger). Degrades to an EMPTY registry (no decoys planted) on
    a missing/unreadable file — keeping the plane inert by default.
    """

    path: Path

    def load(self) -> DecoyRegistry:
        import json

        try:
            if not self.path.is_file():
                return DecoyRegistry()
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return DecoyRegistry()
        decoys: list[PlantedDecoy] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(obj, Mapping):
                continue
            decoy_id = _as_str(_first(obj, _DECOY_ID_ALIASES))
            canary = _as_str(_first(obj, _CANARY_ALIASES))
            marker = _as_str(_first(obj, _MARKER_ALIASES))
            vantage = _as_str(_first(obj, _PLANE_ALIASES))
            if not (decoy_id or canary or marker):
                continue  # a fully-empty decoy line is unmatchable — skip it
            decoys.append(
                PlantedDecoy(
                    decoy_id=decoy_id,
                    canary_cred_id=canary,
                    injected_marker=marker,
                    vantage=vantage,
                )
            )
        return DecoyRegistry.of(decoys)


# ---------------------------------------------------------------------------
# The sensor
# ---------------------------------------------------------------------------


class HoneytokenDecoySensor:
    """P14 instrument — emits one PROVEN ``Incidence`` per HONORED decoy trip.

    Construct with a configurable ``registry`` (the planted-decoy ledger) and a
    configurable ``trip_source`` (the trip-event feed) — exactly the
    ``governance_stream`` / ``kernel_ebpf`` pattern of wrapping a real source behind
    the sensor. INERT BY DEFAULT: with no registry NO decoy is planted, with no
    ``trip_source`` nothing is sensed, and a trip against an UNplanted decoy is
    ignored. ``sense`` honors a trip only when it matches a planted decoy and emits
    one incidence per honored trip. Degrades to empty; NEVER raises.

    ``sense`` ignores ``SenseContext`` (the decoy registry + trip source are
    supplied at construction, not via the filesystem context the slice planes use),
    but accepts it to satisfy the ``EngineSensor`` protocol.
    """

    plane_id: PlaneId = PlaneId.HONEYTOKEN

    def __init__(
        self,
        registry: "DecoyRegistry | Iterable[PlantedDecoy] | None" = None,
        trip_source: TripSource = None,
        *,
        catchability: float = HONEYTOKEN_CATCHABILITY,
    ) -> None:
        if registry is None:
            self._registry = DecoyRegistry()
        elif isinstance(registry, DecoyRegistry):
            self._registry = registry
        else:
            # Any iterable of planted decoys → a registry (degrade to empty on a
            # bad iterable rather than raising at construction).
            try:
                self._registry = DecoyRegistry.of(registry)
            except Exception as exc:  # noqa: BLE001 — degrade, never raise on build
                _logger.info("sieve: honeytoken registry degraded to empty: %s", exc)
                self._registry = DecoyRegistry()
        self._trip_source = trip_source
        self._catchability = catchability

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401, ARG002
        """Ingest the trip-event feed into PROVEN ``Incidence`` records.

        - Resolves the trip source (a callable hook is invoked; an iterable is used
          directly). A ``None`` source, a raising callable, or a non-iterable
          result degrades to an empty iterable — NEVER raises.
        - INERT when no decoys are planted: an empty registry matches nothing, so
          the plane senses nothing even with a trip source wired (the §8
          default-safe posture).
        - For each trip event, matches it against the planted-decoy registry; an
          UNplanted-decoy trip is ignored. A HONORED trip emits one
          ``Incidence(plane=HONEYTOKEN, admissibility=PROVEN)`` keyed on the
          IDENTITY-grade ``{decoy_id, canary_cred_id, injected_marker}`` (the
          ``injected_marker`` is the N3 cross-plane JOIN KEY that fuses an agent's
          read- and act-footprints) plus the BRIDGING ``caller_fingerprint``, with
          ``tripped_at`` carried as an attr for receipts.
        - Returns an empty iterable on a missing/empty/unplanted source.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _resolve_rows(self) -> list[Mapping[str, object]]:
        """Materialize the configured trip source into a list of event mappings.

        Degrades to ``[]`` on a missing source, a callable that raises, a
        non-iterable result, or rows that are not mappings (those are skipped).
        Never raises.
        """
        source = self._trip_source
        if source is None:
            return []
        try:
            raw = source() if callable(source) else source
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: honeytoken trip source raised, degrading empty: %s", exc)
            return []
        rows: list[Mapping[str, object]] = []
        try:
            for item in raw:  # type: ignore[union-attr]
                if isinstance(item, Mapping):
                    rows.append(item)
        except TypeError:
            return []  # the source returned a non-iterable; degrade empty
        except Exception as exc:  # noqa: BLE001 — a lazy iterator faulting mid-stream
            _logger.info("sieve: honeytoken trip iteration faulted: %s", exc)
            return rows
        return rows

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:  # noqa: ARG002
        # Inert by default: no decoys planted → nothing to honor a trip against.
        if self._registry.is_empty():
            return
        rows = self._resolve_rows()
        if not rows:
            return
        for idx, row in enumerate(rows):
            inc = self._trip_to_incidence(idx, row)
            if inc is not None:
                yield inc

    def _trip_to_incidence(
        self, idx: int, row: Mapping[str, object]
    ) -> Incidence | None:
        """Project one trip event into a PROVEN P14 incidence (if it is honored).

        Returns ``None`` for a malformed trip or a trip against an UNplanted decoy
        (so the stream simply has fewer incidences — never a raise).
        """
        decoy_id = _as_str(_first(row, _DECOY_ID_ALIASES))
        canary = _as_str(_first(row, _CANARY_ALIASES))
        marker = _as_str(_first(row, _MARKER_ALIASES))
        if not (decoy_id or canary or marker):
            return None  # a trip with no decoy/canary/marker handle is unmatchable

        planted = self._registry.match(decoy_id, canary, marker)
        if planted is None:
            # A trip against a decoy we never planted carries no signal we can
            # stand behind — ignore it (it is not one of our manufactured vantages).
            return None

        # Fold the planted decoy's known identifiers in so a trip that matched on,
        # say, the canary still carries the planted decoy_id + marker join key.
        decoy_id = decoy_id or planted.decoy_id
        canary = canary or planted.canary_cred_id
        marker = marker or planted.injected_marker

        keys: dict[str, str] = {}
        # IDENTITY-grade join keys (fuse._IDENTITY_KEYS): two trips of one canary
        # fuse to ONE entity, and an injected marker re-emitted on another plane
        # fuses that plane's footprint to this one (the N3 cross-plane JOIN KEY).
        if decoy_id is not None:
            keys[FootprintField.DECOY_ID.value] = decoy_id
        if canary is not None:
            keys[FootprintField.CANARY_CRED_ID.value] = canary
        if marker is not None:
            keys[FootprintField.INJECTED_MARKER.value] = marker

        # BRIDGING-grade (fuse._BRIDGING_KEYS): a caller fingerprint links a cohort
        # (shared egress/UA) but never merges identities alone.
        fingerprint = _as_str(_first(row, _FINGERPRINT_ALIASES))
        if fingerprint is not None:
            keys[FootprintField.CALLER_FINGERPRINT.value] = fingerprint

        tripped_at = _coerce_tripped_at(_first(row, _TRIPPED_AT_ALIASES))

        attrs: dict[str, str] = {"tripped_at": tripped_at.isoformat()}
        if planted.vantage:
            attrs["vantage"] = planted.vantage
        plane_label = _as_str(_first(row, _PLANE_ALIASES))
        if plane_label:
            attrs["trip_surface"] = plane_label

        footprint = FootprintVector.of(
            plane_id=PlaneId.HONEYTOKEN, keys=keys, attrs=attrs
        )
        ref = decoy_id or canary or marker or f"honeytoken:{idx}"
        try:
            return Incidence(
                plane_id=PlaneId.HONEYTOKEN,
                footprint=footprint,
                catchability=self._catchability,
                # A trip is ground truth — the caller DID exercise the planted
                # decoy. There is no stronger provenance than a bite.
                admissibility=Admissibility.PROVEN,
                raw_evidence_ref=f"honeytoken_trip:{ref}",
                observed_at=tripped_at,
            )
        except ValueError:
            # A verifier-injected out-of-range catchability degrades to a dropped
            # row, never a raised exception.
            return None


# ---------------------------------------------------------------------------
# Registry factory (flag-gated, degrade-to-empty)
# ---------------------------------------------------------------------------


def build_honeytoken_decoy_sensor(env: Mapping[str, str]) -> HoneytokenDecoySensor:
    """Factory the registry calls under the ``TEX_SIEVE_P14_DECOY`` flag.

    INERT BY DEFAULT (the §8 "inert (no decoys planted)" posture): with no
    ``TEX_SIEVE_P14_REGISTRY`` path set — or a missing file — NO decoy is planted,
    so the plane senses nothing even when the flag is on and a trip source is
    wired. The decoy registry and trip source are configurable file shims for local
    dev / tests:

    - ``TEX_SIEVE_P14_REGISTRY`` — a recorded decoy-registry JSONL path (one planted
      decoy per line). Absent / missing → empty registry → inert plane.
    - ``TEX_SIEVE_P14_TRIPS``    — a recorded trip-log JSONL path (one trip per line,
      the SAME shape a live honeytoken-alert webhook emits, read by the labeled
      ``_FixtureTripSource`` shim). Absent / missing → no trips → empty plane.

    A live deployment re-registers with its real in-process decoy ledger + alert
    hook wired as the ``registry`` / ``trip_source`` (no code change). Never raises.
    """
    registry_path = (env.get(HONEYTOKEN_REGISTRY_ENV) or "").strip()
    registry: DecoyRegistry = (
        _FixtureRegistrySource(Path(registry_path)).load()
        if registry_path
        else DecoyRegistry()
    )
    trips_path = (env.get(HONEYTOKEN_TRIPS_ENV) or "").strip()
    trip_source: TripSource = (
        _FixtureTripSource(Path(trips_path)) if trips_path else None
    )
    return HoneytokenDecoySensor(registry=registry, trip_source=trip_source)


__all__ = [
    "HoneytokenDecoySensor",
    "build_honeytoken_decoy_sensor",
    "DecoyRegistry",
    "PlantedDecoy",
    "TripSource",
    "HONEYTOKEN_CATCHABILITY",
    "HONEYTOKEN_TRIPS_ENV",
    "HONEYTOKEN_REGISTRY_ENV",
]
