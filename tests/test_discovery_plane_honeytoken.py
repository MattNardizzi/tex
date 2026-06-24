"""
P14 ACTIVE honeytoken / decoy-lattice plane tests
(``tex.discovery.engine.sensors.honeytoken_decoy``).

Proves the only ACTIVE vantage in the roster on the case it exists for: a
zero-passive-signal agent that bypasses every gate still BITES a planted decoy,
and the planted marker MANUFACTURES a cross-plane join key for the no-common-key
fusion case (RESEARCH_LOG.md N3, WS-5).

What is proven here, each mapping to a HARD RULE / the mandate:

1. A planted agent that trips a decoy resolves to a PROVEN ``Incidence`` on
   ``PlaneId.HONEYTOKEN`` with the contract footprint
   ``{decoy_id, canary_cred_id, caller_fingerprint, tripped_at}``.
2. The N3 INJECTED-MARKER JOIN KEY: a marker seeded on a READ vantage and
   re-emitted on an ACT vantage fuses one agent's read- and act-footprints into
   ONE ``SieveEntity`` — a common identifier MANUFACTURED for footprints that
   share none naturally.
3. Two trips of one canary credential fuse to ONE entity (the canary is an
   IDENTITY-grade join key), and the negative control: an UNplanted-decoy trip is
   ignored (no false finding).
4. INERT BY DEFAULT: with NO decoys planted the plane senses nothing even with a
   trip source wired (the §8 "inert (no decoys planted)" posture); a missing trip
   source / file degrades to EMPTY and NEVER raises.
5. Flag-gating: built only behind ``TEX_SIEVE_P14_DECOY``; the registry yields
   nothing by default and the plane stays inert with no registry even when the
   flag is on.

The fixtures are faithful trip-log / decoy-registry JSONL — the SAME shape a real
honeytoken-alert webhook / in-process decoy ledger emits; the local shim only
substitutes the trip SOURCE (a file for the live alert stream).

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_honeytoken.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.honeytoken_decoy import (
    HONEYTOKEN_REGISTRY_ENV,
    HONEYTOKEN_TRIPS_ENV,
    DecoyRegistry,
    HoneytokenDecoySensor,
    PlantedDecoy,
    build_honeytoken_decoy_sensor,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# ---------------------------------------------------------------------------
# Fixture builders (the SAME shape a honeytoken-alert webhook / decoy ledger emit).
# ---------------------------------------------------------------------------


def _trip(
    *,
    decoy_id: str | None = None,
    canary_cred_id: str | None = None,
    injected_marker: str | None = None,
    caller_fingerprint: str | None = None,
    tripped_at: str = "2026-05-01T12:00:00.000Z",
) -> dict:
    row: dict = {"tripped_at": tripped_at}
    if decoy_id is not None:
        row["decoy_id"] = decoy_id
    if canary_cred_id is not None:
        row["canary_cred_id"] = canary_cred_id
    if injected_marker is not None:
        row["injected_marker"] = injected_marker
    if caller_fingerprint is not None:
        row["caller_fingerprint"] = caller_fingerprint
    return row


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Proof 1 — a planted agent that bites emits a correct PROVEN incidence.
# ---------------------------------------------------------------------------


def test_planted_agent_trip_emits_proven_incidence_with_contract_footprint(
    tmp_path: Path,
) -> None:
    registry = DecoyRegistry.of(
        [
            PlantedDecoy(
                decoy_id="decoy-mcp-billing",
                canary_cred_id="canary-AKIA-9f12",
                injected_marker="mk-7e3a",
                vantage="mcp",
            )
        ]
    )
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(
        trips,
        [
            _trip(
                decoy_id="decoy-mcp-billing",
                canary_cred_id="canary-AKIA-9f12",
                caller_fingerprint="198.51.100.7",
            )
        ],
    )

    sensor = build_honeytoken_decoy_sensor(
        {HONEYTOKEN_REGISTRY_ENV: "", HONEYTOKEN_TRIPS_ENV: str(trips)}
    )
    # The factory registry path is empty above, so wire the registry directly to
    # prove the in-process ledger path (the live deployment shape).
    sensor = HoneytokenDecoySensor(registry=registry, trip_source=_file_source(trips))
    incidences = list(sensor.sense(SenseContext()))

    assert len(incidences) == 1
    inc = incidences[0]

    # A bite is ground truth: PROVEN, on the P14 plane, tz-aware.
    assert inc.plane_id is PlaneId.HONEYTOKEN
    assert inc.admissibility is Admissibility.PROVEN
    assert inc.observed_at.tzinfo is not None

    fp = inc.footprint
    # The contract footprint {decoy_id, canary_cred_id, caller_fingerprint,
    # tripped_at}. decoy_id + canary are IDENTITY-grade join keys; the marker is
    # folded in from the planted decoy; caller_fingerprint is bridging.
    assert fp.key(FootprintField.DECOY_ID.value) == "decoy-mcp-billing"
    assert fp.key(FootprintField.CANARY_CRED_ID.value) == "canary-AKIA-9f12"
    assert fp.key(FootprintField.INJECTED_MARKER.value) == "mk-7e3a"
    assert fp.key(FootprintField.CALLER_FINGERPRINT.value) == "198.51.100.7"
    assert fp.attr("tripped_at") is not None
    assert fp.attr("vantage") == "mcp"


def _file_source(path: Path):
    """A tiny callable trip source over a JSONL file (mirrors the live alert hook)."""

    def _source():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)

    return _source


# ---------------------------------------------------------------------------
# Proof 2 — N3 injected-marker JOIN KEY fuses read- and act-footprints (no common key).
# ---------------------------------------------------------------------------


def test_injected_marker_fuses_read_and_act_footprints_to_one_entity(
    tmp_path: Path,
) -> None:
    # An agent READS a honey-document carrying marker "mk-join-42" on the READ
    # vantage, then RE-EMITS that marker on the ACT vantage (a decoy write). The
    # two trips share NO natural identifier except the planted marker — the N3
    # manufactured join key must fuse them to ONE entity.
    registry = DecoyRegistry.of(
        [
            PlantedDecoy(decoy_id="honey-doc-read", injected_marker="mk-join-42", vantage="read"),
            PlantedDecoy(decoy_id="decoy-write-sink", injected_marker="mk-join-42", vantage="act"),
        ]
    )
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(
        trips,
        [
            _trip(decoy_id="honey-doc-read", injected_marker="mk-join-42"),
            _trip(decoy_id="decoy-write-sink", injected_marker="mk-join-42"),
        ],
    )

    sensor = HoneytokenDecoySensor(registry=registry, trip_source=_file_source(trips))
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 2  # two distinct decoy surfaces tripped

    # The fuse stage closes the IDENTITY-grade injected_marker transitively: the
    # read-footprint and the act-footprint are the SAME agent.
    entities = resolve(incidences)
    assert len(entities) == 1
    ent = entities[0]
    assert len(ent.incidences) == 2
    # Both P14 capture occasions are attested on the one entity.
    assert PlaneId.HONEYTOKEN in ent.planes_seen


# ---------------------------------------------------------------------------
# Proof 3 — two trips of one canary fuse; the negative control: unplanted is ignored.
# ---------------------------------------------------------------------------


def test_two_trips_of_one_canary_fuse_to_one_entity(tmp_path: Path) -> None:
    registry = DecoyRegistry.of([PlantedDecoy(canary_cred_id="canary-token-abc")])
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(
        trips,
        [
            _trip(canary_cred_id="canary-token-abc", caller_fingerprint="10.0.0.1"),
            _trip(canary_cred_id="canary-token-abc", caller_fingerprint="10.0.0.2"),
        ],
    )
    sensor = HoneytokenDecoySensor(registry=registry, trip_source=_file_source(trips))
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 2
    # The canary is IDENTITY-grade: both bites are the SAME planted secret = one agent.
    entities = resolve(incidences)
    assert len(entities) == 1


def test_unplanted_decoy_trip_is_ignored(tmp_path: Path) -> None:
    # Negative control: a trip against a decoy we NEVER planted carries no signal
    # we can stand behind — it must be ignored (no false finding).
    registry = DecoyRegistry.of([PlantedDecoy(decoy_id="decoy-we-planted")])
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(
        trips,
        [
            _trip(decoy_id="some-other-decoy", caller_fingerprint="10.0.0.9"),
            _trip(canary_cred_id="not-our-canary"),
        ],
    )
    sensor = HoneytokenDecoySensor(registry=registry, trip_source=_file_source(trips))
    assert list(sensor.sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# Proof 4 — INERT by default / degrade to EMPTY (never raise).
# ---------------------------------------------------------------------------


def test_inert_when_no_decoys_planted_even_with_trips(tmp_path: Path) -> None:
    # The §8 "inert (no decoys planted)" posture: an empty registry matches
    # nothing, so a wired trip source still senses NOTHING.
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(trips, [_trip(decoy_id="d1"), _trip(canary_cred_id="c1")])
    sensor = HoneytokenDecoySensor(registry=DecoyRegistry(), trip_source=_file_source(trips))
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_no_trip_source() -> None:
    # A planted registry but no trip source → nothing sensed, never raises.
    sensor = HoneytokenDecoySensor(registry=DecoyRegistry.of([PlantedDecoy(decoy_id="d1")]))
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_trip_file_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    sensor = build_honeytoken_decoy_sensor(
        {
            HONEYTOKEN_REGISTRY_ENV: str(_planted_registry_file(tmp_path)),
            HONEYTOKEN_TRIPS_ENV: str(missing),
        }
    )
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_on_raising_trip_source(tmp_path: Path) -> None:
    def _boom():
        raise RuntimeError("alert hook down")

    sensor = HoneytokenDecoySensor(
        registry=DecoyRegistry.of([PlantedDecoy(decoy_id="d1")]), trip_source=_boom
    )
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_on_malformed_trips(tmp_path: Path) -> None:
    fixture = tmp_path / "garbage.jsonl"
    fixture.write_text("not json\n{}\n[]\n", encoding="utf-8")
    sensor = build_honeytoken_decoy_sensor(
        {
            HONEYTOKEN_REGISTRY_ENV: str(_planted_registry_file(tmp_path)),
            HONEYTOKEN_TRIPS_ENV: str(fixture),
        }
    )
    # Malformed / empty-handle lines degrade to fewer trips, never an exception.
    assert list(sensor.sense(SenseContext())) == []


def _planted_registry_file(tmp_path: Path) -> Path:
    reg = tmp_path / "registry.jsonl"
    reg.write_text(
        json.dumps({"decoy_id": "d1", "canary_cred_id": "c1", "injected_marker": "m1"}) + "\n",
        encoding="utf-8",
    )
    return reg


# ---------------------------------------------------------------------------
# Proof 5 — flag-gating: OFF by default; inert with no registry even when flag on.
# ---------------------------------------------------------------------------


def test_plane_is_flag_gated_off_by_default() -> None:
    # No TEX_SIEVE_* flag set → the registry builds NO sensors at all.
    assert build_active_sensors({}) == []


def test_flag_on_but_no_registry_is_inert(tmp_path: Path) -> None:
    # Flag ENABLED + a trip source wired, but NO decoy registry → inert (no decoys
    # planted), the §8 default-safe posture for the active plane.
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(trips, [_trip(decoy_id="d1")])
    sensors = build_active_sensors(
        {"TEX_SIEVE_P14_DECOY": "1", HONEYTOKEN_TRIPS_ENV: str(trips)}
    )
    p14 = [s for s in sensors if s.plane_id is PlaneId.HONEYTOKEN]
    assert len(p14) == 1
    assert list(p14[0].sense(SenseContext())) == []


def test_flag_on_with_registry_and_trips_emits_via_registry(tmp_path: Path) -> None:
    reg = _planted_registry_file(tmp_path)
    trips = tmp_path / "trips.jsonl"
    _write_jsonl(trips, [_trip(decoy_id="d1", caller_fingerprint="203.0.113.5")])
    sensors = build_active_sensors(
        {
            "TEX_SIEVE_P14_DECOY": "1",
            HONEYTOKEN_REGISTRY_ENV: str(reg),
            HONEYTOKEN_TRIPS_ENV: str(trips),
        }
    )
    p14 = [s for s in sensors if s.plane_id is PlaneId.HONEYTOKEN]
    assert len(p14) == 1
    incs = list(p14[0].sense(SenseContext()))
    assert len(incs) == 1
    assert incs[0].admissibility is Admissibility.PROVEN
    assert incs[0].footprint.key(FootprintField.DECOY_ID.value) == "d1"


# ---------------------------------------------------------------------------
# Construction-safety: a fully-empty planted decoy is rejected (unmatchable).
# ---------------------------------------------------------------------------


def test_empty_planted_decoy_is_rejected() -> None:
    import pytest

    with pytest.raises(ValueError):
        PlantedDecoy()


def test_incidence_footprint_is_a_real_footprint_vector() -> None:
    # Guard: the emitted footprint is a FootprintVector on the honeytoken plane.
    registry = DecoyRegistry.of([PlantedDecoy(decoy_id="d1")])
    sensor = HoneytokenDecoySensor(
        registry=registry, trip_source=[{"decoy_id": "d1"}]
    )
    incs = list(sensor.sense(SenseContext()))
    assert len(incs) == 1
    assert isinstance(incs[0], Incidence)
    assert isinstance(incs[0].footprint, FootprintVector)
    assert incs[0].footprint.plane_id is PlaneId.HONEYTOKEN
