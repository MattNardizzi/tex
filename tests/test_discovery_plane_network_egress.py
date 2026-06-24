"""
P1–P4 NETWORK-EGRESS plane tests (``engine.sensors.network_egress``).

Proves the contract for the universal passive-egress net:

1. a PLANTED agent flow → a correct ``Incidence`` on ``PlaneId.NETWORK_EGRESS``
   carrying the P1–P4 footprint keys (ja4/ja4s/sni/asn/egress_ip/h2_settings_hash
   + the BEHAVIORAL token_waveform_sig/cadence_sig);
2. the BEHAVIORAL split: two agents behind ONE egress (same workload/ja4/sni)
   differ in waveform/cadence and resolve to TWO incidences — the thing the old
   stub (keyed only on workload/ja4/sni) could not do;
3. the agent-vs-human waveform tell: a 1:1-packetization flow is marked human-ish
   while a bundled flow is agent-ish;
4. degrade-to-EMPTY: no source, an unreadable fixture, a non-model destination,
   and a malformed fixture all yield zero incidences and NEVER raise;
5. flag-gating: the registry builds the sensor ONLY under ``TEX_SIEVE_P1_JA4``,
   and the default (no flag) yields nothing;
6. the LABELED LOCAL SHIM reads the SAME OCSF/Zeek-style flow shape off disk;
7. the legacy ``NetworkEgressConnector`` still emits the expected candidate
   (delegation preserved its behavior).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tex.discovery.engine.models import Admissibility, FootprintField, PlaneId
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.network_egress import (
    LocalFlowFixtureSource,
    NetworkEgressSensor,
    StaticFlowSource,
    build_network_egress_sensor,
    group_flows,
    parse_ocsf_flow_records,
    provider_for_host,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# --------------------------------------------------------------------------- #
# Fixtures — flow records in the OCSF/Zeek-style shape the real feed emits
# --------------------------------------------------------------------------- #


def _planted_agent_flow() -> dict:
    """One headless agent making a bundled (API) call to OpenAI over h2.

    A record in the cross-shape the parser accepts: flat proxy fields + a TLS
    block + a raw ``record_sizes`` series the parser quantizes into the waveform.
    """
    return {
        "source_workload": "vm-build-07",
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "ja4s": "t130200_1301_a56c5b993250",
        "sni": "api.openai.com",
        "asn": "AS13335",
        "egress_ip": "104.18.7.42",
        "h2_settings_hash": " akamai:1:65536;2:0;3:1000",
        "alpn": "h2",
        "first_seen": "2026-05-01T00:00:00Z",
        "last_seen": "2026-05-02T00:00:00Z",
        "connection_count": 60,
        "bytes_out": 184320,
        # bundled API call: large multi-token records → "bundled" mode.
        "record_sizes": [512, 488, 530, 502],
        # a tight periodic cron loop → low-entropy cadence.
        "inter_arrival_ms": [1000, 1000, 1001, 999, 1000, 1000],
        "evidence_ref": "zeek/ssl.log:8841",
    }


def _human_chatbot_flow() -> dict:
    """A HUMAN driving a chatbot UI behind the SAME egress (1:1 packetization)."""
    return {
        "source_workload": "vm-build-07",
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",  # same client stack
        "sni": "api.openai.com",  # same destination
        "connection_count": 4,
        # 1:1 per-token SSE framing → "1:1" mode (a human-UI tell).
        "record_sizes": [12, 9, 14, 11, 13],
        # bursty, irregular human typing cadence → high-entropy.
        "inter_arrival_ms": [120, 3400, 800, 50, 5200, 240, 1100],
        "evidence_ref": "zeek/ssl.log:9002",
    }


# --------------------------------------------------------------------------- #
# 1. planted agent → correct Incidence
# --------------------------------------------------------------------------- #


def test_planted_agent_emits_correct_incidence():
    sensor = NetworkEgressSensor(source=StaticFlowSource(flows=(_planted_agent_flow(),)))
    incs = list(sensor.sense(SenseContext()))
    assert len(incs) == 1
    inc = incs[0]

    assert inc.plane_id is PlaneId.NETWORK_EGRESS
    assert inc.footprint.plane_id is PlaneId.NETWORK_EGRESS
    assert inc.admissibility is Admissibility.OBSERVED
    assert 0.0 <= inc.catchability <= 1.0
    assert inc.observed_at.tzinfo is not None
    assert inc.raw_evidence_ref == "zeek/ssl.log:8841"

    fp = inc.footprint
    # P1–P4 keys are all present and the behavioral layer is materialized.
    assert fp.key(FootprintField.JA4.value) == "t13d1516h2_8daaf6152771_b186095e22b6"
    assert fp.key(FootprintField.JA4S.value) == "t130200_1301_a56c5b993250"
    assert fp.key(FootprintField.SNI.value) == "api.openai.com"
    assert fp.key(FootprintField.ASN.value) == "AS13335"
    assert fp.key(FootprintField.EGRESS_IP.value) == "104.18.7.42"
    assert fp.key(FootprintField.H2_SETTINGS_HASH.value)
    # The BEHAVIORAL signatures the old stub lacked:
    assert fp.key(FootprintField.TOKEN_WAVEFORM_SIG.value) is not None
    assert "bundled" in fp.key(FootprintField.TOKEN_WAVEFORM_SIG.value)
    assert fp.key(FootprintField.CADENCE_SIG.value) is not None
    assert "periodic" in fp.key(FootprintField.CADENCE_SIG.value)

    assert fp.attr("model_provider") == "openai"
    assert fp.attr("packetization_mode") == "bundled"
    assert fp.attr("metadata_only") == "true"


def test_footprint_keys_are_bridging_grade_in_fuse():
    """Every network-egress key must classify as BRIDGING (never identity)."""
    from tex.discovery.engine.fuse import _grade_for_key
    from tex.discovery.engine.models import EdgeGrade

    for field in (
        FootprintField.JA4,
        FootprintField.JA4S,
        FootprintField.SNI,
        FootprintField.ASN,
        FootprintField.EGRESS_IP,
        FootprintField.H2_SETTINGS_HASH,
        FootprintField.TOKEN_WAVEFORM_SIG,
        FootprintField.CADENCE_SIG,
    ):
        assert _grade_for_key(field.value) is EdgeGrade.BRIDGING, field.value


# --------------------------------------------------------------------------- #
# 2 + 3. behavioral split + agent-vs-human waveform tell
# --------------------------------------------------------------------------- #


def test_two_agents_behind_one_egress_split_on_behavior():
    """Same workload/ja4/sni but different waveform+cadence → two incidences."""
    sensor = NetworkEgressSensor(
        source=StaticFlowSource(flows=(_planted_agent_flow(), _human_chatbot_flow()))
    )
    incs = list(sensor.sense(SenseContext()))
    # The OLD grouper (keyed only on workload/ja4/sni) would have collapsed these
    # to ONE group. The behavioral key separates them.
    assert len(incs) == 2

    waveforms = {
        i.footprint.key(FootprintField.TOKEN_WAVEFORM_SIG.value) for i in incs
    }
    cadences = {i.footprint.key(FootprintField.CADENCE_SIG.value) for i in incs}
    assert len(waveforms) == 2  # distinct packetization
    assert len(cadences) == 2  # distinct cadence entropy

    modes = {i.footprint.attr("packetization_mode") for i in incs}
    assert modes == {"bundled", "1:1"}  # agent-ish vs human-ish


def test_waveform_classifies_packetization_mode():
    agent = parse_ocsf_flow_records([_planted_agent_flow()])[0]
    human = parse_ocsf_flow_records([_human_chatbot_flow()])[0]
    assert agent.packetization_mode == "bundled"
    assert human.packetization_mode == "1:1"
    # And the cadence burstiness separates a cron loop from interactive typing.
    assert "periodic" in (agent.cadence_sig or "")
    assert "periodic" not in (human.cadence_sig or "")


# --------------------------------------------------------------------------- #
# 4. degrade to EMPTY (never raise)
# --------------------------------------------------------------------------- #


def test_degrades_empty_when_no_source():
    sensor = NetworkEgressSensor(source=None)
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_empty_on_non_model_egress():
    flow = dict(_planted_agent_flow(), sni="example.com")
    sensor = NetworkEgressSensor(source=StaticFlowSource(flows=(flow,)))
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_empty_on_unreadable_fixture(tmp_path: Path):
    missing = tmp_path / "does_not_exist.jsonl"
    sensor = NetworkEgressSensor(source=LocalFlowFixtureSource(fixture_path=missing))
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_empty_on_malformed_fixture(tmp_path: Path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json at all\n<<<garbage>>>\n", encoding="utf-8")
    sensor = NetworkEgressSensor(source=LocalFlowFixtureSource(fixture_path=bad))
    assert list(sensor.sense(SenseContext())) == []


def test_raising_source_degrades_empty():
    def _boom(_ctx):
        raise RuntimeError("feed down")

    sensor = NetworkEgressSensor(source=_boom)
    # Must swallow the source error and degrade to empty, never propagate.
    assert list(sensor.sense(SenseContext())) == []


# --------------------------------------------------------------------------- #
# 5 + 6. the labeled local shim reads the real flow shape off disk
# --------------------------------------------------------------------------- #


def test_local_fixture_shim_reads_jsonl(tmp_path: Path):
    fixture = tmp_path / "flows.jsonl"
    fixture.write_text(
        json.dumps(_planted_agent_flow()) + "\n", encoding="utf-8"
    )
    sensor = NetworkEgressSensor(source=LocalFlowFixtureSource(fixture_path=fixture))
    incs = list(sensor.sense(SenseContext()))
    assert len(incs) == 1
    assert incs[0].footprint.attr("model_provider") == "openai"


def test_local_fixture_shim_reads_json_array(tmp_path: Path):
    fixture = tmp_path / "flows.json"
    fixture.write_text(
        json.dumps([_planted_agent_flow(), _human_chatbot_flow()]), encoding="utf-8"
    )
    sensor = NetworkEgressSensor(source=LocalFlowFixtureSource(fixture_path=fixture))
    assert len(list(sensor.sense(SenseContext()))) == 2


# --------------------------------------------------------------------------- #
# 5. flag-gating through the registry
# --------------------------------------------------------------------------- #


def test_registry_builds_sensor_only_under_flag(tmp_path: Path):
    fixture = tmp_path / "flows.jsonl"
    fixture.write_text(json.dumps(_planted_agent_flow()) + "\n", encoding="utf-8")

    # Default: no flag → the plane is NOT built.
    assert all(
        s.plane_id is not PlaneId.NETWORK_EGRESS
        for s in build_active_sensors({})
    )

    # Flag enabled + fixture path → the real sensor IS built and senses.
    env = {
        "TEX_SIEVE_P1_JA4": "1",
        "TEX_SIEVE_P1_FLOW_FIXTURE": str(fixture),
    }
    built = [s for s in build_active_sensors(env) if s.plane_id is PlaneId.NETWORK_EGRESS]
    assert len(built) == 1
    incs = list(built[0].sense(SenseContext()))
    assert len(incs) == 1
    assert incs[0].footprint.attr("model_provider") == "openai"


def test_factory_degrades_empty_without_fixture():
    """Flag on but no fixture/source env → an inert sensor (senses nothing)."""
    sensor = build_network_egress_sensor({"TEX_SIEVE_P1_JA4": "1"})
    assert sensor.plane_id is PlaneId.NETWORK_EGRESS
    assert list(sensor.sense(SenseContext())) == []


# --------------------------------------------------------------------------- #
# 7. provider resolution + legacy connector delegation
# --------------------------------------------------------------------------- #


def test_provider_resolution():
    assert provider_for_host("api.openai.com") == "openai"
    assert provider_for_host("bedrock-runtime.us-east-1.amazonaws.com") == "aws_bedrock"
    assert provider_for_host("example.com") is None
    assert provider_for_host("") is None
    # A self-hosted MCP endpoint still reads as agent egress.
    assert provider_for_host("tools.mcp.internal.corp") == "generic_model_endpoint"


def test_legacy_connector_still_catches_headless_agent():
    """The delegated legacy connector preserves its witness-layer behavior."""
    from tex.discovery.connectors.network_egress import NetworkEgressConnector
    from tex.discovery.connectors.base import ConnectorContext

    flows = [
        {
            "source_workload": "laptop-mnardizzi",
            "sni": "api.openai.com",
            "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
            "first_seen": "2026-05-01T00:00:00Z",
            "last_seen": "2026-05-02T00:00:00Z",
            "connection_count": 60,
        },
        {  # non-model egress is ignored
            "source_workload": "laptop-mnardizzi",
            "sni": "example.com",
            "ja4": "x",
            "connection_count": 5,
        },
    ]
    conn = NetworkEgressConnector(flows=flows)
    cands = list(conn.scan(ConnectorContext(tenant_id="acme")))
    assert len(cands) == 1
    assert cands[0].evidence["model_provider"] == "openai"


def test_group_flows_drops_non_model():
    feats = parse_ocsf_flow_records(
        [dict(_planted_agent_flow(), sni="not-a-model.example.com")]
    )
    assert group_flows(feats) == []
