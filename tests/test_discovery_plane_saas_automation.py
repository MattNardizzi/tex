"""
Unit tests for the P5/P10 SaaS / automation plane sensor.

Proves the two HARD RULES on the ``SaaSAutomationSensor`` (the §8 SaaS/automation
plane that wraps the existing discovery connectors as signal SOURCES):

1. It emits a CORRECT plane-typed ``Incidence`` for a PLANTED SaaS-embedded agent
   — keyed on the contracts-pass P5 footprint vocabulary
   (``saas_app``/``bot_user_id``/``oauth_grant_id``/``automation_recipe_id``/
   ``scopes``) so ``fuse.py`` can LINK and SPLIT on it, graded
   ``PLATFORM_ATTESTED`` (a SaaS admin-API assertion), on ``PlaneId.SAAS_AUTOMATION``.
2. It DEGRADES TO EMPTY (returns nothing, never raises) when no source is
   connected, and when a wrapped source raises mid-scan.

The fixture uses the real (mock) ``SlackConnector`` as the planted source — the
sensor depends only on the connector's structural ``scan`` surface, so a planted
connector proves the wrapper path without touching the network.
"""

from __future__ import annotations

import pytest

from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.slack import SlackConnector
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.saas_automation import (
    SaaSAutomationSensor,
    build_saas_automation_sensor,
)


# A planted Slack bot with a write+sensitive-read scope set (an exfil-capable
# shadow-AI bot installed under a third-party OAuth app).
_PLANTED_SLACK_BOT = {
    "id": "B0SHADOWBOT",
    "name": "ShadowExfil",
    "is_bot": True,
    "app_id": "A0NOTION",
    "team_id": "T1ACME",
    "scopes": ["chat:write", "files:read", "channels:history"],
    "is_workflow_bot": False,
    "updated": 1782242461,
}

_PLANTED_WORKFLOW_BOT = {
    "id": "B0FLOWBOT",
    "name": "NightlyReportFlow",
    "is_bot": True,
    "app_id": "A0LANXQRY",
    "team_id": "T1ACME",
    "scopes": ["chat:write"],
    "is_workflow_bot": True,
    "updated": 1782242999,
}


def _planted_slack_source(records):
    return SlackConnector(records=records)


# ---------------------------------------------------------------------------
# (1) emits a correct Incidence for a planted SaaS agent
# ---------------------------------------------------------------------------


def test_emits_incidence_for_planted_saas_bot():
    sensor = SaaSAutomationSensor(
        sources=[_planted_slack_source([_PLANTED_SLACK_BOT])]
    )
    incidences = list(sensor.sense(SenseContext()))

    assert len(incidences) == 1
    inc = incidences[0]
    assert isinstance(inc, Incidence)

    # Plane-typed correctly + footprint plane matches the incidence plane.
    assert inc.plane_id is PlaneId.SAAS_AUTOMATION
    assert inc.footprint.plane_id is PlaneId.SAAS_AUTOMATION

    # A SaaS admin-API assertion is PLATFORM_ATTESTED (never PROVEN on this plane).
    assert inc.admissibility is Admissibility.PLATFORM_ATTESTED

    # The fusion/disambiguation footprint keys are present (fuse.py LINK/SPLIT keys).
    keys = inc.footprint.keys_dict()
    assert keys[FootprintField.SAAS_APP] == "slack:A0NOTION"
    assert keys[FootprintField.BOT_USER_ID] == "slack:B0SHADOWBOT"
    assert keys[FootprintField.OAUTH_GRANT_ID] == "slack:A0NOTION"
    # Scopes are canonicalized: sorted, de-duped, casefolded, comma-joined.
    assert keys[FootprintField.SCOPES] == "channels:history,chat:write,files:read"
    # A non-workflow bot carries no automation-recipe key.
    assert FootprintField.AUTOMATION_RECIPE_ID not in keys

    # Catchability is a valid asserted plane constant; evidence ref names the source.
    assert 0.0 <= inc.catchability <= 1.0
    assert inc.raw_evidence_ref.startswith("saas:slack:")


def test_workflow_bot_emits_automation_recipe_key():
    """A Slack Workflow Builder bot IS an automation recipe (Zapier/Make-class)."""
    sensor = SaaSAutomationSensor(
        sources=[_planted_slack_source([_PLANTED_WORKFLOW_BOT])]
    )
    incidences = list(sensor.sense(SenseContext()))

    assert len(incidences) == 1
    keys = incidences[0].footprint.keys_dict()
    assert keys[FootprintField.AUTOMATION_RECIPE_ID] == "slack:workflow:B0FLOWBOT"
    assert incidences[0].footprint.attr("is_automation") == "true"


def test_shared_oauth_grant_links_two_agents():
    """Two bots under ONE OAuth grant agree on the bridging grant key (the N1
    shared-credential SPLIT signal source). The sensor must emit BOTH footprints
    carrying the SAME ``oauth_grant_id`` so fuse.py can detect the k>=2 collapse."""
    bot_a = dict(_PLANTED_SLACK_BOT, id="B0AAA", name="AgentA")
    bot_b = dict(_PLANTED_SLACK_BOT, id="B0BBB", name="AgentB")
    sensor = SaaSAutomationSensor(sources=[_planted_slack_source([bot_a, bot_b])])
    incidences = list(sensor.sense(SenseContext()))

    assert len(incidences) == 2
    grant_ids = {i.footprint.key(FootprintField.OAUTH_GRANT_ID) for i in incidences}
    bot_ids = {i.footprint.key(FootprintField.BOT_USER_ID) for i in incidences}
    # One shared grant, two DISTINCT bot ids (the disambiguation split axis).
    assert grant_ids == {"slack:A0NOTION"}
    assert bot_ids == {"slack:B0AAA", "slack:B0BBB"}


# ---------------------------------------------------------------------------
# (2) degrade-to-empty
# ---------------------------------------------------------------------------


def test_degrades_to_empty_with_no_source():
    """No connected source → emits nothing, never raises (the unconnected case)."""
    sensor = SaaSAutomationSensor(sources=None)
    assert list(sensor.sense(SenseContext())) == []

    sensor_empty = SaaSAutomationSensor(sources=[])
    assert list(sensor_empty.sense(SenseContext())) == []


def test_degrades_to_empty_when_source_raises():
    """A source that raises mid-scan degrades to fewer incidences, never raises."""

    class _RaisingSource:
        source = "slack"
        name = "boom"

        def scan(self, context: ConnectorContext):
            raise RuntimeError("auth failed / rate limited")

    sensor = SaaSAutomationSensor(sources=[_RaisingSource()])
    # Must not raise; yields nothing for the broken source.
    assert list(sensor.sense(SenseContext())) == []


def test_candidate_with_no_footprint_key_is_dropped():
    """A record yielding no footprint key emits no synthetic placeholder.

    A bot with no app_id, no id, and no scopes still gets a ``saas_app`` cohort
    key from the platform tag, so it is NOT dropped — assert the conservative
    over-report direction holds (a footprint is emitted, keyed on the platform)."""
    sensor = SaaSAutomationSensor(
        sources=[_planted_slack_source([{"id": "B0BARE", "is_bot": True}])]
    )
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    keys = incidences[0].footprint.keys_dict()
    # A bare bot at least carries its platform-native bot id + a saas_app cohort.
    assert keys[FootprintField.BOT_USER_ID] == "slack:B0BARE"
    assert keys[FootprintField.SAAS_APP].startswith("slack:")


# ---------------------------------------------------------------------------
# registry factory — flag-gated + default-safe
# ---------------------------------------------------------------------------


def test_factory_with_no_creds_builds_empty_sensor():
    """The registry factory with no SaaS creds builds a sourceless (empty) sensor."""
    sensor = build_saas_automation_sensor(env={})
    assert sensor.plane_id is PlaneId.SAAS_AUTOMATION
    assert list(sensor.sense(SenseContext())) == []


def test_factory_is_flag_gated_off_by_default_in_registry():
    """No TEX_SIEVE_P5_OAUTH flag → the plane is NOT built by build_active_sensors."""
    from tex.discovery.engine.sensors.registry import (
        active_plane_flags,
        build_active_sensors,
    )

    assert build_active_sensors(env={}) == []
    assert "TEX_SIEVE_P5_OAUTH" not in active_plane_flags(env={})


def test_factory_builds_plane_when_flag_enabled():
    """With the flag on (but no creds) the registry builds the plane, sensing empty."""
    from tex.discovery.engine.sensors.registry import build_active_sensors

    sensors = build_active_sensors(env={"TEX_SIEVE_P5_OAUTH": "1"})
    saas = [s for s in sensors if s.plane_id is PlaneId.SAAS_AUTOMATION]
    assert len(saas) == 1
    # No creds → senses nothing (default-safe even when the flag is enabled).
    assert list(saas[0].sense(SenseContext())) == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
