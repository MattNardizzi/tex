"""
P6/P7 managed-control plane tests (``sensors.managed_control``).

Proves the three load-bearing properties the plane contract requires:

1. A PLANTED managed agent (Bedrock + OpenAI fixtures, wrapped through the real
   ``AwsBedrockConnector`` / ``OpenAIConnector`` as SIGNAL SOURCES) emits a
   correct ``PLATFORM_ATTESTED`` ``Incidence`` carrying the §8 P6/P7 footprint
   fields {control_plane, managed_agent_id, model, region, role_arn}.
2. Two distinct managed agents sharing ONE ``role_arn`` carry the bridging
   ``role_arn`` but distinct IDENTITY-grade ``managed_agent_id`` — the N1
   shared-credential split surface (fuse keeps them separable).
3. The plane DEGRADES TO EMPTY (never raises) when no source/cred is configured,
   when a source raises, and when the registry factory is built without creds.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_managed_control.py -q
"""

from __future__ import annotations

from typing import Any, Iterable

from tex.discovery.connectors.aws_bedrock import AwsBedrockConnector
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.openai_assistants import OpenAIConnector
from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    EdgeGrade,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.managed_control import (
    ManagedControlSensor,
    connector_source,
    oidc_issuance_source,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# ---------------------------------------------------------------------------
# Fixtures — planted managed agents on two real control-plane connectors
# ---------------------------------------------------------------------------

_BEDROCK_RECORDS = [
    {
        "agentId": "bedrock-agent-7a2b",
        "agentName": "AssayPilot",
        "foundationModel": "anthropic.claude-3-7-sonnet-20250219-v1:0",
        "status": "PREPARED",
        "environmentTag": "prod",
        "iamRoleArn": "arn:aws:iam::1234:role/assay-pilot-exec",
        "region": "us-east-1",
        "actionGroups": ["s3_read", "s3_write"],
    },
]

_OPENAI_RECORDS = [
    {
        "id": "asst_abc123",
        "name": "ContractDrafter",
        "model": "gpt-4o",
        "tools": [{"type": "code_interpreter"}],
        "created_at": 1782242461,
    },
]


def _bedrock_source():
    """The Bedrock connector wrapped as a managed-control SIGNAL source."""
    return connector_source(
        AwsBedrockConnector(records=_BEDROCK_RECORDS), "aws_bedrock"
    )


def _openai_source():
    """The OpenAI Assistants connector wrapped as a managed-control source.

    The mock connector's evidence carries ``model``; the source adapter reads it.
    """
    return connector_source(
        OpenAIConnector(records=_OPENAI_RECORDS), "openai_assistants"
    )


# ---------------------------------------------------------------------------
# 1. A planted managed agent emits a correct PLATFORM_ATTESTED incidence
# ---------------------------------------------------------------------------


def test_planted_managed_agent_emits_platform_attested_incidence() -> None:
    sensor = ManagedControlSensor([_bedrock_source(), _openai_source()])
    incidences = list(sensor.sense(SenseContext()))

    assert len(incidences) == 2, "one incidence per planted managed agent"
    for inc in incidences:
        assert inc.plane_id is PlaneId.MANAGED_CONTROL
        assert inc.footprint.plane_id is PlaneId.MANAGED_CONTROL
        assert inc.admissibility is Admissibility.PLATFORM_ATTESTED
        assert 0.0 <= inc.catchability <= 1.0
        assert inc.raw_evidence_ref.startswith("managed_control:")
        assert inc.observed_at.tzinfo is not None

    by_id = {inc.footprint.key("managed_agent_id"): inc for inc in incidences}
    assert set(by_id) == {"bedrock-agent-7a2b", "asst_abc123"}

    # The Bedrock agent carries the full §8 P6/P7 footprint contract.
    bedrock = by_id["bedrock-agent-7a2b"]
    assert bedrock.footprint.key("control_plane") == "aws_bedrock"
    assert bedrock.footprint.key("agent_external_id") == "AssayPilot"
    assert (
        bedrock.footprint.key("model")
        == "anthropic.claude-3-7-sonnet-20250219-v1:0"
    )
    assert bedrock.footprint.key("role_arn") == "arn:aws:iam::1234:role/assay-pilot-exec"
    # role_arn is mirrored to iam_role so the supply-chain plane can bridge.
    assert bedrock.footprint.key("iam_role") == "arn:aws:iam::1234:role/assay-pilot-exec"


def test_region_field_passes_through_when_source_surfaces_it() -> None:
    """``region`` is carried when a source surfaces it (the §8 P6/P7 contract).

    The in-repo ``AwsBedrockConnector`` mock does not yet project ``region`` into
    its evidence, so this proves the field passthrough on a source that does —
    exactly what a live Bedrock connector populating ``evidence['region']``
    (or a raw control-plane row) yields.
    """

    def _region_source(context: ConnectorContext) -> Iterable[dict[str, Any]]:  # noqa: ARG001
        return [
            {
                "control_plane": "azure_ai",
                "managed_agent_id": "azure-agent-9c",
                "agent_name": "ReportWriter",
                "model": "gpt-4o",
                "region": "westeurope",
                "role_arn": "/subscriptions/abc/resourceGroups/ai/agents/report",
            }
        ]

    sensor = ManagedControlSensor([_region_source])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    fp = incidences[0].footprint
    assert fp.key("region") == "westeurope"
    assert fp.key("control_plane") == "azure_ai"
    assert fp.key("model") == "gpt-4o"


def test_managed_agent_id_is_identity_grade_join_key() -> None:
    """Two re-scans of the same managed agent fuse to ONE entity (identity-grade
    ``managed_agent_id`` closes transitively in ``fuse.py``)."""
    sensor = ManagedControlSensor([_bedrock_source(), _bedrock_source()])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 2  # same agent seen on two scans

    entities = resolve(incidences)
    assert len(entities) == 1, "same managed_agent_id fuses to one entity"
    entity = entities[0]
    # The fusing edge must be IDENTITY-grade.
    assert any(e.grade is EdgeGrade.IDENTITY for e in entity.edges)


def test_shared_role_arn_is_bridging_split_surface() -> None:
    """Two DISTINCT managed agents sharing one ``role_arn`` stay separable: the
    bridging ``role_arn`` links them (N1 shared-credential signal) but does NOT
    merge them — distinct ``managed_agent_id`` keeps two entities."""
    shared_role = "arn:aws:iam::1234:role/shared-exec"
    records = [
        {
            "agentId": "agent-alpha",
            "agentName": "Alpha",
            "iamRoleArn": shared_role,
            "region": "us-east-1",
        },
        {
            "agentId": "agent-beta",
            "agentName": "Beta",
            "iamRoleArn": shared_role,
            "region": "us-east-1",
        },
    ]
    source = connector_source(AwsBedrockConnector(records=records), "aws_bedrock")
    sensor = ManagedControlSensor([source])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 2

    entities = resolve(incidences)
    assert len(entities) == 2, "shared role_arn must NOT merge distinct agents"
    # The N1 shared-credential verdict names the collapsing role.
    verdicts = [v for ent in entities for v in ent.shared_credential_verdicts]
    assert any(f"role_arn={shared_role}" == v.credential_id for v in verdicts)


def test_oidc_issuance_source_carries_signed_identity() -> None:
    """The P7 vault/CI-OIDC source surfaces the OIDC subject as a signed-id."""
    source = oidc_issuance_source(
        [
            {
                "sub": "spiffe://ci/runner-42",
                "agent_name": "DeployBot",
                "role_arn": "arn:aws:iam::1234:role/deploy",
                "issued_at": 1782242461,
            }
        ]
    )
    sensor = ManagedControlSensor([source])
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    inc = incidences[0]
    assert inc.footprint.key("oidc_sub") == "spiffe://ci/runner-42"
    assert inc.footprint.key("managed_agent_id") == "spiffe://ci/runner-42"
    assert inc.footprint.key("control_plane") == "vault_ci_oidc"


# ---------------------------------------------------------------------------
# 3. Degrade-to-empty: missing source / raising source / no creds via registry
# ---------------------------------------------------------------------------


def test_degrades_to_empty_when_no_source_configured() -> None:
    sensor = ManagedControlSensor()  # no sources = the no-creds default
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_source_yields_nothing() -> None:
    sensor = ManagedControlSensor([_empty_source])
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_source_raises() -> None:
    sensor = ManagedControlSensor([_raising_source])
    # A raising source must NOT propagate — the plane degrades to empty.
    assert list(sensor.sense(SenseContext())) == []


def test_registry_factory_degrades_empty_without_creds() -> None:
    """The registry factory, even with its flag ON, builds an inert sensor when
    no managed-control creds are present (default-safe on a prod deploy)."""
    sensors = build_active_sensors({"TEX_SIEVE_P6_AUDIT": "1"})
    managed = [s for s in sensors if s.plane_id is PlaneId.MANAGED_CONTROL]
    assert len(managed) == 1
    assert list(managed[0].sense(SenseContext())) == []


def test_registry_default_off_does_not_build_the_plane() -> None:
    """With no flag set, the managed-control plane is not active at all."""
    sensors = build_active_sensors({})
    assert all(s.plane_id is not PlaneId.MANAGED_CONTROL for s in sensors)


def test_oidc_source_degrades_empty_on_none() -> None:
    sensor = ManagedControlSensor([oidc_issuance_source(None)])
    assert list(sensor.sense(SenseContext())) == []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _empty_source(context: ConnectorContext) -> Iterable[dict[str, Any]]:  # noqa: ARG001
    return ()


def _raising_source(context: ConnectorContext) -> Iterable[dict[str, Any]]:  # noqa: ARG001
    raise RuntimeError("control-plane auth failure")
