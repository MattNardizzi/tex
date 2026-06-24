"""
P6/P7 — the MANAGED-CONTROL plane (``PlaneId.MANAGED_CONTROL``).

The managed control plane is the vantage where a *cloud platform itself* attests
that an agent exists: AWS Bedrock AgentCore (``ListAgents``/``GetAgent``), OpenAI
Assistants (``/v1/assistants``), Azure AI agents, the OCSF/CloudTrail cloud-audit
stream (P6 — which principal called which API), and the secrets-vault / CI-OIDC
issuance plane (P7 — where ephemeral workload identities are born). RESEARCH_LOG
§P5–P7: this is the static∪dynamic control-plane spine; it catches the
seconds-lived identity *if streamed* and the managed agent the directory missed.

This is a ``PLATFORM_ATTESTED`` plane (models.py ``Admissibility``): a managed
control plane asserting an agent is trusted only as far as the platform — never
ground truth like an eBPF-bound syscall (PROVEN) or an exercised tool-DAG
(OBSERVED), but stronger than a self-declared card (CLAIMED).

Footprint fields (the §8 P6/P7 contract, names from ``FootprintField``):

- ``managed_agent_id`` — the control-plane-minted stable agent id (Bedrock
  ``agentId``, OpenAI ``asst_…``, the OCSF actor/resource handle, the OIDC
  subject). This is **IDENTITY-grade** in ``fuse.py`` (``_IDENTITY_KEYS``): the
  same managed agent seen on N control planes / re-scans fuses to one entity.
- ``control_plane`` / ``model`` / ``region`` / ``role_arn`` — **BRIDGING-grade**
  cohorts (``fuse._BRIDGING_KEYS``): they LINK (a shared ``role_arn`` is the N1
  shared-credential bridge that collapses k agents) but never MERGE two strong
  components alone. ``role_arn`` is also carried as ``iam_role`` so the static
  supply-chain plane (P8) can bridge to a managed agent sharing the same role.
- ``agent_external_id`` — the human-readable agent name, also IDENTITY-grade, so
  a managed agent named ``AssayPilot`` fuses with its actions-trail sightings.

Disambiguation (split) axis: two distinct Bedrock agents that share ONE
``role_arn`` carry the same bridging ``role_arn`` but distinct
``managed_agent_id`` — the resolver keeps them as two strong components bridged
by the role (the N1 shared-credential split signal), never merged.

Sources are wrapped, not reimplemented. The sensor takes a list of
``ControlPlaneSource`` callables; each yields ``CandidateAgent`` records from an
existing connector (``AwsBedrockConnector`` / ``OpenAIConnector`` /
``OcsfAuditConnector``) or a vault/CI-OIDC issuance reader. The factory in
``registry`` builds the sources from env (an injected mock-source list for tests,
real connectors when creds are present) and returns an EMPTY-sensing sensor when
no source/cred is configured — the literal "degrade to EMPTY, never raise" rule.

SLICE STATUS (honest, mirrors ``actions_trail``): the ``catchability`` this
sensor stamps is an ASSERTED plane constant (provider-API completeness over the
managed cohort), NOT a measured recall; the count-based slice estimator carries
but does not consume it. Measurement is a Phase-5 target.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Callable, Iterable, Iterator, Sequence

from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED recall of the managed-control plane over the cohort it CAN see (the
#: agents a managed platform / audit log / vault attests). A slice constant, NOT
#: measured — provider-API completeness is high for declared agents but blind to
#: anything that never registers / never authenticates through the directory;
#: that blindness is the estimator's named blind spot, not faked here. The
#: count-based slice estimator carries-but-does-not-consume this value.
MANAGED_CONTROL_CATCHABILITY = 0.9


#: A control-plane source: given a ``ConnectorContext`` it yields raw
#: agent-shaped records from one managed platform. Each record is a plain dict
#: (the connector's ``CandidateAgent`` projected to a dict, or a raw API row);
#: the sensor adapts it to a managed-control footprint. A source that has no
#: creds / no feed yields nothing — that is how the plane degrades to empty.
ControlPlaneSource = Callable[[ConnectorContext], Iterable[dict[str, Any]]]


# ---------------------------------------------------------------------------
# Source adapters over the existing connectors (signal SOURCES, not rebuilds)
# ---------------------------------------------------------------------------


def _candidate_to_record(candidate: Any, control_plane: str) -> dict[str, Any]:
    """Project a ``CandidateAgent`` to the flat managed-control record shape.

    The connectors already extract model / role / region into the candidate's
    ``evidence`` map (see ``aws_bedrock`` / ``openai_assistants`` /
    ``cloud_audit_ocsf``). This pulls the managed-control fields out of that
    canonical shape so the sensor's footprint builder is connector-agnostic.
    """
    evidence = getattr(candidate, "evidence", None) or {}
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "control_plane": control_plane,
        "managed_agent_id": getattr(candidate, "external_id", None),
        "agent_name": getattr(candidate, "name", None),
        "model": (
            getattr(candidate, "model_name_hint", None)
            or evidence.get("foundation_model")
            or evidence.get("model")
        ),
        "region": evidence.get("region") or evidence.get("aws_region"),
        "role_arn": (
            evidence.get("iam_role_arn")
            or evidence.get("role_arn")
            or evidence.get("resource_arn")
        ),
        "last_seen_active_at": getattr(candidate, "last_seen_active_at", None),
        "framework": getattr(candidate, "framework_hint", None),
    }


def connector_source(connector: Any, control_plane: str) -> ControlPlaneSource:
    """Wrap an existing discovery connector as a managed-control source.

    ``connector`` is any object exposing ``scan(context) -> Iterable`` (the
    ``DiscoveryConnector`` protocol — ``AwsBedrockConnector``,
    ``OpenAIConnector``, ``OcsfAuditConnector``, their live counterparts). The
    returned source scans it and projects each ``CandidateAgent`` to the flat
    record shape. A connector that raises (auth failure, rate limit) degrades to
    NO records, never propagating the exception out of the plane.
    """

    def _source(context: ConnectorContext) -> Iterable[dict[str, Any]]:
        try:
            candidates = list(connector.scan(context))
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info(
                "managed_control: source %s degraded to empty: %s",
                control_plane,
                exc,
            )
            return ()
        return [_candidate_to_record(c, control_plane) for c in candidates]

    return _source


def oidc_issuance_source(
    records: Sequence[dict[str, Any]] | None,
    control_plane: str = "vault_ci_oidc",
) -> ControlPlaneSource:
    """A P7 vault / CI-OIDC issuance source over already-read issuance records.

    Each record names a workload identity born at the control plane: an OIDC
    token issuance (``sub`` / ``aud`` / ``role_arn``), a Vault dynamic-credential
    mint, or a CI pipeline service principal. The reader (a Vault audit-log tail,
    a CI-OIDC issuer feed) lives in the deployment; this source only adapts the
    already-materialized rows so the plane stays pure-stdlib and degrades to
    empty when ``records`` is ``None``/empty.
    """
    rows = list(records or [])

    def _source(context: ConnectorContext) -> Iterable[dict[str, Any]]:  # noqa: ARG001
        out: list[dict[str, Any]] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            sub = r.get("sub") or r.get("subject") or r.get("oidc_sub")
            out.append(
                {
                    "control_plane": control_plane,
                    "managed_agent_id": sub or r.get("managed_agent_id"),
                    "agent_name": r.get("agent_name") or sub,
                    "model": r.get("model"),
                    "region": r.get("region"),
                    "role_arn": r.get("role_arn") or r.get("aud"),
                    "last_seen_active_at": r.get("issued_at") or r.get("last_seen_active_at"),
                    "framework": r.get("framework") or "ci_oidc",
                    "oidc_sub": sub,
                }
            )
        return out

    return _source


# ---------------------------------------------------------------------------
# The sensor
# ---------------------------------------------------------------------------


def _coerce_observed_at(value: Any) -> datetime:
    """Best-effort tz-aware timestamp; falls back to now(UTC) so one odd row
    never drops an otherwise-valid managed-control sighting."""
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OSError, ValueError, OverflowError):
            return datetime.now(UTC)
    if isinstance(value, str) and value.strip():
        try:
            v = value.strip()
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            return datetime.fromisoformat(v).astimezone(UTC)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


def _clean(value: Any) -> str | None:
    """A non-empty stripped string, or ``None``."""
    if value is None:
        return None
    s = str(value).strip()
    return s or None


class ManagedControlSensor:
    """Emits one ``Incidence`` per managed-agent attestation (P6/P7).

    Construct with a list of ``ControlPlaneSource`` callables (built by the
    registry factory from env — real connectors when creds are present, an
    injected fixture source in tests). ``sense`` scans every source, adapts each
    record to a managed-control ``FootprintVector``, and emits one
    ``PLATFORM_ATTESTED`` incidence per attested agent.

    Degrades to EMPTY (never raises) when:
    - no sources were configured (``sources`` is empty) — the no-creds default;
    - every source yields nothing (no feed / auth failure handled in the source);
    - a record carries no usable ``managed_agent_id`` and no name to anchor it.
    """

    plane_id: PlaneId = PlaneId.MANAGED_CONTROL

    def __init__(
        self,
        sources: Sequence[ControlPlaneSource] | None = None,
        *,
        tenant_id: str = "default",
        catchability: float = MANAGED_CONTROL_CATCHABILITY,
    ) -> None:
        self._sources: tuple[ControlPlaneSource, ...] = tuple(sources or ())
        self._tenant_id = tenant_id
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: ARG002
        """Scan every configured control-plane source into ``Incidence`` records.

        ``context`` (the file-roots ``SenseContext``) is unused by this plane —
        the managed-control vantage is API/audit-fed, not a directory — but the
        signature matches ``EngineSensor`` so the registry can drive it uniformly.
        Returns an empty list when no source is configured or none yields a row;
        NEVER raises.
        """
        return list(self._iter())

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self) -> Iterator[Incidence]:
        if not self._sources:
            return
        conn_ctx = ConnectorContext(tenant_id=self._tenant_id)
        for idx, source in enumerate(self._sources):
            try:
                records = list(source(conn_ctx))
            except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
                _logger.info("managed_control: source #%d degraded to empty: %s", idx, exc)
                continue
            for ridx, record in enumerate(records):
                inc = self._record_to_incidence(record, idx, ridx)
                if inc is not None:
                    yield inc

    def _record_to_incidence(
        self, record: Any, source_idx: int, row_idx: int
    ) -> Incidence | None:
        if not isinstance(record, dict):
            return None

        managed_agent_id = _clean(record.get("managed_agent_id"))
        agent_name = _clean(record.get("agent_name"))
        control_plane = _clean(record.get("control_plane")) or "managed_control"
        if managed_agent_id is None and agent_name is None:
            # Nothing to attribute this attestation to — drop it, never raise.
            return None

        # --- keys: identity-grade anchors + bridging-grade cohorts ----------
        keys: dict[str, str] = {FootprintField.CONTROL_PLANE.value: control_plane}
        if managed_agent_id is not None:
            # IDENTITY-grade: the control-plane-minted stable id fuses the same
            # managed agent across planes / re-scans.
            keys[FootprintField.MANAGED_AGENT_ID.value] = managed_agent_id
        if agent_name is not None:
            # IDENTITY-grade human handle: fuses with the actions-trail sighting
            # of the same named agent (cross-plane join with ACTIONS_TRAIL).
            keys["agent_external_id"] = agent_name

        role_arn = _clean(record.get("role_arn"))
        if role_arn is not None:
            # BRIDGING-grade: a shared role_arn is the N1 shared-credential bridge
            # (k agents under one IAM role) — links, never merges alone. Also
            # mirrored as iam_role so the static supply-chain plane can bridge.
            keys[FootprintField.ROLE_ARN.value] = role_arn
            keys[FootprintField.IAM_ROLE.value] = role_arn

        region = _clean(record.get("region"))
        if region is not None:
            keys[FootprintField.REGION.value] = region

        model = _clean(record.get("model"))
        if model is not None:
            # BRIDGING-grade coarse cohort (same model != same agent).
            keys[FootprintField.MODEL.value] = model

        oidc_sub = _clean(record.get("oidc_sub"))
        if oidc_sub is not None:
            # P7 signed identity anchor — IDENTITY-grade in fuse.py.
            keys[FootprintField.OIDC_SUB.value] = oidc_sub

        # --- attrs: descriptive payload (not matched on) --------------------
        attrs: dict[str, str] = {}
        framework = _clean(record.get("framework"))
        if framework is not None:
            attrs[FootprintField.FRAMEWORK.value] = framework

        footprint = FootprintVector.of(
            plane_id=PlaneId.MANAGED_CONTROL, keys=keys, attrs=attrs
        )
        ref = f"managed_control:{control_plane}:src{source_idx}:row{row_idx}"
        try:
            return Incidence(
                plane_id=PlaneId.MANAGED_CONTROL,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.PLATFORM_ATTESTED,
                raw_evidence_ref=ref,
                observed_at=_coerce_observed_at(record.get("last_seen_active_at")),
            )
        except ValueError:
            # A defensive guard (e.g. an out-of-range catchability) degrades to a
            # dropped row, never a raised exception.
            return None


__all__ = [
    "ManagedControlSensor",
    "ControlPlaneSource",
    "connector_source",
    "oidc_issuance_source",
    "MANAGED_CONTROL_CATCHABILITY",
]
