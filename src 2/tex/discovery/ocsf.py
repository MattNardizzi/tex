"""
OCSF normalization — one schema for every audit plane.

The audit plane is the doctrine's sweet spot: a control-plane log that fires
*outside* the workload's reachability surface, so it is tamper-resistant
*and* agentless. The trap is building a CloudTrail-specific parser, then an
Azure-specific one, then a Splunk one. The field already solved this: the
Open Cybersecurity Schema Framework (OCSF) is the vendor-neutral schema that
Amazon Security Lake normalizes CloudTrail (and Azure audit, and custom
sources) into — CloudTrail management events become the OCSF *Authentication*,
*Account Change*, and *API Activity* classes. A consumer that speaks OCSF
reads every one of those sources with a single parser.

So Tex's audit plane consumes **OCSF events** as its canonical input. A
deployment that already runs Security Lake hands Tex OCSF directly; one that
reads a raw CloudTrail trail runs it through the adapter here first. Either
way the connector downstream sees one shape, and adding a new audit source is
a new adapter, never a new connector.

Content-free: only the actor identity, the operation, the resource, and the
time are read — never request bodies or any payload an agent emitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable


# OCSF class_uids relevant to agent discovery. We treat any of them as a
# sighting; API Activity (an agent acting) is the strongest discovery signal.
OCSF_API_ACTIVITY = 6003
OCSF_AUTHENTICATION = 3002
OCSF_ACCOUNT_CHANGE = 3001


@dataclass(frozen=True, slots=True)
class OcsfEvent:
    """
    The slice of an OCSF event the discovery layer needs — actor, action,
    resource, time, and provenance of the log itself. Construct from a
    normalized OCSF record via :meth:`from_ocsf`, or from a raw CloudTrail
    record via :func:`cloudtrail_to_ocsf`.
    """

    actor_id: str          # stable principal id of the acting agent / NHI
    actor_name: str        # human-facing name (ARN tail, principal name)
    activity: str          # the operation (OCSF activity_name / api.operation)
    resource_arn: str      # the resource the agent acted on / as
    occurred_at: datetime
    product_vendor: str    # who produced the log (AWS, Microsoft, ...)
    product_name: str      # the log source (CloudTrail, Entra audit, ...)
    class_uid: int
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_ocsf(cls, record: dict[str, Any]) -> "OcsfEvent | None":
        """Build from an already-OCSF-normalized record (e.g. Security Lake)."""
        actor = (record.get("actor") or {})
        user = actor.get("user") or actor.get("app") or {}
        actor_id = str(user.get("uid") or user.get("name") or "").strip()
        # Prefer a resource ARN/uid as the agent's stable handle when present.
        resources = record.get("resources") or []
        resource_arn = ""
        if resources and isinstance(resources[0], dict):
            resource_arn = str(resources[0].get("uid") or resources[0].get("name") or "")
        handle = resource_arn or actor_id
        if not handle:
            return None
        api = record.get("api") or {}
        metadata = record.get("metadata") or {}
        product = metadata.get("product") or {}
        return cls(
            actor_id=handle,
            actor_name=str(user.get("name") or _arn_tail(resource_arn) or handle),
            activity=str(api.get("operation") or record.get("activity_name") or "unknown"),
            resource_arn=resource_arn,
            occurred_at=_ocsf_time(record.get("time")),
            product_vendor=str(product.get("vendor_name") or "unknown"),
            product_name=str(product.get("name") or "unknown"),
            class_uid=int(record.get("class_uid") or OCSF_API_ACTIVITY),
            raw=record,
        )


def cloudtrail_to_ocsf(record: dict[str, Any]) -> dict[str, Any]:
    """
    Adapt one raw AWS CloudTrail record into an OCSF-shaped dict. Mirrors
    Security Lake's own mapping closely enough for the discovery fields:
    CloudTrail management/data events → OCSF API Activity, with the actor
    identity and the acted-on resource preserved.
    """
    user_identity = record.get("userIdentity") or {}
    resources = record.get("resources") or []
    ocsf_resources = [
        {"uid": r.get("ARN") or r.get("arn"), "type": r.get("type")}
        for r in resources
        if isinstance(r, dict)
    ]
    return {
        "class_uid": OCSF_API_ACTIVITY,
        "class_name": "API Activity",
        "activity_name": record.get("eventName"),
        "time": record.get("eventTime"),
        "actor": {
            "user": {
                "uid": user_identity.get("principalId") or user_identity.get("arn"),
                "name": user_identity.get("userName")
                or _arn_tail(user_identity.get("arn") or ""),
            }
        },
        "api": {
            "operation": record.get("eventName"),
            "service": {"name": record.get("eventSource")},
        },
        "resources": ocsf_resources,
        "metadata": {"product": {"vendor_name": "AWS", "name": "CloudTrail"}},
        "src_endpoint": {"ip": record.get("sourceIPAddress")},
    }


def normalize(records: Iterable[dict[str, Any]], *, source_format: str = "ocsf") -> Iterable[OcsfEvent]:
    """
    Normalize an iterable of audit records into ``OcsfEvent``s. ``source_format``
    is ``"ocsf"`` for already-normalized input (Security Lake) or
    ``"cloudtrail"`` for raw CloudTrail JSON.
    """
    for record in records:
        ocsf = cloudtrail_to_ocsf(record) if source_format == "cloudtrail" else record
        event = OcsfEvent.from_ocsf(ocsf)
        if event is not None:
            yield event


def _arn_tail(arn: str) -> str:
    if not arn:
        return ""
    tail = arn.rsplit("/", 1)[-1]
    return tail or arn.rsplit(":", 1)[-1]


def _ocsf_time(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        # OCSF time is epoch milliseconds.
        return datetime.fromtimestamp(value / 1000.0, tz=UTC)
    if isinstance(value, str):
        try:
            v = value[:-1] + "+00:00" if value.endswith("Z") else value
            return datetime.fromisoformat(v).astimezone(UTC)
        except ValueError:
            pass
    return datetime.now(UTC)
