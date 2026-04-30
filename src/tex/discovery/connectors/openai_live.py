"""
Live OpenAI Assistants connector.

This is the real-API counterpart to ``OpenAIConnector`` (the mock).
Where the mock takes a fixture list and turns each record into a
``CandidateAgent``, this connector calls the OpenAI API and turns
each returned assistant into a ``CandidateAgent``. The translation
logic is deliberately shared with the mock so the *shape* of the
candidate produced by both is identical: only the data source
differs.

The connector is constructed with an API key (and optional
organization / project headers). It uses ``urllib`` rather than the
``openai`` SDK so the dependency surface stays minimal — Tex already
ships without that SDK and we don't want to add a heavy import to the
hot path of an evaluation just to satisfy discovery.

Failure modes:

- missing or invalid API key → ``ConnectorError`` (caught by the
  service and recorded as a structured scan error)
- HTTP 429 / 5xx → ``ConnectorError`` with the upstream status
- network timeout → ``ConnectorTimeout``
- malformed response → ``ConnectorError``

The connector never crashes the runtime. The discovery service
catches ``ConnectorError`` and records it on the scan run.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, Iterable
from urllib import error as urlerror
from urllib import request as urlrequest

from tex.discovery.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    ConnectorTimeout,
)
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)


_logger = logging.getLogger(__name__)

_DEFAULT_API_BASE = "https://api.openai.com/v1"
_ASSISTANTS_PATH = "/assistants"
_PAGE_LIMIT = 100  # Maximum the API will return per page

# Same risk taxonomy as the mock connector — we deliberately reuse it
# so the candidate produced by the mock and the live connector
# differ only in source data, never in classification.
_DANGEROUS_TOOL_TYPES: frozenset[str] = frozenset(
    {"code_interpreter", "function", "retrieval", "file_search", "web_search"}
)


class OpenAIAssistantsLiveConnector(BaseConnector):
    """
    Live connector against the OpenAI Assistants API.

    Use this in production. For tests, use ``OpenAIConnector`` from
    ``tex.discovery.connectors.openai_assistants``.
    """

    def __init__(
        self,
        *,
        api_key: str,
        organization: str | None = None,
        project: str | None = None,
        api_base: str = _DEFAULT_API_BASE,
        name: str = "openai_assistants_live",
    ) -> None:
        super().__init__(
            source=DiscoverySource.OPENAI,
            name=name,
        )
        if not api_key or not api_key.strip():
            raise ValueError("api_key must be non-empty")
        self._api_key = api_key.strip()
        self._organization = organization.strip() if organization else None
        self._project = project.strip() if project else None
        self._api_base = api_base.rstrip("/")

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        cursor: str | None = None
        produced = 0
        while True:
            page = self._fetch_page(cursor=cursor, context=context)
            for record in page.get("data", []) or []:
                if produced >= context.max_candidates:
                    return
                try:
                    yield self._build_candidate(record, context)
                except Exception as exc:  # noqa: BLE001
                    # One malformed record cannot abort the scan.
                    _logger.warning(
                        "openai_assistants_live: skipping malformed record: %s",
                        exc,
                    )
                    continue
                produced += 1
            if not page.get("has_more"):
                return
            last_id = page.get("last_id")
            if not last_id or last_id == cursor:
                return
            cursor = last_id

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _fetch_page(
        self,
        *,
        cursor: str | None,
        context: ConnectorContext,
    ) -> dict[str, Any]:
        url = f"{self._api_base}{_ASSISTANTS_PATH}?limit={_PAGE_LIMIT}&order=desc"
        if cursor:
            url = f"{url}&after={cursor}"

        req = urlrequest.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("OpenAI-Beta", "assistants=v2")
        req.add_header("Content-Type", "application/json")
        if self._organization:
            req.add_header("OpenAI-Organization", self._organization)
        if self._project:
            req.add_header("OpenAI-Project", self._project)

        try:
            with urlrequest.urlopen(req, timeout=context.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
        except urlerror.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:  # noqa: BLE001
                pass
            raise ConnectorError(
                f"openai_assistants_live: HTTP {exc.code} from OpenAI: {detail}"
            ) from exc
        except urlerror.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if "timed out" in str(reason).lower():
                raise ConnectorTimeout(
                    f"openai_assistants_live: timeout after "
                    f"{context.timeout_seconds}s"
                ) from exc
            raise ConnectorError(
                f"openai_assistants_live: network error: {reason}"
            ) from exc
        except TimeoutError as exc:
            raise ConnectorTimeout(
                f"openai_assistants_live: timeout after "
                f"{context.timeout_seconds}s"
            ) from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ConnectorError(
                f"openai_assistants_live: malformed JSON response from OpenAI"
            ) from exc

        if not isinstance(payload, dict):
            raise ConnectorError(
                "openai_assistants_live: unexpected response shape"
            )
        return payload

    # ------------------------------------------------------------------
    # Candidate construction (shared shape with the mock)
    # ------------------------------------------------------------------

    def _build_candidate(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        tools: list[dict[str, Any]] = list(record.get("tools", []) or [])
        tool_types: list[str] = []
        function_names: list[str] = []
        for tool in tools:
            t_type = str(tool.get("type", "")).casefold()
            if t_type:
                tool_types.append(t_type)
            if t_type == "function":
                fn = tool.get("function", {}) or {}
                fn_name = fn.get("name")
                if isinstance(fn_name, str):
                    function_names.append(fn_name.casefold())

        file_ids = [
            str(f) for f in record.get("file_ids", []) or [] if isinstance(f, str)
        ]
        # v2 assistants attach files via tool_resources; flatten any
        # known buckets (file_search, code_interpreter) into the same
        # data_scopes list the mock uses.
        tool_resources = record.get("tool_resources", {}) or {}
        if isinstance(tool_resources, dict):
            for bucket in tool_resources.values():
                if not isinstance(bucket, dict):
                    continue
                for fid in bucket.get("file_ids", []) or []:
                    if isinstance(fid, str):
                        file_ids.append(fid)

        has_code_interp = "code_interpreter" in tool_types
        has_functions = "function" in tool_types
        unique_dangerous = {t for t in tool_types if t in _DANGEROUS_TOOL_TYPES}

        if has_code_interp and has_functions:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif has_code_interp:
            risk_band = DiscoveryRiskBand.HIGH
        elif len(unique_dangerous) >= 2:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(function_names),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(sorted(set(tool_types) | set(function_names))),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(file_ids),
            surface_unbounded=has_code_interp and has_functions,
        )

        created_dt = _epoch_to_dt(record.get("created_at"))

        evidence = {
            "model": record.get("model"),
            "tool_types": tool_types,
            "function_names": function_names,
            "file_ids": file_ids,
            "metadata": record.get("metadata", {}),
            "raw_id": record.get("id"),
            "live": True,
        }

        confidence = 0.95  # live data is more trustworthy than mock fixtures
        owner_hint = (record.get("metadata") or {}).get("owner")

        return CandidateAgent(
            source=DiscoverySource.OPENAI,
            tenant_id=context.tenant_id,
            external_id=str(record["id"]),
            name=str(record.get("name") or record["id"]),
            owner_hint=owner_hint,
            description=record.get("description"),
            model_provider_hint="openai",
            model_name_hint=record.get("model"),
            framework_hint="openai_assistants",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=created_dt,
            evidence=evidence,
            tags=("openai", "assistants", "live"),
        )


def _epoch_to_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OSError, ValueError):
            return None
    return None
