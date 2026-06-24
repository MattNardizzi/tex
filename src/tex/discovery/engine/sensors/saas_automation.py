"""
P5/P10 — the SaaS / AUTOMATION plane (``PlaneId.SAAS_AUTOMATION``).

The SaaS-embedded & automation surface (ARCHITECTURE.md §8 P5/P8/P10;
RESEARCH_LOG.md §P5–P7, §P10): the agents and bots that live INSIDE the
business-line SaaS apps an org already runs — Slack/Salesforce/GitHub bots, the
first- vs third-party **OAuth consent grants** that admit shadow-AI ingress, and
the **automation recipes** (Zapier/Make/Power-Automate/RPA) that act on a
schedule with no human in the loop. RESEARCH_LOG.md frames this as the *slow*
(poll-bound) capture occasion whose distinct value is first-vs-third-party
consent visibility — a SaaS app with no introspection API becomes a NAMED blind
spot, never a silent zero.

This is a wrapper plane, NOT a new collector: it reuses the already-built,
already-tested discovery CONNECTORS (``slack_live`` / ``slack`` / ``github`` /
``salesforce`` / ``mcp_server``) purely as SIGNAL SOURCES. Each connector knows
how to enumerate its platform's agents/bots and emits ``CandidateAgent`` records
carrying the app-side evidence (granted ``scopes``/``permissions``, the
``app_id``, the bot user id, MCP tool sets). The sensor adapts that platform
shape into plane-typed ``Incidence`` leaves — exactly the "adapt the platform
shape to ``Incidence``" contract in ``sensors/base.py``, the same posture as the
live connectors (``slack_live`` iterates the real API; the mocks iterate injected
records).

Footprint (the contracts-pass P5 vocabulary, ``models.FootprintField``):

- ``saas_app``              — the platform/app the agent is embedded in
                              (``slack:Notion``, ``salesforce:Agentforce``,
                              ``github:copilot-chat``, ``mcp:github-mcp``). The
                              coarse cohort + the third-party-consent surface.
- ``bot_user_id``          — the platform-native bot / client / agent id
                              (Slack ``B…``/``U…``, the SF object id, the GH
                              installation id, the MCP client id). The shared
                              service-credential whose collapse is the N1 split.
- ``oauth_grant_id``       — the consent grant / installation the agent acts
                              under (Slack ``app_id``, the GH installation id).
                              A SHARED grant behind k agents is the N1 signal.
- ``automation_recipe_id`` — the Zapier/Make/Power-Automate/RPA recipe id when
                              the source exposes one (workflow bots, scheduled
                              flows). Present only when the platform names it.
- ``scopes``               — the canonicalized granted scope/permission set, a
                              stable bridging cohort key (a popular scope set is
                              shared by many → the N5 ``1/anon_set_size`` discount
                              drives it to ≈0 evidence; a rare one links tightly).

All five names are BRIDGING-grade in ``fuse._BRIDGING_KEYS`` — they LINK the same
agent seen on N planes and, crucially, a SHARED grant/bot/app/recipe collapsing k
distinct agents is the positive shared-credential SPLIT signal (N1). They are
deliberately NOT identity-grade: a self-asserted SaaS credential never *merges*
two strong components on its own.

Admissibility (``models.Admissibility``): a SaaS admin API ASSERTS the grant, so
the base grade is ``PLATFORM_ATTESTED`` (trusted only as far as the platform). An
MCP tool-set the agent was OBSERVED actually exercising is graded ``OBSERVED``
(an exercised behavior we watched). Never ``PROVEN`` — no ground-truth on this
plane.

Catchability is an ASSERTED plane constant in the slice (NOT a measured recall;
RESEARCH_LOG.md §8 — measured catchability / signed-cohort recall is a Phase-5
target the count-based estimator does not yet consume).

HARD RULES honored:
- **Degrade to EMPTY, never raise.** A sensor constructed with NO connected
  source senses nothing. A connector that raises mid-scan (auth/rate-limit)
  degrades to *fewer* incidences, never an exception — exactly like
  ``ConduitConnectionsConnector`` returning inert when unconnected.
- **Flag-gated OFF by default.** Activation is the registry's job behind
  ``TEX_SIEVE_P5_OAUTH``; the factory below builds a LIVE source ONLY when its
  credential env var is present, and otherwise returns a sensor with no sources
  (which senses empty). Nothing activates on a merge-to-main / prod deploy.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Iterable, Iterator, Mapping, Protocol, Sequence, runtime_checkable

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

#: ASSERTED recall of the SaaS/automation plane over the agents its source
#: connectors CAN enumerate (a slice constant, NOT measured; measurement deferred
#: to Phase 5 — provider-API declared coverage / signed-cohort recall). A SaaS
#: app with no admin/introspection API is OUTSIDE this cohort and is a NAMED blind
#: spot the estimator reports, never folded into this recall. The count-based
#: slice estimator carries-but-does-not-consume this value.
SAAS_AUTOMATION_CATCHABILITY: float = 1.0

#: The default tenant id the sensor scans under when ``SenseContext`` carries no
#: tenant (the slice ``SenseContext`` has no tenant field; the connectors require
#: one). Overridable per-source via the factory. Lower-cased to satisfy the
#: ``BaseConnector`` tenant filter.
_DEFAULT_TENANT = "default"


@runtime_checkable
class _SaaSSource(Protocol):
    """The minimal surface the sensor needs from a wrapped connector.

    Every discovery connector (``DiscoveryConnector`` in ``connectors/base.py``)
    already satisfies this: it has a ``source`` tag, a ``name``, and a
    ``scan(context)`` that yields ``CandidateAgent`` records. The sensor depends
    only on this structural surface so ANY connector (live or mock) can be a
    source without a new adapter, and a verifier can inject a planted connector.
    """

    source: Any
    name: str

    def scan(self, context: ConnectorContext) -> Iterable[Any]:
        ...


def _canonical_scopes(values: Iterable[Any]) -> str:
    """A stable, order-independent canonical form of a granted scope/perm set.

    Sorted + de-duplicated + casefolded + comma-joined so two agents granted the
    SAME set agree on the ``scopes`` bridging key regardless of source ordering
    (so the N5 anonymity-set discount sees the true cohort size). Empty input →
    empty string (the caller omits an empty key rather than emitting a blank).
    """
    out: set[str] = set()
    for v in values:
        if isinstance(v, str) and v.strip():
            out.add(v.strip().casefold())
    return ",".join(sorted(out))


def _coerce_dt(value: Any) -> datetime | None:
    """Best-effort tz-aware datetime from a connector's ``last_seen_active_at``."""
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    return None


class SaaSAutomationSensor:
    """Emits one ``Incidence`` per SaaS-embedded / automation agent footprint.

    Construct with a sequence of SOURCE connectors (live or mock). ``sense`` runs
    each source's ``scan`` and adapts every ``CandidateAgent`` into a plane-typed
    ``Incidence``. A sensor constructed with NO sources (the default-safe degrade
    the registry factory returns when no creds are present) senses nothing.

    The wrapped connectors are SIGNAL SOURCES only — the sensor never mutates the
    registry/ledger (that boundary belongs downstream); it only translates the
    app-side evidence into the plane's footprint vocabulary.
    """

    plane_id: PlaneId = PlaneId.SAAS_AUTOMATION

    def __init__(
        self,
        sources: Sequence[_SaaSSource] | None = None,
        *,
        tenant_id: str = _DEFAULT_TENANT,
        catchability: float = SAAS_AUTOMATION_CATCHABILITY,
        timeout_seconds: float = 30.0,
        max_candidates: int = 5_000,
    ) -> None:
        self._sources: tuple[_SaaSSource, ...] = tuple(sources or ())
        self._tenant_id = (tenant_id or _DEFAULT_TENANT).strip() or _DEFAULT_TENANT
        self._catchability = catchability
        self._timeout_seconds = timeout_seconds
        self._max_candidates = max_candidates

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401
        """Adapt every wrapped source's ``CandidateAgent`` stream into incidences.

        - With no sources (unconnected), returns an empty iterable.
        - Runs each source's ``scan`` under a ``ConnectorContext``; a source that
          raises (auth / rate-limit / schema) is logged and SKIPPED, degrading to
          fewer incidences — never an exception.
        - Emits one ``Incidence`` per ``CandidateAgent`` whose evidence yields at
          least one footprint key, keyed on
          ``{saas_app, bot_user_id, oauth_grant_id, automation_recipe_id,
          scopes}`` (only the present ones), with disambiguating attrs.
        - ``admissibility`` = ``OBSERVED`` when an MCP/tool DAG was exercised,
          else ``PLATFORM_ATTESTED`` (a SaaS admin API assertion).
        - Returns an empty iterable on any missing/unreadable source; NEVER raises.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:
        if not self._sources:
            return
        ctx = ConnectorContext(
            tenant_id=self._tenant_id,
            timeout_seconds=self._timeout_seconds,
            max_candidates=self._max_candidates,
        )
        for source in self._sources:
            yield from self._sense_source(source, ctx)

    def _sense_source(
        self, source: _SaaSSource, ctx: ConnectorContext
    ) -> Iterator[Incidence]:
        """Scan one source, degrading the WHOLE source to empty on any raise."""
        try:
            candidates = list(source.scan(ctx))
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info(
                "sieve: saas_automation source %s degraded to empty: %s",
                getattr(source, "name", source),
                exc,
            )
            return
        for candidate in candidates:
            inc = self._candidate_to_incidence(source, candidate)
            if inc is not None:
                yield inc

    def _candidate_to_incidence(
        self, source: _SaaSSource, candidate: Any
    ) -> Incidence | None:
        """Translate one ``CandidateAgent`` into a SaaS/automation footprint.

        Pulls the app-side signal out of the candidate's ``evidence`` bag (the
        connectors stash ``scopes``/``permissions``/``app_id``/``raw_id`` there)
        and the canonical ``external_id`` / ``framework_hint`` off the candidate
        itself. A candidate that yields NO footprint key is dropped (never a
        synthetic placeholder).
        """
        try:
            evidence = dict(getattr(candidate, "evidence", {}) or {})
        except (TypeError, ValueError):
            evidence = {}

        platform = self._platform_tag(source)
        keys: dict[str, str] = {}

        # --- saas_app: platform[:app] coarse cohort + third-party-consent key --
        app_id = evidence.get("app_id")
        app_label = app_id or getattr(candidate, "framework_hint", None) or platform
        keys[FootprintField.SAAS_APP] = (
            f"{platform}:{app_label}" if platform else str(app_label)
        )

        # --- bot_user_id: the platform-native bot / client / agent id ----------
        bot_user_id = (
            evidence.get("raw_id")
            or getattr(candidate, "external_id", None)
        )
        if bot_user_id:
            keys[FootprintField.BOT_USER_ID] = f"{platform}:{bot_user_id}"

        # --- oauth_grant_id: the consent grant / installation the agent acts under
        if app_id:
            keys[FootprintField.OAUTH_GRANT_ID] = f"{platform}:{app_id}"

        # --- automation_recipe_id: Zapier/Make/Power-Automate/RPA / workflow ---
        recipe_id = self._recipe_id(evidence, candidate)
        if recipe_id:
            keys[FootprintField.AUTOMATION_RECIPE_ID] = f"{platform}:{recipe_id}"

        # --- scopes: the canonical granted scope/permission cohort key ---------
        scopes = self._scopes(evidence, candidate)
        if scopes:
            keys[FootprintField.SCOPES] = scopes

        # No footprint key at all → nothing to fuse on; drop (never a placeholder).
        if not keys:
            return None

        attrs = self._attrs(source, candidate, evidence, platform)
        admissibility = self._admissibility(evidence)

        footprint = FootprintVector.of(
            plane_id=PlaneId.SAAS_AUTOMATION, keys=keys, attrs=attrs
        )
        observed_at = _coerce_dt(getattr(candidate, "last_seen_active_at", None))
        ref = f"saas:{platform}:{bot_user_id or app_label}"
        try:
            return Incidence(
                plane_id=PlaneId.SAAS_AUTOMATION,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=admissibility,
                raw_evidence_ref=ref,
                observed_at=observed_at or datetime.now(UTC),
            )
        except ValueError:
            # A defensive guard (e.g. an out-of-range catchability) degrades to a
            # dropped row, never a raised exception.
            return None

    # ------------------------------------------------------------------
    # field extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _platform_tag(source: _SaaSSource) -> str:
        """A stable lower-case platform tag from the source's ``DiscoverySource``."""
        src = getattr(source, "source", None)
        value = getattr(src, "value", None) or src
        if value is None:
            return getattr(source, "name", "saas") or "saas"
        return str(value).strip().casefold() or "saas"

    @staticmethod
    def _recipe_id(evidence: Mapping[str, Any], candidate: Any) -> str | None:
        """The automation recipe / workflow id when the source names one.

        Covers Zapier/Make/Power-Automate/RPA + Slack Workflow Builder bots
        (``is_workflow_bot``). Present only when the platform actually exposes a
        recipe handle — never synthesized.
        """
        for name in ("automation_recipe_id", "recipe_id", "workflow_id", "flow_id"):
            v = evidence.get(name)
            if isinstance(v, str) and v.strip():
                return v.strip()
        # A Slack Workflow Builder bot IS an automation recipe; key it on the bot
        # id so its scheduled-flow nature is captured even with no recipe handle.
        if evidence.get("is_workflow_bot"):
            raw = evidence.get("raw_id") or getattr(candidate, "external_id", None)
            if raw:
                return f"workflow:{raw}"
        return None

    @staticmethod
    def _scopes(evidence: Mapping[str, Any], candidate: Any) -> str:
        """Canonical granted-scope/permission cohort key from the evidence bag.

        Connectors stash the grant under ``scopes`` (Slack) or ``permissions``
        (Salesforce/GitHub); GitHub permissions are a ``{perm: level}`` dict.
        """
        scopes = evidence.get("scopes")
        if isinstance(scopes, (list, tuple, set)):
            canon = _canonical_scopes(scopes)
            if canon:
                return canon
        perms = evidence.get("permissions")
        if isinstance(perms, dict):
            return _canonical_scopes(f"{k}:{v}" for k, v in perms.items())
        if isinstance(perms, (list, tuple, set)):
            return _canonical_scopes(perms)
        # Fall back to the candidate's declared tool hints if it exposes them.
        hints = getattr(candidate, "capability_hints", None)
        tools = getattr(hints, "inferred_tools", None)
        if isinstance(tools, (list, tuple)):
            return _canonical_scopes(tools)
        return ""

    @staticmethod
    def _admissibility(evidence: Mapping[str, Any]) -> Admissibility:
        """OBSERVED for an exercised tool/MCP DAG, else PLATFORM_ATTESTED.

        An MCP source records the tool names the client was OBSERVED calling
        (``tool_names``); that is an exercised behavior we watched. Everything
        else on this plane is a platform admin-API assertion.
        """
        if evidence.get("tool_names") or evidence.get("exercised_tools"):
            return Admissibility.OBSERVED
        return Admissibility.PLATFORM_ATTESTED

    @staticmethod
    def _attrs(
        source: _SaaSSource,
        candidate: Any,
        evidence: Mapping[str, Any],
        platform: str,
    ) -> dict[str, str]:
        """Descriptive (non-matching) attrs for receipts + capability mapping."""
        attrs: dict[str, str] = {"platform": platform}
        name = getattr(candidate, "name", None)
        if isinstance(name, str) and name.strip():
            attrs["display_name"] = name.strip()
        risk = getattr(candidate, "risk_band", None)
        risk_val = getattr(risk, "value", None) or risk
        if risk_val is not None:
            attrs["risk_band"] = str(risk_val)
        framework = getattr(candidate, "framework_hint", None)
        if isinstance(framework, str) and framework.strip():
            attrs["framework"] = framework.strip()
        if evidence.get("is_workflow_bot"):
            attrs["is_automation"] = "true"
        owner = getattr(candidate, "owner_hint", None)
        if isinstance(owner, str) and owner.strip():
            attrs["owner_hint"] = owner.strip()
        return attrs


# ---------------------------------------------------------------------------
# Registry factory — flag-gated, degrade-to-empty (TEX_SIEVE_P5_OAUTH)
# ---------------------------------------------------------------------------


def build_saas_automation_sensor(env: Mapping[str, str]) -> SaaSAutomationSensor:
    """Registry factory for the P5/P10 plane (``TEX_SIEVE_P5_OAUTH``).

    Builds the sensor with whatever LIVE sources the environment is credentialed
    for, and NO sources otherwise — so a flag-enabled-but-uncredentialed env
    senses empty rather than raising (the §8 default-safe degrade). The flag
    itself is checked by ``build_active_sensors`` BEFORE this factory runs; this
    factory only decides which sources are reachable.

    Recognized credentials (all optional, each independently degrading):
      - ``SLACK_TOKEN`` (+ optional ``SLACK_TEAM_ID``) → live Slack source.

    Salesforce/GitHub/MCP have no committed live connector here yet, so they are
    omitted until one lands (their mocks are test-only and never wired live).
    A verifier injects its own planted source by constructing ``SaaSAutomationSensor``
    directly — this factory is only the production wiring.
    """
    sources: list[_SaaSSource] = []
    tenant_id = (env.get("TEX_SIEVE_TENANT") or _DEFAULT_TENANT).strip() or _DEFAULT_TENANT

    slack_token = env.get("SLACK_TOKEN") or env.get("TEX_SIEVE_SLACK_TOKEN")
    if slack_token and slack_token.strip():
        try:
            from tex.discovery.connectors.slack_live import SlackLiveConnector

            sources.append(
                SlackLiveConnector(
                    token=slack_token.strip(),
                    team_id=(env.get("SLACK_TEAM_ID") or "").strip() or None,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a bad cred degrades that source
            _logger.info("sieve: saas_automation slack source unavailable: %s", exc)

    return SaaSAutomationSensor(sources=sources, tenant_id=tenant_id)


__all__ = [
    "SaaSAutomationSensor",
    "build_saas_automation_sensor",
    "SAAS_AUTOMATION_CATCHABILITY",
]
