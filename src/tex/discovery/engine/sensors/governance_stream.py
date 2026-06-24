"""
P11 / P0 — the GOVERNANCE-STREAM plane (``PlaneId.GOVERNANCE_STREAM``) plus its
P0 coverage-health token-conservation residual (``PlaneId.COVERAGE_HEALTH``).

The WHITE-SPACE leg (ARCHITECTURE.md §8 P11/P0; RESEARCH_LOG.md §1 P11/P0, N3):
**any agent that asks Tex's PDP for a decision self-discovers by the act of
asking.** Every ``StandingGovernance.decide`` / ``AgentEvaluationSuite`` call, every
OTel ``execute_tool`` / ``invoke_agent`` span, and every model-provider
billing/usage time-series row is a passive, near-zero-latency, near-zero-cost
capture occasion that already lives INSIDE the governance boundary. SIEVE taps
that decision-event stream and turns each event into one
``Incidence(plane=GOVERNANCE_STREAM, admissibility=OBSERVED)`` whose footprint
is ``{pdp_agent_id, agent_external_id, otel_trace_id, tool_name,
billing_account, decided_at}`` — the agent's own request to be governed becomes
its discovery footprint.

Why this is a genuinely-distinct vantage (independence, ARCHITECTURE.md §11):
the governance stream is an *application-layer* tap (the PDP/OTel/billing rail),
physically distinct from the passive-network planes (P1–P4), the endpoint-eBPF
plane (P9), and the active-decoy plane (P14). An agent that bypasses the gate at
the network layer is still seen here the moment it asks for ONE decision; an
agent that asks for a decision but writes a file outside the workspace is seen
here and NOT on the fs-write plane. That complementarity is what keeps the
capture-recapture estimator valid.

The cross-plane fusion JOIN KEY is the agent identifier: this sensor emits
``agent_external_id`` (and ``agent_id`` when present) which ``fuse.py`` grades
IDENTITY, so a governance-stream sighting of ``AssayPilot`` fuses to the SAME
``SieveEntity`` as that agent's ACTIONS_TRAIL / FS_WRITE footprints. The
``pdp_agent_id`` / ``otel_trace_id`` / ``tool_name`` / ``billing_account`` keys
ride as bridging/descriptive evidence: ``billing_account`` is a coarse cohort
(``fuse._BRIDGING_KEYS``) so a single shared billing account that collapses k
agents becomes the positive N1 split signal rather than over-merging them.

------------------------------------------------------------------------------
P0 coverage-health — the token-conservation residual (N3, a positive shadow signal)
------------------------------------------------------------------------------
When the source supplies token volumes, this sensor ALSO reconciles
``billing_tokens − otel_span_tokens − network_implied_tokens`` per billing
account (RESEARCH_LOG.md N3 / §1 P0). A positive residual means tokens were
BILLED that NO OTel span and NO network flow accounts for — provably-spent
inference the telemetry never saw, i.e. a quantified shadow-VOLUME signal that
a dark agent exists below the instrumented planes. It is emitted as one
``Incidence(plane=COVERAGE_HEALTH, admissibility=PLATFORM_ATTESTED)`` carrying
the residual magnitude, so the honesty layer can NAME a dark vantage instead of
silently reporting zero uncertainty. A zero/negative residual (telemetry
conserves) emits nothing — absence of a shadow is not a finding.

------------------------------------------------------------------------------
SOURCE (configurable; degrade-empty)
------------------------------------------------------------------------------
The sensor consumes a **configurable source** — an in-process event hook or a
decision-log iterator — supplied at construction (NOT hardcoded), exactly like
``slack_live`` / ``openai_live`` wrap a real connector as a SIGNAL SOURCE behind
the sensor. The source is any zero-argument callable returning an iterable of
plain decision-event mappings (or such an iterable directly). With NO source
configured the sensor degrades to EMPTY — it senses nothing and never raises,
honoring the default-safe / flag-gated-OFF posture (``TEX_SIEVE_P11_OTEL`` /
``TEX_SIEVE_P0_COVERAGE``). A source that raises, yields a malformed row, or is
absent degrades to *fewer incidences*, never an exception.

Catchability here is an ASSERTED plane recall (a slice constant): an agent that
calls the PDP is seen with near-certainty, but agents that NEVER ask for a
decision are out-of-cohort and are the estimator's job (named in the blind-spot
ledger), not faked here. The count-based slice estimator carries-but-does-not-
consume this value; measured catchability is a Phase-5 target.

References: ARCHITECTURE.md §8 (P11/P0 flag table), §11 (vantage independence);
RESEARCH_LOG.md §1 P11/P0, N3 (token-conservation residual).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime
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

#: ASSERTED recall of the governance-stream plane over PDP-calling agents (a
#: slice constant, NOT measured; measurement deferred to Phase 5). An agent that
#: asks Tex for ONE decision is seen with near-certainty; agents that never ask
#: are out-of-cohort and surfaced by the estimator's blind-spot ledger, not faked
#: here. The count-based slice estimator carries-but-does-not-consume this value.
GOVERNANCE_STREAM_CATCHABILITY = 1.0

#: A source of decision events: either an iterable of event mappings, or a
#: zero-argument callable returning one (an in-process event hook / a
#: decision-log iterator). ``None`` means "no source configured" → degrade empty.
EventSource = (
    Callable[[], Iterable[Mapping[str, object]]]
    | Iterable[Mapping[str, object]]
    | None
)

#: Event field aliases → the canonical footprint name. The tap accepts the
#: vocabulary the real rails (StandingGovernance decision log / OTel GenAI spans /
#: provider usage API) emit, mapping each to one ``FootprintField``.
_AGENT_EXTERNAL_ALIASES: tuple[str, ...] = (
    "agent_external_id",
    "agent",
    "agent_name",
    "pdp_agent_name",
)
_AGENT_ID_ALIASES: tuple[str, ...] = ("agent_id", "agent_uuid", "subject_id")
_PDP_AGENT_ALIASES: tuple[str, ...] = ("pdp_agent_id", "principal", "actor_id")
_TRACE_ALIASES: tuple[str, ...] = ("otel_trace_id", "trace_id", "traceId")
_TOOL_ALIASES: tuple[str, ...] = ("tool_name", "tool", "action_type", "operation")
_BILLING_ALIASES: tuple[str, ...] = (
    "billing_account",
    "billing_account_id",
    "api_key_id",
    "workspace_id",
    "account",
)
_DECIDED_AT_ALIASES: tuple[str, ...] = ("decided_at", "ts", "timestamp", "time")

#: Token-volume aliases for the P0 token-conservation residual (N3).
_BILLING_TOKENS_ALIASES: tuple[str, ...] = (
    "billing_tokens",
    "billed_tokens",
    "usage_tokens",
)
_OTEL_TOKENS_ALIASES: tuple[str, ...] = (
    "otel_span_tokens",
    "span_tokens",
    "otel_tokens",
)
_NETWORK_TOKENS_ALIASES: tuple[str, ...] = (
    "network_implied_tokens",
    "network_tokens",
    "flow_tokens",
)


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


def _as_float(val: object | None) -> float | None:
    """Best-effort float, or ``None`` (a malformed token count is dropped)."""
    if val is None:
        return None
    try:
        return float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _coerce_decided_at(val: object | None) -> datetime:
    """tz-aware decision time from epoch seconds or an ISO string.

    Falls back to now(UTC) on anything unparseable so a single odd row never
    drops an otherwise-valid governance observation.
    """
    if val is None:
        return datetime.now(UTC)
    # Epoch seconds (int/float or numeric string).
    f = _as_float(val)
    if f is not None and not isinstance(val, bool):
        try:
            return datetime.fromtimestamp(f, tz=UTC)
        except (ValueError, OverflowError, OSError):
            return datetime.now(UTC)
    # ISO-8601 string.
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


class GovernanceStreamSensor:
    """Emits one ``Incidence`` per PDP decision event (P11) + the P0 residual.

    Construct with a configurable ``source`` — an in-process event hook (a
    zero-arg callable returning an iterable of event mappings) or a decision-log
    iterator (an iterable of event mappings) — exactly the
    ``slack_live``/``openai_live`` pattern of wrapping a real connector as a
    SIGNAL SOURCE behind the sensor. With ``source=None`` (the default) the
    sensor degrades to EMPTY: it senses nothing and never raises.

    ``sense`` ignores ``SenseContext`` (the governance source is supplied at
    construction, not via the filesystem context the slice planes use), but
    accepts it to satisfy the ``EngineSensor`` protocol.

    ``plane_id`` is ``GOVERNANCE_STREAM`` (the sensor's primary plane); the P0
    coverage-health residual incidences carry ``COVERAGE_HEALTH`` and are emitted
    only when the source supplies reconcilable token volumes whose residual is
    positive (a shadow-volume signal). Set ``emit_coverage_health=False`` to run
    the pure P11 plane without the P0 residual.
    """

    plane_id: PlaneId = PlaneId.GOVERNANCE_STREAM

    def __init__(
        self,
        source: EventSource = None,
        *,
        catchability: float = GOVERNANCE_STREAM_CATCHABILITY,
        emit_coverage_health: bool = True,
    ) -> None:
        self._source = source
        self._catchability = catchability
        self._emit_coverage_health = emit_coverage_health

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401, ARG002
        """Tap the configured decision-event source into ``Incidence`` records.

        - Resolves the source (a callable hook is invoked; an iterable is used
          directly). A ``None`` source, a raising callable, or a non-iterable
          result degrades to an empty iterable — NEVER raises.
        - For each event mapping, emits one P11 ``GOVERNANCE_STREAM`` incidence
          keyed on ``{agent_external_id, agent_id?, pdp_agent_id?,
          otel_trace_id?, tool_name?, billing_account?}`` (``agent_external_id``
          is the IDENTITY-grade cross-plane fusion join key) with attrs
          ``{verdict?, decided_at}``, ``admissibility=OBSERVED``.
        - When ``emit_coverage_health`` is set and the events carry reconcilable
          token volumes, emits the P0 ``COVERAGE_HEALTH`` token-conservation
          residual incidence(s) for any billing account whose
          ``billing − otel − network`` residual is positive (a shadow signal).
        - Returns an empty iterable on a missing/unreadable/empty source.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _resolve_rows(self) -> list[Mapping[str, object]]:
        """Materialize the configured source into a list of event mappings.

        Degrades to ``[]`` on a missing source, a callable that raises, a
        non-iterable result, or rows that are not mappings (those are skipped).
        Never raises.
        """
        source = self._source
        if source is None:
            return []
        try:
            raw = source() if callable(source) else source
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: governance-stream source raised, degrading empty: %s", exc)
            return []
        rows: list[Mapping[str, object]] = []
        try:
            for item in raw:  # type: ignore[union-attr]
                if isinstance(item, Mapping):
                    rows.append(item)
        except TypeError:
            # The source returned a non-iterable; degrade empty.
            return []
        except Exception as exc:  # noqa: BLE001 — a lazy iterator that faults mid-stream
            _logger.info("sieve: governance-stream iteration faulted: %s", exc)
            return rows
        return rows

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:  # noqa: ARG002
        rows = self._resolve_rows()
        if not rows:
            return

        for idx, row in enumerate(rows):
            inc = self._row_to_incidence(idx, row)
            if inc is not None:
                yield inc

        if self._emit_coverage_health:
            yield from self._coverage_health_residuals(rows)

    def _row_to_incidence(
        self, idx: int, row: Mapping[str, object]
    ) -> Incidence | None:
        """Project one decision event into a P11 governance-stream incidence."""
        agent_external = _as_str(_first(row, _AGENT_EXTERNAL_ALIASES))
        pdp_agent = _as_str(_first(row, _PDP_AGENT_ALIASES))
        # An event must attribute to SOME agent handle to be a footprint; without
        # one the row carries no discoverable entity, so it is skipped (not an
        # error). Fall back to the pdp principal as the external handle.
        if agent_external is None:
            agent_external = pdp_agent
        if agent_external is None:
            return None

        keys: dict[str, str] = {FootprintField.PDP_AGENT_ID: agent_external}
        # ``agent_external_id`` is the IDENTITY-grade cross-plane join key (so the
        # same agent's ACTIONS_TRAIL / FS_WRITE footprints fuse to one entity).
        keys["agent_external_id"] = agent_external

        agent_id = _as_str(_first(row, _AGENT_ID_ALIASES))
        if agent_id is not None:
            keys["agent_id"] = agent_id  # also IDENTITY-grade in fuse.py
        if pdp_agent is not None and pdp_agent != agent_external:
            keys[FootprintField.PDP_AGENT_ID] = pdp_agent
            keys["agent_external_id"] = agent_external

        trace_id = _as_str(_first(row, _TRACE_ALIASES))
        if trace_id is not None:
            keys[FootprintField.OTEL_TRACE_ID] = trace_id
        tool_name = _as_str(_first(row, _TOOL_ALIASES))
        if tool_name is not None:
            keys[FootprintField.TOOL_NAME] = tool_name
        billing = _as_str(_first(row, _BILLING_ALIASES))
        if billing is not None:
            keys[FootprintField.BILLING_ACCOUNT] = billing

        decided_at = _coerce_decided_at(_first(row, _DECIDED_AT_ALIASES))

        attrs: dict[str, str] = {"decided_at": decided_at.isoformat()}
        verdict = _as_str(row.get("verdict"))
        if verdict is not None:
            attrs["verdict"] = verdict
        risk = _as_str(row.get("risk"))
        if risk is not None:
            attrs["risk"] = risk

        footprint = FootprintVector.of(
            plane_id=PlaneId.GOVERNANCE_STREAM, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.GOVERNANCE_STREAM,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.OBSERVED,
                raw_evidence_ref=trace_id or f"governance_stream:{idx}",
                observed_at=decided_at,
            )
        except ValueError:
            # A verifier-injected out-of-range catchability degrades to a dropped
            # row, never a raised exception.
            return None

    def _coverage_health_residuals(
        self, rows: Sequence[Mapping[str, object]]
    ) -> Iterator[Incidence]:
        """Emit P0 token-conservation residual incidences (N3).

        Per billing account, sum ``billing_tokens``, ``otel_span_tokens`` and
        ``network_implied_tokens``; a strictly-positive
        ``billing − otel − network`` residual is provably-billed inference that
        no span and no flow accounts for — a quantified shadow-VOLUME signal that
        a dark agent exists below the instrumented planes. Only positive
        residuals are emitted; a conserving (zero/negative) account is silent
        (absence of a shadow is not a finding). Accounts that supply no token
        volumes at all are skipped — no token data is not a zero residual.
        """
        # account -> [billing, otel, network] accumulators, and whether ANY
        # token field was present for that account (else we cannot reconcile).
        agg: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])
        seen_tokens: dict[str, bool] = defaultdict(bool)
        latest: dict[str, datetime] = {}

        for row in rows:
            billing = _as_str(_first(row, _BILLING_ALIASES)) or "__unattributed__"
            b = _as_float(_first(row, _BILLING_TOKENS_ALIASES))
            o = _as_float(_first(row, _OTEL_TOKENS_ALIASES))
            n = _as_float(_first(row, _NETWORK_TOKENS_ALIASES))
            if b is None and o is None and n is None:
                continue
            seen_tokens[billing] = True
            agg[billing][0] += b or 0.0
            agg[billing][1] += o or 0.0
            agg[billing][2] += n or 0.0
            when = _coerce_decided_at(_first(row, _DECIDED_AT_ALIASES))
            if billing not in latest or when > latest[billing]:
                latest[billing] = when

        for account, (billing_tok, otel_tok, net_tok) in agg.items():
            if not seen_tokens.get(account):
                continue
            residual = billing_tok - otel_tok - net_tok
            if residual <= 0.0:
                continue  # telemetry conserves → no shadow → no finding
            keys = {
                FootprintField.BILLING_ACCOUNT: account,
                "coverage_signal": "token_conservation_residual",
            }
            attrs = {
                "residual_tokens": str(residual),
                "billing_tokens": str(billing_tok),
                "otel_span_tokens": str(otel_tok),
                "network_implied_tokens": str(net_tok),
            }
            footprint = FootprintVector.of(
                plane_id=PlaneId.COVERAGE_HEALTH, keys=keys, attrs=attrs
            )
            try:
                yield Incidence(
                    plane_id=PlaneId.COVERAGE_HEALTH,
                    footprint=footprint,
                    catchability=self._catchability,
                    # The residual is reconciled from PLATFORM books (billing) vs
                    # platform telemetry (spans) — a platform-attested signal, not
                    # a directly-observed agent footprint.
                    admissibility=Admissibility.PLATFORM_ATTESTED,
                    raw_evidence_ref=f"token_conservation_residual:{account}",
                    observed_at=latest.get(account, datetime.now(UTC)),
                )
            except ValueError:
                continue


def build_governance_stream_sensor(env: Mapping[str, str]) -> GovernanceStreamSensor:
    """Registry factory for the P11/P0 governance-stream sensor (degrade-empty).

    The registry hands this the process ``env`` mapping. There is no source to
    construct from env alone — the governance event source is an in-process hook
    wired at runtime by the host (``register_sensor`` with a configured
    instance), so the env-built sensor is a faithful INERT sensor: it has no
    source and therefore senses nothing. This keeps the flag-gated activation
    path (``TEX_SIEVE_P11_OTEL``) default-safe — enabling the flag without
    wiring a real hook yields an empty plane, never a crash. ``emit_coverage_
    health`` follows ``TEX_SIEVE_P0_COVERAGE`` so the P0 residual stays opt-in.
    """
    emit_p0 = (env.get("TEX_SIEVE_P0_COVERAGE", "") or "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }
    return GovernanceStreamSensor(source=None, emit_coverage_health=emit_p0)


__all__ = [
    "GovernanceStreamSensor",
    "build_governance_stream_sensor",
    "GOVERNANCE_STREAM_CATCHABILITY",
    "EventSource",
]
