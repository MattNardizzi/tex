"""
EcosystemEngine — primary entrypoint for ecosystem governance.

Replaces per-action adjudication. Every existing six-layer-pipeline verdict
gets injected into the ecosystem graph as an event, and the ecosystem engine
emits the ecosystem-level verdict that subsumes it.

The eight-step pipeline:

  1. ontology check       — event conforms to type system?
  2. graph projection     — current ecosystem state
  3. contract check       — agent behavioral contracts violated?       (P1 stub)
  4. governance graph LTS — legal transition under active institutional graph? (P1 stub)
  5. causal attribution   — what prior events causally enable this?    (P1 stub)
  6. drift detection      — does this event spike any tracked drift signal? (P1 stub)
  7. systemic risk        — bounded-compromise score under this event  (P2 stub)
  8. intervention select  — if not PERMIT, what cost-bounded intervention? (P2 stub)

Architecture (Microsoft Agent Governance Toolkit, April 2026, three-plane model)
--------------------------------------------------------------------------------
* Enforcement plane: ``evaluate()``, sub-millisecond when the flag is off,
  single-digit-millisecond when on with empty P1/P2 stubs.
* Control plane: P1 collaborators (contracts/institutional/causal/drift) are
  injectable but not on the critical path today.
* Audit plane: ``attest_state()`` produces the SCITT-shaped Signed Statement
  insurers and NAIC examiners verify offline.

Per-agent overhead budget per AAF (arxiv 2512.18561) §6: < 5% of the control
loop. For a Python implementation this maps to:
  * disabled path:   < 100 µs
  * enabled, no P1:  < 10 ms p99

Priority
--------
P0 — wire skeleton in days 1-14 (using in-memory graph). P1 — full causal +
governance LTS + drift in days 31-90. P2 — full intervention + digital twin
in days 90+.

References
----------
- AAF (arxiv 2512.18561 v3, March 2026): eight-step runtime layer.
- Institutional AI (arxiv 2601.10599, 2601.11369, January 2026):
  governance-graph LTS framing for steps 4 and 8.
- IETF SCITT architecture draft -22 (April 2026): attestation envelope.
- RFC 9162 (Certificate Transparency v2): window Merkle root format.
- Microsoft Agent Governance Toolkit (open-sourced April 2026):
  three-plane (Enforcement / Control / Audit) deployment pattern.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

from tex.ecosystem._attestation import (
    build_attestation_payload,
    build_envelope,
    sign_envelope,
)
from tex.ecosystem._window import empty_root, merkle_root
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState
from tex.ecosystem.verdict import (
    EcosystemAxisScores,
    EcosystemVerdict,
    EcosystemVerdictKind,
)
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.event import genesis_ledger_hash
from tex.events.exceptions import LedgerAppendError
from tex.events.ledger import InMemoryLedger
from tex.graph.exceptions import GraphMutationError, UnknownActorError
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.observability.telemetry import emit_event
from tex.ontology.validator import OntologyValidator


# Environment flag the operator flips to enable ecosystem governance.
# Default off — existing six-layer pipeline runs untouched.
_ENV_FLAG_NAME: str = "TEX_ECOSYSTEM"


def _read_flag_from_env() -> bool:
    return os.environ.get(_ENV_FLAG_NAME, "0") == "1"


def _neutral_axis_scores(*, drift_delta: float = 0.0) -> EcosystemAxisScores:
    """
    Build the neutral axis scores returned by the P0 pipeline.

    Steps 3-7 are stubs in P0; the engine emits neutral axis scores so
    downstream consumers (dashboards, evidence chain readers) can already
    branch on the field shape. P1/P2 will populate real scores.

    The drift_delta defaults to 0.0 ("no measured drift") rather than nan
    or "unknown" because the field is typed ``float`` on
    ``EcosystemAxisScores``; a P1 drift package will replace this stub.
    """
    return EcosystemAxisScores(
        contract_violation_severity=0.0,
        governance_graph_legality=1.0,  # 1.0 = legal under active LTS
        causal_attribution_confidence=0.0,
        drift_delta=drift_delta,
        systemic_risk_under_event=0.0,
        bounded_compromise_score=0.0,
    )


# Single neutral instance reused on every PERMIT — frozen, so sharing is safe.
_NEUTRAL_AXIS_SCORES: EcosystemAxisScores = _neutral_axis_scores()


# Sentinel for the disabled-engine pre-state hash: callers can branch on this
# string ("ecosystem_disabled") instead of having to special-case None.
_DISABLED_STATE_HASH: str = "ecosystem_disabled"


class EcosystemEngine:
    """The top-level ecosystem-state evaluator."""

    def __init__(
        self,
        *,
        ontology: OntologyValidator | None = None,
        graph: InMemoryTemporalKG | None = None,
        projection: StateProjection | None = None,
        events: InMemoryLedger | None = None,
        provenance: CryptoProvenance | None = None,
        # P1/P2 collaborators — accepted for forward compatibility but not
        # invoked on the critical path in P0.
        contracts: object | None = None,
        institutional: object | None = None,
        causal: object | None = None,
        drift: object | None = None,
        systemic: object | None = None,
        intervention: object | None = None,
        enabled: bool | None = None,
    ) -> None:
        """
        Construct an ecosystem engine.

        Parameters
        ----------
        ontology, graph, projection, events, provenance
            P0 collaborators. Required when ``enabled`` resolves True.
            Wired through dependency injection so tests can swap any of
            them for fakes / spies.
        contracts, institutional, causal, drift, systemic, intervention
            P1/P2 collaborators reserved for future steps. Accepted now so
            call sites do not change when those packages land.
        enabled
            Tri-state. ``None`` means read ``TEX_ECOSYSTEM`` from env.
            ``True``/``False`` overrides the env (used by tests).
        """
        self._ontology = ontology
        self._graph = graph
        self._projection = projection
        self._events = events
        self._provenance = provenance
        self._contracts = contracts
        self._institutional = institutional
        self._causal = causal
        self._drift = drift
        self._systemic = systemic
        self._intervention = intervention

        self._enabled: bool = (
            _read_flag_from_env() if enabled is None else bool(enabled)
        )

        if self._enabled:
            self._assert_p0_collaborators_wired()

    # ------------------------------------------------------------------ public

    @property
    def enabled(self) -> bool:
        """Whether the engine will perform real evaluation or short-circuit."""
        return self._enabled

    def evaluate(self, proposed: ProposedEvent) -> EcosystemVerdict:
        """
        Evaluate a proposed event against the current ecosystem state.

        TODO(P0): Step 1 — ontology.validate_event(proposed)             [done]
        TODO(P0): Step 2 — graph.project_state_at(proposed.timestamp)    [done]
        TODO(P1): Step 3 — contracts.check_all_for(proposed.actor, proposed)
        TODO(P1): Step 4 — institutional.check_transition_legal(state, proposed)
        TODO(P1): Step 5 — causal.attribute_dependencies(proposed, state)
        TODO(P1): Step 6 — drift.score_delta(state, proposed)
        TODO(P2): Step 7 — systemic.bounded_compromise_under(state + proposed)
        TODO(P2): Step 8 — intervention.select_if_needed(verdict_so_far)
        TODO(P0): emit EcosystemVerdict with axis scores + recommended interv. [done]
        TODO(P0): on PERMIT, append the event to the ledger and update graph   [done]

        Reference: AAF (arxiv 2512.18561) §4.1 — pipeline ordering;
                   Institutional AI (arxiv 2601.10599) §3 — LTS framing
                   for steps 4 and 8.
        """
        proposed_event_id = self._derive_event_id(proposed)

        if not self._enabled:
            # Disabled: O(1) inert PERMIT, no mutation, no telemetry spam.
            # Single telemetry event for diagnosability.
            emit_event(
                "ecosystem.engine.evaluate.disabled",
                proposed_event_kind=proposed.event_kind,
                proposed_actor=proposed.actor_entity_id,
            )
            return EcosystemVerdict(
                kind=EcosystemVerdictKind.PERMIT,
                proposed_event_id=proposed_event_id,
                issued_at=_now_utc(),
                axis_scores=_NEUTRAL_AXIS_SCORES,
                ecosystem_state_hash_before=_DISABLED_STATE_HASH,
                ecosystem_state_hash_after=None,
                rationale="ecosystem governance disabled (TEX_ECOSYSTEM=0)",
                evidence_record_id=None,
                recommended_intervention_id=None,
            )

        # --- Step 1: ontology validation ---
        # The ontology validator enforces type-system invariants. Any failure
        # here is a hard FORBID — the event is malformed and must not enter
        # the graph or the ledger.
        assert self._ontology is not None  # guaranteed by __init__ check
        ok, errors = self._ontology.validate_event(proposed)
        if not ok:
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=(
                    "step 1 ontology violation: " + "; ".join(errors)
                ),
                state_hash_before=_DISABLED_STATE_HASH,
                reason="ontology",
            )

        # --- Step 2: graph projection (state at proposed.proposed_at) ---
        # We project the state *before* admitting the event so the verdict
        # carries the pre-event state hash; the post-event hash is set on
        # PERMIT below after the graph has been updated.
        assert self._projection is not None and self._graph is not None
        try:
            state_before: EcosystemState = self._projection.project_at(
                proposed.proposed_at
            )
        except Exception as exc:  # pragma: no cover - defensive
            # Projection is pure-read; failure here means the graph is in a
            # bad state (e.g., naive datetime). We FORBID rather than crash.
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=f"step 2 projection failure: {exc}",
                state_hash_before=_DISABLED_STATE_HASH,
                reason="projection",
            )

        # Frontier addition (not in the AAF abstract but required by SOTA
        # multi-agent governance per Institutional AI §3 and SAGA): the actor
        # must be a registered ecosystem entity. Ontology validation is
        # type-only; entity presence is graph-only.
        if not self._graph._has_entity(proposed.actor_entity_id):
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=(
                    f"step 2 unknown actor: entity "
                    f"{proposed.actor_entity_id!r} not registered in graph"
                ),
                state_hash_before=state_before.state_hash,
                reason="unknown_actor",
            )

        # --- Steps 3-7: P1/P2 stubs ---
        # All return neutral. Telemetry-only so dashboards can later spot
        # the gap. Per AAF §6 the per-agent budget here is < 5% of the
        # control loop, so we deliberately keep this branch trivial today.
        emit_event(
            "ecosystem.engine.steps_3_7.skipped",
            proposed_event_id=proposed_event_id,
            note="P1/P2 axes return neutral; full pipeline lands in later threads",
        )
        axis_scores = _NEUTRAL_AXIS_SCORES

        # --- Step 8: intervention selection ---
        # In P0 we never reach FORBID-via-axis (steps 3-7 are neutral), so
        # step 8 is a no-op. Reserved here for the call-site shape.

        # --- PERMIT path: append to ledger + graph; recompute state hash ---
        assert self._events is not None and self._provenance is not None
        try:
            event = self._events.append_proposed(
                proposed,
                provenance=self._provenance,
                event_id=proposed_event_id,
            )
        except LedgerAppendError as exc:
            return self._forbid(
                proposed_event_id=proposed_event_id,
                rationale=f"ledger append failed: {exc}",
                state_hash_before=state_before.state_hash,
                reason="ledger_append",
            )

        try:
            self._graph.add_event(
                event_id=event.event_id,
                kind=event.kind,
                actor=event.actor_entity_id,
                target=event.target_entity_id,
                payload=dict(event.payload),
                timestamp=event.timestamp,
                upstream=event.upstream_event_ids,
            )
        except (GraphMutationError, UnknownActorError) as exc:
            # Ledger append succeeded but graph rejected the edge — typically
            # a missing target entity. The ledger record is durable; we surface
            # this as ABSTAIN rather than FORBID because the audit trail
            # already captured the event. Operators repair the graph and
            # replay.
            emit_event(
                "ecosystem.engine.evaluate.graph_inconsistent",
                proposed_event_id=event.event_id,
                detail=str(exc),
            )
            return EcosystemVerdict(
                kind=EcosystemVerdictKind.ABSTAIN,
                proposed_event_id=event.event_id,
                issued_at=_now_utc(),
                axis_scores=axis_scores,
                ecosystem_state_hash_before=state_before.state_hash,
                ecosystem_state_hash_after=None,
                rationale=(
                    f"event recorded in ledger but graph rejected edge: {exc}"
                ),
                evidence_record_id=event.event_id,
                recommended_intervention_id=None,
            )

        state_hash_after = self._graph.state_hash(proposed.proposed_at)

        emit_event(
            "ecosystem.engine.evaluate.ok",
            proposed_event_id=event.event_id,
            event_kind=event.kind,
            sequence_number=event.sequence_number,
            state_hash_before=state_before.state_hash,
            state_hash_after=state_hash_after,
        )

        return EcosystemVerdict(
            kind=EcosystemVerdictKind.PERMIT,
            proposed_event_id=event.event_id,
            issued_at=_now_utc(),
            axis_scores=axis_scores,
            ecosystem_state_hash_before=state_before.state_hash,
            ecosystem_state_hash_after=state_hash_after,
            rationale=(
                f"step 1 ontology ok; step 2 projection ok; steps 3-7 neutral "
                f"(P1/P2); admitted at sequence {event.sequence_number}"
            ),
            evidence_record_id=event.event_id,
            recommended_intervention_id=None,
        )

    def attest_state(
        self,
        *,
        period_start_iso: str,
        period_end_iso: str,
    ) -> bytes:
        """
        Produce an ecosystem-state attestation: a single signed packet plus
        bounded-compromise certificate for the period.

        This is the artifact the insurer / NAIC / FTC verifier consumes.

        Wire format
        -----------
        SCITT-shaped Signed Statement: canonical-JSON envelope with CWT
        claims (iss/sub/iat/nbf/exp), payload type, and payload dict;
        followed by a signature trailer carrying a base64 signature plus
        ``key_id`` and ``algorithm`` lines so verifiers do not need a
        Tex-specific parser. See ``tex.ecosystem._attestation``.

        Payload contents
        ----------------
        * ``state_hash_at_end``    — graph state hash at ``period_end``
        * ``window_merkle_root``  — RFC 9162 §2.1 Merkle root over events
                                    in the window, sorted by
                                    (timestamp, event_id)
        * ``ledger_head_sequence``, ``ledger_head_record_hash`` — anchor
                                    the window into the global hash chain
        * event count + first/last sequence numbers in the window

        Reference
        ---------
        - IETF SCITT architecture draft -22 §6 (Signed Statement structure).
        - RFC 9162 §2.1 (Merkle Tree Hash).
        - AAF (arxiv 2512.18561) §4.2 (cryptographically verifiable
          interaction provenance).

        TODO(P1): aggregate ecosystem state hash for the period   [done — window_merkle_root]
        TODO(P2): include bounded-compromise certificate
        TODO(P0): sign with ML-DSA via tex.pqcrypto                [done — pluggable provider]
        TODO(P1): swap wire format to ``application/scitt-statement+cose``
                  once cbor2 is approved.
        TODO(P1): include a VDF-anchored ``time_anchor`` so ``nbf``/``exp``
                  are un-backdatable (eprint 2026/737).
        """
        if not self._enabled:
            raise RuntimeError(
                "EcosystemEngine.attest_state requires the engine to be "
                "enabled (TEX_ECOSYSTEM=1 or enabled=True at construction)"
            )

        period_start = _parse_iso_aware(period_start_iso, "period_start_iso")
        period_end = _parse_iso_aware(period_end_iso, "period_end_iso")
        if period_end < period_start:
            raise ValueError(
                "period_end_iso must be >= period_start_iso "
                f"(got start={period_start.isoformat()}, "
                f"end={period_end.isoformat()})"
            )

        assert self._graph is not None and self._events is not None
        assert self._provenance is not None

        # State hash at the end of the period (entity/event content snapshot).
        state_hash_at_end = self._graph.state_hash(period_end)

        # Walk the ledger for events that fall inside the window. The ledger
        # is small (< 1M records per AAF §6 storage analysis), so a linear
        # scan is fine for P0; a P1 backend with a time-indexed projection
        # would replace this.
        all_events = self._events.stream_after(0)
        events_in_window = [
            ev for ev in all_events
            if period_start <= ev.timestamp <= period_end
        ]
        # Canonical ordering for the Merkle tree: (timestamp, event_id).
        # Same total order ``_canonical_state_at`` uses for events.
        events_in_window.sort(key=lambda e: (e.timestamp, e.event_id))

        if events_in_window:
            window_merkle_root = merkle_root(
                [e.record_hash for e in events_in_window]
            )
            first_seq: int | None = events_in_window[0].sequence_number
            last_seq: int | None = events_in_window[-1].sequence_number
        else:
            window_merkle_root = empty_root()
            first_seq = None
            last_seq = None

        # Ledger head at end of period: latest event with timestamp <=
        # period_end. If none, anchor to genesis sentinel + sequence 0.
        head_event = None
        for ev in all_events:
            if ev.timestamp <= period_end:
                if head_event is None or ev.sequence_number > head_event.sequence_number:
                    head_event = ev
        if head_event is None:
            ledger_head_sequence = 0
            ledger_head_record_hash = genesis_ledger_hash()
        else:
            ledger_head_sequence = head_event.sequence_number
            ledger_head_record_hash = head_event.record_hash

        payload = build_attestation_payload(
            state_hash_at_end=state_hash_at_end,
            window_merkle_root=window_merkle_root,
            ledger_head_sequence=ledger_head_sequence,
            ledger_head_record_hash=ledger_head_record_hash,
            event_count_in_window=len(events_in_window),
            first_sequence_in_window=first_seq,
            last_sequence_in_window=last_seq,
        )
        envelope = build_envelope(
            issued_at=_now_utc(),
            period_start=period_start,
            period_end=period_end,
            payload=payload,
        )

        # Sign through the same provenance/provider abstraction the ledger
        # uses so an operator flipping ECDSA -> ML-DSA-65 does not need to
        # touch this code path.
        packet = sign_envelope(
            envelope=envelope,
            signing_key=self._provenance._key,  # noqa: SLF001 — internal field
            provider=self._provenance.provider,
        )

        emit_event(
            "ecosystem.engine.attest.ok",
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            event_count_in_window=len(events_in_window),
            window_merkle_root=window_merkle_root,
            state_hash_at_end=state_hash_at_end,
        )
        return packet

    # ----------------------------------------------------------------- helpers

    def _assert_p0_collaborators_wired(self) -> None:
        """Fail fast if a required P0 collaborator was not injected."""
        missing: list[str] = []
        if self._ontology is None:
            missing.append("ontology")
        if self._graph is None:
            missing.append("graph")
        if self._projection is None:
            missing.append("projection")
        if self._events is None:
            missing.append("events")
        if self._provenance is None:
            missing.append("provenance")
        if missing:
            raise ValueError(
                "EcosystemEngine enabled but missing P0 collaborators: "
                + ", ".join(missing)
            )

    @staticmethod
    def _derive_event_id(proposed: ProposedEvent) -> str:
        """
        Derive a stable event_id for the proposed event.

        The ledger generates random ids by default; for ecosystem-engine
        round-trips we want the verdict's ``proposed_event_id`` to match
        the resulting ledger ``event_id`` so consumers can join across
        traces. Format mirrors ``CryptoProvenance``'s default:
        ``evt_<uuid4-hex12>``.
        """
        return f"evt_{uuid4().hex[:12]}"

    def _forbid(
        self,
        *,
        proposed_event_id: str,
        rationale: str,
        state_hash_before: str,
        reason: str,
    ) -> EcosystemVerdict:
        """Build a FORBID verdict and emit telemetry."""
        emit_event(
            "ecosystem.engine.evaluate.forbidden",
            proposed_event_id=proposed_event_id,
            reason=reason,
            rationale=rationale,
        )
        return EcosystemVerdict(
            kind=EcosystemVerdictKind.FORBID,
            proposed_event_id=proposed_event_id,
            issued_at=_now_utc(),
            axis_scores=_NEUTRAL_AXIS_SCORES,
            ecosystem_state_hash_before=state_hash_before,
            ecosystem_state_hash_after=None,
            rationale=rationale,
            evidence_record_id=None,
            recommended_intervention_id=None,
        )


# --------------------------------------------------------------- module helpers


def _now_utc() -> datetime:
    """Wall-clock UTC datetime; centralized for test monkey-patching."""
    return datetime.now(UTC)


def _parse_iso_aware(value: str, field_name: str) -> datetime:
    """
    Parse an ISO-8601 string and require timezone-awareness.

    The graph and ledger reject naive datetimes (Thread 2/3 invariant); we
    propagate the same rule to attestation period bounds.
    """
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid ISO-8601 datetime: {exc}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware (RFC 3339)")
    return parsed.astimezone(UTC)
