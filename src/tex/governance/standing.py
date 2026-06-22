"""
Standing governance — the live PDP that switches on the instant ignition
seals the inventory.

================================================================== DOCTRINE

Discovery answers "what is in the estate." Standing governance answers the
harder thing the operator actually means by "watch them": *rule on every
action, at all times, and let nothing through that shouldn't — including the
agent that appeared four seconds ago.*

The architecture is the PEP/PDP split the 2026 frontier converged on:

  * The PEP (policy ENFORCEMENT point) is the thing physically in the path
    that blocks. It is commodity and deployment-bound: an eBPF/Tetragon
    kernel hook that transparently redirects the connect() syscall, a
    protocol-aware MCP/mesh gateway, or the in-process TexGate. It is NOT
    authored here — it is configured at deploy. Every PEP does exactly one
    thing: it asks Tex, synchronously, "may this action cross?" and obeys.

  * The PDP (policy DECISION point) is the brain that answers. That is THIS
    module. It is the part nobody has built right, because everyone else
    ships an empirical proxy (regex prompt-injection, RBAC tool filters,
    LLM-as-judge) and Tex ships a *witness with a correctness floor*.

Why the decision is microseconds, not a model call: discovery already did
the slow work. Each agent's declared capability surface (its sealed blast
radius — which action types, channels, environments, recipients it may
touch) is pre-computed and held in memory on the registry. So the inline
decision is a cache-hot structural check, not a round trip and not an LLM
call. The deep six-layer evaluation runs only for actions that clear the
structural floor, and anything genuinely ambiguous becomes an ABSTAIN that
the engine refuses to settle alone — surfaced to the one voice, never
auto-released.

Two tiers:

  1. STRUCTURAL FLOOR (inline, microseconds, fail-closed).
        - Unknown / unsealed / not-running agent  -> FORBID.
          This is the answer to "even the second new ones are added": an
          agent Tex has not sealed an identity for has no PERMIT on file, so
          its first action is forbidden by default. The absence of a proof
          *is* a forbid. New agents are governed the instant they act; the
          standing scan then seals them, and only then can they be permitted.
        - Action outside the agent's sealed capability surface -> FORBID.
          (capability confinement — the CaMeL line, enforced structurally.)

  2. DEEP ADJUDICATION (for actions that clear the floor).
        Delegates to the full EvaluateActionCommand — the real six-layer
        PDP that fuses identity, behaviour, capability, and content, seals
        the decision into the hash-chained evidence ledger, and returns a
        Verdict.
          PERMIT  -> released.
          FORBID  -> blocked, sealed.
          ABSTAIN -> a HeldDecision is pushed into the held-decision sink
                     (the governor asking permission, the one unprompted
                     voice) AND the action is blocked. Fail-closed: an
                     unresolved hold never releases on its own.

Fail-closed is absolute. If resolution is impossible — no agent, no surface,
the deep PDP raised — the verdict is FORBID, never PERMIT. The lower bound
holds even when Tex itself is degraded.

Governed vs. observed: activation records, per tenant, how many agents Tex
can actually rule on (sealed, in the registry) versus merely sees. That gap
is the truth the voice is honest about. Standing governance does not pretend
to govern an estate it has only mapped; it names the edge of control the
same way provenance names the edge of sight.

This module is intentionally additive and defensive. It composes existing,
already-built primitives (the agent registry, the EvaluateActionCommand, the
held sink, the provenance engine) into the live path. It changes none of
them. If a dependency is missing, every method degrades to the safe answer:
FORBID.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable
from uuid import UUID, uuid4

from tex.domain.verdict import Verdict
from tex.selfgov.governor import describe_standing_activate, gate_controller_mutation

__all__ = [
    "DecisionOutcome",
    "GovernedPosture",
    "StandingGovernance",
]


# Agents that are not eligible to act under the standing watch. A SLEEPING or
# REVOKED agent that attempts an action is forbidden on its face; a
# QUARANTINED one likewise. PENDING and ACTIVE are "running" — PENDING is a
# freshly-discovered agent awaiting governance, which is exactly the case the
# fail-closed floor must cover.
_NON_ACTING_STATUSES = {"SLEEPING", "REVOKED", "QUARANTINED"}

# Action types whose CONTENT Tex could not read. The PEP labels them so the
# honest verdict can be ASK rather than a content-blind PERMIT:
#   * ``http_opaque_body`` — a request whose body uses a Content-Encoding Tex
#     cannot decode (br/zstd/unknown, a malformed stream, or a decompression
#     bomb). LIVE on the plaintext proxy path (pep/proxy._to_decision): every
#     real request is checked, so a forbidden payload cannot ride out gzipped.
#   * ``https_opaque`` — TLS egress the PEP could not MITM-terminate. The PDP
#     rule is live, but its only PRODUCER (rule_opaque -> TlsFront) is still
#     test-only / off the live deploy path (pep/tls_front.py), so it does not
#     yet fire on real TLS traffic until the TLS front is deployed.
# Such an action cannot be adjudicated on content, so it resolves to ABSTAIN (a
# held decision), never a content-blind PERMIT and, by doctrine, not a blanket
# FORBID. See ``decide``.
_UNINSPECTABLE_ACTION_TYPES = frozenset({"https_opaque", "http_opaque_body"})


@dataclass(frozen=True, slots=True)
class DecisionOutcome:
    """The result of a single standing-governance ruling.

    ``verdict`` is the control decision. ``released`` is the single boolean a
    PEP obeys: True iff the action may cross into the real world. Everything
    else is provenance for the voice and the ledger.
    """

    verdict: Verdict
    released: bool
    reason: str
    tier: str  # "floor" | "deep"
    agent_id: UUID | None = None
    decision_id: UUID | None = None
    evidence_hash: str | None = None
    held: bool = False
    # The raw deep EvaluationResponse when Tier 2 ran, so a transport can
    # hand the gate the authoritative response instead of a synthesis. None
    # for floor verdicts (there is no deep response to carry). Never
    # serialized — it is in-process plumbing for the gate path only.
    response: Any | None = None
    # Why this outcome FORBID, coarsely, so the live forbid-set feed can tell a
    # destination-attributable deny (worth warming the kernel hot set) from an
    # agent-scoped one (the destination is incidental). One of:
    #   "identity"  — no sealed identity for the agent (agent-scoped; do NOT feed)
    #   "lifecycle" — agent not in a governable state (agent-scoped; do NOT feed)
    #   "surface"   — action/recipient outside the agent's sealed surface (feed)
    #   "deep"      — denied by full adjudication (feed)
    #   "deep_error"— deep PDP unavailable/raised, failed closed (do NOT feed)
    # None for non-FORBID outcomes. Never serialized — in-process plumbing only.
    forbid_scope: str | None = None
    # The agent's permitted tool subset, resolved server-side from the SAME
    # sealed capability surface this ruling confined against. Carried so a remote
    # PEP (HttpDecisionClient) can drive its emission gate off the decision it
    # already made — no extra round-trip, race-free (the surface that ruled is the
    # surface that tightens the egressed bytes). ``None`` => surface unrestricted
    # or unresolved (the gate then leaves the body unchanged). Only populated on a
    # released (PERMIT) outcome.
    allowed_tools: tuple[str, ...] | None = None
    # A stable digest of the resolved surface's tool allowlist (the emission
    # constraint's ``H``), RECORDED for audit/observability so a relying party
    # can see WHICH surface the PDP ruled under. HONEST SCOPE: the PEP does NOT
    # currently verify this against the piggybacked surface — the emission gate
    # tightens off ``allowed_tools``, not this digest — so today it is an audit
    # field, not a binding. None when there is no tool restriction to commit.
    surface_seal_hash: str | None = None

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "verdict": str(self.verdict),
            "released": self.released,
            "reason": self.reason,
            "tier": self.tier,
            "agent_id": str(self.agent_id) if self.agent_id else None,
            "decision_id": str(self.decision_id) if self.decision_id else None,
            "evidence_hash": self.evidence_hash,
            "held": self.held,
            # Piggyback the permitted tool subset + its digest so a remote PEP can
            # drive the emission gate off this same decision (None when there is
            # no tool restriction to apply).
            "allowed_tools": (
                list(self.allowed_tools) if self.allowed_tools is not None else None
            ),
            "surface_seal_hash": self.surface_seal_hash,
        }


@dataclass(frozen=True, slots=True)
class GovernedPosture:
    """The governed-vs-observed boundary for one tenant.

    ``governed`` is the count of agents Tex can actually rule on (sealed and
    running in the registry). ``observed`` is everything the planes have seen.
    The gap is the edge of control. ``spoken`` is the line the voice uses; it
    never shows a dashboard, it states the truth.
    """

    tenant: str
    governed: int
    observed: int
    active_since: datetime | None

    @property
    def ungoverned(self) -> int:
        return max(0, self.observed - self.governed)

    @property
    def spoken(self) -> str:
        if self.observed == 0:
            return "Nothing to govern yet."
        if self.ungoverned == 0:
            noun = "agent" if self.governed == 1 else "agents"
            return f"I'm ruling on all {self.governed} {noun}."
        g_noun = "agent" if self.governed == 1 else "agents"
        u_noun = "one" if self.ungoverned == 1 else str(self.ungoverned)
        watch = "it doesn't" if self.ungoverned == 1 else "they don't"
        return (
            f"I'm ruling on {self.governed} {g_noun}. "
            f"{u_noun.capitalize()} I can still only watch — {watch} route "
            "through me yet."
        )

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "governed": self.governed,
            "observed": self.observed,
            "ungoverned": self.ungoverned,
            "active_since": self.active_since.isoformat() if self.active_since else None,
            "spoken": self.spoken,
            "object": None,
        }


class StandingGovernance:
    """The live PDP, switched on per tenant the moment ignition seals the
    inventory.

    Construct once at runtime composition; activate per tenant on ignition.
    ``decide`` is what every PEP calls. It always reads the *live* registry,
    so correctness never depends on a refresh tick — a brand-new agent that
    the standing scan has not yet sealed simply isn't in the registry, and the
    fail-closed floor forbids it until it is.
    """

    def __init__(
        self,
        *,
        agent_registry: Any,
        evaluate_command: Any | None = None,
        held_sink: Any | None = None,
        provenance_engine: Any | None = None,
        forbid_sink: Callable[..., Any] | None = None,
        default_channel: str = "api",
        default_environment: str = "production",
    ) -> None:
        self._registry = agent_registry
        self._evaluate = evaluate_command
        self._held = held_sink
        self._provenance = provenance_engine
        # Optional live-decision sink (forbid_source.feed_from_decision). When
        # set (TEX_FORBID_AUTOFEED on), a destination-attributable FORBID warms
        # the kernel hot set. None => the feed is inert (default; behaviour is
        # byte-for-byte unchanged). Feeding NEVER affects the ruling returned.
        self._forbid_sink = forbid_sink
        self._default_channel = default_channel
        self._default_environment = default_environment
        self._lock = threading.RLock()
        # tenant (casefolded) -> activated_at
        self._active: dict[str, datetime] = {}

    # ------------------------------------------------------------------ lifecycle

    def activate(self, tenant: str) -> GovernedPosture:
        """Switch on standing governance for a tenant.

        Called the instant ignition completes discovery and the inventory is
        running. Idempotent: re-activating refreshes the posture. Warming the
        capability surfaces is a side effect of reading the registry; the
        decision path does not depend on it having happened.
        """
        tid = (tenant or "").strip().casefold()
        if not tid:
            return GovernedPosture(tenant="", governed=0, observed=0, active_since=None)
        # Reflexive gate: deny by NOT mutating (the only caller swallows
        # exceptions — api/discovery_surface_routes.py — so a raise-based deny
        # would be invisible AND fragile). Denial returns the live posture.
        if not gate_controller_mutation(lambda: describe_standing_activate(tid)).allowed:
            return self.posture(tid)
        with self._lock:
            if tid not in self._active:
                self._active[tid] = datetime.now(UTC)
        return self.posture(tid)

    def is_active(self, tenant: str) -> bool:
        tid = (tenant or "").strip().casefold()
        with self._lock:
            return tid in self._active

    def posture(self, tenant: str) -> GovernedPosture:
        """The governed-vs-observed boundary for a tenant. Read live."""
        tid = (tenant or "").strip().casefold()
        with self._lock:
            since = self._active.get(tid)
        observed = governed = 0
        for agent in self._list_tenant_agents(tid):
            observed += 1
            if self._is_governable(agent):
                governed += 1
        return GovernedPosture(
            tenant=tid, governed=governed, observed=observed, active_since=since
        )

    # ------------------------------------------------------------------ decision

    # FORBID scopes whose denial is attributable to the destination/recipient
    # (not the agent), so warming the kernel hot set with that destination is
    # sound. Agent-scoped denials ("identity"/"lifecycle") and fail-closed
    # errors ("deep_error") are excluded: the destination is incidental there.
    _DESTINATION_FORBID_SCOPES: frozenset[str] = frozenset({"surface", "deep"})

    def decide(
        self,
        *,
        tenant: str,
        action_type: str,
        content: str,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        agent_id: UUID | str | None = None,
        agent_external_id: str | None = None,
        session_id: str | None = None,
    ) -> DecisionOutcome:
        """Rule on one action. The single call every PEP makes.

        Thin wrapper over :meth:`_decide_core` that, after the ruling, feeds a
        *destination-attributable* FORBID to the live forbid-set sink when one
        is wired (``TEX_FORBID_AUTOFEED``). The feed is best-effort and can
        never change or break the outcome the PEP obeys — the action proceeds on
        ``released`` regardless. ``decide_for_request`` routes through here too,
        so the in-process gate feeds the same set (exactly once per ruling).
        """
        outcome = self._decide_core(
            tenant=tenant,
            action_type=action_type,
            content=content,
            channel=channel,
            environment=environment,
            recipient=recipient,
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            session_id=session_id,
        )
        self._maybe_feed_forbid_set(
            outcome, action_type=action_type, recipient=recipient, tenant=tenant
        )
        return outcome

    def _maybe_feed_forbid_set(
        self,
        outcome: DecisionOutcome,
        *,
        action_type: str,
        recipient: str | None,
        tenant: str,
    ) -> None:
        """Warm the kernel hot set from a live, destination-attributable FORBID.

        No-op unless a sink is wired AND the outcome is a FORBID whose scope is
        destination-attributable (not agent-scoped/error). The sink itself
        further requires a network-egress action and a host recipient, and
        scopes + TTLs the entry per tenant. Wrapped so a sink failure never
        touches the ruling."""
        if self._forbid_sink is None or outcome.verdict is not Verdict.FORBID:
            return
        if outcome.forbid_scope not in self._DESTINATION_FORBID_SCOPES:
            return
        try:
            self._forbid_sink(
                action_type=action_type,
                recipient=recipient,
                tenant=tenant,
                decision_id=(
                    str(outcome.decision_id) if outcome.decision_id else None
                ),
                reason=outcome.reason,
            )
        except Exception:  # noqa: BLE001 — feeding must never break the decision
            pass

    def _decide_core(
        self,
        *,
        tenant: str,
        action_type: str,
        content: str,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        agent_id: UUID | str | None = None,
        agent_external_id: str | None = None,
        session_id: str | None = None,
    ) -> DecisionOutcome:
        """Rule on one action. The single call every PEP makes.

        Fail-closed throughout: any path that cannot resolve a confident
        PERMIT returns FORBID. PERMIT is only ever returned by the deep PDP
        for an agent that is sealed, running, and acting within its surface.
        """
        tid = (tenant or "").strip().casefold()
        channel = channel or self._default_channel
        environment = environment or self._default_environment

        # ---- Tier 1: structural floor (inline, microseconds, fail-closed) ----

        agent = self._resolve_agent(tid, agent_id, agent_external_id)
        if agent is None:
            # Unknown / unsealed agent. The absence of a proof is a forbid.
            return self._forbid_floor(
                None,
                "No sealed identity for this agent. Forbidding until discovery "
                "seals it.",
                scope="identity",
            )

        if not self._is_governable(agent):
            return self._forbid_floor(
                self._agent_uuid(agent),
                "Agent is not in a running, governable state.",
                scope="lifecycle",
            )

        surface = getattr(agent, "capability_surface", None)
        if surface is not None and not self._within_surface(
            surface, action_type, channel, environment, recipient
        ):
            return self._forbid_floor(
                self._agent_uuid(agent),
                "Action falls outside the agent's sealed capability surface.",
                scope="surface",
            )

        # ---- G9: un-inspectable content -> ABSTAIN (ASK), never a silent PERMIT.
        # The PEP labels content it could not read: a compressed/undecodable
        # request body ``http_opaque_body`` (live on the plaintext path) or TLS
        # egress it could not MITM-terminate ``https_opaque`` (PDP rule live;
        # producer TlsFront still deploy-gated). Its
        # content cannot be adjudicated, so Tex refuses to settle alone (rule 2:
        # uncertainty -> ABSTAIN) and surfaces a hold. This sits AFTER the
        # structural FORBID floor — an unknown / ungovernable / out-of-surface
        # agent is still FORBIDden, the more-cautious deterministic deny winning
        # — and BEFORE deep adjudication, so an opaque action that clears the
        # floor can never reach a content-blind PERMIT. It is the action CLASS
        # that is uninspectable, not a probabilistic score, so it never fires a
        # structural FORBID and only ever holds an otherwise-PERMIT-eligible
        # action (monotone: PERMIT -> ABSTAIN, never FORBID -> ABSTAIN).
        if action_type in _UNINSPECTABLE_ACTION_TYPES:
            return self._abstain_uninspectable(
                self._agent_uuid(agent),
                tenant=tid,
                action_type=action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
            )

        # ---- Tier 2: deep adjudication (full six-layer PDP, sealed) ----

        if self._evaluate is None:
            # No deep PDP wired: the floor is all we have. Structurally
            # in-bounds is necessary but not sufficient, so fail closed
            # rather than release on a partial check.
            return self._forbid_floor(
                self._agent_uuid(agent),
                "Deep adjudication unavailable; refusing to release on the "
                "structural floor alone.",
                scope="deep_error",
            )

        outcome = self._adjudicate_deep(
            agent=agent,
            tenant=tid,
            action_type=action_type,
            content=content,
            channel=channel,
            environment=environment,
            recipient=recipient,
            session_id=session_id,
        )
        # Piggyback the agent's permitted tool subset on a RELEASED outcome so a
        # remote PEP can drive its emission gate off this same decision (race-free:
        # the surface that confined this ruling is the surface that tightens the
        # egressed bytes). Off-path for FORBID/ABSTAIN — nothing egresses.
        if outcome.released:
            return self._attach_surface_piggyback(outcome, surface)
        return outcome

    @staticmethod
    def _attach_surface_piggyback(
        outcome: DecisionOutcome, surface: Any | None
    ) -> DecisionOutcome:
        """Stamp a released outcome with the surface's permitted tool subset.

        Reuses ``tex.emission.compile_constraint`` (the SAME compile the in-process
        emission gate runs) so the digest matches what the gate would seal. Returns
        the outcome unchanged when there is no tool restriction to commit (an
        unrestricted surface, or none) — the gate then leaves the body unchanged.
        Fail-soft: a compile error must never break the ruling, so it degrades to
        no piggyback (the remote gate falls back to no-op, exactly as today)."""
        if surface is None:
            return outcome
        allowed = getattr(surface, "allowed_tools", None)
        if not allowed:
            return outcome  # unrestricted on tools — nothing to tighten
        try:
            from dataclasses import replace

            from tex.emission import compile_constraint

            constraint = compile_constraint(surface)
            return replace(
                outcome,
                allowed_tools=tuple(allowed),
                surface_seal_hash=constraint.digest(),
            )
        except Exception:  # noqa: BLE001 — piggyback is best-effort; ruling stands
            return outcome

    def decide_for_request(
        self, request: Any, tenant: str | None = None
    ) -> DecisionOutcome:
        """Run the two-tier PDP from an EvaluationRequest the gate built.

        This is the in-process PEP bridge: the existing TexGate (and its
        framework adapters) construct an EvaluationRequest; routing it here
        instead of straight to the deep command means the fail-closed floor,
        capability confinement, identity resolution, and ABSTAIN-to-voice all
        apply. Tenant is taken from the request's runtime identity when not
        passed explicitly.
        """
        identity = getattr(request, "agent_identity", None)
        resolved_tenant = (
            tenant
            or (getattr(identity, "tenant_id", None) if identity else None)
            or "default"
        )
        return self.decide(
            tenant=resolved_tenant,
            action_type=getattr(request, "action_type", "") or "",
            content=getattr(request, "content", "") or "",
            channel=getattr(request, "channel", None),
            environment=getattr(request, "environment", None),
            recipient=getattr(request, "recipient", None),
            agent_id=getattr(request, "agent_id", None),
            agent_external_id=(
                getattr(identity, "external_agent_id", None) if identity else None
            ),
            session_id=getattr(request, "session_id", None),
        )

    # ------------------------------------------------------------------ tiers

    def _adjudicate_deep(
        self,
        *,
        agent: Any,
        tenant: str,
        action_type: str,
        content: str,
        channel: str,
        environment: str,
        recipient: str | None,
        session_id: str | None,
    ) -> DecisionOutcome:
        from tex.domain.evaluation import EvaluationRequest

        agent_uuid = self._agent_uuid(agent)
        try:
            request = EvaluationRequest(
                request_id=uuid4(),
                action_type=action_type,
                content=content,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_uuid,
                session_id=session_id,
            )
            result = self._evaluate.execute(request)
        except Exception:  # noqa: BLE001 — fail closed on any engine error
            return self._forbid_floor(
                agent_uuid,
                "Deep adjudication raised; failing closed.",
                tier="deep",
                scope="deep_error",
            )

        response = getattr(result, "response", None) or result
        verdict = getattr(response, "verdict", None)
        decision_id = getattr(response, "decision_id", None)
        evidence_hash = getattr(response, "evidence_hash", None)

        if verdict is Verdict.PERMIT:
            return DecisionOutcome(
                verdict=Verdict.PERMIT,
                released=True,
                reason="Released by full adjudication.",
                tier="deep",
                agent_id=agent_uuid,
                decision_id=decision_id,
                evidence_hash=evidence_hash,
                response=response,
            )

        if verdict is Verdict.ABSTAIN:
            # The engine refused to settle alone. Surface it to the one voice
            # and block. An unresolved hold never releases on its own.
            #
            # Carry the Layer-4 Hold (engine/hold.py) the PDP produced: the
            # two-sided certified band, the epistemic/aleatoric type, and the
            # single pivotal fact that would resolve it. It rides on the held
            # decision so the vigil speaks the type and the question — never
            # the case file. Falls back to the flat note when (older runtime)
            # no hold is present.
            hold = self._extract_hold(response)
            note = (
                hold.get("sentence")
                if isinstance(hold, dict) and hold.get("sentence")
                else (
                    f"I need to know if I can let this through "
                    f"({action_type}). It's yours to decide."
                )
            )
            self._raise_hold(
                agent_id=agent_uuid,
                kind=str(action_type),
                confidence=float(getattr(response, "confidence", 0.0) or 0.0),
                note=note,
                detail={
                    "channel": channel,
                    "environment": environment,
                    "recipient": recipient,
                    "tenant_id": tenant,
                    "dimension": "execution",
                    "decision_id": str(decision_id) if decision_id else None,
                    "evidence_hash": evidence_hash,
                },
                hold=hold,
                decision_id=(str(decision_id) if decision_id else None),
                anchor_sha256=evidence_hash,
            )
            return DecisionOutcome(
                verdict=Verdict.ABSTAIN,
                released=False,
                reason="Held for a human; not released.",
                tier="deep",
                agent_id=agent_uuid,
                decision_id=decision_id,
                evidence_hash=evidence_hash,
                held=True,
                response=response,
            )

        # FORBID, or anything non-PERMIT/non-ABSTAIN -> fail closed.
        return DecisionOutcome(
            verdict=Verdict.FORBID,
            released=False,
            reason="Forbidden by full adjudication.",
            tier="deep",
            agent_id=agent_uuid,
            decision_id=decision_id,
            evidence_hash=evidence_hash,
            response=response,
            forbid_scope="deep",
        )

    def _forbid_floor(
        self,
        agent_id: UUID | None,
        reason: str,
        *,
        tier: str = "floor",
        scope: str = "floor",
    ) -> DecisionOutcome:
        return DecisionOutcome(
            verdict=Verdict.FORBID,
            released=False,
            reason=reason,
            tier=tier,
            agent_id=agent_id,
            forbid_scope=scope,
        )

    def _abstain_uninspectable(
        self,
        agent_id: UUID | None,
        *,
        tenant: str,
        action_type: str,
        channel: str,
        environment: str,
        recipient: str | None,
    ) -> DecisionOutcome:
        """ABSTAIN on un-inspectable egress: surface a hold and block (G9).

        The companion to :meth:`_forbid_floor` for the cases where Tex cannot
        read the content — TLS egress it could not terminate (``https_opaque``)
        or a request body in an encoding it cannot decode (``http_opaque_body``).
        The content is unreadable, so the verdict is ASK, not a guess: push a
        ``HeldDecision`` to the one voice and return ``released=False`` so an
        unresolved hold never lets the action through (fail-closed). ABSTAIN is
        the only verdict that raises a user-facing hold (CLAUDE.md rule 2); a
        FORBID here would be a silent blanket block, which is exactly what the
        doctrine says un-inspectability must NOT collapse to.
        """
        body_case = action_type == "http_opaque_body"
        if body_case:
            note = (
                f"An agent is sending a request to "
                f"{recipient or 'an unknown destination'} whose body is in a "
                "format I can't decode. I can't see what's inside, so I can't "
                "clear it on my own — it's yours to decide."
            )
            reason_code = "uninspectable_request_body"
        else:
            note = (
                f"An agent is sending traffic to "
                f"{recipient or 'an unknown destination'} over a channel I can't "
                "read. I can't see what's inside, so I can't clear it on my own — "
                "it's yours to decide."
            )
            reason_code = "uninspectable_tls_content"
        self._raise_hold(
            agent_id=agent_id,
            kind=str(action_type),
            confidence=0.0,
            note=note,
            detail={
                "channel": channel,
                "environment": environment,
                "recipient": recipient,
                "tenant_id": tenant,
                "dimension": "execution",
                "reason": reason_code,
            },
        )
        return DecisionOutcome(
            verdict=Verdict.ABSTAIN,
            released=False,
            reason="Un-inspectable content; held for a human (not released).",
            tier="floor",
            agent_id=agent_id,
            held=True,
        )

    # ------------------------------------------------------------------ helpers

    def _raise_hold(
        self,
        *,
        agent_id: UUID | None,
        kind: str,
        confidence: float,
        note: str,
        detail: dict[str, Any],
        hold: dict[str, Any] | None = None,
        decision_id: str | None = None,
        anchor_sha256: str | None = None,
    ) -> None:
        if self._held is None or agent_id is None:
            return
        try:
            from tex.provenance.feed import HeldDecision

            self._held.append(
                HeldDecision(
                    agent_id=agent_id,
                    kind=kind,
                    confidence=confidence,
                    note=note,
                    detail=detail,
                    hold=hold,
                    decision_id=decision_id,
                    anchor_sha256=anchor_sha256,
                )
            )
        except Exception:  # noqa: BLE001 — surfacing a hold must never break the ruling
            pass

    @staticmethod
    def _extract_hold(response: Any) -> dict[str, Any] | None:
        """Pull the Layer-4 Hold dict out of a PDP response/decision.

        The PDP stamps it at ``metadata['pdp']['hold']`` on every ABSTAIN
        (engine/pdp.py). Tolerant of either a response carrying ``metadata``
        or a wrapper exposing ``decision.metadata``; returns None if absent so
        an older engine degrades to the flat note.
        """
        meta = getattr(response, "metadata", None)
        if meta is None:
            decision = getattr(response, "decision", None)
            meta = getattr(decision, "metadata", None)
        if not isinstance(meta, dict):
            return None
        pdp = meta.get("pdp")
        if isinstance(pdp, dict):
            hold = pdp.get("hold")
            if isinstance(hold, dict):
                return hold
        hold = meta.get("hold")
        return hold if isinstance(hold, dict) else None

    def _resolve_agent(
        self,
        tenant: str,
        agent_id: UUID | str | None,
        agent_external_id: str | None,
    ) -> Any | None:
        # By stable UUID first.
        if agent_id is not None:
            uid = agent_id if isinstance(agent_id, UUID) else _as_uuid(agent_id)
            if uid is not None:
                try:
                    agent = self._registry.get(uid)
                except Exception:  # noqa: BLE001
                    agent = None
                if agent is not None and self._agent_tenant(agent) == tenant:
                    return agent
        # Otherwise by external id / name within the tenant.
        if agent_external_id:
            for agent in self._list_tenant_agents(tenant):
                if (
                    getattr(agent, "external_agent_id", None) == agent_external_id
                    or getattr(agent, "name", None) == agent_external_id
                ):
                    return agent
        return None

    def _list_tenant_agents(self, tenant: str) -> list[Any]:
        try:
            return [
                a
                for a in self._registry.list_all()
                if self._agent_tenant(a) == tenant
            ]
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _agent_tenant(agent: Any) -> str:
        return (getattr(agent, "tenant_id", "") or "").strip().casefold()

    @staticmethod
    def _agent_uuid(agent: Any) -> UUID | None:
        val = getattr(agent, "agent_id", None) or getattr(agent, "id", None)
        if isinstance(val, UUID):
            return val
        return _as_uuid(val) if val is not None else None

    @staticmethod
    def _is_governable(agent: Any) -> bool:
        status = str(getattr(agent, "lifecycle_status", "") or "").upper()
        return status not in _NON_ACTING_STATUSES

    @staticmethod
    def _within_surface(
        surface: Any,
        action_type: str,
        channel: str,
        environment: str,
        recipient: str | None,
    ) -> bool:
        """Structural capability confinement. Any check that exists and fails
        rejects the action; missing checks are treated as permissive so a
        surface that declares nothing does not silently widen — that case is
        caught by deep adjudication, not the floor."""
        try:
            checks = (
                ("permits_action_type", action_type),
                ("permits_channel", channel),
                ("permits_environment", environment),
                ("permits_recipient", recipient),
            )
            for method_name, arg in checks:
                method = getattr(surface, method_name, None)
                if callable(method) and not method(arg):
                    return False
            return True
        except Exception:  # noqa: BLE001
            return False


def _as_uuid(value: Any) -> UUID | None:
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None
