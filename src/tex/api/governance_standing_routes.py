"""
/v1/govern — the PEP-facing decision surface for standing governance.

This is the thin seam the enforcement point talks to. Whatever sits in the
path — an eBPF/Tetragon kernel hook, an MCP/mesh gateway, the in-process
TexGate — calls ``POST /v1/govern/decide`` synchronously before letting an
action cross, and obeys ``released``. The brain behind it is StandingGovernance
(see governance/standing.py): pre-loaded capability surfaces for the
microsecond floor, the full six-layer EvaluateActionCommand for deep
adjudication, ABSTAIN routed to the one voice, FORBID by default.

``GET /v1/govern/posture`` is the governed-vs-observed boundary, spoken —
the truth the voice is honest about: how much of the estate Tex can actually
rule on versus merely watch.

Output obeys the same doctrine as the discovery surface: ``spoken`` carries
meaning; ``object`` carries a bare handle or null. The screen never holds an
answer.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, TexPrincipal

__all__ = ["build_governance_standing_router", "build_jwks_router"]


# --------------------------------------------------------------------------- #
# Taint-Gated Mint (TG-PCC B1+) — the per-(aud, act) integrity FLOOR table.    #
#                                                                              #
# AGENT-INDEPENDENCE BY CONSTRUCTION: the floor lives in OPERATOR-OWNED MODULE  #
# CODE — there is no request field that can set it, so a caller can never lower #
# the bar it must clear. The default is the most-trusted floor (TRUSTED) so a   #
# capability-issuing mint requires operands that descend purely from trusted    #
# roots unless an operator explicitly relaxes a specific (aud, act). The floor  #
# is expressed on the CaMeL/FIDES integrity axis (TRUSTED=0 < USER=1 <          #
# UNTRUSTED=2; ⊒floor = label.integrity <= floor.integrity) — the SAME encoding #
# the producer-signed prov_commit carries, so the in-route check and the        #
# offline re-check apply the identical predicate.                              #
# --------------------------------------------------------------------------- #


def _default_integrity_floor():
    from tex.camel.capability import CapabilityLevel, ConfidentialityLevel, FidesLabel

    # The conservative default: operands must be fully TRUSTED on the integrity
    # axis and no more sensitive than PUBLIC. An untrusted-derived operand
    # (integrity == UNTRUSTED) is structurally under this floor and cannot mint.
    return FidesLabel(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
    )


def _floor_for(aud: str, act: str):
    """Resolve the integrity floor for a released (audience, action).

    An operator may relax specific (aud, act) pairs via the module-level
    ``_INTEGRITY_FLOOR`` override map (operator code, never request input). Any
    miss falls back to the conservative default. Fail-closed: an unrecognized
    pair is held to the strongest floor, never silently waved through.
    """
    return _INTEGRITY_FLOOR.get((aud, act)) or _default_integrity_floor()


# Operator override map (empty by default; populated in operator code only).
# Keyed by (audience, action_type) -> FidesLabel floor.
_INTEGRITY_FLOOR: dict[tuple[str, str], Any] = {}


class DecideRequest(BaseModel):
    """What a PEP sends. Mirrors an EvaluationRequest's edge, plus the agent
    handle the PEP observed (a stable UUID where it has one, otherwise an
    external id or name)."""

    action_type: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=50_000)
    channel: str | None = Field(default=None, max_length=50)
    environment: str | None = Field(default=None, max_length=50)
    recipient: str | None = Field(default=None, max_length=500)
    agent_id: UUID | None = None
    agent_external_id: str | None = Field(default=None, max_length=300)
    session_id: str | None = Field(default=None, max_length=200)
    tenant_id: str | None = Field(default=None, max_length=200)


class MintRequest(BaseModel):
    """What a caller sends to ``POST /v1/govern/mint`` — the same decision edge a
    ``/decide`` PEP sends, PLUS the capability/token inputs (audience, ttl, and a
    mandatory RFC-9449 DPoP proof that carries the holder's key).

    ``scope`` is deliberately NOT a field: scope is derived from the released
    decision (``act:<action_type>``), never echoed from the caller, so a caller
    can never widen the credential beyond what Tex permitted (RFC 8693 — the AS
    decides scope)."""

    # --- decision inputs (mapped 1:1 onto StandingGovernance.decide() kwargs) ---
    action_type: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=50_000)
    channel: str | None = Field(default=None, max_length=50)
    environment: str | None = Field(default=None, max_length=50)
    recipient: str | None = Field(default=None, max_length=500)
    agent_id: UUID | None = None
    agent_external_id: str | None = Field(default=None, max_length=300)
    session_id: str | None = Field(default=None, max_length=200)
    tenant_id: str | None = Field(default=None, max_length=200)
    # --- capability/token inputs ---
    audience: str | None = Field(default=None, max_length=500)  # RFC 8707 resource indicator
    ttl: int = Field(default=300, gt=0, le=300)  # SOTA short TTL, 60–300s
    dpop_proof: str = Field(min_length=1, max_length=8192)  # RFC 9449 PoP proof (REQUIRED)
    # --- TG-PCC taint label (B1+, default-OFF behind TEX_TAINT_GATED_MINT) ------ #
    # A TRUSTED LABEL PRODUCER (the in-path PEP / CaMeL interpreter / quarantine
    # store that actually observed the operands) stamps these. They are NOT
    # agent-asserted: ``label_signature`` is an HMAC the agent cannot forge
    # (it does not hold ``TEX_TAINT_LABEL_SECRET``), so the agent cannot raise its
    # own integrity. Absent (or with a bad signature) under the taint flag, the
    # mint FAILS CLOSED — never permits. The intent commit binds the token to the
    # exact (method, resource, params) the producer attested.
    intent_method: str | None = Field(default=None, max_length=100)
    intent_resource: str | None = Field(default=None, max_length=500)
    intent_params: Any = None  # canonicalized into the intent_commit
    operand_label_integrity: int | None = Field(default=None, ge=0, le=2)
    operand_label_confidentiality: int | None = Field(default=None, ge=0, le=3)
    operand_label_id: str | None = Field(default=None, max_length=128)
    lineage_root: str | None = Field(default=None, max_length=128)
    label_signature: str | None = Field(default=None, max_length=128)


def _governance(request: Request):
    gov = getattr(request.app.state, "standing_governance", None)
    if gov is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="standing governance not attached",
        )
    return gov


def _default_plane_registry():
    """Build a fresh, EMPTY PlaneSignalRegistry honoring the operator TTL env
    overrides. Used when no registry is attached at composition — an empty store
    yields all-DECIDE-ONLY, which is the correct resting state. NEVER cached on
    app.state here (no signal is ever upgraded by the act of reading)."""
    import os

    from tex.governance.plane_signals import (
        _DEFAULT_CRED_TTL_S,
        _DEFAULT_POLL_TTL_S,
        PlaneSignalRegistry,
    )

    def _ttl(name: str, default: float) -> float:
        raw = os.environ.get(name, "").strip()
        if not raw:
            return default
        try:
            val = float(raw)
            return val if val > 0 else default
        except ValueError:
            return default

    return PlaneSignalRegistry(
        cred_ttl_s=_ttl("TEX_PLANE_CRED_TTL_S", _DEFAULT_CRED_TTL_S),
        poll_ttl_s=_ttl("TEX_PLANE_POLL_TTL_S", _DEFAULT_POLL_TTL_S),
    )


def _resolve_tenant(principal: TexPrincipal, override: str | None) -> str:
    if override and principal.can_access_tenant(override):
        return override.strip().casefold()
    return principal.tenant


def _refusal_payload(
    outcome: Any, *, reason_override: str | None = None
) -> dict[str, Any]:
    """The no-token body for a non-released (FORBID/HOLD) or taint-refused mint.
    There is no ``access_token``/``token`` field — a refusal NEVER carries a
    credential.

    ``reason_override`` is set for a taint refusal (insufficient integrity): the
    outcome itself was a PERMIT, so the deny reason is the floor breach, and a
    taint refusal is a HARD deny (``held=False``), never a HOLD."""
    held = False if reason_override is not None else bool(getattr(outcome, "held", False))
    return {
        "released": False,
        "held": held,
        "verdict": (
            "FORBID" if reason_override is not None else str(getattr(outcome, "verdict", "FORBID"))
        ),
        "decision_id": (
            str(outcome.decision_id) if getattr(outcome, "decision_id", None) else None
        ),
        "reason": (
            reason_override
            if reason_override is not None
            else getattr(outcome, "reason", None)
        ),
    }


def build_governance_standing_router() -> APIRouter:
    router = APIRouter(prefix="/v1/govern", tags=["governance-standing"])

    @router.post(
        "/decide",
        summary="Rule on one action — the call every enforcement point makes",
    )
    def decide(
        request: Request,
        body: DecideRequest,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        gov = _governance(request)
        tenant = _resolve_tenant(principal, body.tenant_id)
        outcome = gov.decide(
            tenant=tenant,
            action_type=body.action_type,
            content=body.content,
            channel=body.channel,
            environment=body.environment,
            recipient=body.recipient,
            agent_id=body.agent_id,
            agent_external_id=body.agent_external_id,
            session_id=body.session_id,
        )
        # GOVERNANCE-STREAM DISCOVERY (P11): record this gate call so the SIEVE
        # governance-stream plane self-discovers ANY agent that asks Tex for a
        # decision — the act of asking reveals the agent. Best-effort + bounded;
        # discovery NEVER changes or breaks the decision the PEP obeys.
        try:
            from tex.discovery.engine.sensors.governance_stream import record_decision

            record_decision(
                {
                    "agent_external_id": body.agent_external_id,
                    "agent_id": str(body.agent_id) if body.agent_id is not None else None,
                    "tool_name": body.action_type,
                    "verdict": str(getattr(outcome, "verdict", "")) or None,
                    "tenant": tenant,
                }
            )
        except Exception:  # noqa: BLE001 — discovery never breaks the decision
            pass
        # PROOF-CARRYING ENFORCEMENT (dormant unless a decision ledger is wired,
        # i.e. TEX_SEAL_DECISIONS=1): seal an offline-verifiable ENFORCEMENT
        # receipt for this PEP decision so a missing receipt reads as a bypass.
        # Fail-closed and best-effort — sealing NEVER changes or breaks the
        # decision the PEP obeys (the action proceeds on ``released`` regardless).
        ledger = getattr(request.app.state, "decision_ledger", None)
        if ledger is not None:
            try:
                from tex.provenance.enforcement_seal import seal_enforcement_decision

                seal_enforcement_decision(
                    ledger,
                    action_type=body.action_type,
                    channel=body.channel or "api",
                    environment=body.environment or "production",
                    recipient=body.recipient,
                    agent_id=(
                        str(body.agent_id)
                        if body.agent_id is not None
                        else (body.agent_external_id or None)
                    ),
                    verdict=str(getattr(outcome, "verdict", "FORBID")),
                    released=bool(getattr(outcome, "released", False)),
                    decision_id=(
                        str(outcome.decision_id)
                        if getattr(outcome, "decision_id", None)
                        else None
                    ),
                    reason=getattr(outcome, "reason", None),
                    tier=getattr(outcome, "tier", None),
                    held=bool(getattr(outcome, "held", False)),
                )
            except Exception:  # noqa: BLE001 — sealing must never break the decision
                pass

        # The one boolean a PEP obeys is ``released``. The rest is provenance.
        return outcome.to_jsonable()

    @router.get(
        "/posture",
        summary="Governed vs. observed — the edge of control, spoken",
    )
    def posture(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        gov = _governance(request)
        tenant = _resolve_tenant(principal, tenant_id)
        return gov.posture(tenant).to_jsonable()

    @router.get(
        "/forbid-set",
        summary="The hot FORBID destinations the kernel floor blocks inline",
    )
    def forbid_set(
        request: Request,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        # The kernel-floor PEP (pep/kernel) polls this to warm its in-kernel
        # verdict cache so the highest-confidence denials are blocked in
        # microseconds, before a packet leaves, without a userspace round trip.
        # This is deliberately the HOT SET only — not the policy. Absence from
        # it is never permit: every destination not listed flows through the
        # transparent redirect to the proxy for the full two-tier decision.
        # An empty set means "decide everything at the proxy," the safe default.
        #
        # The set is sourced by a ForbidSource (governance/forbid_source.py):
        # high-confidence FORBID host:port destinations fed at composition or
        # via the TEX_FORBID_SET env, resolved to IPv4 at read time (each poll).
        # Fail-closed throughout: no source / unresolvable / malformed -> [].
        _governance(request)  # same precondition as the rest of /v1/govern
        # ``epoch`` is a monotonic version of the set (bumped on every mutation)
        # so the kernel loader can reject a stale/replayed response (epoch < the
        # last it applied) — cheap anti-rollback, no signing infra. Unknown JSON
        # fields are ignored by the Go decoder, so this is backward-compatible.
        epoch = 0
        try:
            from tex.governance.forbid_source import resolve_forbid_source

            source = resolve_forbid_source(request.app.state)
            if source is not None:
                entries = source.for_tenant(principal.tenant)
                epoch = source.epoch
            else:
                entries = []
        except Exception:  # noqa: BLE001 — a degraded source never fails open
            entries = []
        return {"forbid": entries, "count": len(entries), "epoch": epoch}

    @router.get(
        "/local-forbid-set",
        summary="The HMAC-signed local-action FORBID set the in-kernel local PEP enforces",
    )
    def local_forbid_set(
        request: Request,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        # The local-action kernel PEP (pep/kernel/localpep) polls this to warm its
        # in-kernel (cgroup, inode) deny map. Unlike the network forbid-set this is
        # HMAC-SIGNED (shared TEX_LOCAL_PEP_SECRET): the loader verifies the exact
        # bytes at the enforcement point, so a compromised agent can neither forge
        # the set nor strip an entry. Fail-closed + default-OFF: an unwired source
        # is treated as empty, and with no secret configured the envelope is inert
        # (the loader rejects the empty signature and keeps its existing denies —
        # revoke-wins), so this route changes nothing until the PEP is provisioned.
        import os

        from tex.governance.local_forbid_source import (
            LocalForbidSource,
            resolve_local_forbid_source,
        )

        _governance(request)  # same precondition as the rest of /v1/govern
        secret = os.environ.get("TEX_LOCAL_PEP_SECRET", "")
        if not secret:
            return {"set_canonical": "", "sig": "", "inert": True}
        source = resolve_local_forbid_source(request.app.state) or LocalForbidSource()
        return source.signed_response(principal.tenant, secret=secret)

    @router.get(
        "/agents/plane",
        summary="Per-agent enforcement-plane badge — derived from LIVE signals, never optimistic",
    )
    def agents_plane(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        """For each governed agent, derive exactly ONE enforcement plane from a
        LIVE, OBSERVED signal — and DEGRADE on absence/staleness, never upgrade
        on capability/availability.

        Default-OFF behind ``TEX_PLANE_STATUS`` (inert 503 when unset). Even with
        the flag ON the signal registry defaults EMPTY, so every governed agent
        reads ``DECIDE-ONLY`` with ``last_handshake_ts=null`` — the correct,
        honest resting state (and the only true output on Render, where there is
        no in-path Body and no downstream demand-verifier wired).

        HONEST CEILING (do not change behavior to contradict any of this):

        * **Never optimistic.** A plane upgrades ONLY from a recorded, fresh,
          OBSERVED signal. Broker/mint availability, route existence, and the
          flag itself are NOT signals — they never upgrade a plane.
        * **CREDENTIAL-ENFORCED** requires an observed B3 demand-verifier
          handshake (a downstream resource ran the verifier and accepted a
          Tex-minted cred), recorded within ``TEX_PLANE_CRED_TTL_S``. No such
          producer is wired today, so this is empty by default.
        * **IN-PATH-BLOCKING** requires a fresh forbid-set poll (a live
          kernel/proxy PEP heartbeat) for the tenant, within
          ``TEX_PLANE_POLL_TTL_S``. No poll-recency producer is wired today, and
          on Render no loader polls — so this is structurally unreachable there.
        * **Possession != authorization.** A minted token proves WHO, not INTENT
          (replayable by a hijacked agent), and an agent's own standing
          credential that bypasses the verifier records NO handshake and keeps
          the agent at DECIDE-ONLY.
        """
        # --- A. FLAG GATE (default-OFF, first thing — inert when unset) -------- #
        import os

        on = os.environ.get("TEX_PLANE_STATUS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not on:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="plane status route disabled",
            )

        # --- B. GOVERNANCE PRECONDITION (503 if unwired) ---------------------- #
        gov = _governance(request)

        # --- C. TENANT -------------------------------------------------------- #
        tenant = _resolve_tenant(principal, tenant_id)

        # --- D. SIGNAL REGISTRY (default-EMPTY) ------------------------------- #
        # A registry attached at composition is read live; an unwired app gets a
        # fresh EMPTY registry, so every agent derives the floor. Either way the
        # read is PURE and can only UPGRADE off a recorded, fresh signal — and the
        # default-empty store upgrades nothing.
        from tex.governance.plane_signals import PlaneSignalRegistry

        registry = getattr(request.app.state, "plane_signal_registry", None)
        if registry is None:
            registry = _default_plane_registry()

        # --- E. ENUMERATE GOVERNED AGENTS + DERIVE PER-AGENT PLANE ------------ #
        # Only governed agents (the ones Tex can actually rule on); each one's
        # plane is derived independently from the live signals for that agent /
        # its tenant. No signal => DECIDE-ONLY. Stale signal => degrades.
        agents: list[dict[str, Any]] = []
        for agent in gov._list_tenant_agents(tenant):  # noqa: SLF001 — same accessor /posture uses
            if not gov._is_governable(agent):  # noqa: SLF001
                continue
            uid = gov._agent_uuid(agent)  # noqa: SLF001
            agent_id = str(uid) if uid is not None else str(
                getattr(agent, "external_agent_id", None)
                or getattr(agent, "name", "")
                or ""
            )
            agents.append(registry.derive(agent_id, tenant).to_jsonable())

        return {"tenant": tenant, "agents": agents, "count": len(agents)}

    @router.post(
        "/mint",
        summary="Mint a sender-bound capability — only if the action is PERMITTED",
    )
    def mint(
        request: Request,
        body: MintRequest,
        principal: TexPrincipal = Depends(RequireScope("decision:write")),
    ):
        """CAPABILITY-BEFORE on the out-of-path plane: rule on one action, and
        mint a short-lived, action-scoped, sender-bound (RFC 7800/9449 ``cnf``)
        Tex capability token ONLY when the ruling RELEASED it. FORBID/HOLD ⇒ no
        token. Default-OFF behind ``TEX_GOVERN_MINT`` (inert 503 when unset).

        HONEST SCOPE — this route does NOT overclaim (do not change the behavior
        to contradict any of this):

        * **Issuance-gating, not in-path blocking.** This mints a credential; it
          does NOT sit in the request path. A FORBID means the agent cannot get a
          Tex credential — it does NOT, by itself, stop an agent that ignores Tex
          and calls the resource directly. The action is stopped only where an
          in-path Body (proxy / eBPF) or a resource that DEMANDS Tex credentials
          exists.
        * **Confused-deputy ceiling.** Sender-binding (``cnf.jkt``) ties the token
          to a holder key the caller proved possession of, so a stolen *token* is
          useless without the private key. Confinement is exactly ``aud`` (RFC
          8707) + ``act`` + ``scope`` (the single released action) — no finer.
        * **No jti replay cache.** ``verify_pop_proof`` keeps no nonce cache: a
          captured DPoP proof can be replayed within its freshness window against
          the same ``bind``. B1 adds no cache (tokens are short-TTL).
        * **Offline / symmetric-HMAC verify.** The credential is HMAC-signed
          (``texauth.v1`` domain-separated), NOT an asymmetric/RS256 JWT. Any
          verifier must share ``authority_secret`` or delegate verify to Tex.
        * **API-principal identity, not agent-card attestation.** The bound
          identity attests "the API caller authenticated under ``RequireScope``
          and named this agent handle" — it is NOT cryptographic agent-card
          attestation (the proxy path verifies a signed card). The PoP proof DOES
          bind the token to a holder key the caller proved possession of.
        """
        # --- A. FLAG GATE (default-OFF, first thing — inert when unset) -------- #
        import os

        on = os.environ.get("TEX_GOVERN_MINT", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not on:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="govern mint route disabled",
            )

        # --- B. GOVERNANCE PRECONDITION (503 if unwired) ---------------------- #
        gov = _governance(request)

        # --- C. TENANT -------------------------------------------------------- #
        tenant = _resolve_tenant(principal, body.tenant_id)

        # --- D. DECIDE (same kwargs shape as /decide) ------------------------- #
        outcome = gov.decide(
            tenant=tenant,
            action_type=body.action_type,
            content=body.content,
            channel=body.channel,
            environment=body.environment,
            recipient=body.recipient,
            agent_id=body.agent_id,
            agent_external_id=body.agent_external_id,
            session_id=body.session_id,
        )

        # --- E. GATE ON VERDICT — refuse-before-mint -------------------------- #
        # ``released`` is True iff the ruling PERMITted the action; a non-released
        # outcome (FORBID, or ABSTAIN+held=HOLD) NEVER mints a token.
        if not getattr(outcome, "released", False):
            payload = _refusal_payload(outcome)
            # FORBID ⇒ 403 (a forbidden request, no credential). HOLD (ABSTAIN +
            # held) ⇒ 202 (awaiting human review — neither permitted nor denied).
            code = (
                status.HTTP_202_ACCEPTED
                if payload["held"]
                else status.HTTP_403_FORBIDDEN
            )
            return JSONResponse(status_code=code, content=payload)

        # --- E2. TAINT GATE (TG-PCC B1+, default-OFF) — refuse-before-sign ----- #
        # The action was PERMITTED (released). The taint gate is a SECOND,
        # orthogonal floor: an action whose operands derive from UNTRUSTED /
        # quarantined data is structurally unable to obtain a token, even though
        # the verdict released it. The integrity label is AGENT-INDEPENDENT — it
        # is stamped + HMAC-signed by a trusted label producer (the in-path PEP /
        # CaMeL interpreter / quarantine store) with an operator secret the
        # calling agent does not hold; mint VERIFIES that signature here. The
        # floor is operator-owned module code (``_floor_for``), not request input.
        #
        # HONEST CEILING (do not claim away): the label assessor is in the TCB —
        # this gate moves trust to the producer, it does not remove it. It closes
        # the UNTRUSTED-DERIVATION vector at issuance; it does not adjudicate
        # confused-deputy WITHIN already-trusted operands. ``lineage_root`` is a
        # commitment, not the DAG. Issuance-gating, not in-path blocking.
        #
        # This whole block runs ONLY under TEX_TAINT_GATED_MINT; with the flag
        # unset control falls straight through to section F and B1 behaves
        # byte-for-byte as today (no intent_commit/prov_commit are embedded).
        tg_intent_commit: str | None = None
        tg_prov_commit: dict[str, Any] | None = None
        taint_on = os.environ.get("TEX_TAINT_GATED_MINT", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if taint_on:
            from tex.authority.broker import canonical_intent_commit
            from tex.authority.taint_label import (
                ProvenanceCommitment,
                build_pdp_commitment,
                label_producer_secret,
                sign_label_envelope,
                verify_label_envelope,
            )
            from tex.camel.capability import (
                CapabilityLevel,
                ConfidentialityLevel,
                FidesLabel,
            )

            # LIVE PRODUCER (TG-PCC B1+, default-OFF, nested under the taint flag):
            # when on, TEX'S OWN PDP is the label producer. The route derives the
            # commitment from ``outcome.integrity_label`` (the IFC-derived,
            # agent-independent label the PDP computed for THIS ruling) and
            # SELF-SIGNS it in-process with the operator secret — IGNORING the
            # caller's operand_label_* / label_signature entirely. The agent
            # cannot supply or raise its own label: that is the substance of
            # agent-independence. Unset => the legacy caller-presented +
            # verify-caller-HMAC path runs byte-for-byte as today.
            live_on = os.environ.get(
                "TEX_TAINT_LABEL_LIVE", ""
            ).strip().lower() in {"1", "true", "yes", "on"}

            t_audience = body.audience or body.recipient
            if not t_audience:
                # No audience to key the floor on => fail closed (deny, not 500).
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=_refusal_payload(
                        outcome,
                        reason_override="insufficient_integrity: no audience to key the floor",
                    ),
                )

            floor = _floor_for(t_audience, body.action_type)
            secret = label_producer_secret()

            if live_on:
                # --- LIVE: Tex's PDP produced the label; self-sign in process. ---
                # Fail closed when there is no producer secret (the agent could
                # otherwise self-produce a valid-looking label) or when the PDP
                # attached no label (e.g. a floor-tier PERMIT with no deep run —
                # impossible for a released deep PERMIT, but defended explicitly):
                # absence of an agent-independent label means "refuse", never mint.
                if secret is None or getattr(outcome, "integrity_label", None) is None:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content=_refusal_payload(
                            outcome,
                            reason_override=(
                                "insufficient_integrity: no PDP-produced label / "
                                f"no producer secret for aud={t_audience} "
                                f"act={body.action_type}"
                            ),
                        ),
                    )
                pdp_label = outcome.integrity_label
                label = FidesLabel(
                    integrity=pdp_label.integrity,
                    confidentiality=pdp_label.confidentiality,
                )
                commit = build_pdp_commitment(
                    pdp_label,
                    floor=floor,
                    aud=t_audience,
                    act=body.action_type,
                )
                # Tex SELF-SIGNS in-process — the agent never holds the secret and
                # never supplies a signature. There is no verify-CALLER step in
                # LIVE mode because the commitment is self-authored, not
                # caller-attested. We sign-then-self-verify as a serialization /
                # tamper self-check (a defective envelope fails CLOSED, never
                # mints); the token's authenticity itself comes from the broker's
                # signature over the embedded prov_commit downstream.
                _label_signature = sign_label_envelope(commit, secret=secret)
                if not verify_label_envelope(commit, _label_signature, secret=secret):
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content=_refusal_payload(
                            outcome,
                            reason_override=(
                                "insufficient_integrity: PDP label self-seal "
                                "failed (fail-closed)"
                            ),
                        ),
                    )
            else:
                # --- LEGACY (default): caller-presented producer label + verify. ---
                # FAIL CLOSED if the trusted-producer label is absent / unverifiable.
                # A missing producer secret, a missing label, or a bad signature ALL
                # refuse — the agent cannot self-assert integrity, so absence of an
                # independent label means "treat as tainted / refuse", never permit.
                missing = (
                    secret is None
                    or body.operand_label_integrity is None
                    or body.operand_label_confidentiality is None
                    or not body.label_signature
                    or not body.lineage_root
                    or not body.operand_label_id
                )
                if missing:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content=_refusal_payload(
                            outcome,
                            reason_override=(
                                "insufficient_integrity: no verifiable trusted-producer "
                                f"label for aud={t_audience} act={body.action_type}"
                            ),
                        ),
                    )

                label = FidesLabel(
                    integrity=CapabilityLevel(int(body.operand_label_integrity)),
                    confidentiality=ConfidentialityLevel(
                        int(body.operand_label_confidentiality)
                    ),
                )
                commit = ProvenanceCommitment(
                    label=label,
                    floor=floor,
                    lineage_root=str(body.lineage_root),
                    label_id=str(body.operand_label_id),
                    aud=t_audience,
                    act=body.action_type,
                )

                # The label must be AUTHENTIC — signed by the trusted producer.
                if not verify_label_envelope(
                    commit, str(body.label_signature), secret=secret  # type: ignore[arg-type]
                ):
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content=_refusal_payload(
                            outcome,
                            reason_override=(
                                "insufficient_integrity: trusted-producer label "
                                "signature invalid"
                            ),
                        ),
                    )

            # The authentic/self-signed label must DOMINATE the floor (meet ⊒
            # floor). An UNTRUSTED-derived operand floors the meet to UNTRUSTED and
            # fails here — refuse BEFORE any PoP parse, key resolution, or
            # broker.mint. SHARED by both legs.
            if not commit.dominates_floor():
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=_refusal_payload(
                        outcome,
                        reason_override=(
                            "insufficient_integrity: meet="
                            f"{label.integrity.name} ⋢ floor={floor.integrity.name} "
                            f"for aud={t_audience} act={body.action_type}"
                        ),
                    ),
                )

            # Cleared the floor: this token will carry the SIGNED intent + prov
            # commitments so an offline verifier can re-check label ⊒ floor and the
            # exact bound action. ``params`` defaults to the audience/recipient
            # edge when the producer did not present an explicit method/resource.
            method = body.intent_method or body.action_type
            resource = body.intent_resource or t_audience
            params = body.intent_params if body.intent_params is not None else {}
            tg_intent_commit = canonical_intent_commit(method, resource, params)
            tg_prov_commit = commit.to_prov_commit()

        # --- F. ESTABLISH SENDER KEY + VERIFY PoP (only reached when released) - #
        # Mirror broker._resolve_exchange_cnf: parse the proof body -> holder JWK
        # -> public key -> RFC-7638 thumbprint, then PROVE possession before mint.
        import base64
        import json

        from tex.authority import pop

        audience = body.audience or body.recipient
        if not audience:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="no audience (RFC 8707 resource indicator) and no recipient",
            )

        try:
            body_b64 = body.dpop_proof.partition(".")[0]
            proof_body = json.loads(
                base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
            )
            jwk = proof_body.get("jwk")
            pub = pop.load_public_key(jwk)
            subject_jkt = pop.thumbprint(pub)
        except Exception:  # noqa: BLE001 — any parse/load defect fails closed
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="malformed dpop proof",
            )

        # Deterministic, caller-reproducible bind. The ``tex-pop-mint:`` prefix is
        # distinct from ``tex-pop-exchange:`` / ``tex-pop-use:`` so a proof for one
        # context can never replay into another.
        mint_bind = f"tex-pop-mint:{subject_jkt}:{audience}:{body.action_type}"
        pr = pop.verify_pop_proof(
            body.dpop_proof, cnf_jkt=subject_jkt, bind=mint_bind, now=None
        )
        if not pr.ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"pop proof rejected: {pr.reason}",
            )

        # --- G. ATTESTED IDENTITY (API-principal level — see docstring) ------- #
        from tex.identity.agent_credential import AttestedIdentity

        subject_id = (
            str(body.agent_id)
            if body.agent_id
            else (body.agent_external_id or principal.tenant)
        )
        att = AttestedIdentity(
            verified=True,
            status="api_principal",
            issuer=principal.tenant,
            claimed_agent_id=subject_id,
        )

        # --- H. SCOPE = requested ∩ scope_allowed_by(decision) ---------------- #
        # Same intersection the proxy's _broker_scope_policy computes, reproduced
        # inline (the standing path produces a DecisionOutcome, not a Decision).
        # Format ``act:<action_type>`` (+ ``act:<action_type>@<recipient>`` when
        # the recipient is known). NEVER widen; never echo caller scope.
        allowed = {f"act:{body.action_type}"}
        if body.recipient:
            allowed.add(f"act:{body.action_type}@{body.recipient}")
        requested = {f"act:{body.action_type}"}
        scope = sorted(requested & allowed)
        if not scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="decision allows no scope",
            )

        # --- I. CONSTRUCT BROKER (lazy, PoP-only) + MINT ---------------------- #
        from tex.authority.broker import CredentialBroker

        broker = CredentialBroker(
            issuer="tex-authority",
            store=None,  # stateless mint; revocation/single-use is the in-path proxy's job
            allow_bearer=False,  # PoP-only — matches the proxy posture
            require_exchange_pop=True,
        )
        # When the taint gate cleared and an asymmetric TG-PCC key is available,
        # sign the token with Ed25519 so a remote verifier can re-check the signed
        # intent_commit / prov_commit OFFLINE (no shared secret). With the taint
        # flag off, or no Ed25519 key resolvable, fall back to the default HMAC leg
        # — keeping today's B1 behavior byte-for-byte. mint() fails CLOSED if
        # ed25519 is requested but no key resolves, so we only request it when one
        # is present.
        sign_alg = "hmac"
        if tg_prov_commit is not None:
            from tex.authority.broker import authority_ed25519_key

            if authority_ed25519_key() is not None:
                sign_alg = "ed25519"
        minted = broker.mint(
            att,
            audience=audience,
            action=body.action_type,
            scope=scope,
            ttl=int(body.ttl),
            cnf_public_key=pub,  # the proven holder key from step F
            decision_id=str(outcome.decision_id),
            single_use=False,  # stateless (store=None); not single-use/revocable here
            sign_alg=sign_alg,
            intent_commit=tg_intent_commit,  # None unless the taint gate cleared
            prov_commit=tg_prov_commit,  # None unless the taint gate cleared
        )
        if minted is None:
            # fail-closed: no signing secret, unverified identity, uncoercible
            # key, or bearer-on-PoP-only. NEVER 500, NEVER emit a token.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="capability mint refused (fail-closed)",
            )

        # --- RFC-8693-shaped PERMIT response (hand-built; no to_jsonable) ----- #
        return {
            "access_token": minted.token,
            "token_type": minted.token_type,  # "DPoP" (cnf bound)
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": int(minted.claims["exp"] - minted.claims["iat"]),
            "scope": list(minted.scope),
            "decision_id": str(outcome.decision_id),
            "cnf": {"jkt": minted.cnf_jkt},  # RFC 9449 sender-binding
            "jti": minted.jti,
            "audience": minted.audience,
            "expiry": minted.expiry.isoformat(),
            "released": True,
        }

    return router


def build_jwks_router() -> APIRouter:
    """The public JWKS discovery surface — GET ``/.well-known/tex-jwks.json``.

    Publishes ONLY Tex's Ed25519 PUBLIC signing key (``{kty:OKP, crv:Ed25519,
    x, kid, use, alg}``) so a remote verifier can check a Tex-signed capability
    token OFFLINE from a pinned public key. NEVER exposes private material.

    HONEST SCOPE — PARITY plumbing, not beyond-frontier:

    * This is issuance-side enablement of *asymmetric, offline* verify (the
      DEPLOYED shape — AIP / Biscuit / Vouchsafe). A JWKS lets a remote verifier
      check Tex's signature without a shared secret; it does NOT by itself stop
      an agent that ignores Tex (out-of-path, like /mint).
    * Default-OFF behind ``TEX_TGPCC``: with the flag unset the endpoint serves
      an empty ``{"keys": []}`` (the asymmetric plane is inert and no key is
      published), so default boot exposes no key material.
    """
    router = APIRouter(tags=["tex"])

    @router.get(
        "/.well-known/tex-jwks.json",
        summary="Tex Ed25519 public signing key (JWKS) — capability verify",
    )
    def tex_jwks() -> dict[str, Any]:
        # Default-OFF: tgpcc_public_jwks() returns {"keys": []} when the plane is
        # off or no key resolves. It NEVER includes private bytes.
        from tex.authority.broker import tgpcc_public_jwks

        return tgpcc_public_jwks()

    return router
