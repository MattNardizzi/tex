"""
SIEVE OUTPUT ADAPTER — the one-way projector into registry + ledger.

The MANDATORY governance boundary (ARCHITECTURE.md §7). A resolved
``SieveEntity`` is written through exactly the path ``service._apply`` uses
(service.py L691-721): ``registry.save(AgentIdentity)`` FIRST, then
``discovery_ledger.append(candidate, outcome)`` LAST, with the reconciliation
index linked in between so ``StandingGovernance.decide`` (which reads the live
registry on every action) can govern the entity.

This module REUSES the governance boundary and rebuilds nothing else. It fills
the ``SieveEntity.to_candidate_agent`` / ``to_reconciliation_outcome`` /
``reconciliation_key`` stubs in ``models`` against the real domain shapes
(``tex.domain.discovery.CandidateAgent`` / ``ReconciliationOutcome`` /
``DiscoverySource`` / ``ReconciliationAction`` / ``DiscoveryFindingKind`` and
``tex.domain.agent.AgentIdentity`` / ``CapabilitySurface``).

Identity-boundary shim (ARCHITECTURE.md §1.3): SIEVE's internal identity is the
probabilistic ``entity_id``. At the output boundary it projects to a STABLE
reconciliation key — ``generic:<tenant>:sieve-<entity_id>`` — written into
``AgentIdentity.metadata`` as ``discovery_source`` / ``discovery_external_id`` so
the existing ``ReconciliationIndex`` and ``PresenceTracker`` keep keying the
entity across scans instead of churning it as "new" every window.
"""

from __future__ import annotations

from typing import Mapping, Protocol
from uuid import UUID

from tex.discovery.engine.models import SieveEntity
from tex.domain.agent import AgentIdentity, CapabilitySurface
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryFindingKind,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)

# ---------------------------------------------------------------------------
# Boundary constants — the stable shim the index/PresenceTracker key on.
# ---------------------------------------------------------------------------

#: The discovery source SIEVE projects under. GENERIC because the entity is a
#: cross-plane probabilistic fusion, not a single platform's native object; the
#: source is part of the reconciliation key so it must be stable forever.
SIEVE_SOURCE: DiscoverySource = DiscoverySource.GENERIC

#: Tenant the slice projects under. ``AgentIdentity.tenant_id`` defaults to
#: "default"; the reconciliation key composed by ``_key_from_metadata``
#: (service.py L149) uses the agent's tenant, so the candidate and the saved
#: identity MUST agree on it or the index would never re-link the entity.
SIEVE_TENANT: str = "default"

#: External-id prefix stamped on the entity so a SIEVE-projected agent is
#: distinguishable in the ledger and its key is collision-free with any native
#: connector's external ids.
_EXTERNAL_ID_PREFIX: str = "sieve-"


# ---------------------------------------------------------------------------
# Structural protocols — the subset of the real stores the adapter calls.
# ---------------------------------------------------------------------------


class _Registry(Protocol):
    """The subset of ``InMemoryAgentRegistry`` the adapter calls.

    ``list_all`` powers the registered-agent bind (``_bind_registered_agent``);
    a registry without it degrades to the mint path, never a crash.
    """

    def save(self, agent):  # noqa: ANN001, ANN201 - AgentIdentity in/out
        ...

    def list_all(self):  # noqa: ANN201 - tuple[AgentIdentity, ...]
        ...


class _Ledger(Protocol):
    """The subset of ``InMemoryDiscoveryLedger`` the adapter calls."""

    def append(self, *, candidate, outcome):  # noqa: ANN001, ANN201
        ...


class _Index(Protocol):
    """The subset of ``ReconciliationIndex`` the adapter calls."""

    def link(self, *, key: str, agent_id) -> None:  # noqa: ANN001
        ...

    def get_agent_id(self, key: str):  # noqa: ANN201
        ...


# ---------------------------------------------------------------------------
# Entity → boundary projections (these FILL the models.py stubs).
# ---------------------------------------------------------------------------


def _external_id(entity: SieveEntity) -> str:
    """Stable platform-side identifier for the output-boundary shim.

    The ``reconciliation_key`` survives ONLY as an output-boundary shim
    (ARCHITECTURE.md §1.3); the entity's internal identity is ``entity_id``.
    For the index/PresenceTracker to RE-LINK the same agent across scans (rather
    than churn it as "new" every window) the boundary key must be stable across
    runs — but ``entity_id`` is minted fresh by each stateless ``resolve`` call
    in the slice (streaming state that would carry it forward is Phase 6). So the
    boundary id is anchored on the entity's DURABLE cross-scan handle:

    - ``merge_axis`` when present — the stable agent identifier the component is
      stitched on (an ``agent_external_id`` or the shared ``workspace_path``);
      this is the same anchor on every run, so the same agent re-links.
    - ``entity_id`` only as the last-resort fallback when no merge anchor exists.

    This is NOT a single forgeable attribute treated as IDENTITY — the resolver
    already decided fusion; the merge_axis is merely the chosen stable LABEL the
    boundary keys on. A different agent yields a different merge_axis and a
    different key.
    """
    anchor = entity.merge_axis or str(entity.entity_id)
    return f"{_EXTERNAL_ID_PREFIX}{anchor}"


def reconciliation_key(entity: SieveEntity, tenant: str = SIEVE_TENANT) -> str:
    """The stable output-boundary key for ``ReconciliationIndex`` linking.

    Mirrors ``CandidateAgent.reconciliation_key`` (domain L379) and
    ``_key_from_metadata`` (service.py L149) EXACTLY:
    ``f"{source}:{tenant}:{external_id.casefold()}"``. Both the candidate and
    the saved ``AgentIdentity.metadata`` carry the parts that compose this key,
    so the index re-links the entity across scans rather than churning it. The
    ``tenant`` defaults to ``SIEVE_TENANT`` but the live path threads the tenant
    being watched so discovered agents land in the SAME tenant as the estate.
    """
    return f"{SIEVE_SOURCE}:{tenant}:{_external_id(entity).casefold()}"


def _bind_registered_agent(
    registry: _Registry, tenant: str, handles: tuple[str | None, ...]
):  # noqa: ANN201 - AgentIdentity | None
    """Find the already-registered agent this entity IS, or ``None``.

    The govstream plane discovers an agent by the very identifier it GOVERNS
    under: ``StandingGovernance._resolve_agent`` binds ``decide()`` calls to a
    registered agent by ``external_agent_id`` OR ``name`` within the tenant, so
    the output boundary must be at least that smart. Without this bind, a
    registered agent that asks for one decision re-enters the registry as a
    second ``sieve-*`` row and the estate double-counts (20 real agents spoken
    as "forty agents running").

    Matching, within the tenant only: exact equality against the agent's
    ``external_agent_id``, ``name``, or its stored MINTED identity —
    ``metadata["discovery_external_id"]``, the boundary id ``project`` stamps
    on every row it creates — wins; a casefolded match is the fallback (the
    reconciliation key itself casefolds, so case drift between the observed id
    and the registered name must not re-mint). The minted-identity leg is what
    makes a RE-SWEEP reconcile to the very row a previous sweep minted, even
    when the caller's index has no memory of it (a fresh, un-bootstrapped
    index) or an operator has since renamed the row: N entities → N rows,
    forever. No match → ``None`` → the caller mints, which is how a
    genuinely-unknown/shadow agent still lands as a NEW row (the capability
    this plane exists for — never removed, per the discovery mandate).

    Never raises: a registry without ``list_all`` or one that faults degrades
    to ``None`` (the pre-bind mint behavior), so SIEVE keeps its
    never-break-ignite contract.
    """
    wanted = tuple(h.strip() for h in handles if isinstance(h, str) and h.strip())
    if not wanted:
        return None
    list_all = getattr(registry, "list_all", None)
    if not callable(list_all):
        return None
    try:
        agents = list_all()
    except Exception:  # noqa: BLE001 — discovery never breaks on a faulting store
        return None
    tenant_cf = (tenant or "").strip().casefold()
    wanted_cf = {h.casefold() for h in wanted}
    fallback = None
    for agent in agents:
        try:
            agent_tenant = (getattr(agent, "tenant_id", "") or "").strip().casefold()
            if agent_tenant != tenant_cf:
                continue
            metadata = getattr(agent, "metadata", None)
            minted_id = (
                metadata.get("discovery_external_id")
                if isinstance(metadata, Mapping)
                else None
            )
            ids = tuple(
                v
                for v in (
                    getattr(agent, "external_agent_id", None),
                    getattr(agent, "name", None),
                    minted_id,
                )
                if isinstance(v, str) and v
            )
            if any(v in wanted for v in ids):
                return agent
            if fallback is None and any(v.casefold() in wanted_cf for v in ids):
                fallback = agent
        except Exception:  # noqa: BLE001 — one odd row never drops the bind
            continue
    return fallback


def _risk_band(entity: SieveEntity) -> DiscoveryRiskBand:
    """Coarse risk opinion. An attribution conflict (N4) is never auto-trusted.

    A coherent fusion is MEDIUM (the default for an unverified discovery); an
    entity the incoherence detector flagged (``attribution_conflict``) is HIGH so
    it routes through operator review rather than auto-promotion.
    """
    return DiscoveryRiskBand.HIGH if entity.attribution_conflict else DiscoveryRiskBand.MEDIUM


def _capability_hints(entity: SieveEntity) -> DiscoveredCapabilityHints:
    """Project the entity's observed capability tuple into the hint shape.

    The slice carries only a coarse observed capability tuple on the entity;
    map it to ``inferred_action_types`` (the dimension the trail plane actually
    observed). Empty stays empty — "no restriction observed", never a fabricated
    surface.
    """
    return DiscoveredCapabilityHints(
        inferred_action_types=tuple(entity.capability),
    )


def to_candidate_agent(entity: SieveEntity, tenant: str = SIEVE_TENANT) -> CandidateAgent:
    """Project a resolved entity to the canonical ``CandidateAgent`` shape.

    Carries ``fusion_confidence`` through as ``confidence``, the stable
    ``external_id`` derived from ``entity_id``, and stamps the fusion receipt +
    cross-plane evidence into ``evidence`` so the ledger story is complete.
    """
    name = entity.label or _external_id(entity)
    evidence: dict[str, object] = {
        "sieve_entity_id": str(entity.entity_id),
        "fusion_confidence": round(float(entity.fusion_confidence), 6),
        "fusion_receipt": list(entity.fusion_receipt),
        "merge_axis": entity.merge_axis,
        "split_axis": entity.split_axis,
        "planes_seen": sorted(p.value for p in entity.planes_seen),
        "attribution_conflict": entity.attribution_conflict,
    }
    if entity.contradicting_pair is not None:
        evidence["contradicting_pair"] = [
            entity.contradicting_pair[0].value,
            entity.contradicting_pair[1].value,
        ]

    return CandidateAgent(
        source=SIEVE_SOURCE,
        tenant_id=tenant,
        external_id=_external_id(entity),
        name=name,
        description="SIEVE-resolved entity (cross-plane probabilistic fusion)",
        risk_band=_risk_band(entity),
        confidence=float(entity.fusion_confidence),
        capability_hints=_capability_hints(entity),
        evidence=evidence,
    )


def _finding_and_action(
    entity: SieveEntity, *, is_new: bool
) -> tuple[DiscoveryFindingKind, ReconciliationAction]:
    """Map the resolution result to a ledger finding_kind + action.

    - A fresh entity → ``NEW_AGENT`` / ``REGISTERED`` (the registry write fired).
    - A re-seen entity → ``KNOWN_AGENT_UNCHANGED`` / ``NO_OP_KNOWN_UNCHANGED``
      (the slice does not yet diff surfaces; Phase 4 fills the drift path).

    An ``attribution_conflict`` does NOT change the action here — the conflict is
    carried as a ledger ``finding`` + evidence so a downstream policy decides;
    the adapter's job is to land the entity governably, not to adjudicate.
    """
    if is_new:
        return DiscoveryFindingKind.NEW_AGENT, ReconciliationAction.REGISTERED
    return (
        DiscoveryFindingKind.KNOWN_AGENT_UNCHANGED,
        ReconciliationAction.NO_OP_KNOWN_UNCHANGED,
    )


def to_reconciliation_outcome(
    entity: SieveEntity,
    candidate: CandidateAgent,
    *,
    is_new: bool,
    resulting_agent_id: UUID | None = None,
    extra_findings: tuple[str, ...] = (),
) -> ReconciliationOutcome:
    """Project to a ``ReconciliationOutcome`` for the discovery ledger.

    Carries ``fusion_confidence`` through, attaches the fusion receipt and any
    ``contradicting_pair`` as ``findings`` so the ledger is auditable, and tags
    the resulting agent id when a registry write happened. ``extra_findings``
    lets the projector append boundary-level facts (e.g. the registered-agent
    bind) so the ledger row tells the whole story.
    """
    finding_kind, action = _finding_and_action(entity, is_new=is_new)

    findings: list[str] = [
        f"fusion_confidence={entity.fusion_confidence:.4f}",
        f"planes_seen={','.join(sorted(p.value for p in entity.planes_seen))}",
    ]
    findings.extend(f"receipt:{ref}" for ref in entity.fusion_receipt)
    if entity.attribution_conflict and entity.contradicting_pair is not None:
        a, b = entity.contradicting_pair
        findings.append(f"attribution_conflict:{a.value}|{b.value}")
    findings.extend(extra_findings)

    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=candidate.reconciliation_key,
        finding_kind=finding_kind,
        action=action,
        confidence=float(entity.fusion_confidence),
        resulting_agent_id=resulting_agent_id,
        findings=tuple(findings),
    )


def _candidate_to_agent_identity(
    candidate: CandidateAgent, entity: SieveEntity
) -> AgentIdentity:
    """Build the ``AgentIdentity`` a new entity registers as.

    The stable reconciliation-key parts are stamped into ``metadata`` so
    ``_key_from_metadata`` (service.py L149) reconstructs the SAME key the
    candidate carries — this is what makes ``ReconciliationIndex`` re-link the
    entity across scans instead of treating it as new (the churn risk called out
    in ARCHITECTURE.md §7).
    """
    surface = CapabilitySurface(
        allowed_action_types=candidate.capability_hints.inferred_action_types,
    )
    return AgentIdentity(
        name=candidate.name,
        owner=candidate.owner_hint or "sieve",
        description=candidate.description,
        tenant_id=candidate.tenant_id,
        trust_tier=candidate.risk_band.suggested_trust_tier,
        capability_surface=surface,
        metadata={
            "discovery_source": str(candidate.source),
            "discovery_external_id": candidate.external_id,
            "sieve_entity_id": str(entity.entity_id),
            "discovery_confidence": round(float(entity.fusion_confidence), 6),
        },
    )


# ---------------------------------------------------------------------------
# The one-way projector — registry FIRST, ledger LAST (mirrors service._apply).
# ---------------------------------------------------------------------------


def project(
    entity: SieveEntity,
    registry: _Registry,
    ledger: _Ledger,
    index: _Index,
    *,
    tenant: str = SIEVE_TENANT,
) -> None:
    """Write one resolved entity through the governance boundary.

    Mirrors ``service._apply`` registry-first / ledger-last (service.py
    L691-721):

    1. Build the ``CandidateAgent`` and its stable reconciliation key.
    2. Ask the index whether this entity is already linked (stable cross-scan
       lookup). A None means "not yet linked".
    3. NOT LINKED → bind before minting: an entity whose durable handle
       (``merge_axis``/``label``/name/boundary external id) matches a
       REGISTERED agent's ``external_agent_id``, ``name``, or stored minted
       identity (``metadata["discovery_external_id"]``) within the tenant IS
       that agent — the same binding ``StandingGovernance._resolve_agent``
       applies to every ``decide()`` call — so link the sieve key to the
       existing ``agent_id`` and mint nothing (the govstream double-count
       fix). The minted-identity leg makes a RE-SWEEP reconcile to the row a
       previous sweep minted (idempotent sweeps: N entities → N rows forever),
       even across an index with no memory or an operator rename. Only an
       entity that binds to NOTHING is genuinely new.
    4. NEW → save a fresh ``AgentIdentity`` through ``registry.save`` (which
       passes through ``gate_controller_mutation``; a blocked save returns the
       existing/echoed identity — HONOR it, never crash), then ``index.link``
       the stable key to the saved ``agent_id``. This is the shadow-agent
       capability and it MUST survive: an unknown agent still lands as a new,
       governable row.
    5. KNOWN → no registry mutation in the slice (Phase 4 fills surface drift);
       reuse the linked agent_id.
    6. Append ONE ledger row LAST, always — the durable, hash-chained record.

    Returns ``None``; side effects are the registry + ledger writes. Honors the
    returned ``AgentIdentity`` from a gate-blocked save as a silent no-op so a
    self-governance refusal never breaks the projection.
    """
    candidate = to_candidate_agent(entity, tenant)
    key = reconciliation_key(entity, tenant)

    existing_agent_id = index.get_agent_id(key)
    extra_findings: tuple[str, ...] = ()
    if existing_agent_id is None:
        registered = _bind_registered_agent(
            registry,
            tenant,
            (entity.merge_axis, entity.label, candidate.name, candidate.external_id),
        )
        if registered is not None:
            bound_id = getattr(registered, "agent_id", None) or getattr(
                registered, "id", None
            )
            if bound_id is not None:
                existing_agent_id = bound_id
                index.link(key=key, agent_id=bound_id)
                extra_findings = (
                    f"bound_to_registered_agent:{bound_id} "
                    "(external-id/name/minted-identity match within tenant; "
                    "no new row minted)",
                )
    is_new = existing_agent_id is None

    resulting_agent_id: UUID | None = existing_agent_id
    if is_new:
        identity = _candidate_to_agent_identity(candidate, entity)
        # registry.save passes through gate_controller_mutation: a blocked save
        # is a silent no-op that returns the (echoed) identity. Honor whatever
        # it returns — never crash on a refusal.
        saved = registry.save(identity)
        resulting_agent_id = saved.agent_id
        index.link(key=key, agent_id=saved.agent_id)

    outcome = to_reconciliation_outcome(
        entity,
        candidate,
        is_new=is_new,
        resulting_agent_id=resulting_agent_id,
        extra_findings=extra_findings,
    )

    # LEDGER LAST — the durable hash-chained record, after the registry write.
    ledger.append(candidate=candidate, outcome=outcome)


# ---------------------------------------------------------------------------
# Bind the projections onto SieveEntity so the models.py stubs are live.
# ---------------------------------------------------------------------------


def _entity_reconciliation_key(self: SieveEntity) -> str:
    return reconciliation_key(self)


def _entity_to_candidate_agent(self: SieveEntity) -> CandidateAgent:
    return to_candidate_agent(self)


def _entity_to_reconciliation_outcome(
    self: SieveEntity,
    candidate: CandidateAgent,
    resulting_agent_id: UUID | None = None,
) -> ReconciliationOutcome:
    # ``is_new`` is inferred from whether a resulting agent id was supplied; the
    # canonical path goes through ``project`` which is explicit, but binding the
    # method keeps the models.py contract callable in isolation (tests/receipts).
    return to_reconciliation_outcome(
        self,
        candidate,
        is_new=resulting_agent_id is not None,
        resulting_agent_id=resulting_agent_id,
    )


# Fill the models.py stubs in place so callers may use either the free functions
# (the canonical ``project`` path) or the ``entity.method()`` form.
SieveEntity.reconciliation_key = _entity_reconciliation_key  # type: ignore[method-assign]
SieveEntity.to_candidate_agent = _entity_to_candidate_agent  # type: ignore[method-assign]
SieveEntity.to_reconciliation_outcome = _entity_to_reconciliation_outcome  # type: ignore[method-assign]


__all__ = [
    "project",
    "reconciliation_key",
    "to_candidate_agent",
    "to_reconciliation_outcome",
    "SIEVE_SOURCE",
    "SIEVE_TENANT",
]
