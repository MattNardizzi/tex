"""
Metaguard — deterministic deny/caution signatures for Tex's OWN controller
mutations (Wave 2 / L5, reflexive self-governance).

[Architecture: Layer 4 (Execution Governance) — reflexive stratum]

What this is
------------
The structural-floor sibling for the *reflexive* surface: where
``specialists/structural_floor.py`` recognises deterministic deny signatures in
content evaluations (PCAS Datalog deny, IFC type violation, …), this module
recognises deterministic signatures in **controller-mutation descriptors** —
attempts to change what Tex itself decides next (policy activation, agent
lifecycle loosening, key material, evidence destruction).

Structural-floor contract (same as ``structural_floor.py``, sacred):
  * A signature fires ONLY on typed descriptor fields (an old/new threshold
    comparison, a lifecycle state pair, a mutation class). It NEVER reads a
    probabilistic score — a high ``risk_score`` anywhere in the payload can
    neither fire nor silence a signature (pinned by test).
  * Signatures only ever LOWER the gate verdict (monotone): a FLOOR signature
    forces FORBID, a CAUTION signature demotes PERMIT→ABSTAIN. Nothing here can
    raise a PDP ABSTAIN/FORBID back toward PERMIT.

Signature classes (research-early; the census of WHAT counts as weakening is
deliberately narrow and named — see ``selfgov/governor.py`` for the surface
census this rules over):

FLOOR (deterministic FORBID — forbidden mutation classes):
  * ``metaguard.governor_self_target`` — the mutation targets the reflexive
    governor's own deploy-frozen stratum (its policy family, its binding).
    This is the two-level construction that kills the regress: level-0 is
    immutable in-process, so "gate the gate" terminates by construction.
  * ``metaguard.revoked_resurrection`` — lifecycle transition out of the
    terminal REVOKED state (an un-deletion would falsify the day-90 kill).

CAUTION (deterministic PERMIT→ABSTAIN — uncertainty resolves to a hold):
  * ``metaguard.quarantine_lift``       — QUARANTINED → ACTIVE/PENDING (the
    sharpest verdict-RAISING mutation: a quarantined agent's every action
    routes to ABSTAIN; lifting that floor needs a human).
  * ``metaguard.governance_weakening``  — a policy write/activation whose named
    axes loosen governance vs the currently active policy (see
    ``weakening_axes``).
  * ``metaguard.capability_widening``   — an agent-registry save that widens
    the agent's capability surface (moves the structural floor).
  * ``metaguard.key_material_mutation`` — in-process signing-key mutations
    (register/clear/replace); authorship of the evidence chain is at stake.
  * ``metaguard.evidence_destruction``  — policy delete/clear (destroys replay
    material the locked spec depends on).

Honesty:
  * These signatures are an enumerated, deterministic rule-set — maturity
    ``research-early``. They are NOT a completeness claim over all weakening
    mutations (e.g. attestation-trust changes are enumerated-deferred in the
    governor census). UNVERIFIED beyond the tests that pin each signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

# Mutation-class constants (shared vocabulary with selfgov.governor — defined
# here so both the governor and the signatures import one leaf module).
POLICY_WRITE = "policy_write"
POLICY_ACTIVATE = "policy_activate"
POLICY_DELETE = "policy_delete"
POLICY_CLEAR = "policy_clear"
PROPOSAL_APPLY = "proposal_apply"
PROPOSAL_ROLLBACK = "proposal_rollback"
GOVERNANCE_ACTIVATE = "governance_activate"
LIFECYCLE_TRANSITION = "lifecycle_transition"
AGENT_SAVE = "agent_save"
KEY_MUTATION = "key_mutation"
GOVERNOR_BINDING = "governor_binding"

# The governor's own (deploy-frozen) policy family — level-0 of the two-level
# stratum. Any stored-policy mutation claiming this family is an impersonation
# of the frozen stratum and floors. Kept in lock-step with
# ``selfgov.governor.GOVERNOR_POLICY_ID`` by a test.
GOVERNOR_POLICY_ID = "reflexive-governor"

_EPS = 1e-9

# Lifecycle states, compared as casefolded strings so this module stays a leaf
# (no ``tex.domain.agent`` import; ``AgentLifecycleStatus`` is a StrEnum whose
# values are the uppercase names).
_TERMINAL = "revoked"
_QUARANTINED = "quarantined"
_RAISED_TARGETS = frozenset({"active", "pending"})
_LOWERED_TARGETS = frozenset({"quarantined", "sleeping", "revoked"})


@dataclass(frozen=True, slots=True)
class MetaguardSignature:
    """One deterministic signature over a typed mutation descriptor."""

    code: str
    reason: str


@dataclass(frozen=True, slots=True)
class MetaguardResult:
    """Aggregate metaguard outcome for one controller-mutation descriptor.

    ``no_change`` — the descriptor describes a byte-identical / target-missing
    write: not a mutation at all, deterministic pass, nothing to govern.
    ``protective_pass`` — the mutation moves the system TOWARD caution
    (quarantine, sleep, standing-governance activation, capability narrowing,
    new registration, stage-write of an inactive snapshot). Denying it would
    itself weaken governance, so it passes deterministically — and is sealed.
    """

    floor: tuple[MetaguardSignature, ...]
    caution: tuple[MetaguardSignature, ...]
    protective_pass: bool
    no_change: bool

    @property
    def fired(self) -> bool:
        return bool(self.floor or self.caution)

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(s.code for s in self.floor) + tuple(
            s.code for s in self.caution
        )


NEUTRAL_METAGUARD = MetaguardResult(
    floor=(), caution=(), protective_pass=False, no_change=False
)


def weakening_axes(
    old: Mapping[str, Any] | None, new: Mapping[str, Any] | None
) -> tuple[str, ...]:
    """Named axes on which ``new`` loosens governance relative to ``old``.

    Deterministic, typed comparisons only. ``permit_threshold`` is the maximum
    fused score that still permits; ``forbid_threshold`` the minimum that
    forbids — RAISING either widens the permissive region. Removing blocked
    terms / recognizers / block severities / sensitive entities removes
    deterministic protection. Missing inputs compare as "no axes" — the gate
    then falls through to the PDP rather than fabricating a signature.
    """
    if not old or not new:
        return ()
    axes: list[str] = []
    for key, direction in (
        ("permit_threshold", +1),
        ("forbid_threshold", +1),
        ("minimum_confidence", -1),
    ):
        try:
            old_v = float(old[key])
            new_v = float(new[key])
        except (KeyError, TypeError, ValueError):
            continue
        if direction > 0 and new_v > old_v + _EPS:
            axes.append(key)
        if direction < 0 and new_v < old_v - _EPS:
            axes.append(key)
    for key in (
        "blocked_terms",
        "enabled_recognizers",
        "deterministic_block_severities",
        "sensitive_entities",
    ):
        old_set = {str(item) for item in (old.get(key) or ())}
        new_set = {str(item) for item in (new.get(key) or ())}
        if old_set - new_set:
            axes.append(key)
    return tuple(axes)


def widened_dimensions(
    old_surface: Mapping[str, Any] | None, new_surface: Mapping[str, Any] | None
) -> tuple[str, ...]:
    """Capability-surface dimensions that WIDEN from ``old`` to ``new``.

    The ``CapabilitySurface`` convention (domain/agent.py): an empty tuple
    means *unrestricted*. A dimension widens when a restriction is dropped
    entirely (non-empty → empty) or when a new allowance is added to an
    existing restriction (additions widen even alongside removals — mixed
    changes fail toward caution). Restricting a previously-unrestricted
    dimension (empty → non-empty) is a NARROWING, never a widening.
    """
    if old_surface is None or new_surface is None:
        return ()
    widened: list[str] = []
    keys = set(old_surface) | set(new_surface)
    for key in sorted(keys):
        old_set = {str(item) for item in (old_surface.get(key) or ())}
        new_set = {str(item) for item in (new_surface.get(key) or ())}
        if not old_set:
            continue  # was unrestricted; adding a restriction narrows
        if not new_set:
            widened.append(key)  # restriction removed → unrestricted
        elif new_set - old_set:
            widened.append(key)  # new allowance added
    return tuple(widened)


def _lifecycle_signatures(
    old_status: str | None, new_status: str | None
) -> tuple[tuple[MetaguardSignature, ...], tuple[MetaguardSignature, ...]]:
    """(floor, caution) signatures for a lifecycle state pair."""
    floor: list[MetaguardSignature] = []
    caution: list[MetaguardSignature] = []
    old_s = (old_status or "").strip().casefold()
    new_s = (new_status or "").strip().casefold()
    if not old_s or not new_s or old_s == new_s:
        return (), ()
    if old_s == _TERMINAL:
        floor.append(
            MetaguardSignature(
                code="metaguard.revoked_resurrection",
                reason=(
                    f"lifecycle transition out of terminal REVOKED "
                    f"({old_status} -> {new_status}) would falsify the "
                    f"irreversible day-90 kill"
                ),
            )
        )
    elif old_s == _QUARANTINED and new_s in _RAISED_TARGETS:
        caution.append(
            MetaguardSignature(
                code="metaguard.quarantine_lift",
                reason=(
                    f"quarantine lift ({old_status} -> {new_status}) raises "
                    f"the agent's verdict floor (QUARANTINED routes every "
                    f"action to ABSTAIN); requires a human hold resolution"
                ),
            )
        )
    return tuple(floor), tuple(caution)


def evaluate_metaguard(descriptor: Any) -> MetaguardResult:
    """Classify one controller-mutation descriptor against the signature set.

    ``descriptor`` is duck-typed (``selfgov.governor.MutationDescriptor``):
    ``mutation_class``, ``subject_id``, ``payload``. Pure; never raises on
    missing payload fields (absent facts simply fire no signature — the gate
    then still routes the mutation through the PDP, fail-closed).
    """
    payload: Mapping[str, Any] = getattr(descriptor, "payload", None) or {}
    mutation_class = str(getattr(descriptor, "mutation_class", ""))

    if payload.get("no_change") is True:
        return MetaguardResult(
            floor=(), caution=(), protective_pass=False, no_change=True
        )

    floor: list[MetaguardSignature] = []
    caution: list[MetaguardSignature] = []

    # ── FLOOR: governor self-target (level-0, deploy-frozen) ───────────────
    targets_governor = (
        mutation_class == GOVERNOR_BINDING
        or str(payload.get("policy_id") or "") == GOVERNOR_POLICY_ID
        or str(payload.get("new_policy_id") or "") == GOVERNOR_POLICY_ID
    )
    if targets_governor:
        floor.append(
            MetaguardSignature(
                code="metaguard.governor_self_target",
                reason=(
                    "mutation targets the reflexive governor's deploy-frozen "
                    "stratum (its policy family or binding); level-0 is "
                    "immutable in-process by construction"
                ),
            )
        )

    # ── lifecycle pair rules (apply to set_lifecycle AND to saves that carry
    #    a lifecycle flip — registry.save replaces the record wholesale) ─────
    lc_floor, lc_caution = _lifecycle_signatures(
        payload.get("old_status"), payload.get("new_status")
    )
    floor.extend(lc_floor)
    caution.extend(lc_caution)

    # ── CAUTION: named weakening axes (computed by the descriptor builder
    #    via ``weakening_axes`` — typed comparisons, never scores) ──────────
    axes = tuple(payload.get("weakening_axes") or ())
    if axes:
        caution.append(
            MetaguardSignature(
                code="metaguard.governance_weakening",
                reason=(
                    "mutation loosens governance vs the active policy on "
                    f"named axes: {', '.join(str(a) for a in axes)}"
                ),
            )
        )

    widened = tuple(payload.get("widened_dimensions") or ())
    if widened:
        caution.append(
            MetaguardSignature(
                code="metaguard.capability_widening",
                reason=(
                    "agent save widens the capability surface on: "
                    f"{', '.join(str(w) for w in widened)} (moves the "
                    "structural floor)"
                ),
            )
        )

    if mutation_class == KEY_MUTATION:
        caution.append(
            MetaguardSignature(
                code="metaguard.key_material_mutation",
                reason=(
                    "in-process signing-key mutation (evidence-chain "
                    "authorship is at stake); requires a human hold resolution"
                ),
            )
        )

    if mutation_class in (POLICY_DELETE, POLICY_CLEAR):
        caution.append(
            MetaguardSignature(
                code="metaguard.evidence_destruction",
                reason=(
                    "policy delete/clear destroys replay material (the locked "
                    "spec reconstitutes historical decisions from snapshots)"
                ),
            )
        )

    # ── protective pass: mutations that move TOWARD caution ───────────────
    new_s = str(payload.get("new_status") or "").strip().casefold()
    protective = not floor and not caution and (
        mutation_class == GOVERNANCE_ACTIVATE
        or (mutation_class == LIFECYCLE_TRANSITION and new_s in _LOWERED_TARGETS)
        or payload.get("new_registration") is True
        or payload.get("stage_write") is True
        or payload.get("narrowing") is True
    )

    return MetaguardResult(
        floor=tuple(floor),
        caution=tuple(caution),
        protective_pass=protective,
        no_change=False,
    )


__all__ = [
    "AGENT_SAVE",
    "GOVERNANCE_ACTIVATE",
    "GOVERNOR_BINDING",
    "GOVERNOR_POLICY_ID",
    "KEY_MUTATION",
    "LIFECYCLE_TRANSITION",
    "MetaguardResult",
    "MetaguardSignature",
    "NEUTRAL_METAGUARD",
    "POLICY_ACTIVATE",
    "POLICY_CLEAR",
    "POLICY_DELETE",
    "POLICY_WRITE",
    "PROPOSAL_APPLY",
    "PROPOSAL_ROLLBACK",
    "evaluate_metaguard",
    "weakening_axes",
    "widened_dimensions",
]
