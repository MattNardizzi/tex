"""
Sanctions and restorative paths.

A sanction makes deviation from legal states unprofitable. A restorative
path returns the system to a legal state.

Reference
---------
arxiv 2601.11369 (Bracale Syrnikov et al., 2026) — Section 6.2.2 / Table 4
"Sanction Ladder": Warning, Fine, Credit (restorative), Suspension. Section
4.1 "Deterrence as the mechanism-level objective" gives the calibration
condition pS >= Δπ — sanction expected loss must dominate per-round collusive
rent. arxiv 2601.10599 (Pierucci et al., 2026) §5.1 formalises this as the
Pigouvian correction u_i^I(a) = u_i(a) - S_i(a).

Section 4.2 "Restorative paths" enumerates three restoration kinds:
  - time-driven expiry (e.g., warning -> active after duration_rounds)
  - credit-based rehabilitation (fined -> credited -> active)
  - "clean" restoration (fined -> active without credit)

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass


# ABDICO rule IDs are stable join identifiers per arxiv 2601.11369 §4.1.
# Edge keys follow the format "<RULE_ID>:<from_state>-><to_state>" so a
# single rule can fan out to multiple transitions while remaining auditable.


@dataclass(frozen=True, slots=True)
class Sanction:
    """
    A manifest-declared sanction. The Controller looks these up by
    sanction_id when a transition's sanction_on_violation fires.

    Fields
    ------
    sanction_id
        Stable identifier referenced by LegalTransition.sanction_id.
    description
        Human-legible rationale (rendered into Institutional notices per
        arxiv 2601.11369 Appendix C).
    cost_to_actor
        Expected discounted loss to the sanctioned actor (the S in
        pS >= Δπ). Units are caller-defined (currency, utility, profit
        fraction).
    cost_to_system
        Externality cost to the broader ecosystem (e.g., welfare loss from
        a suspension). Used by the intervention engine for cost-bounded
        selection (P2; see tex.intervention.bounded_compromise).
    enforcement_action
        The mechanical action the Controller takes. Maps onto the paper's
        sanction ladder (Table 4):
          - "warning"                -> public notice, no economic penalty
          - "fine"                   -> monetary penalty (use fine_rate + tier)
          - "suspension"             -> remove actor for duration_rounds
          - "revoke_capability"      -> Tex extension: revoke a capability
          - "reduce_trust"           -> Tex extension: reduce trust score
          - "require_human_approval" -> Tex extension: gate next N actions
          - "block"                  -> drop the proposed event
          - "quarantine"             -> sandbox the actor
    tier
        Sanction tier (1, 2, 3) for fine-type sanctions per Table 5.
        None for non-fine actions.
    fine_rate
        Fraction of round profits to deduct (0.35, 0.75, 1.00 per Table 5).
        None for non-fine actions.
    fine_floor
        Minimum monetary penalty regardless of round profits ($200 per
        Table 5). None for non-fine actions.
    duration_rounds
        For suspension: how many rounds the actor is removed (paper uses 5).
        None for instantaneous actions.

    TODO(P2): wire fine_rate / fine_floor / tier into a numeric sanction
        engine that integrates with tex.intervention.engine. For Thread 12
        the Controller only records the sanction_id; numeric application
        is the responsibility of downstream cost-bounded selection.
    """

    sanction_id: str
    description: str
    cost_to_actor: float
    cost_to_system: float
    enforcement_action: str
    tier: int | None = None
    fine_rate: float | None = None
    fine_floor: float | None = None
    duration_rounds: int | None = None


@dataclass(frozen=True, slots=True)
class RestorativePath:
    """
    A manifest-declared path back to a legal state.

    Per arxiv 2601.11369 §4.2 "Restorative paths": "Restoration is itself
    part of the graph: sanctions are reversible when evidence improves."
    Three kinds documented in the paper:
      - "expiry"            -> time-driven (warning->active, suspended->active)
      - "credit_relief"     -> credit-based (fined->credited->active)
      - "clean_restoration" -> direct restoration (fined->active w/o credit)

    Fields
    ------
    path_id
        Stable identifier referenced by LegalTransition.restorative_path_id
        and by ControllerDecision.restorative_path_id.
    description
        Human-legible explanation (rendered into "REHABILITATED" notices
        per Appendix C.3).
    restorative_event_kinds
        EventKinds whose emission contributes to the restoration condition.
        For "expiry" paths this is typically empty (time alone restores).
        For "credit_relief" this lists the events that earn credits.
    target_legal_state_id
        The state the actor returns to (almost always "active").
    restoration_kind
        Which of the three paper-defined kinds this path implements.
    condition
        Path-specific parameters. For expiry: {"duration_rounds": int}.
        For credit_relief: {"clean_rounds_required": int, "credits_required": int}.
        For clean_restoration: {"clean_rounds_required": int}.
        Per Table 5 paper defaults: clean_rounds_required=2,
        credits_required=1, decay_window=10.

    TODO(P2): full credit accounting (earned/spent/decay window=10 rounds
        per Table 5) lives in a future CreditLedger; Thread 12 only models
        the path declaration, not the credit balance arithmetic.
    """

    path_id: str
    description: str
    restorative_event_kinds: tuple[str, ...]
    target_legal_state_id: str
    restoration_kind: str = "expiry"
    condition: dict | None = None


_VALID_RESTORATION_KINDS: frozenset[str] = frozenset(
    {"expiry", "credit_relief", "clean_restoration"}
)

_VALID_ENFORCEMENT_ACTIONS: frozenset[str] = frozenset(
    {
        "warning",
        "fine",
        "suspension",
        "revoke_capability",
        "reduce_trust",
        "require_human_approval",
        "block",
        "quarantine",
    }
)


def validate_sanction(s: Sanction) -> None:
    """Raise ValueError if the Sanction is structurally invalid."""
    if not s.sanction_id:
        raise ValueError("Sanction.sanction_id must be non-empty")
    if s.enforcement_action not in _VALID_ENFORCEMENT_ACTIONS:
        raise ValueError(
            f"Sanction.enforcement_action {s.enforcement_action!r} not in "
            f"{sorted(_VALID_ENFORCEMENT_ACTIONS)}"
        )
    if s.cost_to_actor < 0 or s.cost_to_system < 0:
        raise ValueError("Sanction costs must be non-negative")
    if s.enforcement_action == "fine":
        if s.tier is None or s.tier not in (1, 2, 3):
            raise ValueError("fine sanction requires tier in {1,2,3}")
        if s.fine_rate is None or not (0.0 <= s.fine_rate <= 1.0):
            raise ValueError("fine sanction requires 0<=fine_rate<=1")
    if s.enforcement_action == "suspension":
        if s.duration_rounds is None or s.duration_rounds <= 0:
            raise ValueError("suspension sanction requires positive duration_rounds")


def validate_restorative_path(p: RestorativePath) -> None:
    """Raise ValueError if the RestorativePath is structurally invalid."""
    if not p.path_id:
        raise ValueError("RestorativePath.path_id must be non-empty")
    if p.restoration_kind not in _VALID_RESTORATION_KINDS:
        raise ValueError(
            f"restoration_kind {p.restoration_kind!r} not in "
            f"{sorted(_VALID_RESTORATION_KINDS)}"
        )
    if not p.target_legal_state_id:
        raise ValueError("RestorativePath.target_legal_state_id must be non-empty")
