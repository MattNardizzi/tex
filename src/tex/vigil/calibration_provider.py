"""
[Architecture: Cross-cutting (Vigil cognition)] — the calibration-hold provider.

Learning does not get its own state, its own list, or its own dashboard. A
calibration proposal surfaces as a *second kind of hold* inside the existing
Held state: one proposal at a time, pull-only, the gentlest priority. It maps
to the exact held-card payload the decision provider produces, so the surface
renders it with the same gesture and the same seal — only ``hold.kind`` tells
them apart.

A held *decision* (money, an irreversible action) always outranks a proposal.
This provider is therefore composed *after* the decision provider
(``CompositeHeldProvider``, decision-first): it is only consulted when nothing
is waiting on a human right now, and it never interrupts a held decision or
breaks silence with urgency.

The card speaks meaning, never numbers. The proposed thresholds and the
anytime-valid safety bound travel in the payload as pure handles
(``proposed_change``, ``safety_bound``) — the surface raises them only when the
operator reaches for proof, then lets them dissolve.

Read-only and defensive: a malformed proposal or an empty store yields
``None`` and the vigil falls through to its posture-true line.
"""

from __future__ import annotations

from typing import Any

__all__ = ["CalibrationProposalVigilProvider", "CompositeHeldProvider"]


class CompositeHeldProvider:
    """Tries each provider's ``current`` in order; returns the first hit.

    Order is precedence. The decision provider is first so a real held
    decision always wins the single held-card slot over a calibration
    proposal — a proposal never preempts a decision waiting on a human.
    """

    __slots__ = ("_providers",)

    def __init__(self, providers: list[Any]) -> None:
        self._providers = [p for p in providers if p is not None]

    def current(self, tenant: str | None) -> dict[str, Any] | None:
        for provider in self._providers:
            current = getattr(provider, "current", None)
            if not callable(current):
                continue
            try:
                payload = current(tenant)
            except Exception:  # noqa: BLE001 — never break the vigil cycle
                payload = None
            if payload is not None:
                return payload
        return None


class CalibrationProposalVigilProvider:
    """Adapts the freshest pending CalibrationProposal into the held-card seam."""

    __slots__ = ("_store",)

    def __init__(self, store: Any) -> None:
        self._store = store

    def current(self, tenant: str | None) -> dict[str, Any] | None:
        store = self._store
        if store is None:
            return None
        list_pending = getattr(store, "list_pending", None)
        if not callable(list_pending):
            return None
        try:
            pending = (
                list_pending(tenant_id=tenant) if tenant else list_pending()
            )
        except TypeError:
            try:
                pending = list_pending()
            except Exception:  # noqa: BLE001
                return None
        except Exception:  # noqa: BLE001
            return None

        pending = list(pending or [])
        if not pending:
            return None

        # Freshest still-valid proposal. The store returns PENDING only;
        # newest by created_at is the one whose evidence is current.
        proposal = max(
            pending,
            key=lambda p: getattr(p, "created_at", None) or 0,
        )
        return self._to_payload(proposal)

    # ----- mapping -------------------------------------------------------

    @staticmethod
    def _to_payload(proposal: Any) -> dict[str, Any]:
        diff = getattr(proposal, "diff", None)
        direction = _direction(diff)
        sentence = (
            f"I've watched enough of your decisions to want to {direction} "
            "when I permit. The change is mine to propose, yours to allow."
        )

        ope = (getattr(proposal, "metadata", {}) or {}).get("ope")
        detail = _safety_sentence(ope)

        proposed_change = None
        if diff is not None:
            proposed_change = {
                "permit_before": diff.permit_threshold_before,
                "permit_after": diff.permit_threshold_after,
                "forbid_before": diff.forbid_threshold_before,
                "forbid_after": diff.forbid_threshold_after,
                "min_confidence_before": diff.minimum_confidence_before,
                "min_confidence_after": diff.minimum_confidence_after,
            }

        proposal_id = str(getattr(proposal, "proposal_id", "") or "") or None

        hold = {
            "kind": "calibration",
            "hold_type": "EPISTEMIC",
            "resolution_mode": "HUMAN_JUDGMENT",
            "resolving_question": "Do you want me to sharpen this way?",
            "sentence": sentence,
            "detail": detail,
            "proposal_id": proposal_id,
            "proposed_change": proposed_change,
            "safety_bound": ope,
        }

        return {
            "id": proposal_id,
            "sentence": sentence,
            "detail": detail,
            "dimension": "learning",
            "surprise": 0.0,
            "agent": None,
            "proof_ref": {"kind": "proposal", "id": proposal_id},
            "anchor_sha256": None,
            "hold": hold,
        }


def _direction(diff: Any) -> str:
    """Speak the meaning of the move, not the numbers.

    A lower permit threshold means Tex permits more readily (loosen); higher
    means it holds more (tighten). Falls back to a neutral verb when the diff
    is absent or flat.
    """
    if diff is None:
        return "recalibrate"
    try:
        before = float(diff.permit_threshold_before)
        after = float(diff.permit_threshold_after)
    except (TypeError, ValueError):
        return "recalibrate"
    if after < before:
        return "loosen"
    if after > before:
        return "tighten"
    return "recalibrate"


def _safety_sentence(ope: dict[str, Any] | None) -> str | None:
    """The provable grounding line, drawn from the anytime-valid OPE bound."""
    if not ope:
        return None
    permits = ope.get("counterfactual_permits")
    ub = ope.get("upper_bound")
    newly = ope.get("newly_released_unsafe")
    if permits is None or ub is None:
        return None
    pct = f"{float(ub) * 100:.0f}%"
    base = (
        f"Across {permits} of your decisions, I can bound the unsafe-release "
        f"rate of this change at no more than {pct} — and prove it."
    )
    if newly:
        base += f" {newly} I currently hold would have reached the world."
    return base
