"""Confirm a hypothesis → ONE sealed L2 correction. Or don't → nothing changes.

This is the only place L3 writes anything, and it writes through L2 — it never
invents its own profile store. A confirmed habit becomes exactly one
``ProfileMemory.apply_correction`` call, so it inherits L2's whole constitution:
the correction is sealed, citable, revocable, tightening-only (``SEALED`` refused),
and provenance-gated (a named operator validated before the write). Confirming a
habit therefore CANNOT do anything an operator could not already do by hand — L3
only saves them from re-deriving the pattern themselves.

THE NO-OP IS THE DEFAULT. If a hypothesis is not confirmed, nothing here runs and
nothing changes — the miner is read-only and a surfaced hypothesis is inert. There
is no "auto-apply", no background confirmation, no path from mining to a verdict
change that does not pass through an explicit human :func:`confirm_hypothesis`
call. :func:`decline_hypothesis` exists only to record (in the caller's audit, not
in any store L3 owns) that a human looked and said no; it writes nothing.

CALIBRATION (L1) IS THE ROUTE'S JOB, NOT OURS — AND WE DON'T FAKE IT. A
decision-backed correction feeds L1's per-tenant conformal floor, but that feed
needs the real ``Decision.final_score``, which only the SERVER-SIDE lookup in L2's
confirm/correct ROUTE has (``tex.api.presence_profile_routes``, per L2's docs). L3
does not have the ``Decision`` object, so it does NOT feed L1 itself — doing so with
a value it cannot read would be exactly the kind of unprovable claim Tex exists to
refuse. Instead, :func:`confirm_hypothesis` passes ``decision_id`` straight into
``apply_correction``; when the orchestrator surfaces habits through L2's route, that
route does the server-side lookup and feeds L1. The receipt carries the
``decision_id`` so the caller can see which decision the calibration feed will key
on. (An out-of-route deployment that wants L1 fed must perform the server-side
``Decision`` lookup itself — a documented follow-up, not a fake hook here.)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from tex.presence.contract import EvidenceRef

from tex.presence.habits.types import HabitHypothesis

_logger = logging.getLogger(__name__)

__all__ = ["HabitConfirmation", "HabitDecline", "confirm_hypothesis", "decline_hypothesis"]


@dataclass(frozen=True, slots=True)
class HabitConfirmation:
    """The receipt of a confirmed habit: the hypothesis it came from, the L2
    correction it produced (citable), and who/when. Re-verifiable: ``profile_ref``
    points at the sealed L2 fact."""

    hypothesis_id: str
    tenant: str
    subject_key: str
    profile_ref: EvidenceRef
    operator: str
    confirmed_at: str
    decision_id: str | None = None
    """The governance decision this habit is about, if any. Passed into the L2
    correction so L2's route can key L1's calibration feed on it. L3 does not feed
    L1 itself (it lacks the ``Decision.final_score``)."""


@dataclass(frozen=True, slots=True)
class HabitDecline:
    """An audit record that a human declined a hypothesis. Writes NOTHING to any
    store — it exists so a caller can log the human's "no" without confusing it for
    a state change."""

    hypothesis_id: str
    tenant: str
    subject_key: str
    operator: str
    declined_at: str


def confirm_hypothesis(
    *,
    hypothesis: HabitHypothesis,
    profile: Any,
    operator: str,
    decision_id: str | None = None,
) -> HabitConfirmation:
    """Seal a confirmed hypothesis as ONE L2 correction and return its receipt.

    ``profile`` is a duck-typed :class:`tex.presence.profile.types.ProfileMemory`
    (the orchestrator's ``app.state.presence_profile``). ``operator`` MUST be the
    SERVER-SIDE identity of the confirming human — never a value from a request body
    (same discipline as ``/decisions/{id}/seal``); we validate it is non-empty and
    let L2's write-gate enforce the rest.

    Fail-closed: raises ``ValueError`` (writing nothing) on a missing operator or a
    malformed hypothesis. Propagates L2's ``ValueError`` if L2 refuses the
    correction (e.g. an inflating tier) — defence in depth on top of L3's own
    refusal to ever construct one.
    """
    if not operator or not operator.strip():
        raise ValueError("confirm_hypothesis requires a non-empty server-side operator identity")
    if profile is None:
        raise ValueError("confirm_hypothesis requires a ProfileMemory to write through")
    action = getattr(hypothesis, "action", None)
    if action is None or action.proposed_tier is None:
        raise ValueError("hypothesis has no tightening action to confirm")

    # The single write — through L2, never around it. subject_key is already the
    # normalised handle L2 keys corrections on, so the ceiling lands on exactly the
    # subject the next verdict for this tenant will be keyed by. decision_id rides
    # through so L2's route can feed L1's calibration on the server-side Decision.
    profile_ref = profile.apply_correction(
        tenant=hypothesis.tenant,
        claim_id=hypothesis.subject_key,
        corrected_tier=action.proposed_tier,
        operator=operator.strip(),
        statement=action.statement,
        decision_id=decision_id,
    )

    return HabitConfirmation(
        hypothesis_id=hypothesis.hypothesis_id,
        tenant=hypothesis.tenant,
        subject_key=hypothesis.subject_key,
        profile_ref=profile_ref,
        operator=operator.strip(),
        confirmed_at=datetime.now(UTC).isoformat(),
        decision_id=decision_id,
    )


def decline_hypothesis(
    *, hypothesis: HabitHypothesis, operator: str
) -> HabitDecline:
    """Record (for the caller's audit only) that a human declined a hypothesis.
    Writes nothing — the no-op IS the behaviour; this just makes it auditable."""
    return HabitDecline(
        hypothesis_id=hypothesis.hypothesis_id,
        tenant=hypothesis.tenant,
        subject_key=hypothesis.subject_key,
        operator=(operator or "").strip(),
        declined_at=datetime.now(UTC).isoformat(),
    )
