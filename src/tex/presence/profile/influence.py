"""How a profile CORRECTION influences the next decision — and the proof it can
only ever TIGHTEN.

This is the load-bearing constitution piece. A correction is applied as a
POST-GATE MONOTONE FOLD: after the truth-gate has produced its verdicts (from
sealed rows alone — a correction never touches the recompute), each verdict whose
subject has an active correction is capped at the correction's ceiling via
:func:`tex.presence.contract.tighten`. Because the only combinator is ``tighten``
(the more-cautious of two tiers), there is NO code path by which a correction can
raise a tier. "Becomes more yours" therefore can never mean "becomes more confident
than it can prove."

THE STABLE SUBJECT KEY (why a correction caps the SAME thing asked again)
------------------------------------------------------------------------
A correction is scoped to a SUBJECT. The naive subject — the brain's ``claim_id``
— is NOT stable across re-asks: it is the LLM's emitted string or a positional
``claim-{index}`` fallback (``grounded_brain.py:179``), so a correction caps a
claim within ONE answer but SILENTLY fails to cap the same thing asked again. The
next-most-obvious subject — the verdict's grounded evidence ``record_id``s — is
ALSO unstable: an AGGREGATE binds a witness SET capped at 64 that grows/truncates
as rows arrive (``queries.py`` ``_count_decisions`` / ``EVIDENCE_CAP``), and a
discovery/event claim binds the moving LATEST sequence (``evidence.py``
``ref_for_discovery_entry``) — so the evidence record-id set changes across re-asks
even though the QUESTION is the same. (Rejected for exactly this reason; keying on
it would reintroduce the silent-cap-failure this module exists to prevent.)

:func:`stable_subject_key` therefore keys on the gate's ROUTING identity
(``routed.query.key`` + ``routed.target``) — a fixed registry entry that is stable
across re-asks AND as rows change ("the tier for the forbid-count question" / "for
agent X's status"). EXACT match only — no embeddings/similarity (similarity is what
causes scope-creep).

The read side does a MONOTONE dual-lookup: it ``tighten``-folds the ceiling for the
STABLE routing subject with the ceiling for the LEGACY subject derived from THIS
re-ask's ``claim_id`` (``_norm_subject(v.claim_id)``). What each arm buys, stated
precisely (no overclaim):

  * **Stable arm** — a correction WRITTEN with ``subject_key=stable_subject_key(...)``
    (the operator-UI path, surfaced via ``compose._surface_object``) is robust
    across re-asks and row changes. This is the fix.
  * **Legacy arm** — preserves the PRE-CHANGE behaviour EXACTLY: a correction
    stored under a bare ``claim_id`` matches only when the brain re-emits that
    SAME ``claim_id`` string. It does NOT retroactively stabilise legacy
    corrections — the legacy key is the volatile one this module exists to retire,
    and nothing persists the original ``claim_id`` to recover it across drift (see
    ``test_legacy_claim_id_correction_silently_fails_across_reask_but_stable_key_holds``).
    Its only job is non-regression (existing/legacy callers keep their old
    behaviour) — always pass ``subject_key`` for a correction that must survive a
    re-ask.

Dual-lookup only ever ADDS a match (never removes one), and ``tighten``-folding two
ceilings can still only LOWER a tier — so it is monotone-safe regardless.

KNOWN GAP (disclosed, deferred to L3): the habit-confirm writer
(``tex.presence.habits.confirm``) currently writes corrections under a mined
claim-TEXT subject via the legacy ``claim_id`` arm — so habit-confirmed corrections
inherit the legacy arm's claim_id-dependence and are NOT yet stable across re-asks.
Closing that needs the L3 habit pipeline to carry the routing identity (it mines
pre-gate, so it cannot call ``stable_subject_key`` today); it is out of this track's
lane and tracked in ``COORDINATION.md``.

NO TIME-DECAY (deliberate, conservative): a correction persists until ``revoke`` —
it never expires on its own. That is the safe default: a tightening should not
silently lapse. If decay is ever added, re-inflation back to a HIGHER tier must
require a fresh POSITIVE seal through the gate (real evidence), NEVER merely elapsed
time — letting a tier rise because a clock advanced would be exactly the "speak
something it cannot currently prove" failure the monotone fold forbids.

Two honesty rules make every emitted verdict coherent with the contract:

  * **Never fabricate a DERIVED floor.** A ``SEALED`` verdict carries no
    ``correctness_floor``; a ``DERIVED`` ceiling applied to it would imply a
    statistical floor the gate never computed. So a cap that would land on
    ``DERIVED`` without a floor present drops to ``ABSTAIN`` instead. (In practice
    every *effective* correction lands on ABSTAIN — it suppresses the claim, which
    ``compose.py`` then strips — except a ``DERIVED`` claim capped at ``DERIVED``,
    a no-op.)
  * **Evidence empty iff ABSTAIN.** When a cap lands on ``ABSTAIN`` the verdict's
    evidence/floor/coverage are cleared, preserving the contract invariant.

Wiring (the orchestrator's ONE additive line — L2 does not edit ``run_presence``):

    detailed = gate.evaluate_detailed(request=..., tenant=tenant, draft=draft,
                                      claims=claims, facts=facts)
    detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed,
                                         profile=app.state.presence_profile)   # ← here
    envelope = build_envelope(detailed, templated_abstain=...)
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from tex.presence.contract import PresenceTier, PresenceVerdict, tighten
from tex.presence.profile.types import ProfileFacts, ProfileMemory, _norm_subject

_logger = logging.getLogger(__name__)

__all__ = [
    "cap_verdict",
    "apply_corrections_to_verdicts",
    "apply_profile_corrections",
    "stable_subject_key",
]

_CORRECTION_TAG = "profile-correction"


def stable_subject_key(evaluation: Any) -> str:
    """The STABLE subject a correction attaches to — derived POST-GATE from the
    gate's ROUTING identity, NOT the volatile brain ``claim_id`` and NOT the
    grounded evidence record-id set (see the module docstring for why both of
    those drift across re-asks).

    Reads a duck-typed :class:`~tex.presence.gate.gate.ClaimEvaluation` (kept
    decoupled from the gate types so this module stays unit-testable in isolation):
    ``evaluation.routed.query.{key,kind}`` + ``evaluation.routed.target``. The same
    question routes to the same registry query regardless of how the brain phrased
    it or how many rows currently match, so the key is stable across re-asks. EXACT
    match only.

    Fallback (only reached for an unrouted claim, which is ABSTAIN and therefore
    never spoken or corrected): key on ``(claim_kind + normalised claim text)``.
    """
    routed = getattr(evaluation, "routed", None)
    query = getattr(routed, "query", None)
    key = getattr(query, "key", None)
    if key:
        qkind = getattr(getattr(query, "kind", None), "value", None) or "?"
        parts = ["q", str(qkind), str(key)]
        target = getattr(routed, "target", None)
        if target is not None:
            parts.append(str(target))
        return _norm_subject(":".join(parts))
    # Unrouted (ABSTAIN) — never corrected in practice; key defensively on text.
    claim = getattr(evaluation, "claim", None)
    kind = getattr(getattr(claim, "kind", None), "value", "unknown")
    text = getattr(claim, "text_span", "") or ""
    return _norm_subject(f"t:{kind}:{text}")


def cap_verdict(
    verdict: PresenceVerdict, ceiling: PresenceTier | None, *, record_id: str | None = None
) -> PresenceVerdict:
    """Return ``verdict`` capped at ``ceiling`` (monotone — only ever lowers).

    ``ceiling=None`` (no correction for this subject) → unchanged. Never raises a
    tier; never fabricates a DERIVED floor; clears evidence/floor/coverage when the
    cap lands on ABSTAIN (contract: evidence empty iff ABSTAIN).
    """
    if ceiling is None:
        return verdict
    capped = tighten(verdict.tier, ceiling)
    if capped is PresenceTier.DERIVED and verdict.correctness_floor is None:
        # Would be a floor-less DERIVED — refuse to fabricate a floor; suppress.
        capped = PresenceTier.ABSTAIN
    if capped is verdict.tier:
        return verdict  # no-op (ceiling no stricter than the gate's tier)

    tag = _CORRECTION_TAG if record_id is None else f"{_CORRECTION_TAG}:{record_id}"
    reason = f"{verdict.reason};{tag}" if verdict.reason else tag
    if capped is PresenceTier.ABSTAIN:
        return replace(
            verdict,
            tier=PresenceTier.ABSTAIN,
            evidence=(),
            correctness_floor=None,
            coverage_mode=None,
            reason=reason,
        )
    # capped is DERIVED with a floor already present (a DERIVED→DERIVED edge that
    # tighten() left unchanged is handled above; this branch is defensive).
    return replace(verdict, tier=capped, reason=reason)


def apply_corrections_to_verdicts(
    *, tenant: str, verdicts: tuple[PresenceVerdict, ...], profile: ProfileMemory | None
) -> tuple[PresenceVerdict, ...]:
    """Cap a tuple of verdicts by this tenant's active corrections. Decoupled from
    the gate (contract types only) so it is unit-testable in isolation. Fail-open
    to the UNCORRECTED verdicts on any profile error — a profile fault must never
    *raise* a tier, and equally must never crash the voice path; the gate's verdict
    already stands on its own."""
    if profile is None or not verdicts:
        return verdicts
    facts = _safe_recall(profile, tenant)
    if facts is None or not facts.facts:
        return verdicts
    out = []
    for v in verdicts:
        # Verdict-only helper: no routing is available here, so it can only consult
        # the LEGACY claim_id subject. The hot path (apply_profile_corrections) keys
        # on the STABLE routing subject; this stays for unit tests / legacy callers.
        subject = _norm_subject(v.claim_id)
        ceiling = facts.tier_ceiling_for_subject(subject)
        out.append(cap_verdict(v, ceiling, record_id=_first_correction_id_for_subject(facts, subject)))
    return tuple(out)


def apply_profile_corrections(
    *, tenant: str | None, evaluations: tuple[Any, ...], profile: ProfileMemory | None
) -> tuple[Any, ...]:
    """The orchestrator seam. Cap each ``ClaimEvaluation``'s verdict by this
    tenant's active corrections, returning a new tuple (the ``recompute``/``routed``
    fields are carried through, so ``compose.build_envelope`` strips a
    correction-suppressed claim exactly as it strips any ABSTAIN).

    Fail-open to the UNCORRECTED evaluations on any error or when ``tenant``/
    ``profile`` is absent — a profile fault may never raise a tier or break voice.
    """
    if profile is None or tenant is None or not evaluations:
        return evaluations
    facts = _safe_recall(profile, tenant)
    if facts is None:
        return evaluations
    try:
        if not facts.facts:  # attribute access guarded — a malformed ProfileFacts.facts must not escape
            return evaluations
        out = []
        for e in evaluations:
            v = e.verdict
            ceiling, record_id = _resolve_correction(facts, e)
            if ceiling is None:
                out.append(e)
                continue
            capped = cap_verdict(v, ceiling, record_id=record_id)
            out.append(e if capped is v else replace(e, verdict=capped))
        return tuple(out)
    except Exception:  # noqa: BLE001 — never break the voice path; keep gate verdicts
        _logger.warning("apply_profile_corrections failed; using uncorrected verdicts", exc_info=True)
        return evaluations


def _resolve_correction(facts: ProfileFacts, evaluation: Any) -> tuple[PresenceTier | None, str | None]:
    """The ceiling (and audit record_id) for one evaluation, as the MONOTONE
    ``tighten``-fold of the STABLE routing subject and the LEGACY ``claim_id``
    subject. Folding two ceilings can only ever lower a tier, so dual-lookup keeps
    legacy-keyed corrections working without any risk of inflation."""
    v = evaluation.verdict
    subjects = [stable_subject_key(evaluation)]
    legacy = _norm_subject(getattr(v, "claim_id", "") or "")
    if legacy and legacy not in subjects:
        subjects.append(legacy)

    ceiling: PresenceTier | None = None
    record_id: str | None = None
    for subject in subjects:
        c = facts.tier_ceiling_for_subject(subject)
        if c is None:
            continue
        ceiling = c if ceiling is None else tighten(ceiling, c)
        if record_id is None or c is ceiling:
            # Attribute the tag to the subject that authored the (current) ceiling.
            record_id = _first_correction_id_for_subject(facts, subject) or record_id
    return ceiling, record_id


def _safe_recall(profile: ProfileMemory, tenant: str) -> ProfileFacts | None:
    try:
        return profile.recall_profile(tenant=tenant)
    except Exception:  # noqa: BLE001
        _logger.warning("profile recall failed; no corrections applied", exc_info=True)
        return None


def _first_correction_id_for_subject(facts: ProfileFacts, subject_key: str) -> str | None:
    """The record_id of the most-cautious active correction stored under an
    already-resolved ``subject_key`` (for the audit tag on the lowered verdict's
    reason)."""
    best: Any | None = None
    for f in facts.corrections():
        if f.subject_key == subject_key and f.corrected_tier is not None:
            if best is None or _stricter(f.corrected_tier, best.corrected_tier):
                best = f
    return best.record_id if best is not None else None


def _stricter(a: PresenceTier, b: PresenceTier | None) -> bool:
    if b is None:
        return True
    return tighten(a, b) is a and a is not b
