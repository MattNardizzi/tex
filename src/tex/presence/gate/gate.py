"""``PresenceTruthGate`` — the deterministic, external truth-gate (Session 2).

For each candidate :class:`PresenceClaim` the gate emits exactly one monotone
:class:`PresenceVerdict`. The verdict's tier is a PURE FUNCTION of what the gate
itself recomputed from sealed rows — never of what the draft asserts. That is the
whole threat model: a hostile draft can route a claim to a query and it can
trigger a *value mismatch*, but a mismatch only ever LOWERS a tier toward ABSTAIN
(monotone, fail-closed). No code path lets a property of the draft RAISE a tier.

Tier law (confident → cautious: SEALED > DERIVED > ABSTAIN):

  * ABSTAIN — no query matched, the match was ambiguous, the recompute found no
    basis, a sealed kind produced no evidence, or the draft span contradicts the
    recomputed value (the draft can only push toward caution).
  * DERIVED — a DERIVED claim the gate computed with a conformal correctness
    floor + honest coverage mode.
  * SEALED — an AGGREGATE/ENTITY/EVENT claim recomputed from rows, with real
    EvidenceRefs bound.

The gate is the SOLE author of the spoken phrasing for a supported claim
(``Recompute.canonical_phrase``); ``compose.py`` speaks that, never the draft's
words — so injected text in a draft cannot reach the user even when the claim is
SEALED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from tex.presence.contract import (
    ClaimKind,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
    tighten,
)
from tex.presence.gate.queries import QUERIES, PresenceQuery, Recompute

__all__ = ["PresenceTruthGate", "RoutedClaim", "ClaimEvaluation"]

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_INT_RE = re.compile(r"\b\d+\b")
_STATUS_WORDS = ("pending", "active", "quarantined", "sleeping", "revoked")


class RoutedClaim:
    """The gate's resolution of one claim: which query (if any), the parsed
    target, and a reason when routing failed."""

    __slots__ = ("query", "target", "reason")

    def __init__(self, query: PresenceQuery | None, target: UUID | None, reason: str) -> None:
        self.query = query
        self.target = target
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ClaimEvaluation:
    """A claim's full evaluation: the contract verdict plus the gate's internal
    recompute (carrying the canonical phrasing) and routing. ``compose.py`` reads
    ``recompute.canonical_phrase`` from here so the spoken line is the gate's own
    phrasing of the recomputed truth — never the draft's words."""

    claim: PresenceClaim
    verdict: PresenceVerdict
    recompute: Recompute | None
    routed: RoutedClaim


def _extract_target(claim_id: str, text_span: str) -> UUID | None:
    """Parse a target agent UUID from the claim_id suffix (``key:<uuid>``) or,
    failing that, from the text span. None when absent."""
    if ":" in (claim_id or ""):
        candidate = claim_id.split(":", 1)[1].strip()
        try:
            return UUID(candidate)
        except (ValueError, AttributeError):
            pass
    m = _UUID_RE.search(text_span or "")
    if m:
        try:
            return UUID(m.group(0))
        except ValueError:
            return None
    return None


def _state(request: Any) -> Any:
    """The store host: ``request.app.state`` on the live path, or a state-like
    object passed directly (tests). None-safe."""
    app = getattr(request, "app", None)
    state = getattr(app, "state", None)
    if state is not None:
        return state
    return request  # a test double exposing the stores directly


def _value_contradicted(value: Any, span: str) -> bool:
    """Does the draft span assert something inconsistent with the recomputed
    value? Conservative + fail-closed: any divergence counts. Used ONLY to lower
    a tier toward ABSTAIN — never to raise one."""
    span = span or ""
    if isinstance(value, bool):  # no boolean claims today; never gate on one
        return False
    if isinstance(value, int):
        ints = {int(m.group(0)) for m in _INT_RE.finditer(span)}
        # If the span states any number, it must state exactly the true value.
        return bool(ints) and ints != {value}
    if isinstance(value, str):
        low = span.casefold()
        competing = {w for w in _STATUS_WORDS if w in low}
        if not competing:
            return False
        return value.casefold() not in competing
    return False  # DERIVED dicts and the like: no scalar faithfulness check


class PresenceTruthGate:
    """The truth-gate. Implements the contract's :class:`TruthGate` protocol."""

    def route(self, claim: PresenceClaim) -> RoutedClaim:
        """Resolve a claim to a query. The ``claim_id`` is the AUTHORITATIVE
        handle: an exact key match wins outright, so hostile words in the span
        cannot drag a well-keyed claim into an ambiguous match. Only when no key
        matches do we fall back to conservative lexical aliases. Zero matches →
        unknown; >1 → ambiguous (both fail closed to ABSTAIN)."""
        cid = (claim.claim_id or "").strip().lower()
        keyed = [
            q for q in QUERIES
            if q.kind is claim.kind and (cid == q.key or cid.startswith(q.key + ":"))
        ]
        if len(keyed) == 1:
            matched = keyed
        elif len(keyed) > 1:
            return RoutedClaim(None, None, "ambiguous-match:" + ",".join(q.key for q in keyed))
        else:
            matched = [
                q for q in QUERIES
                if q.kind is claim.kind and any(a in (claim.text_span or "").lower() for a in q.aliases)
            ]
        if not matched:
            return RoutedClaim(None, None, "no-matching-query")
        if len(matched) > 1:
            keys = ",".join(q.key for q in matched)
            return RoutedClaim(None, None, f"ambiguous-match:{keys}")
        query = matched[0]
        target = _extract_target(claim.claim_id, claim.text_span) if query.needs_target else None
        if query.needs_target and target is None:
            return RoutedClaim(query, None, "missing-target")
        return RoutedClaim(query, target, "routed")

    def recompute_for(
        self, claim: PresenceClaim, *, request: Any, tenant: str | None
    ) -> tuple[RoutedClaim, Recompute | None]:
        """Route + recompute for one claim. The recompute reads ONLY sealed rows;
        the draft is never consulted here."""
        routed = self.route(claim)
        if routed.query is None or (routed.query.needs_target and routed.target is None):
            return routed, None
        rc = routed.query.recompute(_state(request), tenant, routed.target)
        return routed, rc

    def evaluate(
        self,
        *,
        request: Any,
        tenant: str | None,
        draft: str,
        claims: tuple[PresenceClaim, ...],
        facts: Any = None,
    ) -> tuple[PresenceVerdict, ...]:
        return tuple(e.verdict for e in self.evaluate_detailed(
            request=request, tenant=tenant, draft=draft, claims=claims, facts=facts,
        ))

    def evaluate_detailed(
        self,
        *,
        request: Any,
        tenant: str | None,
        draft: str,
        claims: tuple[PresenceClaim, ...],
        facts: Any = None,
    ) -> tuple[ClaimEvaluation, ...]:
        """Full per-claim evaluation. Same verdicts as :meth:`evaluate`, plus the
        recompute (canonical phrasing) and routing for ``compose.py``."""
        return tuple(self._evaluate_one(claim, request=request, tenant=tenant) for claim in claims)

    # ------------------------------------------------------------------ one claim
    def _evaluate_one(
        self, claim: PresenceClaim, *, request: Any, tenant: str | None
    ) -> ClaimEvaluation:
        try:
            routed, rc = self.recompute_for(claim, request=request, tenant=tenant)
        except Exception as exc:  # noqa: BLE001 — gate must never raise into voice
            return ClaimEvaluation(
                claim,
                PresenceVerdict(
                    claim_id=claim.claim_id, tier=PresenceTier.ABSTAIN,
                    reason=f"gate-error:{type(exc).__name__}",
                ),
                None,
                RoutedClaim(None, None, "gate-error"),
            )

        if rc is None:
            return ClaimEvaluation(
                claim,
                PresenceVerdict(claim_id=claim.claim_id, tier=PresenceTier.ABSTAIN, reason=routed.reason),
                None,
                routed,
            )
        if not rc.grounded:
            return ClaimEvaluation(
                claim,
                PresenceVerdict(
                    claim_id=claim.claim_id, tier=PresenceTier.ABSTAIN,
                    reason=rc.reason or "ungrounded",
                ),
                rc,
                routed,
            )

        # ── Base tier from the RECOMPUTE alone (the draft has no vote here) ──
        # The contract requires "evidence empty iff ABSTAIN", so every non-ABSTAIN
        # tier must bind at least one real EvidenceRef. A true zero-count has no
        # positive rows to point at — proving absence needs a completeness proof
        # we do not have — so it ABSTAINS honestly rather than seal "0".
        if not rc.evidence:
            base_tier = PresenceTier.ABSTAIN
        elif claim.kind is ClaimKind.DERIVED:
            base_tier = PresenceTier.DERIVED if rc.correctness_floor is not None else PresenceTier.ABSTAIN
        else:
            base_tier = PresenceTier.SEALED

        # ── The draft may only LOWER (monotone). A value contradiction in the
        #    span forces ABSTAIN; nothing in the draft can raise the tier. ──
        reason = rc.reason
        tier = base_tier
        if base_tier is not PresenceTier.ABSTAIN and _value_contradicted(rc.value, claim.text_span):
            tier = tighten(base_tier, PresenceTier.ABSTAIN)  # == ABSTAIN
            reason = f"{rc.reason};draft-value-mismatch"

        verdict = PresenceVerdict(
            claim_id=claim.claim_id,
            tier=tier,
            evidence=rc.evidence if tier is not PresenceTier.ABSTAIN else (),
            recomputed_value=rc.value,
            correctness_floor=rc.correctness_floor if tier is PresenceTier.DERIVED else None,
            coverage_mode=rc.coverage_mode if tier is PresenceTier.DERIVED else None,
            governance_verdict=rc.governance_verdict,
            reason=reason,
        )
        return ClaimEvaluation(claim, verdict, rc, routed)
