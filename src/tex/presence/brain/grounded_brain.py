"""The grounded brain — an off-the-shelf, swappable model that *proposes* only.

:class:`GroundedReasoner` implements the :class:`~tex.presence.contract.GroundedBrain`
protocol. Handed sealed facts, it asks a swappable
:class:`~tex.semantic.analyzer.StructuredSemanticProvider` (e.g. Claude via
:class:`~tex.semantic.anthropic.AnthropicStructuredSemanticProvider`) for a phrasing
and candidate :class:`~tex.presence.contract.PresenceClaim` s.

Three invariants make this safe:

* **Facts never live in weights.** The provider only ever sees facts in the prompt;
  no fine-tuning, no caching of fact values. The model is a phrasing function.
* **Not load-bearing.** Output is a *proposal*. Session 2's gate re-verifies every
  claim against the sealed evidence; a hallucinated claim cannot survive it.
* **Uncertain ⇒ propose nothing.** A refusal, a transport error, an unparseable
  payload, or a claim whose span isn't in the draft → that claim (or the whole
  proposal) is dropped, and the gate then abstains. With no provider configured the
  brain is a deterministic no-op (equivalent to ``NULL_BRAIN``): it returns
  ``("", ())`` because faithfully parsing an arbitrary natural-language question
  into grounded claims is not something a deterministic stub can do honestly — so
  the safe deterministic behaviour is to defer to the gate's abstention.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Sequence

from tex.presence.brain.prompts import (
    PROPOSAL_TOOL_NAME,
    build_brain_system_prompt,
    build_brain_user_prompt,
)
from tex.presence.contract import ClaimKind, PresenceClaim
from tex.semantic.analyzer import StructuredSemanticProvider

__all__ = ["GroundedReasoner", "build_grounded_brain"]

# A generous safety bound on a non-load-bearing proposal. Dropping proposals past
# this is not "dropping coverage" (the gate would only abstain on missing claims
# anyway) — it caps a pathological model, and we surface that it happened.
_MAX_CLAIMS = 64

_KIND_BY_TOKEN = {k.value: k for k in ClaimKind}


def _coerce_kind(raw: Any) -> ClaimKind | None:
    """Map a model-proposed kind to a real ClaimKind, or None to drop the claim.

    The brain never *guesses* a kind — an unrecognised value drops the claim and
    lets the gate abstain on that span.
    """
    if isinstance(raw, ClaimKind):
        return raw
    if isinstance(raw, str):
        return _KIND_BY_TOKEN.get(raw.strip().lower())
    return None


@dataclass(frozen=True, slots=True)
class GroundedReasoner:
    """A swappable-model phrasing layer. Conforms to ``contract.GroundedBrain``.

    ``provider=None`` makes this a deterministic no-op proposer (NULL_BRAIN-equivalent).
    """

    provider: StructuredSemanticProvider | None = None
    max_claims: int = _MAX_CLAIMS
    last_drops: dict[str, int] = field(default_factory=dict, compare=False)

    # ── GroundedBrain protocol ────────────────────────────────────────────────
    def propose(
        self,
        *,
        question: str,
        tenant: str | None,
        facts: Any,
        tools: tuple[Any, ...],
    ) -> tuple[str, tuple[PresenceClaim, ...]]:
        if self.provider is None:
            # Deterministic fallback: propose nothing; the gate abstains.
            return ("", ())

        tool_names = [getattr(t, "name", str(t)) for t in tools]
        system_prompt = build_brain_system_prompt(tool_names)
        user_prompt = build_brain_user_prompt(question=question, tenant=tenant, facts=facts)

        try:
            payload = self.provider.analyze(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception:
            # Refusal / transport / schema failure → uncertain → propose nothing.
            return ("", ())

        return self._parse_proposal(payload)

    # ── parsing ───────────────────────────────────────────────────────────────
    def _parse_proposal(self, payload: Any) -> tuple[str, tuple[PresenceClaim, ...]]:
        data = self._as_mapping(payload)
        if data is None:
            return ("", ())

        draft = data.get("draft")
        if not isinstance(draft, str):
            return ("", ())
        draft = draft.strip()
        if not draft:
            return ("", ())

        raw_claims = data.get("claims")
        if not isinstance(raw_claims, (list, tuple)):
            raw_claims = ()

        claims: list[PresenceClaim] = []
        seen_ids: set[str] = set()
        dropped_span = 0
        dropped_kind = 0
        dropped_cap = 0

        for index, raw in enumerate(raw_claims):
            if len(claims) >= self.max_claims:
                dropped_cap = len(raw_claims) - index
                break
            if not isinstance(raw, Mapping):
                dropped_kind += 1
                continue

            span = raw.get("text_span")
            if not isinstance(span, str) or not span.strip() or span not in draft:
                dropped_span += 1
                continue

            kind = _coerce_kind(raw.get("kind"))
            if kind is None:
                dropped_kind += 1
                continue

            claim_id = self._claim_id(raw.get("claim_id"), index, seen_ids)
            claims.append(PresenceClaim(claim_id=claim_id, text_span=span, kind=kind))
            seen_ids.add(claim_id)

        # Surface what we dropped — never a silent cap (see CLAUDE.md "no silent caps").
        self.last_drops.clear()
        if dropped_span:
            self.last_drops["span_not_in_draft"] = dropped_span
        if dropped_kind:
            self.last_drops["bad_or_missing_kind"] = dropped_kind
        if dropped_cap:
            self.last_drops["over_max_claims"] = dropped_cap

        return (draft, tuple(claims))

    @staticmethod
    def _as_mapping(payload: Any) -> Mapping[str, Any] | None:
        if isinstance(payload, Mapping):
            return payload
        # A SemanticAnalysis (or any pydantic model) is the wrong shape for a
        # proposal — treat as "nothing proposed" rather than guess at fields.
        model_dump = getattr(payload, "model_dump", None)
        if callable(model_dump):
            dumped = model_dump()
            if isinstance(dumped, Mapping) and "draft" in dumped:
                return dumped
            return None
        if isinstance(payload, str):
            import json

            try:
                parsed = json.loads(payload)
            except (ValueError, TypeError):
                return None
            return parsed if isinstance(parsed, Mapping) else None
        return None

    @staticmethod
    def _claim_id(raw_id: Any, index: int, seen: set[str]) -> str:
        if isinstance(raw_id, str):
            candidate = raw_id.strip()
            if candidate and candidate not in seen:
                return candidate
        return f"claim-{index}"


def build_grounded_brain(
    provider: StructuredSemanticProvider | None = None,
    *,
    max_claims: int = _MAX_CLAIMS,
) -> GroundedReasoner:
    """Build a grounded brain. With ``provider=None`` it is a deterministic no-op
    proposer (NULL_BRAIN-equivalent) so the live voice path keeps working."""
    return GroundedReasoner(provider=provider, max_claims=max_claims)
