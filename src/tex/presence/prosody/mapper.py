"""The tier → prosody mapping and the wire helpers that carry it.

The cardinal honesty rule of this whole package, restated so no future edit can
quietly violate it: **prosody is PERCEIVED confidence, and it is a PURE FUNCTION
of the gate's verdict tier and nothing else.** Not the request text, not the
model's draft, not a "vibe" — only the monotone :class:`PresenceTier`. The
authoritative mapping is the frozen :meth:`ProsodyPlan.from_tier` in
:mod:`tex.presence.contract`; this module does not get to invent a second one.
:class:`EpistemicProsodyMapper` simply *is* that function wearing the
:class:`~tex.presence.contract.ProsodyMapper` protocol, and the wire helpers only
ever move a *tier* across the boundary — never a set of raw knobs a caller could
use to make an ABSTAIN sound assured.

WHY THE WIRE CARRIES A TIER, NOT KNOBS
--------------------------------------
``/v1/speak`` (``tex.api.voice_routes``) is a separate HTTP call from
``/v1/ask``. For the spoken line to sound as confident as — and never more
confident than — the verdict, the *tier* must travel from the ``/v1/ask``
:class:`~tex.presence.contract.AnswerEnvelope` to the ``/v1/speak`` request, and
the plan must be re-derived **server-side** from that tier. If the wire carried
``rate``/``pitch`` directly, a caller could hand-set an assured-sounding plan on
an uncertain answer — exactly the bluff the monotone tier exists to prevent. So
the only thing that crosses is the tier token (the ``StrEnum`` value itself), and
:func:`plan_from_token` recomputes the plan through :meth:`ProsodyPlan.from_tier`.

:func:`prosody_param_for_envelope` is the function the orchestrator threads at
integration time (``main.py`` / ``voice_ask.py`` are out of this track and are
NOT edited): it reads the envelope's ``overall_tier`` — itself the monotone fold
(``tighten``) of every per-claim verdict — so the end-to-end guarantee "the voice
can never sound more confident than the verdict" holds by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.presence.contract import AnswerEnvelope, PresenceTier, ProsodyPlan

__all__ = [
    "EpistemicProsodyMapper",
    "DEFAULT_MAPPER",
    "tier_token",
    "tier_from_token",
    "plan_from_token",
    "prosody_param_for_tier",
    "prosody_param_for_envelope",
]


@dataclass(frozen=True, slots=True)
class EpistemicProsodyMapper:
    """The contract's :class:`~tex.presence.contract.ProsodyMapper`. Its only job
    is to be the pure tier→plan function — stateless, frozen, and unable to read
    anything but the tier it is handed."""

    def plan(self, tier: PresenceTier) -> ProsodyPlan:
        # Delegation, not a second mapping: the source of truth is frozen in the
        # contract so prosody can never be sourced from model "vibe".
        return ProsodyPlan.from_tier(tier)


DEFAULT_MAPPER = EpistemicProsodyMapper()


def tier_token(tier: PresenceTier) -> str:
    """The wire token for a tier. The :class:`PresenceTier` ``StrEnum`` value
    (``"sealed"``/``"derived"``/``"abstain"``) IS the token — there is no second
    vocabulary to drift out of sync."""
    return tier.value


def tier_from_token(token: str | None) -> PresenceTier | None:
    """Parse a wire token back into a tier. Returns ``None`` for an absent or
    unrecognized token — the caller then renders NEUTRAL (no epistemic prosody),
    which is the correct fail-safe: an unspecified verdict must never be voiced as
    *confident*. (Whitespace/case tolerant; nothing else is accepted, so a caller
    can never smuggle raw knobs through this seam.)"""
    if token is None:
        return None
    candidate = token.strip().lower()
    if not candidate:
        return None
    try:
        return PresenceTier(candidate)
    except ValueError:
        return None


def plan_from_token(token: str | None) -> ProsodyPlan | None:
    """The server-side step: token → tier → plan, recomputed purely through
    :meth:`ProsodyPlan.from_tier`. ``None`` when the token names no tier (render
    neutral). This is the ONLY sanctioned way ``/v1/speak`` turns its query
    parameter into a plan."""
    tier = tier_from_token(token)
    return ProsodyPlan.from_tier(tier) if tier is not None else None


def prosody_param_for_tier(tier: PresenceTier) -> str:
    """The ``/v1/speak`` ``prosody`` query value for a known tier."""
    return tier_token(tier)


def prosody_param_for_envelope(envelope: AnswerEnvelope | None) -> str | None:
    """Map a ``/v1/ask`` :class:`~tex.presence.contract.AnswerEnvelope` to the
    ``prosody`` token the client should echo to ``/v1/speak``.

    This is the integration seam's hand-off. It reads ``overall_tier`` (the
    monotone fold of every claim's verdict), so the token reflects the *verdict*,
    never the draft. ``None`` when there is no presence envelope (presence not
    engaged) — the client then omits ``prosody`` and gets today's neutral voice,
    which is honest: no presence verdict ⇒ no epistemic prosody to apply."""
    if envelope is None:
        return None
    return tier_token(envelope.overall_tier)
