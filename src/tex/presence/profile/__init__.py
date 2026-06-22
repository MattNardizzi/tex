"""Tex Presence — per-tenant PROFILE memory + the two-way confirm/correct loop (L2).

The "becomes more yours the more you use it" layer, built ON S5's sealed memory
(:mod:`tex.presence.memory`): a per-tenant PROFILE of learned preferences,
boundaries, and corrections — each one a SEALED, CITABLE, REVOCABLE record, never
model weights. The operator can CONFIRM ("that's right") or CORRECT ("that's wrong /
too confident") a spoken claim's tier; a correction is a sealed LABEL that can only
TIGHTEN a future verdict for that subject (monotone-lowering, enforced by
``tighten`` — never an inflation).

Public surface (the orchestrator wires these in; the live voice path is untouched):

    from tex.presence.profile import (
        build_profile_memory,            # factory → SealedProfileMemory
        apply_profile_corrections,       # the orchestrator's one-line influence wire
        ProfileMemory, ProfileFact, ProfileFacts, ProfileFactKind,  # the L3 seam
    )

See :mod:`tex.presence.profile.types` for the interface L3 builds against and
``PROFILE_INTERFACE.md`` for the posted contract. See ``RESEARCH.md`` for the
2026 frontier survey (mnemonic sovereignty / TierMem / portable agent memory).

HONEST EDGES (baked in; never overclaimed) — see ``types.py`` for the full list:
  * A correction is a LABEL that tightens a boundary, NOT a model retrain.
  * An *upward* correction (to SEALED) is REFUSED — to make Tex speak something as
    fact, seal a fact with evidence (S5), whose write-gate requires evidence.
  * A typed ``believed_value`` is operator-belief metadata only — NEVER spoken (the
    gate recomputes from rows; the model never counts).
  * ``revoke`` is forget-by-avoidance, scoped to THIS store instance; per-tenant
    isolation is application-layer only (no RLS / encryption-at-rest).
  * The profile is INERT without real usage: the V1 claim is "Tex CAN learn your
    preferences, verifiably and revocably," NOT "Tex knows you."
"""

from tex.presence.profile.hooks import build_profile_memory
from tex.presence.profile.influence import (
    apply_corrections_to_verdicts,
    apply_profile_corrections,
    cap_verdict,
    stable_subject_key,
)
from tex.presence.profile.records import SealedProfileFact
from tex.presence.profile.store import SealedProfileMemory
from tex.presence.profile.types import (
    PROFILE_INTERFACE_VERSION,
    PROFILE_STORE_NAME,
    ProfileFact,
    ProfileFactKind,
    ProfileFacts,
    ProfileMemory,
)

__all__ = [
    "build_profile_memory",
    "apply_profile_corrections",
    "apply_corrections_to_verdicts",
    "cap_verdict",
    "stable_subject_key",
    "SealedProfileMemory",
    "SealedProfileFact",
    "ProfileMemory",
    "ProfileFact",
    "ProfileFacts",
    "ProfileFactKind",
    "PROFILE_INTERFACE_VERSION",
    "PROFILE_STORE_NAME",
]
