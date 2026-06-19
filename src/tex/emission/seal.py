"""
Seal the ``DecoderConstraint`` — make the emission mask proof-carrying.

This is the moat move. Masking a forbidden tool out of existence is worth more if
a verdict can later *prove* "this turn was decoded under allowlist ``H``." This
module commits the constraint's stable digest as a ``SealedFact`` onto the SAME
``SealedFactLedger`` the rest of governance uses (``decision_seal`` /
``enforcement_seal``), so a single offline verifier — the ledger's own
``verify_chain`` (integrity) + ``verify_signatures`` (authorship) — checks it,
with no new chain.

Kind choice (and why not a new one): the emission gate is an *enforcement* event —
"the decoder was constrained to allowlist H for this turn" — so it reuses
``SealedFactKind.ENFORCEMENT`` rather than introducing a new kind (which would
mean editing ``provenance/models.py``, outside this track, and perturbing the kind
universe other leaps key on). The ``claim`` names the emission-gate semantics
precisely so a reader never conflates it with a PEP allow/block enforcement fact.

Honesty — what the seal proves and what it does NOT:
  * AUTHORSHIP + INTEGRITY of "the decoder was constrained to digest H": the
    ledger is SHA-256 hash-chained (integrity: no reorder/delete/tamper) and
    ECDSA-P256 signed (authorship), optionally ML-DSA dual-signed. Maturity is
    ``RESEARCH_SOLID``: real, live crypto, newly wired, not externally
    time-anchored.
  * It does NOT prove the mask was *effective at the sampler* (that is a property
    of the actuator — provider-trusted for Approach B, Tex-enforced for Approach
    A), nor that a *permitted* tool was used benignly (intent stays the PDP's
    job). The ``claim`` says so in words.

Fail-closed, observation-only (mirrors ``seal_decision`` / ``seal_enforcement``):
  * ``ledger is None`` -> zero-cost no-op, returns ``None``.
  * an append failure is logged and returns ``None`` — it never raises into the
    decode path and never changes what was masked.
"""

from __future__ import annotations

import logging

from tex.domain.evidence import EvidenceMaturity
from tex.emission.constraint import DecoderConstraint
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

_logger = logging.getLogger(__name__)

# Real, live ECDSA-P256 + hash-chain crypto (authorship + integrity), newly wired
# and not externally anchored — the same honesty convention as the DECISION and
# ENFORCEMENT seals.
_EMISSION_MATURITY = EvidenceMaturity.RESEARCH_SOLID

# The two actuators, named so the sealed fact records which guarantee tier applied.
APPROACH_PROVIDER_TRUSTED = "provider_trusted"  # Approach B (provider enforces)
APPROACH_TEX_ENFORCED = "tex_enforced"  # Approach A (Tex owns the sampler)


def build_constraint_fact(
    constraint: DecoderConstraint,
    *,
    subject_id: str,
    approach: str,
    agent_id: str | None = None,
) -> SealedFact:
    """Map a ``DecoderConstraint`` to a canonical ``SealedFact(ENFORCEMENT)``. Pure.

    The ``claim`` is deliberately narrow: it asserts only that the decoder was
    constrained to allowlist digest ``H`` for this turn, under which actuator tier,
    and that authorship + integrity are sealed — never that the mask was effective
    at the sampler, never anything about the intent of a permitted call.

    ``approach`` must be :data:`APPROACH_PROVIDER_TRUSTED` or
    :data:`APPROACH_TEX_ENFORCED`; the distinction is the difference between
    "the provider says it masked" and "Tex's sampler made it un-emittable" and is
    sealed so a verifier reads the honest guarantee tier.
    """
    if approach not in (APPROACH_PROVIDER_TRUSTED, APPROACH_TEX_ENFORCED):
        raise ValueError(
            f"approach must be {APPROACH_PROVIDER_TRUSTED!r} or "
            f"{APPROACH_TEX_ENFORCED!r}, got {approach!r}"
        )
    digest = constraint.digest()
    agent = agent_id or "unknown"
    if constraint.constrains_tool_names:
        scope = f"{len(constraint.allowed_tool_names)} permitted tool(s)"
    elif constraint.surface_is_unrestricted:
        scope = "NO mask (surface declared unrestricted)"
    else:
        scope = "NO tool-name mask (surface declared no tool restriction)"
    tier_phrase = (
        "un-emittability provider-trusted"
        if approach == APPROACH_PROVIDER_TRUSTED
        else "un-emittability Tex-enforced (sampler-owned)"
    )
    claim = (
        f"emission gate decoded turn under allowlist H={digest[:12]} for agent={agent} "
        f"({scope}, approach={approach}; {tier_phrase}) "
        f"— authorship+integrity sealed; sampler-effectiveness NOT proven here, "
        f"intent of a permitted call NOT judged (PDP's job)"
    )
    detail = {
        "constraint_digest": digest,
        "approach": approach,
        "agent_id": agent_id,
        "allowed_tool_names": list(constraint.allowed_tool_names),
        "constrains_tool_names": constraint.constrains_tool_names,
        "constrains_values": constraint.constrains_values,
        "surface_is_unrestricted": constraint.surface_is_unrestricted,
        "per_tool_schema_tools": sorted(constraint.per_tool_json_schema.keys()),
        "value_regex_roles": sorted(constraint.value_regexes.keys()),
        # Per-element maturity, so no reader over-reads the value tier.
        "maturity_notes": {
            "tool_name_allowlist": "production",
            "value_level_constraints": "research_early",
            "seal": "research_solid",
        },
    }
    return SealedFact(
        kind=SealedFactKind.ENFORCEMENT,
        subject_id=subject_id,
        claim=claim,
        maturity=_EMISSION_MATURITY,
        detail=detail,
    )


def seal_constraint(
    ledger: SealedFactLedger | None,
    constraint: DecoderConstraint,
    *,
    subject_id: str,
    approach: str,
    agent_id: str | None = None,
) -> SealedFactRecord | None:
    """Seal one emission ``DecoderConstraint`` fact into ``ledger`` and return its PCVR.

    Fail-closed and observation-only:
      * ``ledger is None`` -> no-op, return ``None`` (zero cost, decode unchanged).
      * an append failure is logged and returns ``None`` — it never propagates
        into the decode path; what was masked is unaffected.
    """
    if ledger is None:
        return None
    try:
        return ledger.append(
            build_constraint_fact(
                constraint,
                subject_id=subject_id,
                approach=approach,
                agent_id=agent_id,
            )
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break a decode
        _logger.warning(
            "emission-constraint seal failed for subject %s; decode unaffected, fact not sealed",
            subject_id,
            exc_info=True,
        )
        return None
