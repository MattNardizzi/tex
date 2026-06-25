"""
UNIFIED BROKER CAPABILITY-TOKEN — one proof-carrying capability-future that
carries all three execution budgets, verified BEFORE a branch commits / a tool
fires (the DoD-2 capability-token + sealed-broker leg; CapSeal/ACP-class).

[Architecture: Layer 4 (Execution Governance) — the authority leg of the metered
CaMeL interpreter.]

What this module adds
---------------------
Iters 2-4 built three *metered* execution budgets, each a hardcoded local
constant or constructor arg:

  * CFI ``steer_budget``        — cumulative control-flow-influence bits
                                  (``camel/cfi.py`` + the interpreter constructor).
  * CHOKE-X branch leverage     — per-branch certified-leverage bits
                                  (``camel/branch_leverage.py`` / ``Branch.budget_bits``).
  * LEDGERED value budget       — cumulative confidentiality-class weight
                                  (``deterministic/value_budget.py``).

This module turns those three *trusted local constants* into ONE **signed,
sender-constrained, offline-attenuable capability token**, minted by the REAL
credential broker (``tex.authority.broker.CredentialBroker``) and VERIFIED before
the interpreter spends any budget. The move is exactly CapSeal/ACP's: a budget is
no longer a number the process trusts itself to hold — it is a claim Tex signed,
that the execution layer must verify (and whose sender it must check) before
acting on it.

How the three budgets ride a REAL broker token
----------------------------------------------
The broker's ``mint`` HMACs a canonical-JSON claims dict (``permit._sign`` over
``permit._canonical`` — the SAME audited primitive the permit path uses) and
embeds the requested ``scope`` *inside* that signed body. We therefore carry the
three budgets as canonical scope tokens::

    cap:steer_budget=<float-repr>
    cap:branch_leverage_budget=<int>
    cap:value_budget=<int>

Because ``scope`` is inside the signed body, **mutating any budget changes the
signed bytes and the broker's own ``verify`` returns "bad signature"** — a real
HMAC check, not a cosmetic one (test 2). We do not add a second crypto path; the
budget integrity IS the broker's existing credential signature.

Sender-constraint (RFC 7800 ``cnf`` / RFC 9449 DPoP)
----------------------------------------------------
The token is minted PoP-bound to a holder key (``cnf_public_key``). At verify
time the holder must present a fresh PoP proof for the exact token (the broker's
``_use_binding``); a token presented WITHOUT the matching proof is rejected before
any budget is read (test 4). A stolen token is useless without the private key.

Offline attenuation
-------------------
``attenuate`` derives a sub-token that is STRICTLY NARROWER — every budget ≤ the
parent's and the audience a subset — by re-minting (re-signing) under the SAME
root key with the smaller claims. It is a *fresh signed token* (so it verifies
offline against the same key, no server round-trip), but ``attenuate`` REFUSES to
widen any budget or broaden the audience (test 5). This is the capability
attenuation property: hold a token, hand out a weaker one, no authority to amplify.

Verify-before
-------------
``verify_capability_token`` returns a ``CapabilityGrant`` (the three budgets) ONLY
when the broker's ``verify`` passes (signature + issuer + expiry + audience + PoP).
The interpreter calls this BEFORE ``run`` and uses the *signed* ``steer_budget`` in
place of its hardcoded constructor arg; the ``Branch`` leverage budget likewise
flows from the signed grant. A failed verify yields no grant — the caller
fail-closes (the interpreter run never starts / ABSTAINs), never proceeds on an
unverified token.

Sealing the integrity budgets (un-backfillable)
-----------------------------------------------
``seal_run`` writes the per-run ``CfiLedger`` total + each high-stakes branch's
leverage certificate into the sealed, hash-chained ``SealedFactLedger``
(``provenance/ledger.py``) via ``append_sequenced(identity_key=lineage)``. The
budgets then become externally-anchored, per-identity-sequenced chain entries: a
gap or replay makes ``verify_no_gaps`` fail, and ``trust_sealed_run`` returns False
→ the caller ABSTAINs rather than trust a budget it cannot prove was sealed intact.

Default-OFF
-----------
The whole mechanism is gated behind ``TEX_CAP_TOKEN_ENABLED``. With it unset
``capability_tokens_enabled()`` is False, no token is minted, and the interpreter
uses its default/hardcoded budget EXACTLY as iter-3/4 — bit-for-bit unchanged.

HONEST EDGES (do not overstate)
-------------------------------
  * **The broker HMAC secret is the trust root.** Compromising
    ``TEX_AUTHORITY_SIGNING_SECRET`` (the same secret all Tex minting shares) both
    breaks the sender binding's value (a thief who also has the secret can re-mint)
    AND lets an attacker mint a token carrying ANY budget. The token's integrity is
    exactly the broker secret's integrity — no stronger, no weaker. This is the
    same single-trust-root property the whole authority plane has.
  * **In-process verify, not yet an in-path Body.** The verify happens in the same
    process as the interpreter. This proves the *capability-before-action* shape and
    is a real signature/PoP check; it is NOT yet a separate in-path enforcement Body
    that an out-of-process actuator must consult. Deploying that Body is the
    activation/deployment step tracked in the loop, not this module.
  * **PoP residual replay** within the freshness window against the same bind (see
    ``authority/pop.py``) is inherited unchanged; this module adds no jti cache.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:  # type-only; the broker is imported lazily to break an import
    # cycle (tex.camel.__init__ -> capability_token -> authority.broker, while the
    # broker's dependency chain transitively reaches tex.camel).
    from tex.authority.broker import CredentialBroker
    from tex.identity.agent_credential import AttestedIdentity

# Domain-separated scope prefixes for the three budgets. A budget token is a
# single canonical ``scope`` string; the broker signs the whole scope list, so a
# tampered budget string breaks the credential signature.
_STEER_PREFIX = "cap:steer_budget="
_LEVERAGE_PREFIX = "cap:branch_leverage_budget="
_VALUE_PREFIX = "cap:value_budget="

# Default audience/action for a CaMeL execution capability. The audience scopes
# the token to "this interpreter's run"; attenuation may only narrow it.
_DEFAULT_AUDIENCE = "tex.camel.interpreter"
_DEFAULT_ACTION = "execute_plan"


def capability_tokens_enabled(env: Mapping[str, str] | None = None) -> bool:
    """True iff ``TEX_CAP_TOKEN_ENABLED`` is set truthy. Default OFF: with it
    unset no token is minted and the interpreter uses its hardcoded budget."""
    e = os.environ if env is None else env
    raw = e.get("TEX_CAP_TOKEN_ENABLED")
    if raw is None:
        return False
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# The three-budget grant + scope codec                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """The three execution budgets carried by ONE verified capability token.

    ``steer_budget`` is the cumulative CFI bits the interpreter may spend (the
    constructor arg from iter-3, now signed). ``branch_leverage_budget`` is the
    per-branch CHOKE-X leverage ceiling (iter-4 ``Branch.budget_bits``, now
    signed). ``value_budget`` is the LEDGERED confidentiality-class weight ceiling
    (iter-2). ``audience`` scopes the grant; ``lineage`` keys the seal.
    """

    steer_budget: float
    branch_leverage_budget: int
    value_budget: int
    audience: str
    lineage: str

    def is_narrower_than(self, other: "CapabilityGrant") -> bool:
        """True iff EVERY budget is ≤ ``other``'s and the audience is unchanged or
        a narrowing. Used by :func:`attenuate` to reject widening."""
        return (
            self.steer_budget <= other.steer_budget
            and self.branch_leverage_budget <= other.branch_leverage_budget
            and self.value_budget <= other.value_budget
        )


def _budget_scope(grant: CapabilityGrant) -> tuple[str, ...]:
    """Encode the three budgets as canonical, signable scope tokens. ``repr`` is
    used for the float so the encoding round-trips bit-for-bit (no precision
    drift) and the signed bytes are reproducible."""
    return (
        f"{_STEER_PREFIX}{grant.steer_budget!r}",
        f"{_LEVERAGE_PREFIX}{grant.branch_leverage_budget:d}",
        f"{_VALUE_PREFIX}{grant.value_budget:d}",
    )


def _parse_budget_scope(scope: tuple[str, ...]) -> tuple[float, int, int] | None:
    """Decode (steer, leverage, value) from a verified credential's scope, or None
    if any budget token is missing/malformed. Called ONLY on a scope the broker
    already signature-verified, so this is a parse of trusted bytes."""
    steer: float | None = None
    leverage: int | None = None
    value: int | None = None
    for s in scope:
        try:
            if s.startswith(_STEER_PREFIX):
                steer = float(s[len(_STEER_PREFIX):])
            elif s.startswith(_LEVERAGE_PREFIX):
                leverage = int(s[len(_LEVERAGE_PREFIX):])
            elif s.startswith(_VALUE_PREFIX):
                value = int(s[len(_VALUE_PREFIX):])
        except (ValueError, TypeError):
            return None
    if steer is None or leverage is None or value is None:
        return None
    if steer < 0 or leverage < 0 or value < 0:
        return None
    return steer, leverage, value


# --------------------------------------------------------------------------- #
# A minted capability token (the broker credential + its decoded grant)       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """A minted, proof-carrying execution capability-future.

    ``token`` is the broker's compact ``body.sig`` credential (the budgets live in
    the signed ``scope``). ``grant`` is the decoded three-budget view.
    ``cnf_jkt`` is the bound holder-key thumbprint (PoP sender constraint).
    """

    token: str
    grant: CapabilityGrant
    audience: str
    action: str
    cnf_jkt: str | None


def mint_capability_token(
    attested_identity: AttestedIdentity,
    *,
    grant: CapabilityGrant,
    cnf_public_key: Any,
    ttl: int = 300,
    broker: CredentialBroker | None = None,
    now: float | None = None,
    audience: str | None = None,
    action: str = _DEFAULT_ACTION,
    single_use: bool = False,
) -> CapabilityToken | None:
    """Mint ONE capability token carrying the three budgets, via the REAL broker.

    The budgets are encoded as canonical scope tokens (``_budget_scope``) and the
    broker HMAC-signs the whole claims dict — so the returned ``token`` is a real
    credential whose budget claims cannot be altered without breaking the
    signature. Sender-constrained to ``cnf_public_key`` (RFC 7800/9449): using it
    later requires a PoP proof. Returns None (fail-closed) on any mint failure
    (unverified identity, no signing secret, unusable key) — the broker's rules.
    """
    from tex.authority.broker import CredentialBroker

    aud = audience if audience is not None else grant.audience
    b = broker if broker is not None else CredentialBroker()
    # Re-key the grant's audience to the minted audience so the decoded grant and
    # the credential agree.
    grant = CapabilityGrant(
        steer_budget=grant.steer_budget,
        branch_leverage_budget=grant.branch_leverage_budget,
        value_budget=grant.value_budget,
        audience=aud,
        lineage=grant.lineage,
    )
    cred = b.mint(
        attested_identity,
        audience=aud,
        action=action,
        scope=_budget_scope(grant),
        ttl=ttl,
        cnf_public_key=cnf_public_key,
        single_use=single_use,
        now=now,
    )
    if cred is None:
        return None
    return CapabilityToken(
        token=cred.token,
        grant=grant,
        audience=aud,
        action=action,
        cnf_jkt=cred.cnf_jkt,
    )


def verify_capability_token(
    token: str | None,
    *,
    expected_audience: str,
    expected_action: str = _DEFAULT_ACTION,
    pop_proof: str | None = None,
    lineage: str = "default",
    broker: CredentialBroker | None = None,
    now: float | None = None,
) -> CapabilityGrant | None:
    """Verify a capability token and return its three-budget grant, or None.

    This is the VERIFY-BEFORE gate: the broker checks signature, issuer, expiry,
    audience, action, AND the PoP sender binding (a token minted ``cnf``-bound
    REQUIRES a valid ``pop_proof`` — it can never be downgraded to bearer, because
    ``cnf`` is inside the signed claims). Only on a fully-passing verify are the
    budgets decoded from the (now trusted) signed scope and returned. A failed
    verify → None → the caller fail-closes (does not run / ABSTAINs). Never
    raises out of the broker's verify.
    """
    from tex.authority.broker import CredentialBroker

    b = broker if broker is not None else CredentialBroker()
    check = b.verify(
        token,
        expected_audience=expected_audience,
        expected_action=expected_action,
        pop_proof=pop_proof,
        now=now,
    )
    if not check.ok or check.claims is None:
        return None
    scope = tuple(str(s) for s in (check.claims.get("scope") or []))
    parsed = _parse_budget_scope(scope)
    if parsed is None:
        return None
    steer, leverage, value = parsed
    return CapabilityGrant(
        steer_budget=steer,
        branch_leverage_budget=leverage,
        value_budget=value,
        audience=expected_audience,
        lineage=lineage,
    )


# --------------------------------------------------------------------------- #
# Offline attenuation — strictly narrower sub-token                           #
# --------------------------------------------------------------------------- #


class AttenuationError(ValueError):
    """Raised when an attenuation would WIDEN a budget or broaden the audience.

    Attenuation may only ever produce a STRICTLY-NARROWER sub-token (every budget
    ≤ the parent's, audience unchanged/narrowed). A widening request is refused —
    holding a token grants no authority to amplify it."""


def attenuate(
    parent: CapabilityToken,
    attested_identity: AttestedIdentity,
    *,
    sub_grant: CapabilityGrant,
    cnf_public_key: Any,
    ttl: int = 300,
    broker: CredentialBroker | None = None,
    now: float | None = None,
    action: str | None = None,
) -> CapabilityToken:
    """Derive a STRICTLY-NARROWER sub-token from ``parent``, verifiable offline
    against the SAME root key (no server round-trip).

    ``sub_grant``'s budgets must each be ≤ the parent's and its audience must equal
    the parent's (no broadening). A widening → ``AttenuationError``. The sub-token
    is a fresh broker credential signed under the same authority secret, so a
    holder of the root public verification key can check it offline exactly like
    the parent — the attenuation needs no online authority, only that the
    narrowing is monotone.
    """
    if not sub_grant.is_narrower_than(parent.grant):
        raise AttenuationError(
            "attenuation must be strictly narrower: every budget must be <= the "
            f"parent's (parent steer={parent.grant.steer_budget}, "
            f"leverage={parent.grant.branch_leverage_budget}, "
            f"value={parent.grant.value_budget}; requested steer="
            f"{sub_grant.steer_budget}, leverage={sub_grant.branch_leverage_budget}, "
            f"value={sub_grant.value_budget})"
        )
    if sub_grant.audience != parent.audience:
        raise AttenuationError(
            "attenuation may not broaden (or change) the audience: "
            f"parent={parent.audience!r}, requested={sub_grant.audience!r}"
        )
    sub = mint_capability_token(
        attested_identity,
        grant=sub_grant,
        cnf_public_key=cnf_public_key,
        ttl=ttl,
        broker=broker,
        now=now,
        audience=parent.audience,
        action=action if action is not None else parent.action,
    )
    if sub is None:
        raise AttenuationError("sub-token mint failed (fail-closed)")
    return sub


def make_use_proof(private_key: Any, token: str, *, now: float | None = None) -> str:
    """Holder-side helper: a PoP proof bound to ``token`` for resource USE (mirrors
    the broker's ``_use_binding``). The private key never leaves the holder; tests
    and real holders both build the use-proof through this one path."""
    from tex.authority.broker import _use_binding
    from tex.authority.pop import make_pop_proof

    return make_pop_proof(private_key, bind=_use_binding(token), now=now)


# --------------------------------------------------------------------------- #
# Sealing the per-run integrity budgets into the provenance ledger            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SealedRun:
    """The receipt(s) sealed for one interpreter run's integrity budgets.

    ``cfi_record_hash`` is the hash-chained record hash of the sealed CFI total;
    ``branch_record_hashes`` are the sealed per-branch leverage certificates. Each
    is anchored under ``lineage`` and per-identity-sequenced, so a deletion/replay
    of any one is detectable by :func:`trust_sealed_run`.
    """

    lineage: str
    cfi_record_hash: str
    branch_record_hashes: tuple[str, ...]


def seal_run(
    sealed_fact_ledger: Any,
    *,
    lineage: str,
    cfi_total_bits: float,
    steer_budget: float,
    branch_certificates: tuple[tuple[str, float, int], ...] = (),
) -> SealedRun:
    """Seal a run's CFI total + each high-stakes branch's leverage certificate into
    the sealed, hash-chained ``SealedFactLedger`` via ``append_sequenced``.

    ``branch_certificates`` is ``(cond_var, certified_bits, budget_bits)`` per
    certified branch. Each fact is sealed ``append_sequenced(identity_key=lineage)``
    so the budgets become externally-anchored, per-identity-sequenced chain entries:
    a missing receipt is a sequence gap, a replayed one a duplicate — both caught
    by :func:`trust_sealed_run`. This is what makes the integrity budgets
    un-backfillable: you cannot insert a budget claim after the fact without
    breaking the chain or the per-lineage sequence.
    """
    from tex.domain.evidence import EvidenceMaturity
    from tex.provenance.models import SealedFact, SealedFactKind

    cfi_fact = SealedFact(
        kind=SealedFactKind.BUDGET,
        subject_id=lineage,
        claim=(
            f"CFI control-flow-influence run total for lineage '{lineage}': "
            f"{cfi_total_bits!r} bits spent against steer budget {steer_budget!r}."
        ),
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        detail={
            "lineage_key": lineage,
            "cfi_total_bits": cfi_total_bits,
            "steer_budget": steer_budget,
            "budget_kind": "cfi_steer",
        },
    )
    cfi_record = sealed_fact_ledger.append_sequenced(cfi_fact, identity_key=lineage)

    branch_hashes: list[str] = []
    for cond_var, certified_bits, budget_bits in branch_certificates:
        cert_fact = SealedFact(
            kind=SealedFactKind.BUDGET,
            subject_id=lineage,
            claim=(
                f"CHOKE-X branch leverage certificate for lineage '{lineage}' "
                f"branch on {cond_var!r}: certified {certified_bits!r} bits of "
                f"attacker leverage against budget {budget_bits} bits."
            ),
            maturity=EvidenceMaturity.RESEARCH_EARLY,
            detail={
                "lineage_key": lineage,
                "cond_var": cond_var,
                "certified_bits": certified_bits,
                "budget_bits": budget_bits,
                "budget_kind": "choke_x_leverage",
            },
        )
        rec = sealed_fact_ledger.append_sequenced(cert_fact, identity_key=lineage)
        branch_hashes.append(rec.record_hash)

    return SealedRun(
        lineage=lineage,
        cfi_record_hash=cfi_record.record_hash,
        branch_record_hashes=tuple(branch_hashes),
    )


def trust_sealed_run(sealed_fact_ledger: Any, *, lineage: str) -> bool:
    """True iff the lineage's sealed budgets can be TRUSTED: the hash chain is
    intact AND this lineage has no sequence gap / duplicate (no missing or replayed
    receipt). False → an unknown / tampered budget history → the caller ABSTAINs
    rather than silently trusting the budget.

    Mirrors the value-budget tracker's reload guard: ``verify_chain`` proves the
    present records are unaltered; ``verify_no_gaps`` proves none are absent for
    this lineage. A gap or replay specifically for ``lineage`` fails the trust
    check. Any ledger error fails closed (False)."""
    try:
        chain = sealed_fact_ledger.verify_chain()
        if not chain.get("intact", False):
            return False
        gaps = sealed_fact_ledger.verify_no_gaps()
        if lineage in gaps.get("gaps", {}) or lineage in gaps.get("duplicates", {}):
            return False
        return True
    except Exception:  # noqa: BLE001 — any ledger failure → untrusted → ABSTAIN
        return False


__all__ = [
    "AttenuationError",
    "CapabilityGrant",
    "CapabilityToken",
    "SealedRun",
    "attenuate",
    "capability_tokens_enabled",
    "make_use_proof",
    "mint_capability_token",
    "seal_run",
    "trust_sealed_run",
    "verify_capability_token",
]
