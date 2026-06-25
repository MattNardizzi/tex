"""
CHOKE-X — per-branch attacker-leverage certifier (decidable finite-enum fragment).

Complement to CFI-BUDGET (``cfi.py``). CFI bounds the *cumulative* control-flow
influence an untrusted value exerts across a whole run, with a flat per-branch
charge. That flat charge admits a single **high-leverage flip**: one in-budget
branch can still commit an irreversible arm under direct attacker control. CHOKE-X
catches exactly that — it certifies, per high-stakes branch, BEFORE the branch
executes, how many distinct arms an attacker can steer to by varying the untrusted
value over its *declared signed domain*.

The certificate is a **2-safety** property, established by self-composition over
the untrusted domain:

    certified_bits = log2(#distinct arms selected across the whole domain)

- If every value in the domain selects the SAME arm, the branch is *invariant*
  in the untrusted input (the attacker cannot steer it): 0 distinct arms-of-
  variation → ``log2(1) = 0`` certified bits.
- If the domain splits across ``k`` distinct committed arms, the attacker can
  realize at most ``log2(k)`` bits of leverage over the control-flow decision.

Crucially the certifier is **transparent** in the Cecchetti–Myers sense: the
endorsement decision (``certified_bits`` vs the branch's ``budget_bits``) is a
function of the untrusted DOMAIN (the abstract set of all possible attacker
values) and the TRUSTED inputs ONLY. It NEVER reads the single realized untrusted
value. The realized value only selects which arm runs AFTER endorsement is
granted — it can never influence whether endorsement is granted.

Decidable fragment (the thin slice)
-----------------------------------
This module certifies ONLY the **finite-enum** fragment: a branch whose condition
was produced by a node that declared a finite ``output_domain``, and whose arm-
selection is a pure, decidable function of (domain value, trusted env). The
interpreter's arm selection in this slice is Python truthiness of the domain
value — a total function over the finite enum, so exhaustive self-composition is
sound and complete. Interval-numeric and statistical-sampling tiers are
explicitly DEFERRED; a high-stakes branch outside this fragment ABSTAINs (the
interpreter never samples-and-commits).

Honest scope (what this does NOT do)
------------------------------------
- **Sound only for the decidable finite-enum fragment.** A high-stakes guard that
  is free-text / opaque / latent (no finite enumerable signed domain) is NOT
  certified — it ABSTAINs. That is utility deliberately traded for honesty: Tex
  does not guess a leverage bound it cannot prove.
- **Soundness is relative to the SIGNED declared domain.** If a producing node
  lies about its ``output_domain`` (declares ``("yes","no")`` but can emit
  arbitrary strings), CHOKE-X certifies against the lie. The interpreter's
  in-domain runtime check (HALT on out-of-domain output) is the enforcement of
  the declaration, but cannot detect a domain that is honestly-typed yet
  semantically broader than reality.
- **The enum-projection classifier is a separate oracle.** When the real
  attacker channel is free text projected into the enum by some classifier, the
  fidelity of THAT projection is its own trust obligation; CHOKE-X certifies the
  enum→arm map, not the text→enum map.
- **Cross-session / cumulative steering is out of scope** — that is the ledgered
  CFI budget's job (``cfi.py``). CHOKE-X is a single-branch, per-flip certificate.

References: Cecchetti, Myers et al. on *transparent endorsement* / robust
declassification (nonmalleable information flow); 2-safety via self-composition
(Barthe–D'Argenio–Rezk; Terauchi–Aiken). Companion to CaMeL §4.3.
"""

from __future__ import annotations

import math
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:  # avoid an import cycle (plan imports nothing from this module)
    from tex.camel.plan import Branch, DomainScalar


# An arm identifier — opaque label distinguishing which control-flow continuation
# the guard commits to for a given domain value. The thin slice uses the literal
# strings "then" / "else"; the certifier only ever compares them for equality.
Arm = str

# The decidable arm-selection oracle: given a single domain value and the fixed
# trusted environment, return the arm the guard commits to. It MUST be a pure,
# total function over the finite enum domain (no side effects, deterministic).
ArmSelector = Callable[["DomainScalar", "dict[str, object]"], Arm]


class NonDecidableGuard(Exception):
    """Raised when a high-stakes branch's guard is NOT in the decidable finite-
    enum fragment (e.g. its condition has no declared finite ``output_domain``).

    The interpreter catches this and resolves the branch to ABSTAIN — it never
    samples-and-commits a guard it cannot exhaustively certify."""


def truthiness_selector(value: "DomainScalar", trusted_env: dict[str, object]) -> Arm:
    """The thin-slice arm-selection oracle: the interpreter takes the ``then``
    arm iff the condition value is Python-truthy, else the ``else`` arm.

    This mirrors ``_step_branch`` exactly (``chosen = then if cond_value.value
    else else``). It reads ONLY the abstract domain ``value`` passed by the
    certifier's enumeration — never a realized run-time value — and the trusted
    env (unused here, but present so the signature is the general decidable-guard
    contract). Total over any finite scalar domain → exhaustive enum is sound."""
    return "then" if value else "else"


def make_match_selector(match_value: "DomainScalar") -> ArmSelector:
    """Build the value-discriminating arm-selection oracle: the ``then`` arm fires
    iff the domain value EQUALS ``match_value`` (exact equality), else ``else``.

    This mirrors the interpreter's ``match_enabled`` selection exactly, so the
    2-safety certificate is sound w.r.t. actual execution. It lets a fully-truthy
    enum (e.g. ``{refund, no_refund}``) split across both arms — the per-value
    leverage CHOKE-X exists to certify. ``match_value`` is a TRUSTED literal from
    the plan (the P-LLM), never an untrusted value."""

    def _select(value: "DomainScalar", trusted_env: dict[str, object]) -> Arm:
        return "then" if value == match_value else "else"

    return _select


def selector_for(branch: "Branch") -> ArmSelector:
    """The arm-selection oracle for ``branch`` — IDENTICAL to what the interpreter
    uses, so the certificate is sound w.r.t. execution. Equality-discriminating
    when the branch declared ``match_enabled``; Python truthiness otherwise."""
    if branch.match_enabled:
        return make_match_selector(branch.match_value)
    return truthiness_selector


def certify_leverage(
    branch: "Branch",
    untrusted_domain: "tuple[DomainScalar, ...]",
    trusted_env: dict[str, object] | None = None,
    *,
    arm_selector: ArmSelector | None = None,
) -> float:
    """Exhaustive finite-enum leverage certificate (2-safety self-composition).

    Enumerate EVERY value ``v`` in ``untrusted_domain``; with the trusted inputs
    FIXED, evaluate which arm ``arm_selector`` commits for each ``v``. Return::

        certified_bits = log2(#DISTINCT arms selected across the whole domain)

    so an invariant guard (all ``v`` select the same arm) certifies 0 bits, and a
    guard the attacker can flip between ``k`` arms certifies ``log2(k)`` bits.

    This is a 2-safety property: it quantifies over *pairs* of executions that
    differ only in the untrusted value (self-composition) and measures whether
    the public control-flow decision can differ. It is computed from the DOMAIN
    + ``trusted_env`` ONLY — never from any single realized untrusted value
    (transparent endorsement).

    Raises:
        NonDecidableGuard — if ``untrusted_domain`` is ``None`` (the guard is not
            in the decidable finite-enum fragment: no signed finite domain to
            enumerate). The interpreter maps this to ABSTAIN.
        ValueError — on an empty domain (a value that can take *no* value is
            malformed).
    """
    if untrusted_domain is None:
        raise NonDecidableGuard(
            f"branch on {branch.cond_var!r} has no finite enumerable signed "
            f"domain (non-decidable guard: cannot certify leverage)"
        )
    if len(untrusted_domain) < 1:
        raise ValueError("untrusted_domain must be non-empty")

    selector = arm_selector if arm_selector is not None else selector_for(branch)
    env = dict(trusted_env or {})
    selected: set[Arm] = set()
    for v in untrusted_domain:
        selected.add(selector(v, env))

    distinct = len(selected)
    # distinct >= 1 always (domain is non-empty). log2(1) == 0 = invariant guard.
    return math.log2(distinct)


__all__ = [
    "Arm",
    "ArmSelector",
    "NonDecidableGuard",
    "certify_leverage",
    "make_match_selector",
    "selector_for",
    "truthiness_selector",
]
