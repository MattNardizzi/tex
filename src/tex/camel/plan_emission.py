"""
FAITHFUL CaMeL plan-emission from REAL request data — the activation seam.

[Architecture: Layer 4 (Execution Governance) — the compiler that turns a real
request's declared untrusted-read-then-branch structure into a metered CaMeL
``Plan`` the evolved interpreter can run.]

⛔ THE ANTI-THEATER CONTRACT (the rule this module exists to honor)
------------------------------------------------------------------
The plan AND its untrusted provenance must come from the **real request**:

  * The untrusted CONTENT is read from the request itself (``request.content``
    or a declared real field) — it is NEVER synthesized.
  * The branch STRUCTURE (the finite signed domain, the two arms, the sink
    actions, the effect class) is the agent's OWN declared about-to-execute
    branching behaviour, carried on ``request.metadata['camel_branch_flow']``.
  * If the request carries **no genuine untrusted-read-then-branch structure**
    (no ``camel_branch_flow`` block, or a block that does not describe a real
    data-dependent branch over a finite signed domain), this module emits
    **NOTHING** (``None``) — the specialist then correctly abstains. We do NOT
    fabricate a branch for a straight-line flow, do NOT hardcode a plan, and do
    NOT invent an untrusted source.

This is the faithful counterpart of the CaMeL P-LLM emitting a plan: a real
integration declares the branch it is about to take over real untrusted data,
and Tex compiles that declaration into the metered IR so CFI/CHOKE-X can price
and certify it BEFORE the real action runs. The optional LLM-backed P-LLM path
(a model proposing the plan) is a separate, flag-gated enhancement — this
deterministic compiler is the load-bearing, key-free path.

Input shape (``request.metadata['camel_branch_flow']`` — all opt-in)
--------------------------------------------------------------------
A block describing ONE data-dependent branch::

    {
      # WHERE the untrusted content lives in the REAL request. Either
      # "content" (use request.content) or "metadata:<key>" (a declared real
      # field already on the request). NEVER a literal string here — that
      # would be synthesizing untrusted data, which this module refuses.
      "untrusted_source": "email_body",          # logical source label
      "untrusted_from": "content",               # real location: content | metadata:<key>
      # The finite SIGNED domain the agent projects the untrusted content into
      # (its real declared classifier output set). MUST be a finite enum.
      "domain": ["refund", "no_refund"],
      # The arm-selecting value (exact-equality match) + the real sink actions.
      "match_value": "refund",                   # optional; truthiness if absent
      "then_tool": "issue_refund",               # real sink the then-arm calls
      "else_tool": null,                          # optional
      # Real reversibility + per-branch leverage declaration (CHOKE-X).
      "effect_class": "irreversible",            # reversible | irreversible
      "budget_bits": 0                            # per-branch leverage budget
    }

When ``untrusted_from`` resolves to genuinely-present content AND ``domain`` is
a finite enum of ≥1 scalar, a faithful ``EmittedPlan`` is returned. Anything
missing / malformed → ``None`` (abstain). A block that declares no real branch
(e.g. an empty / absent domain) → ``None``.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tex.camel.plan import (
    Assign,
    Branch,
    Call,
    Plan,
    QLLM,
    Read,
    Return,
    Var,
)

_BRANCH_FLOW_KEY = "camel_branch_flow"


class DeterministicDomainProjector:
    """A REAL (deterministic, key-free) enum-projection oracle: project the actual
    untrusted content into exactly one member of the declared finite domain by
    case-insensitive substring/equality match, else emit a sentinel that is NOT in
    the domain → the interpreter HALTs (fail-closed).

    This is the honest, no-LLM ``Q-LLM`` for the faithful path. It NEVER fabricates
    a domain member to force a branch: the projection is a pure function of the real
    content. When the content matches no declared category, it returns a reserved
    out-of-domain marker so the interpreter's in-domain check HALTs rather than
    silently picking an arm — exactly the fail-closed behaviour CHOKE-X relies on.

    As ``branch_leverage.py`` documents, the fidelity of THIS text→enum map is its
    own trust obligation; CHOKE-X certifies the enum→arm map, not this projection.
    A real deployment may swap in an LLM-backed projector (flag-gated, needs a key);
    this deterministic one is the load-bearing default.
    """

    __slots__ = ("_domain",)

    # A marker guaranteed not to be a declared domain member (domains are JSON
    # scalars; this object is not). Projecting to it makes the interpreter HALT.
    _NO_MATCH = "\x00camel:no_domain_match\x00"

    def __init__(self, domain: tuple) -> None:
        self._domain = domain

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:
        body = " ".join(str(i) for i in inputs).casefold()
        # Prefer an exact case-insensitive equality with a declared member; fall
        # back to substring containment. Deterministic, order-stable.
        for member in self._domain:
            if isinstance(member, str) and member.casefold() == body.strip():
                return member
        for member in self._domain:
            if isinstance(member, str) and member.casefold() in body:
                return member
        return self._NO_MATCH

# The scalar types a faithful finite signed domain may range over.
_DOMAIN_SCALARS = (str, int, bool, type(None))


def plan_emission_enabled(env: Mapping[str, str] | None = None) -> bool:
    """True iff ``TEX_CAMEL_EMIT_ENABLED`` is set truthy. Default OFF: with it
    unset the evaluate_action seam never compiles a plan, so behaviour is
    bit-for-bit unchanged."""
    e = os.environ if env is None else env
    raw = e.get("TEX_CAMEL_EMIT_ENABLED")
    if raw is None:
        return False
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class EmittedPlan:
    """A faithfully-compiled CaMeL plan plus the untrusted env that feeds it.

    ``plan`` is the metered IR (a ``Read`` of the real untrusted source → a
    ``QLLM`` that projects it into the declared finite domain → a ``Branch``
    priced by CFI and, when high-stakes, certified by CHOKE-X). ``untrusted_env``
    maps the source label to the REAL untrusted content pulled from the request
    (never synthesized). ``user_prompt`` is the real request content for trace
    context. ``provenance`` records exactly where the untrusted bytes came from
    so an auditor can confirm they were not fabricated.
    """

    plan: Plan
    untrusted_env: dict[str, str]
    user_prompt: str
    provenance: dict[str, str]
    # The REAL deterministic enum-projection oracle bound to this plan's declared
    # finite domain (the ``Q-LLM`` the interpreter runs to project the untrusted
    # content into the domain). Carried with the plan so the specialist wires the
    # exact projector that matches the declared domain.
    projector: DeterministicDomainProjector


def _resolve_untrusted_content(request: Any, untrusted_from: str) -> str | None:
    """Pull the REAL untrusted content out of the request at the declared
    location. ``content`` → ``request.content``; ``metadata:<key>`` → a real
    field already on ``request.metadata``. Returns ``None`` when the declared
    location holds no real content — we never invent it.
    """
    loc = untrusted_from.strip()
    if loc == "content":
        content = getattr(request, "content", None)
        if isinstance(content, str) and content.strip():
            return content
        return None
    if loc.startswith("metadata:"):
        key = loc[len("metadata:"):].strip()
        if not key:
            return None
        metadata = getattr(request, "metadata", None)
        if not isinstance(metadata, Mapping):
            return None
        raw = metadata.get(key)
        # Only a genuinely-present string field counts as real untrusted content.
        if isinstance(raw, str) and raw.strip():
            return raw
        return None
    # Any other location string is unrecognised — fail closed (no plan), never
    # treat the literal as content.
    return None


def _coerce_domain(raw: Any) -> tuple | None:
    """A finite enum of JSON scalars, or ``None`` when absent/malformed/empty.

    An absent or empty domain means there is no real finite branch to meter →
    no plan. We never default a domain."""
    if not isinstance(raw, (list, tuple)):
        return None
    out: list = []
    for v in raw:
        if isinstance(v, _DOMAIN_SCALARS):
            out.append(v)
        else:
            # A non-scalar domain member is malformed → fail closed.
            return None
    if not out:
        return None
    return tuple(out)


def compile_branch_flow(request: Any) -> EmittedPlan | None:
    """Compile the request's declared ``camel_branch_flow`` into a faithful
    metered CaMeL plan, or return ``None`` (→ abstain) when the request carries
    no genuine untrusted-read-then-branch structure.

    FAITHFULNESS GUARANTEES (each a fail-closed ``None`` if unmet):
      * the block must exist and be a mapping;
      * the untrusted content must be REAL and present at the declared request
        location (``_resolve_untrusted_content``) — never synthesized;
      * the projection ``domain`` must be a finite enum of ≥1 scalar — a real
        data-dependent branch;
      * the then-arm must name a real sink tool (a branch with no action is not
        a meaningful flow to meter).
    Anything else → ``None``.
    """
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    block = metadata.get(_BRANCH_FLOW_KEY)
    if not isinstance(block, Mapping):
        return None

    source = block.get("untrusted_source")
    untrusted_from = block.get("untrusted_from")
    if not (isinstance(source, str) and source.strip()):
        return None
    if not (isinstance(untrusted_from, str) and untrusted_from.strip()):
        return None
    source = source.strip()

    content = _resolve_untrusted_content(request, untrusted_from)
    if content is None:
        # The declared untrusted location holds no real content. There is no
        # genuine untrusted read here → emit nothing.
        return None

    domain = _coerce_domain(block.get("domain"))
    if domain is None:
        # No finite signed domain → no real data-dependent branch → no plan.
        return None

    then_tool = block.get("then_tool")
    if not (isinstance(then_tool, str) and then_tool.strip()):
        # A branch that takes no real sink action is not a flow worth metering.
        return None
    then_tool = then_tool.strip()
    else_tool = block.get("else_tool")
    else_tool = else_tool.strip() if isinstance(else_tool, str) and else_tool.strip() else None

    effect_class = block.get("effect_class")
    effect_class = (
        effect_class.strip()
        if isinstance(effect_class, str) and effect_class.strip() in ("reversible", "irreversible")
        else "reversible"
    )

    raw_budget = block.get("budget_bits")
    budget_bits: int | None = None
    if isinstance(raw_budget, bool):
        budget_bits = None
    elif isinstance(raw_budget, int) and raw_budget >= 0:
        budget_bits = raw_budget

    match_value = block.get("match_value")
    match_enabled = "match_value" in block and isinstance(match_value, _DOMAIN_SCALARS)

    # ── Build the faithful metered IR ──────────────────────────────────────
    # Read the REAL untrusted source → project it into the declared finite
    # domain via the quarantined LLM (the declared classifier) → Branch on the
    # projection, priced by CFI and (when high-stakes) certified by CHOKE-X →
    # each arm calls its REAL declared sink tool. The Q-LLM carries the finite
    # output_domain so the Branch is decidable (a Read alone would be untyped).
    then_nodes: tuple = (
        (Call(tool=then_tool, args=(Var(name="projected"),), result_var="then_r"),)
    )
    else_nodes: tuple = (
        (Call(tool=else_tool, args=(Var(name="projected"),), result_var="else_r"),)
        if else_tool is not None
        else ()
    )

    branch_kwargs: dict[str, Any] = {
        "cond_var": "projected",
        "then_nodes": then_nodes,
        "else_nodes": else_nodes,
        "effect_class": effect_class,
    }
    if budget_bits is not None:
        branch_kwargs["budget_bits"] = budget_bits
    if match_enabled:
        branch_kwargs["match_enabled"] = True
        branch_kwargs["match_value"] = match_value

    plan = Plan(
        nodes=(
            Assign(name="raw", expr=Read(source=source)),
            QLLM(
                query=(
                    f"Classify the untrusted {source} into exactly one of the "
                    f"declared categories."
                ),
                inputs=(Var(name="raw"),),
                result_var="projected",
                output_domain=domain,
            ),
            Branch(**branch_kwargs),
            Return(expr=Var(name="projected")),
        ),
        description=(
            f"faithful camel_branch_flow over untrusted {source!r} "
            f"(from {untrusted_from!r})"
        ),
    )

    return EmittedPlan(
        plan=plan,
        untrusted_env={source: content},
        user_prompt=content,
        provenance={
            "untrusted_source": source,
            "untrusted_from": untrusted_from,
            "domain_size": str(len(domain)),
            "effect_class": effect_class,
        },
        projector=DeterministicDomainProjector(domain),
    )


# --------------------------------------------------------------------------- #
# Request-keyed sidecar for the emitted plan                                  #
# --------------------------------------------------------------------------- #
#
# An ``EmittedPlan`` carries a live ``Plan`` object + a projector callable — neither
# is JSON-serializable, so it must NOT be stamped onto ``request.metadata`` (the
# semantic layer JSON-dumps the whole metadata dict). Instead the evaluate_action
# seam stows the emitted plan in this process-local, request-id-keyed sidecar, and
# the evolved ``CamelSpecialist`` pops it back out by request_id inside the same
# evaluate() call. Bounded LRU so a long-running process never leaks. This mirrors
# the value-budget singleton's shared-state discipline.

_SIDECAR_LOCK = threading.Lock()
_SIDECAR: "OrderedDict[str, EmittedPlan]" = OrderedDict()
_SIDECAR_MAX = 4096


def stash_emitted_plan(request_id: str, emitted: EmittedPlan) -> None:
    """Stow the emitted plan for ``request_id`` (the evaluate_action seam)."""
    if not request_id:
        return
    with _SIDECAR_LOCK:
        _SIDECAR[request_id] = emitted
        _SIDECAR.move_to_end(request_id)
        while len(_SIDECAR) > _SIDECAR_MAX:
            _SIDECAR.popitem(last=False)


def take_emitted_plan(request_id: str) -> EmittedPlan | None:
    """Peek the emitted plan for ``request_id`` (the CamelSpecialist). Non-destructive
    read so multiple specialists / the floor can all see the same emitted plan within
    one evaluation; eviction is purely LRU-bounded."""
    if not request_id:
        return None
    with _SIDECAR_LOCK:
        emitted = _SIDECAR.get(request_id)
        if emitted is not None:
            _SIDECAR.move_to_end(request_id)
        return emitted


def _reset_emission_sidecar() -> None:
    """Test-only: clear the sidecar between tests."""
    with _SIDECAR_LOCK:
        _SIDECAR.clear()


__all__ = [
    "DeterministicDomainProjector",
    "EmittedPlan",
    "compile_branch_flow",
    "plan_emission_enabled",
    "stash_emitted_plan",
    "take_emitted_plan",
]
