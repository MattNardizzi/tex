"""
Reflexive self-governance gate (Wave 2 / L5) — Tex's OWN controller mutations
routed through the SAME PDP, the SAME ABSTAIN surface, the SAME monotone+floor
rules, sealed into the SAME ledger.

[Architecture: Layer 5 (Self-Governance) — meta-circular stratum]

The claim (ROADMAP.md L5 row, scoped exactly — this module's honesty boundary)
------------------------------------------------------------------------------
Tex's controller mutations — the writes that change what Tex decides NEXT
(policy activation, proposal apply/rollback, agent lifecycle, capability
surfaces, in-process key material) — route through ``gate_controller_mutation``,
which evaluates each mutation with the real :class:`PolicyDecisionPoint` under a
deploy-frozen governor policy, composes the verdict monotonically with
deterministic ``metaguard`` signatures, DENIES on FORBID/ABSTAIN (deny = do not
mutate; surface the hold), and seals every gate outcome as a
``SealedFact(ENFORCEMENT)`` into the same hash-chained, signed ledger the
DECISION seam (M0) uses. Maturity: **research-early**.

What is NOT claimed (named, so nobody over-reads the module name):
  * NOT "provably cannot ungovern itself" (the L5 North-Star) — that is out of
    scope; this ships gate + seal + enumeration.
  * NOT a proven-complete mutation surface. The census below is enumerated and
    tripwired (``tests/test_reflexive_gov.py``), not proven complete — the
    ROADMAP blocker ("the 4 named seams are NOT the complete mutation
    surface") is *addressed by enumeration*, and the residual is named in
    ``DEPLOY_FROZEN_STRATUM`` + the SHOULD/EXCLUDE lists.
  * NOT protection against arbitrary in-process code. An attacker who can
    execute arbitrary Python in the Tex process can monkeypatch this gate out;
    the threat model is mutation REQUESTS flowing through the governed
    surfaces (HTTP routes, commands, orchestrators, stores).
  * The gate is **inert until bound** (``bind_reflexive_governor``), exactly
    the M0/L9 opt-in convention (``decision_ledger=None`` default,
    ``TEX_SEAL_DECISIONS=1`` opt-in). An unbound process is TODAY's behaviour
    byte-for-byte; binding is the deployment act that turns reflexive
    governance on. Production today does not bind it — say "the capability is
    wired and opt-in," never "Tex is reflexively governed by default."
  * The same-PDP evaluation's *discriminating power on mutation descriptors*
    is today carried almost entirely by the deterministic metaguard
    signatures + the frozen policy thresholds; the probabilistic layers have
    no mutation-specific calibration yet (named research-early gap). The PDP
    reuse buys the shared ABSTAIN surface, the hold contract, the DECISION
    seal, and every future signal (CRC calibration, e-value spine, contracts)
    applying to self-mutations automatically.

Design — two approaches generated, attacked, synthesized (CLAUDE.md depth rule)
------------------------------------------------------------------------------
(A) Route through the real ``PolicyDecisionPoint.evaluate`` (CHOSEN): the
    roadmap's own words ("same PDP / same ABSTAIN surface / same monotone+floor
    rules") are the spec; reuse means self-mutations inherit every current and
    future verdict-path property (M0 DECISION seal, CRC demotion, risk spine,
    behavioural contracts) with zero parallel maintenance. Attack: (1)
    recursion — a mutation evaluation must not itself trigger gated mutations;
    killed by the deploy-frozen stratum + a context-var no-regress backstop
    (any gated mutation attempted DURING a gate evaluation is denied
    deterministically, proven by test); (2) the PDP is uncalibrated for
    mutation descriptors — conceded and named above, mitigated by metaguard.
(B) Standalone deterministic metaguard-only rule engine (REJECTED): simpler, no
    recursion surface — but it forks the verdict semantics into a second
    ABSTAIN surface that WILL drift from ``engine/hold.py``'s contract, it
    contradicts the roadmap's "same PDP" words, and every future verdict-path
    signal would need re-wiring into it. In this codebase the drift risk is
    concrete: ``build_hold`` is the single user-facing hold producer
    (hold.py — non-ABSTAIN returns None); a second hold producer would violate
    the ABSTAIN-only-surfaces invariant the whole product rests on.
Synthesis: (A) with (B)'s rule-set embedded as ``specialists/metaguard.py`` —
deterministic signatures compose monotonically (floor→FORBID,
caution→PERMIT→ABSTAIN, never raise) with the PDP verdict, mirroring exactly
how ``structural_floor.py`` composes with the router.

Two-level deploy-frozen stratum (kills the regress)
---------------------------------------------------
Level 1 (governed, in-process): every census surface below — gated, sealed.
Level 0 (deploy-frozen, NOT mutable in-process): the governor's own policy
(``GOVERNOR_FROZEN_POLICY`` — a code constant, never stored in any policy
store), the metaguard signature set (code), the binding capability token, and
everything in ``DEPLOY_FROZEN_STRATUM``. "Gate the gate" therefore terminates:
a mutation of level-0 is not a gateable in-process operation at all — it is a
redeploy — and any *stored-policy impersonation* of the governor's policy
family floors deterministically (``metaguard.governor_self_target``).

Controller-mutation census (the leap IS the enumeration; tripwired by test)
---------------------------------------------------------------------------
See ``CONTROLLER_MUTATION_CENSUS`` below — every entry carries status WIRED
(a ``gate_controller_mutation`` call sits at the method definition),
COVERED_VIA (the site provably routes through a WIRED chokepoint; the
delegation line is pinned by the tripwire test), EXCLUDED (reason), or
DEPLOY_FROZEN (``DEPLOY_FROZEN_STRATUM``).

Related work (retrieved + verified against arXiv abstracts 2026-06-11; abstract
-level verification only, full texts not read this session):
  * Nidus, arXiv:2604.05080 — externally-enforced constraint framework that
    can govern its own modifications (V-model proof obligations per commit).
  * Aegis, arXiv:2603.16938 — cryptographic runtime governance; immutable
    ethics-policy layer bound at startup + enforcement kernel.
  * "Core Safety Values for Provably Corrigible Agents", arXiv:2507.20964 —
    corrigibility via hierarchically separated utility components.
Delta here: self-mutations are ruled by the SAME production decision engine
that rules customer actions (not a separate kernel), and every self-verdict is
sealed into the same replayable hash-chained ECDSA-P256-signed ledger — the
cryptographic replay-of-self-verdicts. (ECDSA-P256 today; the chain proves
integrity, a signature proves authorship of one record — never collapse them.)
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from tex.domain.evaluation import EvaluationRequest
from tex.domain.evidence import EvidenceMaturity
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord
from tex.specialists import metaguard as _mg
from tex.specialists.metaguard import (
    AGENT_SAVE,
    GOVERNANCE_ACTIVATE,
    GOVERNOR_BINDING,
    KEY_MUTATION,
    LIFECYCLE_TRANSITION,
    MetaguardResult,
    POLICY_ACTIVATE,
    POLICY_CLEAR,
    POLICY_DELETE,
    POLICY_WRITE,
    PROPOSAL_APPLY,
    PROPOSAL_ROLLBACK,
    evaluate_metaguard,
    weakening_axes,
    widened_dimensions,
)

_logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Level-0: the deploy-frozen stratum
# ─────────────────────────────────────────────────────────────────────────────

GOVERNOR_POLICY_ID = _mg.GOVERNOR_POLICY_ID  # "reflexive-governor"
GOVERNOR_POLICY_VERSION = "reflexive-governor-frozen-v1"

# The governor's own policy. A CODE CONSTANT — it never enters any policy
# store, so no in-process mutation path reaches it (level-0). minimum_confidence
# is 0.0 deliberately and honestly: the PDP's confidence on descriptor-JSON
# content is uncalibrated for this action class (measured ~0.58 on neutral
# descriptors), so a confidence gate here would ABSTAIN-deny every routine
# mutation and make bound mode unusable; the deterministic deny power lives in
# metaguard. Revisit when a mutation-risk calibration corpus exists.
GOVERNOR_FROZEN_POLICY = PolicySnapshot(
    policy_id=GOVERNOR_POLICY_ID,
    version=GOVERNOR_POLICY_VERSION,
    is_active=True,
    permit_threshold=0.35,
    forbid_threshold=0.65,
    minimum_confidence=0.0,
)

# What is NOT reachable by this gate in-process. Enumerated so the completeness
# claim is honest: these mutate what Tex decides next but live outside the
# governed in-process surfaces. Changing any of them is a deploy/host operation.
DEPLOY_FROZEN_STRATUM: tuple[tuple[str, str], ...] = (
    (
        "env:TEX_SEAL_DECISIONS",
        "flips DECISION sealing; process environment, read at composition",
    ),
    (
        "env:TEX_NANOZK_ALLOW_SHIM",
        "test-only shim gate for the deactivated nanozk placeholder",
    ),
    (
        "env:TEX_API_KEYS",
        "API authentication material; process environment",
    ),
    (
        "env:DATABASE_URL",
        "selects durable vs in-memory stores; process environment",
    ),
    (
        "env:TEX_EVIDENCE_KEY_DIR",
        "where the evidence seal key file lives; process environment",
    ),
    (
        "file:evidence_seal_key.json",
        "de-facto key rotation = file replacement under TEX_EVIDENCE_KEY_DIR "
        "(no rotation code path exists — voice/attestation.py:34-36); only the "
        "in-process write (evidence.seal._persist_key) is gated",
    ),
    (
        "code:GOVERNOR_FROZEN_POLICY + metaguard signatures",
        "level-0 of the two-level stratum; changing them is a redeploy",
    ),
    (
        "object:binding capability token",
        "unbind/rebind requires the token returned by bind_reflexive_governor; "
        "held by the composition root",
    ),
    (
        "process:arbitrary in-process code execution",
        "monkeypatching the gate itself is outside the threat model (named "
        "honestly; no in-process gate can defend its own text segment)",
    ),
    (
        "object:live ledger / PDP reference swap at the composition root",
        "rebinding main.py wiring variables is a deploy-time concern; "
        "constructing a NEW ledger/PDP object does not mutate the live one",
    ),
)


# ─────────────────────────────────────────────────────────────────────────────
# Census — MUST (WIRED / COVERED_VIA), SHOULD (decided), EXCLUDED (reasons)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class MutationSite:
    """One enumerated entry of the controller-mutation surface."""

    path: str          # repo-relative file
    qualname: str      # Class.method or function
    status: str        # WIRED | COVERED_VIA | EXCLUDED
    note: str          # for COVERED_VIA: the pinned delegation; for EXCLUDED: why


CONTROLLER_MUTATION_CENSUS: tuple[MutationSite, ...] = (
    # ── MUST: the chokepoints (WIRED — gate call at the method definition) ──
    MutationSite("src/tex/stores/policy_store.py", "InMemoryPolicyStore.save", "WIRED", "base store under the wrapper; dev/test compositions use it directly"),
    MutationSite("src/tex/stores/policy_store.py", "InMemoryPolicyStore.activate", "WIRED", "verdict-changing flip"),
    MutationSite("src/tex/stores/policy_store.py", "InMemoryPolicyStore.delete", "WIRED", "evidence destruction"),
    MutationSite("src/tex/stores/policy_store.py", "InMemoryPolicyStore.clear", "WIRED", "evidence destruction"),
    MutationSite("src/tex/memory/policy_snapshot_store.py", "DurablePolicyStore.save", "WIRED", "the ONE live instance (main.py:557 policy_store = memory.policies); save can replace active-version bytes"),
    MutationSite("src/tex/memory/policy_snapshot_store.py", "DurablePolicyStore.save_in_tx", "WIRED", "eval-path idempotent re-persist is a no_change fast pass; byte-replacement is gated"),
    MutationSite("src/tex/memory/policy_snapshot_store.py", "DurablePolicyStore.activate", "WIRED", "THE chokepoint: ActivatePolicyCommand/CalibratePolicyCommand/FeedbackLoopOrchestrator all converge here"),
    MutationSite("src/tex/memory/policy_snapshot_store.py", "DurablePolicyStore.delete", "WIRED", "gated before the postgres delete"),
    MutationSite("src/tex/memory/policy_snapshot_store.py", "DurablePolicyStore.clear", "WIRED", "cache wipe"),
    MutationSite("src/tex/learning/feedback_loop.py", "FeedbackLoopOrchestrator.apply_proposal", "WIRED", "METHOD is the gate unit (save+activate+safety-commit are all-or-nothing on deny; gate sits before approve)"),
    MutationSite("src/tex/learning/feedback_loop.py", "FeedbackLoopOrchestrator.rollback_proposal", "WIRED", "rollback activates an older version; weakening rules apply to the target"),
    MutationSite("src/tex/governance/standing.py", "StandingGovernance.activate", "WIRED", "caller swallows exceptions (api/discovery_surface_routes.py:212-213) → gate denies by NOT mutating, never by raising"),
    MutationSite("src/tex/stores/agent_registry.py", "InMemoryAgentRegistry.save", "WIRED", "capability_surface replacement moves the structural floor; save can also flip lifecycle wholesale (lifecycle rules applied to saves)"),
    MutationSite("src/tex/stores/agent_registry.py", "InMemoryAgentRegistry.set_lifecycle", "WIRED", "QUARANTINED→ACTIVE is a verdict-RAISING mutation reachable entirely outside commands/ (agent_routes.py:1300-1323, dormancy.wake)"),
    MutationSite("src/tex/c2pa/signer.py", "register_signing_key", "WIRED", "in-process key material"),
    MutationSite("src/tex/c2pa/signer.py", "clear_signing_keys", "WIRED", "in-process key material"),
    MutationSite("src/tex/c2pa/signer.py", "set_keystore", "WIRED", "in-process key material (keystore lookup swap)"),
    MutationSite("src/tex/evidence/seal.py", "_persist_key", "WIRED", "the only in-process write of the evidence seal key file; file replacement from outside the process is DEPLOY_FROZEN"),
    # ── MUST: covered via a WIRED chokepoint (delegation pinned by tripwire) ──
    MutationSite("src/tex/commands/activate_policy.py", "ActivatePolicyCommand.execute", "COVERED_VIA", "self._policy_store.activate("),
    MutationSite("src/tex/commands/calibrate_policy.py", "CalibratePolicyCommand.execute", "COVERED_VIA", "self._policy_store.activate("),
    MutationSite("src/tex/memory/system.py", "MemorySystem.activate_policy", "COVERED_VIA", "self.policies.activate("),
    MutationSite("src/tex/memory/system.py", "MemorySystem.record_policy_snapshot", "COVERED_VIA", "self.policies.save("),
    MutationSite("src/tex/stores/agent_registry_postgres.py", "PostgresAgentRegistry.set_lifecycle", "COVERED_VIA", "self._cache.set_lifecycle("),
    MutationSite("src/tex/stores/agent_registry_postgres.py", "PostgresAgentRegistry.save", "COVERED_VIA", "self._cache.save("),
    MutationSite("src/tex/discovery/dormancy.py", "DormancyManager.wake", "COVERED_VIA", "self._registry.set_lifecycle("),
    MutationSite("src/tex/discovery/service.py", "apply (capability surface / quarantine)", "COVERED_VIA", "self._registry.set_lifecycle("),
    MutationSite("src/tex/api/agent_routes.py", "transition_lifecycle", "COVERED_VIA", "registry.set_lifecycle("),
    MutationSite("src/tex/api/learning_routes.py", "apply/rollback proposal routes", "COVERED_VIA", "orch.apply_proposal("),
    # ── SHOULD: enumerated and decided ──
    MutationSite("src/tex/stores/calibration_proposal_store.py", "proposal status transitions", "EXCLUDED", "proposals parameterize nothing until apply_proposal — which is WIRED; staging metadata, not a controller mutation"),
    MutationSite("src/tex/learning/outcome_validator.py", "_quarantine", "EXCLUDED", "produces a ValidationResult marking an OUTCOME quarantined (evidence hygiene); does not transition agent lifecycle or policy"),
    MutationSite("tenant_content_baseline", "baseline writes", "EXCLUDED", "observational baselines feed drift detection (signals may only LOWER a verdict — monotone rule caps their blast radius); enumerated-deferred for a future census revision"),
    MutationSite("src/tex/provenance/ledger.py", "keygen-on-construct (:71-73)", "EXCLUDED", "constructing a NEW ledger does not mutate the live one; the live reference swap is DEPLOY_FROZEN (composition root)"),
    # ── EXCLUDED (one-line reasons, per the census discipline) ──
    MutationSite("decision/precedent/outcome/entity stores", "*", "EXCLUDED", "evidence records — they record what happened, they do not parameterize verdicts"),
    MutationSite("src/tex/api/auth.py", ":279 activate example", "EXCLUDED", "docstring usage example inside RequireScope, not a route"),
    MutationSite("ledger appends", "SealedFactLedger.append / recorder", "EXCLUDED", "governance OUTPUT (append-only evidence), not a controller mutation; gating them would recurse the seal"),
    MutationSite("nanozk / compliance / _pending", "*", "EXCLUDED", "dead code per CLAUDE.md — tested but not wired"),
)

# Enumerated-deferred (named so the residual is visible, per the honesty rule):
# agent attestation/trust-tier changes via registry.save (they move identity-
# stream scoring but not the capability floor) are NOT yet classified by
# metaguard — census v1 gates capability_surface widening and lifecycle flips.


# ─────────────────────────────────────────────────────────────────────────────
# Gate types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class MutationDescriptor:
    """One typed controller-mutation attempt, as the gate sees it."""

    surface: str                 # e.g. "stores.policy_store.InMemoryPolicyStore.activate"
    mutation_class: str          # one of the metaguard mutation-class constants
    subject_id: str | None
    payload: dict[str, Any]      # JSON-safe typed facts (old/new values, flags)
    environment: str = "production"


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """The gate's ruling on one mutation. ``allowed`` is the only field a
    chokepoint consults; everything else is audit surface."""

    allowed: bool
    gated: bool                          # False ⇒ governor unbound (inert; today's behaviour)
    verdict: str                         # "PERMIT" | "ABSTAIN" | "FORBID" | "UNGATED"
    mechanism: str                       # how the ruling was produced (see _MECHANISMS)
    reasons: tuple[str, ...] = ()
    floor_codes: tuple[str, ...] = ()
    caution_codes: tuple[str, ...] = ()
    hold: dict[str, Any] | None = None   # ABSTAIN surface (PDP hold or metaguard hold summary)
    enforcement_record: SealedFactRecord | None = None
    decision_sealed: bool = False        # True when the bound PDP sealed a DECISION fact


_MECHANISMS = (
    "ungated",            # governor unbound — mutation NOT governed (inert default)
    "no_change",          # byte-identical / target-missing: not a mutation; no seal
    "stage_pass",         # new inactive snapshot version: staging, activation is the gate; no seal
    "registration_pass",  # new agent registration: identity births are the behavioural ledger's job; no seal
    "protective_pass",    # mutation toward caution: deterministic pass, sealed
    "pdp+metaguard",      # full evaluation through the same PDP, metaguard-composed
    "no_regress_backstop",# mutation attempted DURING a gate evaluation: deterministic deny
    "error_fail_closed",  # internal gate error: deny (caution direction), never raise
)

_UNGATED = GateOutcome(
    allowed=True, gated=False, verdict="UNGATED", mechanism="ungated",
    reasons=("reflexive governor unbound — mutation not governed (inert default)",),
)


# ─────────────────────────────────────────────────────────────────────────────
# Binding (level-0: requires the capability token to undo)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class _Binding:
    pdp: Any                      # duck-typed: .evaluate(request=..., policy=...) -> PDPResult
    policy: PolicySnapshot
    ledger: Any | None            # duck-typed SealedFactLedger: .append(fact) -> record
    token: object


_BINDING_LOCK = threading.RLock()
_BINDING: _Binding | None = None

# No-regress instrumentation: depth of nested gate PDP evaluations on this
# logical context. The backstop denies any gated mutation attempted while a
# gate evaluation is in flight, so this can never exceed 1 (pinned by test).
_EVAL_DEPTH: ContextVar[int] = ContextVar("tex_selfgov_eval_depth", default=0)
_observed_max_eval_depth = 0  # test-visible high-water mark


def bind_reflexive_governor(
    *,
    pdp: Any,
    ledger: Any | None = None,
    policy: PolicySnapshot | None = None,
) -> object:
    """Bind the gate to a live PDP (+ optionally the shared SealedFactLedger).

    Returns the capability token required to unbind. Re-binding while bound is
    a governor-self-target mutation: it is denied, sealed, and RAISES — the one
    deliberate exception to deny-by-not-raising, because a silently ignored
    bind would leave the caller believing it is governed when it is not
    (fail-open). The composition root must unbind first, with its token.
    """
    global _BINDING
    with _BINDING_LOCK:
        if _BINDING is not None:
            descriptor = MutationDescriptor(
                surface="selfgov.governor.bind_reflexive_governor",
                mutation_class=GOVERNOR_BINDING,
                subject_id=GOVERNOR_POLICY_ID,
                payload={"attempt": "rebind_while_bound"},
            )
            outcome = gate_controller_mutation(descriptor)
            raise RuntimeError(
                "reflexive governor is already bound; rebinding is a "
                f"level-0 mutation and was denied ({outcome.verdict}); "
                "unbind with the binding token first"
            )
        token = object()
        _BINDING = _Binding(
            pdp=pdp,
            policy=policy or GOVERNOR_FROZEN_POLICY,
            ledger=ledger,
            token=token,
        )
        _seal_enforcement(
            _BINDING,
            MutationDescriptor(
                surface="selfgov.governor.bind_reflexive_governor",
                mutation_class=GOVERNOR_BINDING,
                subject_id=GOVERNOR_POLICY_ID,
                payload={"attempt": "bind"},
            ),
            allowed=True,
            verdict="PERMIT",
            mechanism="protective_pass",
            reasons=("reflexive governor bound by the composition root",),
            floor_codes=(),
            caution_codes=(),
        )
        return token


def unbind_reflexive_governor(token: object) -> bool:
    """Unbind with the capability token. A foreign token is a governor-self-
    target mutation: denied (by not mutating — returns ``False``) and sealed."""
    global _BINDING
    with _BINDING_LOCK:
        if _BINDING is None:
            return False
        if token is not _BINDING.token:
            descriptor = MutationDescriptor(
                surface="selfgov.governor.unbind_reflexive_governor",
                mutation_class=GOVERNOR_BINDING,
                subject_id=GOVERNOR_POLICY_ID,
                payload={"attempt": "unbind_without_token"},
            )
            gate_controller_mutation(descriptor)  # floors + seals the attempt
            return False
        _seal_enforcement(
            _BINDING,
            MutationDescriptor(
                surface="selfgov.governor.unbind_reflexive_governor",
                mutation_class=GOVERNOR_BINDING,
                subject_id=GOVERNOR_POLICY_ID,
                payload={"attempt": "unbind_with_token"},
            ),
            allowed=True,
            verdict="PERMIT",
            mechanism="protective_pass",
            reasons=("reflexive governor unbound by the binding token holder",),
            floor_codes=(),
            caution_codes=(),
        )
        _BINDING = None
        return True


def reflexive_governor_bound() -> bool:
    return _BINDING is not None


@contextmanager
def bound_reflexive_governor(
    *,
    pdp: Any,
    ledger: Any | None = None,
    policy: PolicySnapshot | None = None,
):
    """Test/composition helper: bind for the duration of the block."""
    token = bind_reflexive_governor(pdp=pdp, ledger=ledger, policy=policy)
    try:
        yield
    finally:
        unbind_reflexive_governor(token)


# ─────────────────────────────────────────────────────────────────────────────
# The gate
# ─────────────────────────────────────────────────────────────────────────────

def gate_controller_mutation(
    descriptor: MutationDescriptor | Callable[[], MutationDescriptor],
) -> GateOutcome:
    """Rule on one controller mutation. THE single reflexive chokepoint API.

    ``descriptor`` may be a zero-arg callable (the chokepoints pass a lambda)
    so the unbound fast path costs one ``None`` check and never builds the
    descriptor — the inert default is zero-cost on hot paths.

    Contract:
      * unbound → ``allowed=True, gated=False`` (today's behaviour, ungoverned
        and SAID so in the outcome).
      * bound → FORBID/ABSTAIN deny (``allowed=False``); the chokepoint denies
        by NOT mutating, never by raising. PERMIT proceeds. Every governed
        outcome (except the no-mutation fast passes) is sealed as a
        ``SealedFact(ENFORCEMENT)`` when a ledger is bound — fail-closed:
        a seal failure degrades to "not sealed", never to a crashed caller.
      * any internal gate error → deny, fail-closed, never raises.
    """
    binding = _BINDING
    if binding is None:
        return _UNGATED
    try:
        resolved = descriptor() if callable(descriptor) else descriptor
        return _gate_bound(binding, resolved)
    except Exception:
        _logger.exception(
            "reflexive gate internal error — failing closed (mutation denied)"
        )
        reasons = (
            "reflexive gate internal error — fail-closed deny "
            "(caution direction)",
        )
        try:
            fallback = descriptor() if callable(descriptor) else descriptor
        except Exception:
            fallback = MutationDescriptor(
                surface="unknown", mutation_class="unknown",
                subject_id=None, payload={},
            )
        record = _seal_enforcement(
            binding, fallback, allowed=False, verdict="FORBID",
            mechanism="error_fail_closed", reasons=reasons,
            floor_codes=(), caution_codes=(),
        )
        return GateOutcome(
            allowed=False, gated=True, verdict="FORBID",
            mechanism="error_fail_closed", reasons=reasons,
            enforcement_record=record,
        )


def _gate_bound(binding: _Binding, descriptor: MutationDescriptor) -> GateOutcome:
    global _observed_max_eval_depth

    mg = evaluate_metaguard(descriptor)

    # Not a mutation at all (byte-identical write / missing target): pass with
    # no seal — this keeps the per-request eval path (save_in_tx idempotent
    # re-persist, memory/system.py:264) zero-PDP-cost when bound.
    if mg.no_change:
        return GateOutcome(
            allowed=True, gated=True, verdict="PERMIT", mechanism="no_change",
            reasons=("no-change write: state would be byte-identical",),
        )

    # No-regress backstop: a gated mutation attempted DURING a gate evaluation
    # is denied deterministically — no recursion, fail-closed. The deploy-
    # frozen stratum means there is no legitimate reason for the verdict path
    # to mutate a controller surface mid-evaluation.
    if _EVAL_DEPTH.get() > 0:
        reasons = (
            "reflexive no-regress backstop: controller mutation attempted "
            "during a gate evaluation — denied without recursion",
        )
        record = _seal_enforcement(
            binding, descriptor, allowed=False, verdict="FORBID",
            mechanism="no_regress_backstop", reasons=reasons,
            floor_codes=mg.codes, caution_codes=(),
        )
        return GateOutcome(
            allowed=False, gated=True, verdict="FORBID",
            mechanism="no_regress_backstop", reasons=reasons,
            floor_codes=tuple(s.code for s in mg.floor),
            enforcement_record=record,
        )

    # Deterministic fast passes that skip the PDP. stage/registration passes
    # are unsealed (flood control — the verdict-changing step is gated and
    # sealed); protective passes are sealed (rare, governance-relevant).
    if not mg.fired:
        payload = descriptor.payload
        if payload.get("stage_write") is True:
            return GateOutcome(
                allowed=True, gated=True, verdict="PERMIT",
                mechanism="stage_pass",
                reasons=(
                    "stage write (new inactive snapshot version): cannot "
                    "change what Tex decides next until activated — "
                    "activation is the gated step",
                ),
            )
        if payload.get("new_registration") is True:
            return GateOutcome(
                allowed=True, gated=True, verdict="PERMIT",
                mechanism="registration_pass",
                reasons=("new agent registration (identity birth)",),
            )
        if mg.protective_pass:
            reasons = ("mutation moves the system toward caution — denying it "
                       "would itself weaken governance",)
            record = _seal_enforcement(
                binding, descriptor, allowed=True, verdict="PERMIT",
                mechanism="protective_pass", reasons=reasons,
                floor_codes=(), caution_codes=(),
            )
            return GateOutcome(
                allowed=True, gated=True, verdict="PERMIT",
                mechanism="protective_pass", reasons=reasons,
                enforcement_record=record,
            )

    # ── Full ruling: the SAME PDP, metaguard-composed monotonically ────────
    pdp_verdict: Verdict | None = None
    pdp_hold: dict[str, Any] | None = None
    pdp_reasons: tuple[str, ...] = ()
    decision_sealed = False
    depth_token = _EVAL_DEPTH.set(_EVAL_DEPTH.get() + 1)
    try:
        _observed_max_eval_depth = max(_observed_max_eval_depth, _EVAL_DEPTH.get())
        result = binding.pdp.evaluate(
            request=_build_request(descriptor), policy=binding.policy
        )
        pdp_verdict = result.decision.verdict
        pdp_reasons = tuple(result.decision.reasons)
        pdp_meta = result.decision.metadata.get("pdp", {})
        pdp_hold = pdp_meta.get("hold")
        decision_sealed = getattr(binding.pdp, "_decision_ledger", None) is not None
    finally:
        _EVAL_DEPTH.reset(depth_token)

    final = compose_gate_verdict(pdp_verdict, mg)
    allowed = final is Verdict.PERMIT

    reasons = pdp_reasons + tuple(
        s.reason for s in (*mg.floor, *mg.caution)
    )
    hold = pdp_hold
    if final is Verdict.ABSTAIN and hold is None:
        # metaguard demoted a PDP PERMIT: the PDP built no hold (it only
        # builds one for its own ABSTAIN), so surface a deterministic
        # gate-level hold summary on the same contract axes.
        hold = {
            "source": "metaguard",
            "resolution_mode": "human-judgment",
            "pivot": "; ".join(s.reason for s in mg.caution) or "controller mutation held",
            "codes": [s.code for s in mg.caution],
        }

    record = _seal_enforcement(
        binding, descriptor, allowed=allowed, verdict=final.value,
        mechanism="pdp+metaguard", reasons=reasons,
        floor_codes=tuple(s.code for s in mg.floor),
        caution_codes=tuple(s.code for s in mg.caution),
    )
    return GateOutcome(
        allowed=allowed,
        gated=True,
        verdict=final.value,
        mechanism="pdp+metaguard",
        reasons=reasons,
        floor_codes=tuple(s.code for s in mg.floor),
        caution_codes=tuple(s.code for s in mg.caution),
        hold=hold,
        enforcement_record=record,
        decision_sealed=decision_sealed,
    )


def compose_gate_verdict(pdp_verdict: Verdict, mg: MetaguardResult) -> Verdict:
    """Monotone composition — metaguard can only LOWER the PDP verdict.

    floor → FORBID (deterministic structural deny, same authority contract as
    ``specialists/structural_floor.py``); caution demotes PERMIT→ABSTAIN and
    never touches ABSTAIN/FORBID; nothing here can raise a verdict.
    """
    if mg.floor:
        return Verdict.FORBID
    if mg.caution and pdp_verdict is Verdict.PERMIT:
        return Verdict.ABSTAIN
    return pdp_verdict


# Mutation classes whose effect is irreversible — declared to the L4
# reversibility×blast lattice inside the SAME PDP evaluation (the existing
# wired ``metadata["action_class"]`` contract). Blast stays TENANT (the L4 map
# fires the floor only on IRREVERSIBLE×PUBLIC; the TENANT cell is recorded in
# the sealed decision, honestly, without fabricating a FORBID).
_IRREVERSIBLE_CLASSES = frozenset({POLICY_DELETE, POLICY_CLEAR, KEY_MUTATION})


def _build_request(descriptor: MutationDescriptor) -> EvaluationRequest:
    payload_json = json.dumps(
        descriptor.payload, sort_keys=True, separators=(",", ":"), default=str
    )
    summary = {
        "surface": descriptor.surface,
        "mutation_class": descriptor.mutation_class,
        "subject_id": descriptor.subject_id,
        "payload_sha256": hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
    }
    metadata: dict[str, Any] = {
        "controller_mutation": {**summary, "payload": dict(descriptor.payload)},
    }
    if descriptor.mutation_class in _IRREVERSIBLE_CLASSES:
        metadata["action_class"] = {
            "steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "TENANT"}]
        }
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="controller_mutation",
        content=json.dumps(summary, sort_keys=True),
        channel="selfgov",
        environment=descriptor.environment,
        metadata=metadata,
    )


def _seal_enforcement(
    binding: _Binding,
    descriptor: MutationDescriptor,
    *,
    allowed: bool,
    verdict: str,
    mechanism: str,
    reasons: tuple[str, ...],
    floor_codes: tuple[str, ...],
    caution_codes: tuple[str, ...],
) -> SealedFactRecord | None:
    """Seal one ENFORCEMENT fact — fail-closed, mirroring decision_seal.py.

    ``ledger is None`` → no-op ``None``; an append failure is logged and
    degrades to "not sealed", never to a failed mutation ruling.
    """
    if binding.ledger is None:
        return None
    word = "allowed" if allowed else "blocked"
    fact = SealedFact(
        kind=SealedFactKind.ENFORCEMENT,
        subject_id=descriptor.surface,
        claim=(
            f"controller mutation {descriptor.surface} "
            f"({descriptor.mutation_class}) {word} at the reflexive PEP "
            f"under policy {GOVERNOR_POLICY_ID}@{GOVERNOR_POLICY_VERSION} "
            f"— gate outcome sealed (authorship+integrity); verdict "
            f"correctness NOT proven; mutation-surface completeness NOT "
            f"proven (enumerated census, see selfgov.governor)"
        ),
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        detail={
            "allowed": allowed,
            "verdict": verdict,
            "mechanism": mechanism,
            "surface": descriptor.surface,
            "mutation_class": descriptor.mutation_class,
            "subject_id": descriptor.subject_id,
            "payload": dict(descriptor.payload),
            "reasons": list(reasons),
            "floor_codes": list(floor_codes),
            "caution_codes": list(caution_codes),
        },
    )
    try:
        return binding.ledger.append(fact)
    except Exception:  # a seal must never break the gate's ruling
        _logger.warning(
            "ENFORCEMENT seal failed for %s; ruling unaffected, fact not sealed",
            descriptor.surface,
            exc_info=True,
        )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Descriptor builders — duck-typed, exception-safe (a builder error fails the
# gate CLOSED via gate_controller_mutation's catch, it never breaks a caller)
# ─────────────────────────────────────────────────────────────────────────────

def _policy_facts(policy: Any) -> dict[str, Any]:
    if policy is None:
        return {}
    return {
        "permit_threshold": getattr(policy, "permit_threshold", None),
        "forbid_threshold": getattr(policy, "forbid_threshold", None),
        "minimum_confidence": getattr(policy, "minimum_confidence", None),
        "blocked_terms": list(getattr(policy, "blocked_terms", ()) or ()),
        "enabled_recognizers": list(getattr(policy, "enabled_recognizers", ()) or ()),
        "deterministic_block_severities": [
            str(s) for s in (getattr(policy, "deterministic_block_severities", ()) or ())
        ],
        "sensitive_entities": list(getattr(policy, "sensitive_entities", ()) or ()),
    }


def _surface(store: Any, method: str) -> str:
    cls = type(store)
    return f"{cls.__module__}.{cls.__qualname__}.{method}"


def describe_policy_save(store: Any, policy: Any, method: str = "save") -> MutationDescriptor:
    existing = store.get(policy.version)
    payload: dict[str, Any] = {
        "version": policy.version,
        "policy_id": policy.policy_id,
        "new_policy_id": policy.policy_id,
        "is_active_flag": bool(policy.is_active),
    }
    if existing is not None and existing.model_dump(mode="json") == policy.model_dump(mode="json"):
        payload["no_change"] = True
        return MutationDescriptor(
            surface=_surface(store, method), mutation_class=POLICY_WRITE,
            subject_id=policy.version, payload=payload,
        )
    active = store.get_active()
    replaces_active = existing is not None and bool(existing.is_active)
    activates_now = bool(policy.is_active)
    if replaces_active or activates_now:
        old = _policy_facts(active if active is not None else existing)
        payload["weakening_axes"] = list(weakening_axes(old, _policy_facts(policy)))
        payload["replaces_active"] = replaces_active
    elif existing is None:
        payload["stage_write"] = True
    return MutationDescriptor(
        surface=_surface(store, method), mutation_class=POLICY_WRITE,
        subject_id=policy.version, payload=payload,
    )


def describe_policy_activate(store: Any, version: str, method: str = "activate") -> MutationDescriptor:
    active = store.get_active()
    target = store.get(version)
    payload: dict[str, Any] = {"version": version}
    if target is None:
        # Unknown version: the store raises KeyError itself — nothing to govern.
        payload["no_change"] = True
        payload["target_missing"] = True
    else:
        payload["policy_id"] = target.policy_id
        if active is not None and active.version == version:
            payload["no_change"] = True
        else:
            payload["weakening_axes"] = list(
                weakening_axes(_policy_facts(active), _policy_facts(target))
            )
    return MutationDescriptor(
        surface=_surface(store, method), mutation_class=POLICY_ACTIVATE,
        subject_id=version, payload=payload,
    )


def describe_policy_delete(store: Any, version: str, method: str = "delete") -> MutationDescriptor:
    target = store.get(version)
    payload: dict[str, Any] = {"version": version}
    if target is None:
        payload["no_change"] = True
        payload["target_missing"] = True
    else:
        payload["policy_id"] = target.policy_id
        payload["active_deleted"] = bool(target.is_active)
    return MutationDescriptor(
        surface=_surface(store, method), mutation_class=POLICY_DELETE,
        subject_id=version, payload=payload,
    )


def describe_policy_clear(store: Any, method: str = "clear") -> MutationDescriptor:
    count = len(store)
    payload: dict[str, Any] = {"count": count}
    if count == 0:
        payload["no_change"] = True
    return MutationDescriptor(
        surface=_surface(store, method), mutation_class=POLICY_CLEAR,
        subject_id=None, payload=payload,
    )


def describe_proposal_apply(proposal: Any, policy_store: Any) -> MutationDescriptor:
    """Describe an apply_proposal as the nested activation WILL see it.

    All-or-nothing depends on the outer (method-level) gate denying whenever
    the nested ``policy_store.activate`` gate would — otherwise a permitted
    outer apply could half-apply (save + safety-commit + mark-applied around a
    denied activation). ``apply_recommendation`` builds the new policy as a
    ``model_copy`` of the SOURCE with the recommended thresholds, so the
    candidate the nested gate diffs against the ACTIVE policy is exactly
    ``source content-fields + recommended thresholds`` — computed here with
    the same ``weakening_axes`` function. The recommendation's own
    current→recommended diff is unioned in for source≠active drift visibility;
    the outer gate is therefore at least as cautious as the nested one.
    """
    rec = proposal.recommendation
    old = {
        "permit_threshold": rec.current_permit_threshold,
        "forbid_threshold": rec.current_forbid_threshold,
        "minimum_confidence": rec.current_minimum_confidence,
    }
    new = {
        "permit_threshold": rec.recommended_permit_threshold,
        "forbid_threshold": rec.recommended_forbid_threshold,
        "minimum_confidence": rec.recommended_minimum_confidence,
    }
    axes = set(weakening_axes(old, new))
    active = policy_store.get_active()
    source = policy_store.get(proposal.source_policy_version)
    if active is not None and source is not None:
        candidate = {**_policy_facts(source), **new}
        axes |= set(weakening_axes(_policy_facts(active), candidate))
    return MutationDescriptor(
        surface="learning.feedback_loop.FeedbackLoopOrchestrator.apply_proposal",
        mutation_class=PROPOSAL_APPLY,
        subject_id=str(proposal.proposal_id),
        payload={
            "source_policy_version": proposal.source_policy_version,
            "proposed_new_version": proposal.proposed_new_version,
            "old": old,
            "new": new,
            "weakening_axes": sorted(axes),
        },
    )


def describe_proposal_rollback(proposal: Any, policy_store: Any) -> MutationDescriptor:
    target_version = proposal.rollback_target_version
    active = policy_store.get_active()
    target = policy_store.get(target_version) if target_version else None
    return MutationDescriptor(
        surface="learning.feedback_loop.FeedbackLoopOrchestrator.rollback_proposal",
        mutation_class=PROPOSAL_ROLLBACK,
        subject_id=str(proposal.proposal_id),
        payload={
            "rollback_target_version": target_version,
            "weakening_axes": list(
                weakening_axes(_policy_facts(active), _policy_facts(target))
            ),
        },
    )


def describe_standing_activate(tenant: str) -> MutationDescriptor:
    return MutationDescriptor(
        surface="governance.standing.StandingGovernance.activate",
        mutation_class=GOVERNANCE_ACTIVATE,
        subject_id=tenant,
        payload={"tenant": tenant},
    )


def describe_lifecycle(registry: Any, agent_id: Any, status: Any) -> MutationDescriptor:
    existing = registry.get(agent_id)
    new_status = getattr(status, "value", str(status))
    payload: dict[str, Any] = {"new_status": new_status}
    if existing is None:
        payload["no_change"] = True  # store raises AgentNotFoundError itself
        payload["target_missing"] = True
    else:
        old_status = getattr(existing.lifecycle_status, "value", str(existing.lifecycle_status))
        payload["old_status"] = old_status
        if old_status == new_status:
            payload["no_change"] = True
    return MutationDescriptor(
        surface=_surface(registry, "set_lifecycle"),
        mutation_class=LIFECYCLE_TRANSITION,
        subject_id=str(agent_id),
        payload=payload,
    )


def _surface_facts(surface: Any) -> dict[str, Any]:
    return {
        key: list(getattr(surface, key, ()) or ())
        for key in (
            "allowed_action_types",
            "allowed_channels",
            "allowed_environments",
            "allowed_recipient_domains",
            "allowed_tools",
        )
    }


def describe_agent_save(registry: Any, agent: Any) -> MutationDescriptor:
    existing = registry.get(agent.agent_id)
    payload: dict[str, Any] = {}
    if existing is None:
        payload["new_registration"] = True
    else:
        old_status = getattr(existing.lifecycle_status, "value", str(existing.lifecycle_status))
        new_status = getattr(agent.lifecycle_status, "value", str(agent.lifecycle_status))
        old_surface = _surface_facts(existing.capability_surface)
        new_surface = _surface_facts(agent.capability_surface)
        widened = widened_dimensions(old_surface, new_surface)
        payload.update(
            old_status=old_status,
            new_status=new_status,
            widened_dimensions=list(widened),
        )
        if old_surface != new_surface and not widened:
            payload["narrowing"] = True
        elif old_surface == new_surface and old_status == new_status:
            # identity-field-only update (tags/metadata/attestations):
            # enumerated-deferred in census v1 — passes deterministically.
            payload["narrowing"] = True
    return MutationDescriptor(
        surface=_surface(registry, "save"),
        mutation_class=AGENT_SAVE,
        subject_id=str(agent.agent_id),
        payload=payload,
    )


def describe_key_mutation(surface: str, *, key_id: str | None = None) -> MutationDescriptor:
    return MutationDescriptor(
        surface=surface,
        mutation_class=KEY_MUTATION,
        subject_id=key_id,
        payload={"key_id": key_id},
    )


__all__ = [
    "CONTROLLER_MUTATION_CENSUS",
    "DEPLOY_FROZEN_STRATUM",
    "GOVERNOR_FROZEN_POLICY",
    "GOVERNOR_POLICY_ID",
    "GOVERNOR_POLICY_VERSION",
    "GateOutcome",
    "MutationDescriptor",
    "MutationSite",
    "bind_reflexive_governor",
    "bound_reflexive_governor",
    "compose_gate_verdict",
    "describe_agent_save",
    "describe_key_mutation",
    "describe_lifecycle",
    "describe_policy_activate",
    "describe_policy_clear",
    "describe_policy_delete",
    "describe_policy_save",
    "describe_proposal_apply",
    "describe_proposal_rollback",
    "describe_standing_activate",
    "gate_controller_mutation",
    "reflexive_governor_bound",
    "unbind_reflexive_governor",
]
