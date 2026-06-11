"""
Reflexive self-governance (Wave 2 / L5) — the earn-it suite.

Each test FAILS if the behaviour it pins breaks:
  1. Reflexive-completeness: every census-WIRED site carries the gate call at
     its definition; every COVERED_VIA delegation line still exists; the
     mutator classes expose no un-enumerated mutation method (tripwire,
     modelled on the census-reconciliation precedent in
     tests/test_two_sided_hold.py).
  2. Walk-down attack: a mutation that would weaken the governor (weakening
     policy activation — produced by the REAL learning loop — quarantine
     lift, governor-self-target) is denied AND sealed; the chain verifies
     (verify_chain()["intact"] / verify_signatures()["valid"] — dicts).
  3. Deny-by-not-mutating: denial leaves store state byte-identical
     (including the exception-swallowing StandingGovernance path);
     apply_proposal is all-or-nothing.
  4. No-regress: a gated mutation attempted DURING a gate evaluation is
     denied without recursion; eval depth never exceeds 1; the deploy-frozen
     stratum is enumerated.
  5. 0 chain breaks across a sealed mutation session; ENFORCEMENT facts carry
     honest claims (they NAME what is not proven).
  6. The verdict-path spec stays green (run alongside: test_crc_gate,
     test_structural_floor, test_deterministic, test_enforcement,
     test_replay_validator, test_pdp, test_decision_seal).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.agent import AgentIdentity, AgentLifecycleStatus, CapabilitySurface
from tex.domain.evidence import EvidenceMaturity
from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import OutcomeSourceType
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.selfgov import governor as gov
from tex.selfgov.governor import (
    CONTROLLER_MUTATION_CENSUS,
    DEPLOY_FROZEN_STRATUM,
    GOVERNOR_FROZEN_POLICY,
    GOVERNOR_POLICY_ID,
    MutationDescriptor,
    bind_reflexive_governor,
    bound_reflexive_governor,
    compose_gate_verdict,
    describe_policy_activate,
    describe_policy_save,
    gate_controller_mutation,
    reflexive_governor_bound,
    unbind_reflexive_governor,
)
from tex.specialists import metaguard
from tex.specialists.metaguard import (
    MetaguardResult,
    MetaguardSignature,
    evaluate_metaguard,
    weakening_axes,
    widened_dimensions,
)
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.policy_store import InMemoryPolicyStore

REPO_ROOT = Path(__file__).resolve().parents[1]

logging.disable(logging.INFO)  # the PDP's specialist suite is chatty


# ─────────────────────────────────────────────────────────────────────────────
# fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def pdp_module() -> PolicyDecisionPoint:
    """One real PDP per module (the specialist suite is expensive to build).
    Tests that need a ledger-wired PDP build their own."""
    return PolicyDecisionPoint()


@pytest.fixture(autouse=True)
def _governor_clean():
    """Every test starts and ends unbound, with the depth high-water reset."""
    assert not reflexive_governor_bound(), "governor leaked from a prior test"
    gov._observed_max_eval_depth = 0
    yield
    assert not reflexive_governor_bound(), "test leaked a bound governor"


def _strict_policy(version: str = "v1", *, active: bool = False) -> PolicySnapshot:
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=active,
        permit_threshold=0.30,
        forbid_threshold=0.70,
        minimum_confidence=0.50,
        blocked_terms=("ssn",),
        enabled_recognizers=("secrets",),
    )


def _weak_policy(version: str = "v2") -> PolicySnapshot:
    """Weakens vs _strict_policy on every named axis."""
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=False,
        permit_threshold=0.69,   # ↑ permissive region
        forbid_threshold=0.71,   # ↑ FORBID harder to reach
        minimum_confidence=0.0,  # ↓ auto-permit bar
        blocked_terms=(),        # protections removed
        enabled_recognizers=(),
    )


def _store_dump(store: InMemoryPolicyStore) -> list[dict]:
    return [p.model_dump(mode="json") for p in store.list_policies()]


# ─────────────────────────────────────────────────────────────────────────────
# 1 · Reflexive-completeness — the census tripwire
# ─────────────────────────────────────────────────────────────────────────────

def _method_body(text: str, method: str) -> str:
    """Source segment from ``def {method}(`` to the next ``def `` at any indent."""
    idx = text.find(f"def {method}(")
    assert idx != -1, f"def {method}( not found"
    nxt = text.find("def ", idx + 4)
    return text[idx : nxt if nxt != -1 else len(text)]


def test_census_every_wired_site_routes_through_the_gate():
    """Census→code: each WIRED entry has gate_controller_mutation at its
    definition. Removing a gate line (a future bypass) turns this red."""
    for site in CONTROLLER_MUTATION_CENSUS:
        if site.status != "WIRED":
            continue
        text = (REPO_ROOT / site.path).read_text(encoding="utf-8")
        method = site.qualname.split(".")[-1]
        body = _method_body(text, method)
        assert "gate_controller_mutation(" in body, (
            f"{site.path}::{site.qualname} is census-WIRED but its body has "
            "no gate_controller_mutation call — bypass introduced"
        )


def test_census_covered_via_delegations_still_exist():
    """COVERED_VIA entries pin the delegation text: if a caller stops routing
    through its WIRED chokepoint, this turns red."""
    for site in CONTROLLER_MUTATION_CENSUS:
        if site.status != "COVERED_VIA":
            continue
        path = REPO_ROOT / site.path
        assert path.exists(), f"census path vanished: {site.path}"
        text = path.read_text(encoding="utf-8")
        assert site.note in text, (
            f"{site.path}::{site.qualname}: pinned delegation {site.note!r} "
            "no longer present — re-derive the census entry"
        )


def test_census_excluded_entries_carry_reasons():
    for site in CONTROLLER_MUTATION_CENSUS:
        if site.status == "EXCLUDED":
            assert len(site.note.strip()) > 10, f"bare EXCLUDED: {site.qualname}"
        assert site.status in {"WIRED", "COVERED_VIA", "EXCLUDED"}, site.status


# Reverse direction: a NEW public mutator on a governed class must show up
# here (either get census-WIRED or added to the read-only allowlist with a
# conscious decision).
def _read_only_allowlist() -> dict[type, set[str]]:
    from tex.memory.policy_snapshot_store import DurablePolicyStore

    return {
        InMemoryPolicyStore: {
            "get", "require", "get_by_policy_id", "require_by_policy_id",
            "list_versions", "list_policies", "get_active", "require_active",
        },
        DurablePolicyStore: {
            "get", "require", "latest", "active", "get_active",
            "require_active", "get_by_policy_id", "require_by_policy_id",
            "list_versions", "list_policies", "list_all",
            # reload re-hydrates the cache FROM postgres: it can only restore
            # what the durable record holds, never inject in-process state.
            "reload",
        },
        InMemoryAgentRegistry: {
            "get", "require", "require_evaluable", "history", "list_all",
            "list_by_status",
        },
    }


def test_census_reverse_no_unenumerated_public_mutators():
    import inspect

    wired = {
        site.qualname.split(".")[-1]
        for site in CONTROLLER_MUTATION_CENSUS
        if site.status == "WIRED"
    }
    for cls, read_only in _read_only_allowlist().items():
        for name, member in vars(cls).items():
            if name.startswith("_") or not (
                inspect.isfunction(member) or isinstance(member, (staticmethod, classmethod))
            ):
                continue
            assert name in read_only or name in wired, (
                f"{cls.__name__}.{name} is neither census-WIRED nor in the "
                "read-only allowlist — enumerate it (gate it or exclude it "
                "with a reason)"
            )


def test_governor_policy_id_constants_in_lock_step():
    assert metaguard.GOVERNOR_POLICY_ID == GOVERNOR_POLICY_ID


def test_runtime_every_wired_policy_surface_seals_when_exercised():
    """Runtime completeness evidence: exercising the wired policy-store
    surfaces while bound leaves gate outcomes (sealed or fast-pass) and the
    state transitions only where permitted."""
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        store.save(_weak_policy("v2"))          # stage pass (unsealed)
        store.activate("v2")                     # weakening → denied + sealed
        store.delete("v2")                       # evidence destruction → denied + sealed
        store.clear()                            # evidence destruction → denied + sealed
    surfaces = {
        r.fact.subject_id
        for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
    }
    assert any("activate" in s for s in surfaces)
    assert any("delete" in s for s in surfaces)
    assert any("clear" in s for s in surfaces)
    # the denied ops mutated nothing
    assert store.get_active().version == "v1"
    assert store.get("v2") is not None
    assert len(store) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 2 · Walk-down attack — denied + sealed + chain verifies
# ─────────────────────────────────────────────────────────────────────────────

def test_walkdown_weakening_activation_denied_sealed_chain_intact():
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_weak_policy("v2"))
    before = _store_dump(store)

    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        returned = store.activate("v2")
        # deny = don't mutate; the returned snapshot honestly shows un-activated
        assert returned.is_active is False
        assert store.get_active().version == "v1"
        assert _store_dump(store) == before

        # the denial is sealed: DECISION (same PDP, M0 seam) + ENFORCEMENT
        kinds = [r.fact.kind for r in ledger.list_all()]
        assert SealedFactKind.DECISION in kinds
        assert SealedFactKind.ENFORCEMENT in kinds
        blocked = [
            r for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
            if r.fact.detail.get("allowed") is False
        ]
        assert blocked, "denied walk-down left no blocked ENFORCEMENT fact"
        detail = blocked[-1].fact.detail
        assert "metaguard.governance_weakening" in detail["caution_codes"]
        assert detail["verdict"] == "ABSTAIN"

    chain = ledger.verify_chain()
    sigs = ledger.verify_signatures()
    assert chain["intact"] is True and chain["break_at"] is None
    assert sigs["valid"] is True and sigs["invalid_at"] is None


def test_walkdown_hold_surfaces_only_on_abstain():
    """ABSTAIN-only surfaces: the denied-weakening outcome (ABSTAIN) carries a
    hold; a FORBID-floor outcome carries none (FORBID is invisible to the
    operator — engine/hold.py contract, mirrored at the gate)."""
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_weak_policy("v2"))
    pdp = PolicyDecisionPoint()
    with bound_reflexive_governor(pdp=pdp):
        weak_out = gate_controller_mutation(describe_policy_activate(store, "v2"))
        assert weak_out.verdict == "ABSTAIN" and not weak_out.allowed
        assert weak_out.hold is not None
        assert weak_out.hold["resolution_mode"] == "human-judgment"
        assert "metaguard.governance_weakening" in weak_out.hold["codes"]

        floor_out = gate_controller_mutation(
            MutationDescriptor(
                surface="test.selftarget",
                mutation_class=metaguard.POLICY_ACTIVATE,
                subject_id="x",
                payload={"policy_id": GOVERNOR_POLICY_ID},
            )
        )
        assert floor_out.verdict == "FORBID" and not floor_out.allowed
        assert floor_out.hold is None
        assert "metaguard.governor_self_target" in floor_out.floor_codes


def test_walkdown_via_save_replacing_active_bytes_denied():
    """The save() bypass: replacing the ACTIVE version's bytes with weaker
    thresholds without ever calling activate()."""
    store = InMemoryPolicyStore()
    strict = _strict_policy("v1", active=True)
    store.save(strict)
    impostor = strict.model_copy(
        update={"permit_threshold": 0.69, "blocked_terms": ()}
    )
    with bound_reflexive_governor(pdp=PolicyDecisionPoint()):
        store.save(impostor)
        survived = store.get("v1")
        assert survived.permit_threshold == 0.30
        assert survived.blocked_terms == ("ssn",)


def test_quarantine_lift_denied_revocation_floor_wake_permitted():
    reg = InMemoryAgentRegistry()
    quarantined = reg.save(AgentIdentity(name="q-bot", owner="m"))
    reg.set_lifecycle(quarantined.agent_id, AgentLifecycleStatus.QUARANTINED)
    revoked = reg.save(AgentIdentity(name="r-bot", owner="m"))
    reg.set_lifecycle(revoked.agent_id, AgentLifecycleStatus.REVOKED)
    sleeping = reg.save(AgentIdentity(name="s-bot", owner="m"))
    reg.set_lifecycle(sleeping.agent_id, AgentLifecycleStatus.SLEEPING)

    ledger = SealedFactLedger()
    with bound_reflexive_governor(pdp=PolicyDecisionPoint(), ledger=ledger):
        # the sharpest attack: QUARANTINED → ACTIVE (verdict-raising) → held
        out = reg.set_lifecycle(quarantined.agent_id, AgentLifecycleStatus.ACTIVE)
        assert out.lifecycle_status is AgentLifecycleStatus.QUARANTINED

        # terminal resurrection → deterministic FORBID floor
        out = reg.set_lifecycle(revoked.agent_id, AgentLifecycleStatus.ACTIVE)
        assert out.lifecycle_status is AgentLifecycleStatus.REVOKED
        floored = [
            r for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
            if "metaguard.revoked_resurrection" in r.fact.detail.get("floor_codes", [])
        ]
        assert floored and floored[-1].fact.detail["verdict"] == "FORBID"

        # the legitimate human act: SLEEPING → ACTIVE permits via the same PDP
        out = reg.set_lifecycle(sleeping.agent_id, AgentLifecycleStatus.ACTIVE)
        assert out.lifecycle_status is AgentLifecycleStatus.ACTIVE

        # lifecycle LOWERING (toward caution) always passes, deterministically
        out = reg.set_lifecycle(sleeping.agent_id, AgentLifecycleStatus.QUARANTINED)
        assert out.lifecycle_status is AgentLifecycleStatus.QUARANTINED

    assert ledger.verify_chain()["intact"] is True


def test_capability_widening_denied_narrowing_passes():
    reg = InMemoryAgentRegistry()
    narrow = CapabilitySurface(allowed_action_types=("send_email",))
    agent = reg.save(AgentIdentity(name="bot", owner="m", capability_surface=narrow))

    with bound_reflexive_governor(pdp=PolicyDecisionPoint()):
        # dropping the restriction entirely (→ unrestricted) is a widening
        wide = agent.model_copy(update={"capability_surface": CapabilitySurface()})
        out = reg.save(wide)
        assert out.capability_surface.allowed_action_types == ("send_email",)
        assert out.revision == agent.revision  # nothing persisted

        # restricting a previously-unrestricted dimension is a NARROWING
        restricted = agent.model_copy(
            update={
                "capability_surface": CapabilitySurface(
                    allowed_action_types=("send_email",),
                    allowed_channels=("email",),
                )
            }
        )
        out2 = reg.save(restricted)
        assert out2.revision == agent.revision + 1
        assert out2.capability_surface.allowed_channels == ("email",)


def test_governor_self_target_floor_and_binding_capability():
    store = InMemoryPolicyStore()
    impostor = PolicySnapshot(
        policy_id=GOVERNOR_POLICY_ID,
        version="reflexive-governor-frozen-v2",
        is_active=False,
        permit_threshold=0.99,
        forbid_threshold=1.0,
        minimum_confidence=0.0,
    )
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    token = bind_reflexive_governor(pdp=pdp, ledger=ledger)
    try:
        # impersonating the governor's policy family floors at save
        store.save(impostor)
        assert store.get(impostor.version) is None
        floored = [
            r for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
            if "metaguard.governor_self_target" in r.fact.detail.get("floor_codes", [])
        ]
        assert floored

        # rebinding while bound is a level-0 mutation: denied + raises
        with pytest.raises(RuntimeError, match="already bound"):
            bind_reflexive_governor(pdp=pdp, ledger=ledger)

        # unbinding without the capability token: denied by not mutating
        assert unbind_reflexive_governor(object()) is False
        assert reflexive_governor_bound()
    finally:
        assert unbind_reflexive_governor(token) is True
    assert not reflexive_governor_bound()


def test_key_material_mutations_held_when_bound(tmp_path):
    from tex.c2pa import signer as c2pa_signer
    from tex.events._ecdsa_provider import default_signature_provider
    from tex.evidence.seal import _persist_key

    provider = default_signature_provider()
    key = provider.generate_keypair("reflexive-test-key")

    with bound_reflexive_governor(pdp=PolicyDecisionPoint()):
        before = dict(c2pa_signer._LOCAL_KEYSTORE)
        c2pa_signer.register_signing_key(key)
        assert c2pa_signer._LOCAL_KEYSTORE == before

        c2pa_signer.clear_signing_keys()
        assert c2pa_signer._LOCAL_KEYSTORE == before

        target = tmp_path / "evidence_seal_key.json"
        _persist_key(target, key)
        assert not target.exists()

    # unbound: the same write works (today's behaviour)
    _persist_key(tmp_path / "k.json", key)
    assert (tmp_path / "k.json").exists()


# ─────────────────────────────────────────────────────────────────────────────
# 3 · Deny-by-not-mutating — byte-identical state, all-or-nothing composites
# ─────────────────────────────────────────────────────────────────────────────

def test_standing_governance_denial_is_silent_and_state_clean(monkeypatch):
    """The exception-swallowing-caller path: a denial must not raise and must
    not mutate. The gate is forced to deny via monkeypatch — this pins the
    CHOKEPOINT's deny contract, not the gate's rules (tested elsewhere)."""
    from tex.governance import standing as standing_mod
    from tex.stores.agent_registry import InMemoryAgentRegistry as Reg

    governance = standing_mod.StandingGovernance(agent_registry=Reg())

    denied = gov.GateOutcome(
        allowed=False, gated=True, verdict="ABSTAIN", mechanism="pdp+metaguard",
    )
    monkeypatch.setattr(standing_mod, "gate_controller_mutation", lambda d: denied)
    posture = governance.activate("acme")  # must NOT raise
    assert posture.active_since is None
    assert governance.is_active("acme") is False

    monkeypatch.undo()
    # and while actually bound, standing activation is protective → permitted
    ledger = SealedFactLedger()
    with bound_reflexive_governor(pdp=PolicyDecisionPoint(), ledger=ledger):
        posture = governance.activate("acme")
        assert governance.is_active("acme") is True
    sealed = [
        r for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
        if r.fact.detail.get("mutation_class") == "governance_activate"
    ]
    assert sealed and sealed[-1].fact.detail["allowed"] is True


def _build_real_weakening_proposal():
    """Drive the REAL learning loop into proposing a weakening calibration:
    seeded false-FORBIDs make the calibrator loosen thresholds (probed:
    permit 0.34→0.3411 ↑, forbid 0.72→0.7213 ↑, min_conf 0.62→0.6194 ↓)."""
    from tex.learning.calibration_safety import CalibrationSafetyGuard
    from tex.learning.calibrator import build_default_calibrator
    from tex.learning.drift import PolicyDriftMonitor
    from tex.learning.drift_classifier import DriftClassifier
    from tex.learning.feedback_loop import FeedbackLoopOrchestrator
    from tex.learning.outcome_validator import OutcomeValidator
    from tex.learning.poisoning_detector import PoisoningDetector
    from tex.learning.replay import ReplayValidator
    from tex.learning.reporter_reputation import ReporterReputationStore
    from tex.policies.defaults import build_default_policy
    from tex.stores.calibration_proposal_store import CalibrationProposalStore
    from tex.stores.decision_store import InMemoryDecisionStore
    from tex.stores.outcome_store import InMemoryOutcomeStore
    from tex.domain.decision import Decision

    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    policies = InMemoryPolicyStore()
    policies.save(
        build_default_policy().model_copy(
            update={"version": "default-v1", "is_active": True}
        )
    )
    proposals = CalibrationProposalStore()
    orch = FeedbackLoopOrchestrator(
        decisions=decisions,
        outcomes=outcomes,
        policies=policies,
        proposals=proposals,
        validator=OutcomeValidator(decisions=decisions, priors=outcomes),
        reputation=ReporterReputationStore(min_observations_before_decay=2),
        calibrator=build_default_calibrator(),
        safety=CalibrationSafetyGuard(min_interval=timedelta(seconds=0)),
        replay=ReplayValidator(),
        drift_monitor=PolicyDriftMonitor(decision_store=decisions),
        drift_classifier=DriftClassifier(),
        poisoning_detector=PoisoningDetector(),
        cold_start_minimum=10,
    )
    for i in range(20):
        d = Decision(
            request_id=uuid4(),
            verdict=Verdict.FORBID,
            confidence=0.95,
            final_score=0.85,
            action_type="sales_email",
            channel="email",
            environment="production",
            recipient="alice@example.com",
            content_excerpt="hi",
            content_sha256="c" * 64,
            policy_version="default-v1",
            scores={"semantic": 0.85},
            reasons=["risk"],
            uncertainty_flags=[],
            metadata={"tenant_id": "acme"},
            decided_at=datetime.now(UTC),
        )
        decisions.save(d)
        orch.ingest_outcome(
            OutcomeRecord.create(
                decision_id=d.decision_id,
                request_id=d.request_id,
                verdict=Verdict.FORBID,
                outcome_kind=OutcomeKind.BLOCKED,
                was_safe=True,  # FALSE_FORBID → loosening pressure
                reporter=f"reporter-{i % 3}",
                source_type=OutcomeSourceType.HUMAN_REVIEWER,
            )
        )
    result = orch.propose(
        tenant_id="acme", proposed_new_version="default-v2", created_by="test"
    )
    assert result.proposal is not None, result.advisories
    return orch, policies, proposals, result.proposal


def test_apply_proposal_weakening_denied_all_or_nothing():
    orch, policies, proposals, proposal = _build_real_weakening_proposal()
    rec = proposal.recommendation
    # this is a genuine weakening proposal out of the real loop
    assert (
        rec.recommended_permit_threshold > rec.current_permit_threshold
        or rec.recommended_forbid_threshold > rec.current_forbid_threshold
        or rec.recommended_minimum_confidence < rec.current_minimum_confidence
    )
    before_policies = _store_dump(policies)
    before_status = proposal.status

    ledger = SealedFactLedger()
    with bound_reflexive_governor(pdp=PolicyDecisionPoint(), ledger=ledger):
        returned = orch.apply_proposal(
            proposal_id=proposal.proposal_id, approver="attacker"
        )
        # all-or-nothing: none of approve/save/activate/safety-commit ran
        assert returned.status == before_status
        assert proposals.require(proposal.proposal_id).status == before_status
        assert _store_dump(policies) == before_policies
        assert policies.get("default-v2") is None
        assert policies.require_active().version == "default-v1"

    blocked = [
        r for r in ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
        if r.fact.detail.get("mutation_class") == "proposal_apply"
        and r.fact.detail.get("allowed") is False
    ]
    assert blocked, "denied apply_proposal left no blocked ENFORCEMENT fact"
    assert "metaguard.governance_weakening" in blocked[-1].fact.detail["caution_codes"]
    assert ledger.verify_chain()["intact"] is True


def test_apply_proposal_outer_gate_sees_what_nested_activation_sees():
    """All-or-nothing under source≠active: a recommendation that TIGHTENS vs
    its (non-active) source but WEAKENS vs the live active policy must fire
    the OUTER gate — otherwise a permitted outer apply would half-apply
    around a denied nested activation."""
    from types import SimpleNamespace

    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1", active=True))   # active: permit 0.30
    midweak = _strict_policy("v2").model_copy(update={"permit_threshold": 0.60})
    store.save(midweak)                              # non-active source

    proposal = SimpleNamespace(
        proposal_id=uuid4(),
        source_policy_version="v2",
        proposed_new_version="v3",
        recommendation=SimpleNamespace(
            current_permit_threshold=0.60,       # source
            recommended_permit_threshold=0.55,   # tightens vs source…
            current_forbid_threshold=0.70,
            recommended_forbid_threshold=0.70,
            current_minimum_confidence=0.50,
            recommended_minimum_confidence=0.50,
        ),
    )
    descriptor = gov.describe_proposal_apply(proposal, store)
    # …but 0.55 > active 0.30: weakening vs the LIVE policy → outer fires
    assert "permit_threshold" in descriptor.payload["weakening_axes"]
    assert evaluate_metaguard(descriptor).fired


def test_unbound_default_is_byte_for_byte_inert():
    out = gate_controller_mutation(
        MutationDescriptor(
            surface="any", mutation_class=metaguard.POLICY_ACTIVATE,
            subject_id=None, payload={"weakening_axes": ["permit_threshold"]},
        )
    )
    assert out.allowed is True
    assert out.gated is False
    assert out.mechanism == "ungated"
    # and the stores behave exactly as before
    store = InMemoryPolicyStore()
    store.save(_weak_policy("w1"))
    store.activate("w1")
    assert store.get_active().version == "w1"
    store.clear()
    assert len(store) == 0


def test_gate_fails_closed_on_internal_error_without_raising():
    class BrokenPDP:
        pass  # no .evaluate

    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_strict_policy("v2"))  # non-weakening target
    with bound_reflexive_governor(pdp=BrokenPDP()):
        returned = store.activate("v2")  # must not raise
        assert returned.is_active is False
        assert store.get_active().version == "v1"
        out = gate_controller_mutation(describe_policy_activate(store, "v2"))
        assert out.allowed is False
        assert out.mechanism == "error_fail_closed"


# ─────────────────────────────────────────────────────────────────────────────
# 4 · No-regress — the deploy-frozen stratum kills the recursion
# ─────────────────────────────────────────────────────────────────────────────

def test_no_regress_nested_mutation_during_eval_is_denied_without_recursion():
    nested_outcomes: list[gov.GateOutcome] = []

    class NestedMutationPDP:
        """Simulates a future PDP component attempting a controller mutation
        DURING a gate evaluation — the regress the frozen stratum kills."""

        def __init__(self, inner):
            self._inner = inner

        def evaluate(self, *, request, policy):
            nested_outcomes.append(
                gate_controller_mutation(
                    MutationDescriptor(
                        surface="nested.attack",
                        mutation_class=metaguard.POLICY_ACTIVATE,
                        subject_id="x",
                        payload={},
                    )
                )
            )
            return self._inner.evaluate(request=request, policy=policy)

    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_strict_policy("v2"))
    with bound_reflexive_governor(pdp=NestedMutationPDP(PolicyDecisionPoint())):
        result = store.activate("v2")  # outer mutation: gated, evaluates, permits
        assert result.is_active is True

    assert len(nested_outcomes) == 1
    inner = nested_outcomes[0]
    assert inner.allowed is False
    assert inner.mechanism == "no_regress_backstop"
    assert gov._observed_max_eval_depth == 1, (
        "a gate evaluation re-entered the PDP — the no-regress invariant broke"
    )


def test_deploy_frozen_stratum_enumerates_the_ungatable():
    entries = dict(DEPLOY_FROZEN_STRATUM)
    for required in (
        "env:TEX_SEAL_DECISIONS",
        "env:TEX_NANOZK_ALLOW_SHIM",
        "env:TEX_API_KEYS",
        "file:evidence_seal_key.json",
        "object:binding capability token",
        "process:arbitrary in-process code execution",
    ):
        assert required in entries, f"deploy-frozen stratum lost: {required}"
        assert len(entries[required].strip()) > 10
    # level-0 is a code constant that never enters a store
    assert GOVERNOR_FROZEN_POLICY.policy_id == GOVERNOR_POLICY_ID
    assert GOVERNOR_FROZEN_POLICY.version == gov.GOVERNOR_POLICY_VERSION


def test_eval_path_idempotent_repersist_is_a_no_change_fast_pass(monkeypatch):
    """memory/system.py:264 calls save_in_tx with the policy ALREADY stored on
    every evaluation — bound, this must cost zero PDP evaluations and seal
    nothing (flood control), while byte-replacement stays gated."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from tex.memory.policy_snapshot_store import DurablePolicyStore

    store = DurablePolicyStore(bootstrap=False)
    active = _strict_policy("v1", active=True)
    store.save(active)

    ledger = SealedFactLedger()
    with bound_reflexive_governor(pdp=PolicyDecisionPoint(), ledger=ledger):
        sealed_before = len(ledger)
        out = gate_controller_mutation(
            describe_policy_save(store, active, method="save_in_tx")
        )
        assert out.allowed is True
        assert out.mechanism == "no_change"
        assert len(ledger) == sealed_before  # unsealed fast pass
        assert gov._observed_max_eval_depth == 0  # no PDP round-trip

        store.save_in_tx(active, cursor=None)  # the live chokepoint, same path
        assert len(ledger) == sealed_before


# ─────────────────────────────────────────────────────────────────────────────
# 5 · Sealed session — 0 chain breaks, honest ENFORCEMENT claims
# ─────────────────────────────────────────────────────────────────────────────

def test_mixed_mutation_session_zero_chain_breaks_and_honest_claims():
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    reg = InMemoryAgentRegistry()
    agent = reg.save(AgentIdentity(name="bot", owner="m"))

    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        store.save(_weak_policy("v2"))                                     # stage pass
        store.activate("v2")                                               # denied
        tighter = _strict_policy("v3").model_copy(update={"permit_threshold": 0.2})
        store.save(tighter)                                                # stage pass
        store.activate("v3")                                               # permitted
        reg.set_lifecycle(agent.agent_id, AgentLifecycleStatus.QUARANTINED)  # protective
        reg.set_lifecycle(agent.agent_id, AgentLifecycleStatus.ACTIVE)      # denied
        store.delete("v2")                                                 # denied
        store.clear()                                                      # denied

    records = ledger.list_all()
    assert len(records) >= 8  # bind + decisions + enforcements + unbind
    chain = ledger.verify_chain()
    sigs = ledger.verify_signatures()
    assert chain == {"intact": True, "checked": len(records), "break_at": None}
    assert sigs == {"valid": True, "checked": len(records), "invalid_at": None}

    enforcements = ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
    assert enforcements
    for record in enforcements:
        fact = record.fact
        # honest claims: each names what is NOT proven
        assert "correctness NOT proven" in fact.claim
        assert "completeness NOT proven" in fact.claim
        assert fact.maturity is EvidenceMaturity.RESEARCH_EARLY
    # both allowed and blocked outcomes were sealed in ONE chain
    allowed_flags = {r.fact.detail.get("allowed") for r in enforcements}
    assert allowed_flags == {True, False}
    # the session ended in the intended state
    assert store.get_active().version == "v3"
    assert len(store) == 3
    assert reg.require(agent.agent_id).lifecycle_status is AgentLifecycleStatus.QUARANTINED


# ─────────────────────────────────────────────────────────────────────────────
# metaguard unit contracts (structural-floor discipline)
# ─────────────────────────────────────────────────────────────────────────────

def test_metaguard_scores_can_neither_fire_nor_silence_signatures():
    # a payload riddled with high scores fires nothing
    noisy = MutationDescriptor(
        surface="s", mutation_class=metaguard.POLICY_ACTIVATE, subject_id=None,
        payload={"risk_score": 0.99, "score": 1.0, "confidence": 0.0},
    )
    assert evaluate_metaguard(noisy).fired is False
    # and a low score cannot silence a typed weakening
    weak = MutationDescriptor(
        surface="s", mutation_class=metaguard.POLICY_ACTIVATE, subject_id=None,
        payload={"weakening_axes": ["permit_threshold"], "risk_score": 0.0},
    )
    result = evaluate_metaguard(weak)
    assert [s.code for s in result.caution] == ["metaguard.governance_weakening"]


def test_metaguard_composition_is_monotone_lowering_only():
    floor = MetaguardResult(
        floor=(MetaguardSignature(code="f", reason="r"),),
        caution=(), protective_pass=False, no_change=False,
    )
    caution = MetaguardResult(
        floor=(), caution=(MetaguardSignature(code="c", reason="r"),),
        protective_pass=False, no_change=False,
    )
    neutral = MetaguardResult(floor=(), caution=(), protective_pass=False, no_change=False)

    assert compose_gate_verdict(Verdict.PERMIT, floor) is Verdict.FORBID
    assert compose_gate_verdict(Verdict.ABSTAIN, floor) is Verdict.FORBID
    assert compose_gate_verdict(Verdict.PERMIT, caution) is Verdict.ABSTAIN
    # caution never raises an existing ABSTAIN/FORBID
    assert compose_gate_verdict(Verdict.ABSTAIN, caution) is Verdict.ABSTAIN
    assert compose_gate_verdict(Verdict.FORBID, caution) is Verdict.FORBID
    # nothing raises toward PERMIT
    assert compose_gate_verdict(Verdict.FORBID, neutral) is Verdict.FORBID
    assert compose_gate_verdict(Verdict.ABSTAIN, neutral) is Verdict.ABSTAIN
    assert compose_gate_verdict(Verdict.PERMIT, neutral) is Verdict.PERMIT


def test_weakening_axes_is_directional_and_typed():
    strict = {
        "permit_threshold": 0.3, "forbid_threshold": 0.7,
        "minimum_confidence": 0.5, "blocked_terms": ["ssn"],
        "enabled_recognizers": ["secrets"],
        "deterministic_block_severities": ["CRITICAL"],
        "sensitive_entities": [],
    }
    weak = dict(strict, permit_threshold=0.69, blocked_terms=[])
    axes = weakening_axes(strict, weak)
    assert set(axes) == {"permit_threshold", "blocked_terms"}
    # the protective direction fires nothing
    assert weakening_axes(weak, strict) == ()
    # missing inputs fire nothing (the PDP still rules)
    assert weakening_axes(None, weak) == ()
    assert weakening_axes(strict, None) == ()


def test_widened_dimensions_unrestricted_and_additions():
    old = {"allowed_action_types": ["send_email"], "allowed_channels": []}
    assert widened_dimensions(old, {"allowed_action_types": [], "allowed_channels": []}) == (
        "allowed_action_types",
    )
    assert widened_dimensions(
        old, {"allowed_action_types": ["send_email", "wire_money"], "allowed_channels": []}
    ) == ("allowed_action_types",)
    # narrowing an unrestricted dimension is not a widening
    assert widened_dimensions(old, {"allowed_action_types": ["send_email"], "allowed_channels": ["email"]}) == ()
