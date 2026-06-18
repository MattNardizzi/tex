#!/usr/bin/env python3
"""
Verify enforcement receipts OFFLINE — prove the gate's allow/deny was sealed.

``--selftest`` runs a REAL StandingGovernance through the proof-carrying gate
with no network:

  1. an unknown agent's action hits the structural floor -> FORBID -> the wrapped
     callable does NOT run, and an ENFORCEMENT fact (outcome=blocked) is sealed;
  2. a sealed, running, in-surface agent -> PERMIT -> the action runs, and an
     ENFORCEMENT fact (outcome=executed) is sealed;
  3. the ledger's hash chain + ECDSA signatures verify offline; and
  4. a one-field tamper of a sealed fact is caught.

This proves authorship + integrity of "the gate allowed/blocked this action".
It does NOT prove verdict correctness, and the ledger is not externally
time-anchored yet (RFC-3161 anchoring of the ledger is the next phase).
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tex.domain.evaluation import EvaluationResponse  # noqa: E402
from tex.domain.verdict import Verdict  # noqa: E402
from tex.enforcement.errors import TexForbiddenError  # noqa: E402
from tex.enforcement.seal import build_proof_carrying_gate  # noqa: E402
from tex.governance.standing import StandingGovernance  # noqa: E402
from tex.provenance.ledger import SealedFactLedger  # noqa: E402


class _EmptyRegistry:
    def get(self, _uid):
        return None

    def list_all(self):
        return []


class _Agent:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = "ACTIVE"
        self.capability_surface = None
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


class _PermitEvaluate:
    def execute(self, _request):
        return EvaluationResponse(
            decision_id=uuid4(),
            verdict=Verdict.PERMIT,
            confidence=0.95,
            final_score=0.05,
            reasons=["clean"],
            policy_version="selftest",
            evaluated_at=datetime.now(UTC),
        )


def _selftest() -> int:
    print("=" * 72)
    print("ENFORCEMENT RECEIPT SELFTEST — gate a real PDP, seal each decision, catch a tamper")
    print("=" * 72)

    ledger = SealedFactLedger()

    # 1) Unknown agent -> the real structural floor FORBIDs; the callable must NOT run.
    forbid_gov = StandingGovernance(agent_registry=_EmptyRegistry())
    forbid_gate, forbid_obs = build_proof_carrying_gate(forbid_gov, ledger=ledger, tenant="acme")
    forbid_ran = {"v": False}
    forbid_guarded = forbid_gate.wrap(
        lambda *, content: forbid_ran.__setitem__("v", True),
        content_arg="content",
        action_type="rm_rf",
    )
    blocked = False
    try:
        forbid_guarded(content="rm -rf / --no-preserve-root")
    except TexForbiddenError:
        blocked = True
    f = forbid_obs.records[-1].fact.detail
    print(f"\n[forbid ] callable_ran={forbid_ran['v']}  blocked={blocked}  "
          f"sealed outcome={f['outcome']!r} verdict={f['verdict']!r}")

    # 2) Permitted agent -> the action runs; an ALLOW fact is sealed on the SAME ledger.
    agent_id = uuid4()
    permit_gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(agent_id)),
        evaluate_command=_PermitEvaluate(),
    )
    permit_gate, permit_obs = build_proof_carrying_gate(permit_gov, ledger=ledger, tenant="acme")
    permit_ran = {"v": False}
    permit_guarded = permit_gate.wrap(
        lambda *, content: permit_ran.__setitem__("v", True),
        content_arg="content",
        agent_id=agent_id,
        action_type="wire_transfer",
    )
    permit_guarded(content="pay vendor 100")
    p = permit_obs.records[-1].fact.detail
    print(f"[permit ] callable_ran={permit_ran['v']}  "
          f"sealed outcome={p['outcome']!r} verdict={p['verdict']!r}")

    # 3) Offline verification of the whole chain.
    chain = ledger.verify_chain()
    sigs = ledger.verify_signatures()
    print(f"\n[genuine] chain intact={chain['intact']} (checked {chain['checked']})  "
          f"signatures valid={sigs['valid']}")

    # 4) One-field tamper: flip 'allowed' inside the first sealed fact.
    rec = ledger._entries[0]
    bad_fact = rec.fact.model_copy(
        update={"detail": {**rec.fact.detail, "allowed": (not rec.fact.detail["allowed"])}}
    )
    ledger._entries[0] = rec.model_copy(update={"fact": bad_fact})
    tampered = ledger.verify_chain()
    print(f"[tampered] chain intact={tampered['intact']} (break_at={tampered['break_at']})")

    held = (
        blocked
        and not forbid_ran["v"]
        and permit_ran["v"]
        and chain["intact"]
        and sigs["valid"]
        and not tampered["intact"]
    )
    print("\n" + "=" * 72)
    print(f"RESULT: {'ALL CLAIMS HELD' if held else 'A CLAIM FAILED'} "
          f"(forbid blocked the action, permit ran, chain+signatures verified, tamper rejected)")
    print("=" * 72)
    return 0 if held else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify enforcement receipts offline.")
    ap.add_argument("--selftest", action="store_true", help="seal + verify + tamper, no input")
    ap.parse_args(argv)
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
