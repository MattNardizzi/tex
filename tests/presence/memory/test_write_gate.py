"""seal() is write-gated, fail-closed: refuses what is not provably groundable."""

from __future__ import annotations

import pytest

from tex.presence.contract import PresenceClaim, PresenceTier, PresenceVerdict
from tex.presence.memory import SealedPresenceMemory

from .conftest import make_abstain, make_claim_verdict


def test_refuses_abstain(mem: SealedPresenceMemory):
    claim, verdict = make_abstain("unknown_thing")
    with pytest.raises(ValueError, match="non-groundable|ABSTAIN"):
        mem.seal(tenant="acme", claim=claim, verdict=verdict)
    assert mem.recall(tenant="acme", query="") == ()  # nothing written


def test_refuses_claim_verdict_binding_mismatch(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    wrong_claim = PresenceClaim("agent_count", "how many agents", claim.kind)
    with pytest.raises(ValueError, match="binding mismatch"):
        mem.seal(tenant="acme", claim=wrong_claim, verdict=verdict)


def test_refuses_groundable_tier_with_zero_evidence(mem: SealedPresenceMemory):
    # A SEALED tier asserting provability but carrying no EvidenceRef is incoherent.
    claim = PresenceClaim("forbid_count", "how many forbid", make_claim_verdict()[0].kind)
    verdict = PresenceVerdict(claim_id="forbid_count", tier=PresenceTier.SEALED, evidence=(), reason="x")
    with pytest.raises(ValueError, match="zero\\s+evidence|at least one"):
        mem.seal(tenant="acme", claim=claim, verdict=verdict)


def test_refuses_empty_tenant(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    with pytest.raises(ValueError, match="non-empty tenant"):
        mem.seal(tenant="   ", claim=claim, verdict=verdict)
