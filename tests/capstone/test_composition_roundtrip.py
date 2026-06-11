"""
Gate 1 — composition round-trip: full flow → object → serialize → offline
``verify_capstone(bundle_dir, pins)`` green, with every per-property status
matching the leap module's own verifier verdict (no re-implementation
drift), and the two test-mode halves failing CLOSED when their opt-ins are
withdrawn.
"""

from __future__ import annotations

from tex.capstone.manifest import CapstoneVerdict
from tex.capstone.verify import verify_capstone


def test_offline_verification_is_green(offline_result) -> None:
    """The headline: everything checkable from files + pins alone holds."""
    assert offline_result.failed_names() == ()
    assert offline_result.ok is True
    # The full breadth actually ran — all named phases, not a subset.
    names = {c.name for c in offline_result.checks}
    assert {
        "chain1.integrity", "chain1.authorship_pin",
        "chain2.integrity", "chain2.authorship_pin",
        "chain3.integrity", "chain3.authorship_pin",
        "manifest.seal_binding", "manifest.digest_binding", "pins.digest",
        "decision.identity",
        "L1.relation", "L1.seal_binding", "L2.verdict_binding",
        "L3.certificate", "L3.epoch_commitment", "L3.conservation",
        "L4.floor", "L5.ruling",
        "L6.quorum", "L6.root_binding", "L6.consistency", "L6.federated",
        "L7.certificate", "L8.hold", "L9.drift", "L10.fact",
        "L11.commitment", "L11.cross_chain", "L12.recompute",
        "M0.order", "manifest.status_drift",
    } <= names


def test_statuses_match_module_verifiers(capstone_flow, offline_result) -> None:
    """No status drift: what the manifest claims per leap is exactly what
    the module verifiers found offline."""
    manifest = capstone_flow.compose.manifest
    for leap, found in offline_result.offline_status.items():
        assert manifest.property_for(leap).status == found, leap
    # The drift check covers all twelve, not just the ones above.
    assert offline_result.check("manifest.status_drift").ok


def test_manifest_replays_from_disk(capstone_flow) -> None:
    """The sealed digest is over canonical CONTENT: parsing the shipped file
    reproduces the exact digest the chain sealed."""
    raw = (capstone_flow.bundle_dir / "manifest.json").read_bytes()
    reparsed = CapstoneVerdict.model_validate_json(raw)
    assert reparsed.manifest_sha256() == capstone_flow.compose.manifest_sha256
    sealed = capstone_flow.compose.capstone_record.fact.detail
    assert sealed["capstone_manifest_sha256"] == reparsed.manifest_sha256()


def test_l1_fails_closed_without_the_shim_opt_in(
    capstone_flow, capstone_pins
) -> None:
    """Withdraw TEX_ZKPDP_ALLOW_SHIM: the stand-in must be REFUSED by the
    arbiter's own hard gate — and only the L1 checks fail; nothing else in
    the composition is contaminated."""
    closed = verify_capstone(
        capstone_flow.bundle_dir, capstone_pins, allow_shim=False
    )
    assert not closed.check("L1.relation").ok
    assert "zkpdp_shim_not_a_real_proof" in closed.check("L1.relation").detail
    blast_radius = set(closed.failed_names())
    assert blast_radius <= {"L1.relation", "L1.seal_binding", "L4.floor",
                            "manifest.status_drift"}
    # Every chain and every other property still verifies.
    for name in (
        "chain1.integrity", "chain1.authorship_pin", "chain2.authorship_pin",
        "chain3.authorship_pin", "L2.verdict_binding", "L3.certificate",
        "L6.quorum", "L7.certificate", "L11.commitment", "L12.recompute",
    ):
        assert closed.check(name).ok, name


def test_l2_fails_closed_without_test_mode(capstone_flow, capstone_pins) -> None:
    """Withdraw TEX_TEE_ATTESTATION_MODE=test: the alg=none JWT must not
    verify under a production posture."""
    closed = verify_capstone(
        capstone_flow.bundle_dir, capstone_pins, tee_test_mode=False
    )
    assert not closed.check("L2.verdict_binding").ok
    assert closed.check("chain1.integrity").ok
    assert closed.check("L1.relation").ok


def test_compose_consumed_module_verifiers_not_reimplementations(
    capstone_flow,
) -> None:
    """The manifest's verification snapshots carry the module verifiers' own
    fields (reason codes, stand-in flags, issue tuples) — spot-pin the
    load-bearing ones verbatim."""
    manifest = capstone_flow.compose.manifest
    l1 = manifest.property_for("L1").verification
    assert l1["reason"] is None and l1["stand_in"] is True
    assert l1["seal_status"] == "sealed_match"
    l2 = manifest.property_for("L2").verification
    assert l2["reason"] == "ok_test_mode"
    l3 = manifest.property_for("L3").verification
    assert l3["conservation_status"] == "GATED-HOLDS"
    assert l3["attempts_source"] == "derived"
    l7 = manifest.property_for("L7").verification
    assert l7["p_anytime"] == 1.0 and l7["n_breaches"] == 0
    assert l7["is_vacuous"] is False
