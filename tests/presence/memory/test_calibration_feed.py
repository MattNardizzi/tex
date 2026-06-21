"""The learning flywheel: sealed human resolutions → per-tenant conformal floor.

Proves: only `refused` feeds; the score is the real final_score; per-tenant with
no cross-customer learning; the min-n floor keeps a tiny biased sample honestly
transductive; forgetting a contribution leaves no residue; and END-TO-END that the
real Session-2 conformal loader reads the per-tenant file and switches to
`calibrated` mode (so every confirmed resolution tightens the gate).
"""

from __future__ import annotations

import json
import os

from tex.causal.conformal_attribution import compute_conformal_prediction_set
from tex.presence.memory import MIN_CALIBRATION_N, tenant_calibration_env

from .conftest import make_decision


def test_only_refused_feeds(feed):
    assert feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.8), human_verdict="approved") is False
    assert feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.8), human_verdict="held") is False
    assert feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.8), human_verdict="refused") is True
    assert feed.status("acme")["n"] == 1


def test_records_the_real_final_score(feed):
    d = make_decision(final_score=0.73)
    feed.record_resolution(tenant="acme", decision=d, human_verdict="refused")
    entries = [
        json.loads(line)
        for line in feed._ledger_path("acme").read_text().splitlines()
        if line.strip()
    ]
    assert entries[0]["final_score"] == 0.73
    assert entries[0]["decision_id"] == str(d.decision_id)


def test_refuses_missing_or_out_of_range_score(feed):
    # The feed forwards a refused resolution's own final_score UNMODIFIED (proven by
    # test_records_the_real_final_score); here we pin the guards that keep a junk
    # point out: a missing score and an out-of-[0,1] score are refused. The stronger
    # "must be a genuine sealed Decision, not a request value" property is a caller
    # contract — the wired /seal handler passes a server-looked-up Decision.
    assert feed.record_resolution(tenant="acme", decision={"decision_id": "x"}, human_verdict="refused") is False
    assert feed.record_resolution(tenant="acme", decision={"decision_id": "y", "final_score": 1.5}, human_verdict="refused") is False
    assert feed.record_resolution(tenant="acme", decision={"decision_id": "z", "final_score": float("nan")}, human_verdict="refused") is False
    assert feed.status("acme")["n"] == 0


def test_idempotent_per_decision(feed):
    d = make_decision(final_score=0.4)
    assert feed.record_resolution(tenant="acme", decision=d, human_verdict="refused") is True
    assert feed.record_resolution(tenant="acme", decision=d, human_verdict="refused") is True
    assert feed.status("acme")["n"] == 1  # re-resolved, never double-counted


def test_below_min_n_stays_transductive(feed):
    for _ in range(MIN_CALIBRATION_N - 1):
        feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.5), human_verdict="refused")
    st = feed.status("acme")
    assert st["calibrated_active"] is False
    # No scores file → the conformal loader returns None → the gate stays honestly
    # transductive (a tiny selection-biased sample never poses as a guarantee).
    assert not feed.scores_path("acme").exists()


def test_min_n_enables_calibrated_mode_end_to_end(feed):
    for i in range(MIN_CALIBRATION_N):
        feed.record_resolution(
            tenant="acme",
            decision=make_decision(final_score=0.2 + (i % 5) * 0.1),
            human_verdict="refused",
        )
    assert feed.scores_path("acme").exists()
    st = feed.status("acme")
    assert st["calibrated_active"] is True
    assert "selection-conditional" in st["coverage_semantics"]

    # The honest label is written next to the data, not buried.
    prov = json.loads(feed._provenance_path("acme").read_text())
    assert "selection-conditional" in prov["coverage_semantics"]
    assert prov["n"] == MIN_CALIBRATION_N

    # END-TO-END: the real Session-2 conformal path reads THIS tenant's file and
    # switches to calibrated mode. This is the flywheel actually closing.
    trace = [{"step_id": f"s{i}", "agent_id": "a"} for i in range(4)]
    scores = {f"s{i}": 0.1 * i for i in range(4)}
    with tenant_calibration_env(feed, "acme"):
        cps = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)
    assert cps.coverage_mode == "calibrated"


def test_min_n_floor_is_writer_side_only(feed):
    # Honest limitation, PINNED: the conformal CONSUMER applies no n-check. If some
    # other producer writes a sub-threshold scores file at the tenant's path, the
    # consumer announces 'calibrated' off it. Our floor holds ONLY because this feed
    # is the sole producer (it withholds the file below MIN_CALIBRATION_N). This
    # test documents that boundary instead of letting the docstring overclaim.
    sp = feed.scores_path("acme")
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("0.5\n", encoding="utf-8")  # 1 label, far below MIN_CALIBRATION_N

    trace = [{"step_id": f"s{i}", "agent_id": "a"} for i in range(4)]
    scores = {f"s{i}": 0.1 * i for i in range(4)}
    with tenant_calibration_env(feed, "acme"):
        cps = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)
    assert cps.coverage_mode == "calibrated"  # consumer did NOT enforce the floor
    # ...whereas the feed's own accounting (ledger-based) correctly says "not yet":
    assert feed.status("acme")["calibrated_active"] is False


def test_strictly_per_tenant_no_cross_customer_learning(feed):
    for _ in range(MIN_CALIBRATION_N):
        feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.5), human_verdict="refused")
    # globex's floor is untouched by acme's refusals.
    assert feed.status("globex")["n"] == 0
    assert not feed.scores_path("globex").exists()
    assert feed.scores_path("acme") != feed.scores_path("globex")

    # And the gate, pointed at globex, does NOT see acme's calibration.
    trace = [{"step_id": f"s{i}", "agent_id": "a"} for i in range(4)]
    scores = {f"s{i}": 0.1 * i for i in range(4)}
    with tenant_calibration_env(feed, "globex"):
        cps = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)
    assert cps.coverage_mode == "transductive"


def test_forget_resolution_leaves_no_residue(feed):
    for _ in range(MIN_CALIBRATION_N):
        feed.record_resolution(tenant="acme", decision=make_decision(final_score=0.5), human_verdict="refused")
    d = make_decision(final_score=0.9)
    feed.record_resolution(tenant="acme", decision=d, human_verdict="refused")
    assert feed.status("acme")["n"] == MIN_CALIBRATION_N + 1

    assert feed.forget_resolution(tenant="acme", decision_id=str(d.decision_id)) is True
    assert feed.status("acme")["n"] == MIN_CALIBRATION_N
    # Second forget is a no-op (nothing left to remove).
    assert feed.forget_resolution(tenant="acme", decision_id=str(d.decision_id)) is False


def test_env_context_manager_sets_and_restores(feed, monkeypatch):
    monkeypatch.setenv("TEX_CONFORMAL_CALIBRATION_PATH", "/prior/value")
    with tenant_calibration_env(feed, "acme") as path:
        assert path == str(feed.scores_path("acme"))
        assert os.environ["TEX_CONFORMAL_CALIBRATION_PATH"] == path
    # Prior value restored exactly (no leak across tenants/requests).
    assert os.environ["TEX_CONFORMAL_CALIBRATION_PATH"] == "/prior/value"
