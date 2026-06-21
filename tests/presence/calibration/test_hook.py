"""The recording hook the orchestrator wires into /decisions/{id}/seal.

Pins: only `refused` records a label; the score is the real Decision.final_score;
duck-typed resolution shapes; never raises into the seal flow; the default feed
agrees with the gate's reader via TEX_PRESENCE_CALIBRATION_DIR; forgetting works.
"""

from __future__ import annotations

from tex.presence.memory import (
    CalibrationResolution,
    MIN_CALIBRATION_N,
    default_calibration_feed,
    forget_resolution_for_calibration,
    record_resolution_for_calibration,
)

from .conftest import make_decision


def test_only_refused_records_a_label(calib_dir, feed):
    d = make_decision(final_score=0.73)
    assert record_resolution_for_calibration(
        "acme", CalibrationResolution(decision=d, human_verdict="approved")
    ) is False
    assert record_resolution_for_calibration(
        "acme", CalibrationResolution(decision=d, human_verdict="held")
    ) is False
    assert record_resolution_for_calibration(
        "acme", CalibrationResolution(decision=d, human_verdict="refused")
    ) is True
    assert feed.label_count("acme") == 1


def test_default_feed_agrees_with_reader_via_env(calib_dir):
    # The hook (no explicit feed) writes through the default feed; a freshly built
    # default feed reads the same file back — writer and reader agree by env.
    d = make_decision(final_score=0.4)
    record_resolution_for_calibration("acme", CalibrationResolution(decision=d, human_verdict="refused"))
    assert default_calibration_feed().label_count("acme") == 1


def test_accepts_dict_resolution(calib_dir, feed):
    d = make_decision(final_score=0.6)
    assert record_resolution_for_calibration(
        "acme", {"decision": d, "human_verdict": "refused"}
    ) is True
    assert feed.label_count("acme") == 1


def test_never_raises_on_bad_input(calib_dir, feed):
    # Missing pieces, junk types, empty tenant — all return False, none raise.
    assert record_resolution_for_calibration("acme", None) is False
    assert record_resolution_for_calibration("acme", {"human_verdict": "refused"}) is False
    assert record_resolution_for_calibration("acme", {"decision": object()}) is False
    assert record_resolution_for_calibration(
        "", CalibrationResolution(decision=make_decision(final_score=0.5), human_verdict="refused")
    ) is False
    assert feed.label_count("acme") == 0


def test_idempotent_per_decision(calib_dir, feed):
    d = make_decision(final_score=0.5)
    res = CalibrationResolution(decision=d, human_verdict="refused")
    assert record_resolution_for_calibration("acme", res) is True
    assert record_resolution_for_calibration("acme", res) is True  # re-resolve
    assert feed.label_count("acme") == 1  # never double-counted


def test_forget_hook_reverts_below_min_n(calib_dir, feed):
    for _ in range(MIN_CALIBRATION_N):
        record_resolution_for_calibration(
            "acme", CalibrationResolution(decision=make_decision(final_score=0.5), human_verdict="refused")
        )
    extra = make_decision(final_score=0.9)
    record_resolution_for_calibration("acme", CalibrationResolution(decision=extra, human_verdict="refused"))
    assert feed.scores_path("acme").exists()  # calibrated active

    # Forgetting back below the floor withholds the scores file again (the flywheel
    # is honestly reversible — losing labels loses the formal floor).
    assert forget_resolution_for_calibration("acme", str(extra.decision_id)) is True
    assert forget_resolution_for_calibration(
        "acme", str(make_decision(final_score=0.1).decision_id)
    ) is False  # nothing to remove
    assert feed.label_count("acme") == MIN_CALIBRATION_N
