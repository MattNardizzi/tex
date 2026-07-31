"""
Tests for tex.c2pa.sherman_2026_defenses — verifies Tex's posture
against the six attack classes in Sherman et al., arxiv 2604.24890.
"""

from __future__ import annotations

import pytest

from tex.c2pa.sherman_2026_defenses import (
    ShermanAttackClass,
    ShermanDefense,
    ShermanDefensePosture,
    assess_current_posture,
    render_buyer_dossier,
)


def test_six_attack_classes_are_named_per_paper():
    """The six classes from Sherman et al. §3 attack matrix."""
    values = {c.value for c in ShermanAttackClass}
    assert "C1.timestamp_replay" in values
    assert "C2.stale_ocsp" in values
    assert "C3.chain_truncation" in values
    assert "C4.assertion_injection" in values
    assert "C5.ingredient_forgery" in values
    assert "C6.cross_manifest_replay" in values
    assert len(values) == 6


def test_posture_covers_all_six_classes():
    posture = assess_current_posture()
    classes = {d.attack_class for d in posture.defenses}
    assert classes == set(ShermanAttackClass)


def test_all_six_defenses_are_currently_wired():
    """Headline assertion: Tex closes all six Sherman 2026 attack
    classes. Any regression flips this to False."""
    posture = assess_current_posture()
    failures = [
        d.attack_class.value for d in posture.defenses if not d.wired
    ]
    assert posture.sherman_2026_compliant is True, (
        f"Sherman-2026 defense regressions detected: {failures}"
    )


def test_each_defense_names_at_least_one_wired_module():
    posture = assess_current_posture()
    for d in posture.defenses:
        assert len(d.wired_modules) >= 1, (
            f"{d.attack_class.value} has no wired_modules"
        )


def test_each_defense_has_a_spec_anchor():
    posture = assess_current_posture()
    for d in posture.defenses:
        assert d.spec_anchor, f"{d.attack_class.value} has no spec_anchor"


def test_render_buyer_dossier_is_json_serialisable():
    import json

    dossier = render_buyer_dossier()
    # Round-trips through JSON without loss.
    serialised = json.dumps(dossier)
    decoded = json.loads(serialised)
    assert decoded["paper"]["arxiv_id"] == "2604.24890"
    assert decoded["sherman_2026_compliant"] is True
    assert len(decoded["defenses"]) == 6


def test_dossier_lists_paper_anchor():
    dossier = render_buyer_dossier()
    assert dossier["paper"]["title"].startswith("Verifying Provenance")
    assert dossier["paper"]["published"] == "2026-04-27"


def test_specific_defenses_cite_their_modules():
    """Spot-check that the C1 + C2 defenses cite the v2 timestamp +
    OCSP modules I just added — these are the two most important
    closures."""
    posture = assess_current_posture()
    by_class = {d.attack_class: d for d in posture.defenses}

    c1 = by_class[ShermanAttackClass.TIMESTAMP_REPLAY]
    assert any(
        "tex.c2pa.timestamp" in m for m in c1.wired_modules
    ), "C1 defense must cite tex.c2pa.timestamp"

    c2 = by_class[ShermanAttackClass.STALE_OCSP]
    assert any(
        "tex.c2pa.ocsp" in m for m in c2.wired_modules
    ), "C2 defense must cite tex.c2pa.ocsp"
