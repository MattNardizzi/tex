"""The LIVE held card's payload carries WHO and WHAT.

The vigil held provider maps a sink item into the payload the held card
renders. Governance now stamps ``agent_name`` / ``content_excerpt`` /
``action_type`` onto the hold's detail; the payload must surface them —
as a dict under ``detail`` and as the readable ``agent`` — so the live
card presents a hold exactly like the /held rows and the answer's
list_held_waiting rows do. A hold WITHOUT the enrichment must keep the
legacy string-detail payload byte-for-byte (zero regression).
"""

from __future__ import annotations

from types import SimpleNamespace

from tex.vigil.held_provider import HeldDecisionVigilProvider


def _item(detail: dict, note: str = "I need to know if I can let this through (data_delete). It's yours to decide.") -> SimpleNamespace:
    return SimpleNamespace(
        agent_id="0ddddcf8-2722-459a-8673-553272e9e360",
        kind="data_delete",
        note=note,
        detail=detail,
        hold=None,
        decision_id="dec-1",
        anchor_sha256="a" * 64,
    )


def test_enriched_hold_payload_carries_who_and_what() -> None:
    item = _item(
        {
            "agent_name": "DeskSentinel",
            "content_excerpt": "Permanently delete the entire production support tickets table and skip the backup",
            "action_type": "data_delete",
            "tenant_id": "default",
            "decision_id": "dec-1",
        }
    )
    payload = HeldDecisionVigilProvider._to_payload(item)
    assert payload["agent"] == "DeskSentinel"
    assert isinstance(payload["detail"], dict)
    assert payload["detail"]["agent_name"] == "DeskSentinel"
    assert payload["detail"]["content_excerpt"].startswith("Permanently delete")
    assert payload["detail"]["action_type"] == "data_delete"
    # The generic sentence still travels as the sentence — the surface dedupes it.
    assert "let this through" in payload["sentence"]


def test_unenriched_hold_payload_is_unchanged() -> None:
    item = _item({"tenant_id": "default", "note": "held: command", "decision_id": "dec-1"})
    payload = HeldDecisionVigilProvider._to_payload(item)
    # Legacy shape: string (the note), never a dict; agent falls to the raw id.
    assert payload["detail"] == "held: command"
    assert payload["agent"] == "0ddddcf8-2722-459a-8673-553272e9e360"


def test_enrichment_merges_with_layer4_hold_detail() -> None:
    item = _item(
        {
            "agent_name": "QuillFlow",
            "content_excerpt": "Purge the editorial archive",
            "decision_id": "dec-1",
        }
    )
    item.hold = {"sentence": "There's one thing I'd need to know.", "detail": {"band": [0.2, 0.6]}}
    payload = HeldDecisionVigilProvider._to_payload(item)
    assert payload["sentence"] == "There's one thing I'd need to know."
    assert payload["detail"]["band"] == [0.2, 0.6]
    assert payload["detail"]["agent_name"] == "QuillFlow"
    assert payload["detail"]["content_excerpt"] == "Purge the editorial archive"
