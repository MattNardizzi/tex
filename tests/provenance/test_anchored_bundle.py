"""Phase 1 — the sealed-fact bundle can carry an offline-verifiable external
time anchor (RFC-3161), so any ledger fact (incl. ENFORCEMENT) proves an
authority that is NOT Tex saw this exact set of facts no later than gen_time.

Uses a throwaway LOCAL TSA: it exercises the real verification logic offline but
proves nothing about real wall-clock time (only the freetsa path does that).
The point under test is the binding + verification, not the clock.
"""

from __future__ import annotations

from tex.domain.evidence import EvidenceMaturity
from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa
from tex.interchange.external_anchor import CheckpointAnchorRecord, anchor_subject_digest
from tex.provenance.bundle import (
    anchor_ledger_checkpoint,
    export_sealed_fact_bundle,
    verify_sealed_fact_bundle,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind


def _seed_ledger() -> SealedFactLedger:
    ledger = SealedFactLedger()
    for allowed in (False, True):
        ledger.append(
            SealedFact(
                kind=SealedFactKind.ENFORCEMENT,
                subject_id="req-1",
                claim="gate decision (test)",
                maturity=EvidenceMaturity.RESEARCH_SOLID,
                detail={"allowed": allowed, "outcome": "blocked" if not allowed else "executed"},
            )
        )
    return ledger


def _local_anchor_fn(tsa):
    def anchor(snapshot):
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        resp = issue_timestamp_response(digest, tsa, nonce=4242)
        return CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority="local-demo-tsa",
            response_der=resp,
            request_nonce=4242,
        )

    return anchor


def test_anchored_bundle_verifies_external_time():
    ledger = _seed_ledger()
    tsa = mint_local_tsa()
    anchor = anchor_ledger_checkpoint(ledger, anchor_fn=_local_anchor_fn(tsa))
    assert anchor is not None
    bundle = export_sealed_fact_bundle(ledger, export_name="anchored", anchor=anchor)

    report = verify_sealed_fact_bundle(
        bundle,
        pinned_public_key_pem=ledger.public_key_pem,
        pinned_tsa_cert_der=tsa.ca_pin_der,
    )
    assert report.is_valid is True
    assert report.externally_anchored is True
    assert report.anchor_gen_time is not None
    assert report.anchor_failure is None


def test_unpinned_anchor_is_reported_not_asserted():
    ledger = _seed_ledger()
    tsa = mint_local_tsa()
    anchor = anchor_ledger_checkpoint(ledger, anchor_fn=_local_anchor_fn(tsa))
    bundle = export_sealed_fact_bundle(ledger, export_name="anchored", anchor=anchor)

    # No TSA cert pinned -> still valid on the ECDSA path, but external time is
    # NOT asserted (honest: unconfirmed, not proven).
    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=ledger.public_key_pem)
    assert report.is_valid is True
    assert report.externally_anchored is False
    assert report.anchor_failure == "no_tsa_cert_pinned"


def test_tamper_breaks_chain_and_anchor():
    ledger = _seed_ledger()
    tsa = mint_local_tsa()
    anchor = anchor_ledger_checkpoint(ledger, anchor_fn=_local_anchor_fn(tsa))
    bundle = export_sealed_fact_bundle(ledger, export_name="anchored", anchor=anchor)

    # Flip a field inside a sealed fact in the bundle's records.
    rec0 = bundle.records[0]
    bad_fact = rec0.fact.model_copy(update={"detail": {**rec0.fact.detail, "allowed": True}})
    tampered = bundle.model_copy(
        update={"records": (rec0.model_copy(update={"fact": bad_fact}),) + bundle.records[1:]}
    )

    report = verify_sealed_fact_bundle(
        tampered,
        pinned_public_key_pem=ledger.public_key_pem,
        pinned_tsa_cert_der=tsa.ca_pin_der,
    )
    assert report.is_valid is False  # chain replay catches the payload tamper
    assert report.externally_anchored is False  # recomputed root no longer matches the anchor
    assert report.anchor_failure == "anchor_root_mismatch"


def test_legacy_unanchored_bundle_still_valid():
    ledger = _seed_ledger()
    bundle = export_sealed_fact_bundle(ledger, export_name="legacy")  # no anchor

    report = verify_sealed_fact_bundle(
        bundle,
        pinned_public_key_pem=ledger.public_key_pem,
        pinned_tsa_cert_der=mint_local_tsa().ca_pin_der,
    )
    assert report.is_valid is True  # backward compatible
    assert report.externally_anchored is False
    assert report.anchor_failure is None  # nothing claimed, nothing to fail
