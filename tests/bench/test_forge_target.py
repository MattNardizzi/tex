"""
Adversarial suite for the ARMED forge challenge (tex.bench.forge_target +
the committed forge/ artifacts + the canonical-bytes hardening in
tex.bench.evidence_bundle).

These tests load the COMMITTED artifacts (forge/canonical_bundle.*.jsonl and
forge/PUBKEY_STATEMENT*.json) — not freshly generated ones — so they guard that
the SHIPPED bundle stays valid and the SHIPPED pin matches. Every test FAILS if
the property it names breaks. None is xfail'd or skipped.

The load-bearing tests:
  * ``test_resign_forgery_against_committed_pin_fails`` — a no-private-key
    attacker who re-signs a mutated record with their own key passes integrity
    and self-verification but FAILS the pin. This is the whole dare.
  * ``test_noncanonical_payload_rejected`` — written to FAIL on the UNHARDENED
    verifier (it returned valid=True for non-canonical bytes); passes only with
    the canonical-bytes gate. It proves the gate is load-bearing.
  * ``test_verifier_refuses_pin_from_bundle`` — the verifier never reads the pin
    from a bundle-embedded key (the 'key from the same repo' defense).
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tex.bench.evidence_bundle import (
    _stable_json,
    forge_record_by_resigning,
    read_bundle,
    verify_bundle,
)
from tex.bench.forge_target import load_published_pin, verify_forge_target
from tex.evidence.chain import _build_record_hash, _sha256_hex
from tex.evidence.seal import PQ_SIGNATURE_FIELD, build_evidence_chain_signer

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FORGE = _REPO_ROOT / "forge"

_PQ_BUNDLE = _FORGE / "canonical_bundle.pq.jsonl"
_PQ_PIN = _FORGE / "PUBKEY_STATEMENT.json"
_ECDSA_BUNDLE = _FORGE / "canonical_bundle.ecdsa.jsonl"
_ECDSA_PIN = _FORGE / "PUBKEY_STATEMENT.ecdsa.json"


def _pin_b64(pin_path: Path) -> str:
    return load_published_pin(pin_path).public_key_b64


def _records(bundle_path: Path):
    return read_bundle(bundle_path)


def _rebuild_record(record, *, payload_json: str):
    """Re-stamp a record so payload_sha256/record_hash match new payload bytes.

    Models an attacker who controls the stored bytes and the integrity hashes —
    the realistic threat. ``previous_hash`` is preserved so the chain link is
    unchanged (the test isolates the property under attack).
    """
    payload_sha = _sha256_hex(payload_json)
    record_hash = _build_record_hash(
        payload_sha256=payload_sha, previous_hash=record.previous_hash
    )
    return record.model_copy(
        update={
            "payload_json": payload_json,
            "payload_sha256": payload_sha,
            "record_hash": record_hash,
        }
    )


# ── sanity floor: the armed bundles are valid against their committed pins ──


def test_committed_pq_bundle_valid_against_committed_pin() -> None:
    pin = _pin_b64(_PQ_PIN)
    v = verify_bundle(_PQ_BUNDLE, pinned_public_key_b64=pin)
    assert v.valid
    assert v.integrity_ok
    assert v.authorship_ok is True
    assert v.canonical_bytes_ok is True
    assert all(c.canonical_ok for c in v.per_record_signatures)
    assert all(c.key_is_pinned for c in v.per_record_signatures)
    assert set(v.signature_algorithms) == {"composite-ml-dsa-65-ed25519"}


def test_committed_ecdsa_bundle_valid_against_its_pin() -> None:
    pin = _pin_b64(_ECDSA_PIN)
    v = verify_bundle(_ECDSA_BUNDLE, pinned_public_key_b64=pin)
    assert v.valid
    assert v.canonical_bytes_ok is True
    assert all(c.key_is_pinned for c in v.per_record_signatures)
    assert set(v.signature_algorithms) == {"ecdsa-p256"}


@pytest.mark.parametrize("bundle", [_PQ_BUNDLE, _ECDSA_BUNDLE])
def test_committed_bundle_contains_all_target_verdicts(bundle) -> None:
    verdicts: list[str] = []
    human: list[str] = []
    for record in _records(bundle):
        payload = json.loads(record.payload_json)
        if payload.get("record_type") == "decision":
            verdicts.append(payload["verdict"])
        elif payload.get("record_type") == "human_resolution":
            human.append(payload["human_verdict"])
    assert verdicts.count("FORBID") >= 1
    assert verdicts.count("PERMIT") >= 1
    assert verdicts.count("ABSTAIN") >= 1
    assert "refused" in human


# ── the authorship attack (caught ONLY by the out-of-band pin) ─────────────


def test_resign_forgery_against_committed_pin_fails() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)

    adversary = build_evidence_chain_signer(
        key_dir=tempfile.mkdtemp(), key_id="adversary-v1"
    )
    forged_last = forge_record_by_resigning(
        records[-1],
        mutate=lambda p: {**p, "human_verdict": "approved", "verdict": "PERMIT"},
        adversary_signer=adversary,
    )
    forged = records[:-1] + (forged_last,)

    # Integrity is fooled — the attacker signed their own self-consistent forgery.
    unpinned = verify_bundle(forged)
    assert unpinned.integrity_ok is True
    assert unpinned.signatures_self_verify is True

    # ...but the pin rejects it: the foreign key is not Tex's.
    pinned = verify_bundle(forged, pinned_public_key_b64=pin)
    assert pinned.valid is False
    assert pinned.authorship_ok is False
    assert pinned.per_record_signatures[-1].key_is_pinned is False


def test_verifier_refuses_pin_from_bundle() -> None:
    records = _records(_PQ_BUNDLE)
    # Pull the key embedded in a record's signature block.
    payload = json.loads(records[0].payload_json)
    embedded_key = payload[PQ_SIGNATURE_FIELD]["public_key_b64"]

    # load_published_pin only reads the statement file; it cannot be handed a
    # bundle, so there is no path that would treat the embedded key as the pin.
    published = load_published_pin(_PQ_PIN).public_key_b64
    # (In the committed bundle the embedded key DOES equal the published one —
    # that is correct. The defense is that the verifier reads the pin from the
    # statement, not the bundle.) Prove the no-pin path refuses authorship:
    v_nopin = verify_bundle(_PQ_BUNDLE)
    assert v_nopin.authorship_ok is None
    assert v_nopin.valid is False
    # And the published pin is a real out-of-band value, equal to what signed.
    assert embedded_key == published


# ── canonical-bytes gate (FAILS on the unhardened verifier) ────────────────


def test_noncanonical_payload_rejected() -> None:
    # Re-encode a committed record's payload as indent=2 JSON: valid parse, same
    # meaning, NON-canonical bytes. On the unhardened verifier this returned
    # valid=True; the gate must now reject it. payload_sha256/record_hash are
    # recomputed over the non-canonical bytes (the attacker controls them).
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    target = records[0]
    parsed = json.loads(target.payload_json)
    noncanonical = json.dumps(parsed, indent=2)
    assert noncanonical != target.payload_json  # genuinely non-canonical
    bad = _rebuild_record(target, payload_json=noncanonical)
    forged = (bad,) + records[1:]

    v = verify_bundle(forged, pinned_public_key_b64=pin)
    assert v.valid is False
    assert v.canonical_bytes_ok is False
    assert v.per_record_signatures[0].canonical_ok is False


def test_duplicate_key_payload_rejected() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    target = records[0]
    parsed = json.loads(target.payload_json)
    # Inject a trailing duplicate 'verdict' key into the raw bytes. json.loads
    # would last-wins it; the verifier must reject the object outright.
    canonical = _stable_json(parsed)
    assert canonical.endswith("}")
    dup_json = canonical[:-1] + ',"verdict":"PERMIT"}'
    assert json.loads(dup_json)["verdict"] == "PERMIT"  # last-wins on naive parse
    bad = _rebuild_record(target, payload_json=dup_json)
    forged = (bad,) + records[1:]

    v = verify_bundle(forged, pinned_public_key_b64=pin)
    assert v.valid is False
    assert v.per_record_signatures[0].canonical_ok is False


def test_meaning_flip_in_noncanonical_bytes_fails_selfverify() -> None:
    # Flip a verdict inside non-canonical bytes WITHOUT the private key (reuse
    # the existing signature block). This must fail self-verification — proving
    # the malleability is presentation-only and cannot change meaning.
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    # find an ABSTAIN decision to flip
    target = None
    for r in records:
        p = json.loads(r.payload_json)
        if p.get("record_type") == "decision" and p.get("verdict") == "ABSTAIN":
            target = r
            break
    assert target is not None, "no ABSTAIN record to flip"
    parsed = json.loads(target.payload_json)
    parsed["verdict"] = "PERMIT"  # meaning change; signature block left intact
    flipped = json.dumps(parsed, indent=2)
    bad = _rebuild_record(target, payload_json=flipped)
    forged = tuple(bad if r is target else r for r in records)

    v = verify_bundle(forged, pinned_public_key_b64=pin)
    assert v.valid is False
    assert v.signatures_self_verify is False


# ── integrity axis ─────────────────────────────────────────────────────────


def test_byteflip_on_committed_record_breaks_chain() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    target = records[1]
    # Flip one character in the stored bytes WITHOUT recomputing the hashes.
    edited = target.payload_json.replace("FORBID", "PERMIT", 1)
    if edited == target.payload_json:
        edited = ("X" + target.payload_json[1:])
    bad = target.model_copy(update={"payload_json": edited})
    forged = records[:1] + (bad,) + records[2:]
    v = verify_bundle(forged, pinned_public_key_b64=pin)
    assert v.valid is False
    assert "payload_sha256_mismatch" in v.chain_issue_codes


def test_forged_record_hash_caught() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    forged0 = records[0].model_copy(update={"record_hash": "a" * 64})
    v = verify_bundle((forged0,) + records[1:], pinned_public_key_b64=pin)
    assert v.valid is False
    assert "record_hash_mismatch" in v.chain_issue_codes


def test_reorder_and_delete_break_chain() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    # delete the middle record
    mid = len(records) // 2
    deleted = records[:mid] + records[mid + 1 :]
    v_del = verify_bundle(deleted, pinned_public_key_b64=pin)
    assert v_del.valid is False
    assert any(
        code in v_del.chain_issue_codes
        for code in ("chain_link_mismatch", "unexpected_previous_hash")
    )
    # reorder two adjacent records
    reordered = list(records)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    v_re = verify_bundle(tuple(reordered), pinned_public_key_b64=pin)
    assert v_re.valid is False


# ── pin semantics ──────────────────────────────────────────────────────────


def test_wrong_pin_rejects_authentic_bundle() -> None:
    records = _records(_PQ_BUNDLE)
    other = build_evidence_chain_signer(key_dir=tempfile.mkdtemp(), key_id="other-v1")
    wrong_pin = base64.b64encode(other.key.public_key).decode("ascii")
    v = verify_bundle(records, pinned_public_key_b64=wrong_pin)
    assert v.authorship_ok is False
    assert v.valid is False


def test_unpinned_bundle_is_integrity_only() -> None:
    v = verify_bundle(_PQ_BUNDLE)
    assert v.integrity_ok is True
    assert v.authorship_ok is None
    assert v.valid is False


def test_empty_bundle_not_vacuously_valid() -> None:
    v = verify_bundle(())
    assert v.integrity_ok is False
    assert v.valid is False
    assert v.record_count == 0


def test_committed_pin_matches_embedded_signing_key_and_fingerprint() -> None:
    for bundle, pin_path in ((_PQ_BUNDLE, _PQ_PIN), (_ECDSA_BUNDLE, _ECDSA_PIN)):
        pin = load_published_pin(pin_path)
        # fingerprint self-consistency
        raw = base64.b64decode(pin.public_key_b64, validate=True)
        assert hashlib.sha256(raw).hexdigest() == pin.public_key_sha256
        # every record signed by the one published key
        for record in _records(bundle):
            payload = json.loads(record.payload_json)
            block = payload[PQ_SIGNATURE_FIELD]
            assert block["public_key_b64"] == pin.public_key_b64


def test_load_published_pin_refuses_inconsistent_statement(tmp_path) -> None:
    # A statement whose fingerprint does not match its key must be refused.
    pin = load_published_pin(_PQ_PIN)
    bad = {
        "algorithm": pin.algorithm,
        "key_id": pin.key_id,
        "public_key_b64": pin.public_key_b64,
        "public_key_sha256": "0" * 64,  # wrong fingerprint
        "attestor": pin.attestor,
        "note": pin.note,
    }
    bad_path = tmp_path / "bad_statement.json"
    bad_path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        load_published_pin(bad_path)


# ── the concrete signed-silence forge attempt ──────────────────────────────


def test_sealed_abstain_cannot_be_flipped_to_permit_under_pin() -> None:
    pin = _pin_b64(_PQ_PIN)
    records = _records(_PQ_BUNDLE)
    target = None
    for r in records:
        p = json.loads(r.payload_json)
        if p.get("record_type") == "decision" and p.get("verdict") == "ABSTAIN":
            target = r
            break
    assert target is not None
    # Attacker mutates the sealed ABSTAIN toward PERMIT, recomputes hashes, but
    # has no private key (signature block untouched). Must fail under the pin.
    parsed = json.loads(target.payload_json)
    parsed["verdict"] = "PERMIT"
    mutated = _stable_json(parsed)  # even canonical bytes cannot save it
    bad = _rebuild_record(target, payload_json=mutated)
    forged = tuple(bad if r is target else r for r in records)
    v = verify_bundle(forged, pinned_public_key_b64=pin)
    assert v.valid is False
    assert v.signatures_self_verify is False  # meaning changed; digest mismatch


# ── verify_forge_target wiring ──────────────────────────────────────────────


def test_verify_forge_target_agrees_with_verify_bundle() -> None:
    direct = verify_bundle(_PQ_BUNDLE, pinned_public_key_b64=_pin_b64(_PQ_PIN))
    via = verify_forge_target(_PQ_BUNDLE, _PQ_PIN)
    assert via.valid == direct.valid is True


# ── private-key tripwire (CI-grade) ────────────────────────────────────────


def test_private_key_not_committed() -> None:
    # No tracked file under forge/_private_keys/.
    result = subprocess.run(
        ["git", "ls-files", "forge/_private_keys/"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "", (
        f"private key material is tracked by git: {result.stdout!r}"
    )
    # And no committed file under forge/ contains private key material.
    tracked = subprocess.run(
        ["git", "ls-files", "forge/"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    for rel in tracked.stdout.split():
        text = (_REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        assert "private_key_b64" not in text, (
            f"committed forge file {rel} contains a private_key_b64 field"
        )


# ── the existing self-test must still pass (canonical gate didn't break it) ──


def test_self_test_still_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_it_yourself.py"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": "src", "PATH": __import__("os").environ.get("PATH", "")},
    )
    assert result.returncode == 0, (
        f"replay-trial self-test failed after the canonical-bytes hardening:\n"
        f"{result.stdout}\n{result.stderr}"
    )
