"""
Acceptance tests for the standalone verifier (``tex.verifier``).

The contract that matters in front of an auditor:

  * a clean, witness-bearing bundle verifies against the PINNED key — chain,
    signatures, monotonicity witness all green;
  * a tampered hash chain, a bad signature, a wrong pin, and a forged/invalid
    witness each FAIL fail-closed;
  * the optional dual ML-DSA co-signature verifies when present and FAILS when
    tampered;
  * the verifier module imports NO Tex decision-engine code (and, in fact, no
    Tex code at all) — proven by an out-of-process ``sys.modules`` audit;
  * the CLI exit code is fail-closed.

Bundles are sealed by the REAL producer (``SealedFactLedger`` /
``export_sealed_fact_bundle``) and then handed to the verifier as plain JSON, so
a passing test also proves the verifier's zero-import canonical reconstruction
matches the producer byte-for-byte.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.evidence import (
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.provenance.bundle import export_sealed_fact_bundle
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind
from tex.verifier.check import MLDSA_AVAILABLE, verify_bundle

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #
def _valid_witness(final: str = "ABSTAIN", floor: bool = False) -> dict:
    stages = [
        {"name": "router", "verdict_before": "PERMIT", "verdict_after": "ABSTAIN", "score_delta": 0.4},
    ]
    if final == "FORBID":
        stages.append(
            {"name": "floor", "verdict_before": "ABSTAIN", "verdict_after": "FORBID", "score_delta": 1.0}
        )
    return {
        "schema_version": 1,
        "stages": stages,
        "structural_floor_fired": floor,
        "final_verdict": final,
    }


def _decision_fact(verdict: str = "ABSTAIN", witness: dict | None = None) -> SealedFact:
    detail: dict = {"verdict": verdict}
    if witness is not None:
        detail["monotonicity_witness"] = witness
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=str(uuid4()),
        claim=f"verdict sealed: {verdict}",
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        detail=detail,
    )


def _evidence_fact() -> tuple[SealedFact, TexEvidence]:
    ev = TexEvidence(
        stream_id="drift",
        kind=EvidenceKind.E_PROCESS,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=True,
        log_e_value=0.75,
        null_hypothesis_id="drift:no_change",
        filtration_id="drift:s",
        sequentially_predictable=True,
    )
    fact = SealedFact(
        kind=SealedFactKind.DRIFT,
        subject_id="agent-1",
        claim="drift observed",
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        evidence=compose_arithmetic_mean([ev]),
    )
    return fact, ev


def _bundle_dict(*facts: SealedFact) -> tuple[dict, bytes]:
    """Seal the facts with the real producer, return (bundle_json_dict, pubkey)."""
    led = SealedFactLedger()
    for f in facts:
        led.append(f)
    bundle = export_sealed_fact_bundle(led, export_name="exhibit")
    return json.loads(bundle.to_json()), led.public_key_pem


# --------------------------------------------------------------------------- #
# 1) a clean bundle passes
# --------------------------------------------------------------------------- #
def test_clean_witness_bundle_is_valid() -> None:
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.is_valid is True
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    assert report.witness_present is True
    assert report.witness_valid is True
    assert report.witness_failures == ()


def test_clean_floor_forbid_witness_is_valid() -> None:
    bundle, pub = _bundle_dict(_decision_fact("FORBID", _valid_witness("FORBID", floor=True)))
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.is_valid is True
    assert report.witness_valid is True


def test_multi_record_chain_with_evidence_verifies() -> None:
    """Exercises the zero-import canonical reconstruction across multiple records
    AND an evidence-bearing fact — the byte-for-byte match against the producer."""
    ev_fact, _ = _evidence_fact()
    bundle, pub = _bundle_dict(
        _decision_fact("PERMIT", _valid_witness("ABSTAIN")),
        ev_fact,
        _decision_fact("FORBID", _valid_witness("FORBID", floor=True)),
    )
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.record_count == 3
    assert report.is_valid is True
    assert report.chain_intact is True
    assert report.witness_checked == 2


# --------------------------------------------------------------------------- #
# 2) tampered hash chain FAILS
# --------------------------------------------------------------------------- #
def test_tampered_fact_breaks_chain() -> None:
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    # mutate the sealed claim, leaving the stale hashes in place
    bundle["records"][0]["fact"]["claim"] = "a different, unsealed claim"
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.chain_intact is False
    assert report.chain_break_at == 0
    assert report.is_valid is False


def test_tampered_witness_breaks_chain() -> None:
    """A witness lives in the sealed ``detail``, so editing it post-seal is a
    chain break (caught before the witness check even runs)."""
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    bundle["records"][0]["fact"]["detail"]["monotonicity_witness"]["final_verdict"] = "PERMIT"
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.chain_intact is False
    assert report.is_valid is False


def test_reordered_records_break_chain() -> None:
    bundle, pub = _bundle_dict(
        _decision_fact("PERMIT", _valid_witness("ABSTAIN")),
        _decision_fact("FORBID", _valid_witness("FORBID", floor=True)),
    )
    bundle["records"].reverse()
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.chain_intact is False
    assert report.is_valid is False


# --------------------------------------------------------------------------- #
# 3) bad signature / wrong pin FAIL
# --------------------------------------------------------------------------- #
def test_corrupted_signature_fails() -> None:
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    raw = base64.b64decode(bundle["records"][0]["signature_b64"])
    flipped = bytes([raw[0] ^ 0xFF]) + raw[1:]
    bundle["records"][0]["signature_b64"] = base64.b64encode(flipped).decode("ascii")
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert report.chain_intact is True  # bytes still chain
    assert report.signatures_valid is False
    assert report.signature_invalid_at == 0
    assert report.is_valid is False


def test_wrong_pin_fails() -> None:
    bundle, _ = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    other_key = SealedFactLedger().public_key_pem
    report = verify_bundle(bundle, pinned_public_key_pem=other_key)
    assert report.key_matches_pin is False
    assert report.signatures_valid is False
    assert report.is_valid is False


def test_attacker_resigned_bundle_caught_by_pin() -> None:
    real_led = SealedFactLedger()
    real_led.append(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    pinned = real_led.public_key_pem
    attacker = SealedFactLedger()
    for rec in real_led.list_all():
        attacker.append(rec.fact)
    forged = json.loads(export_sealed_fact_bundle(attacker, export_name="forged").to_json())
    report = verify_bundle(forged, pinned_public_key_pem=pinned)
    assert report.key_matches_pin is False  # embedded attacker key != pin
    assert report.signatures_valid is False  # signed by attacker, not Tex
    assert report.is_valid is False


def test_unpinned_is_consistent_but_invalid() -> None:
    bundle, _ = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    report = verify_bundle(bundle, pinned_public_key_pem=None)
    assert report.internally_consistent is True  # chain + sig (vs embedded) ok
    assert report.key_pinned is False
    assert report.is_valid is False  # authorship unproven without a pin


# --------------------------------------------------------------------------- #
# 4) forged / invalid witness FAILS (chain + signature still valid)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "witness, sealed_verdict, needle",
    [
        # a stage raises the verdict back toward PERMIT
        (
            {
                "stages": [
                    {"verdict_before": "PERMIT", "verdict_after": "ABSTAIN", "score_delta": 0.5},
                    {"verdict_before": "ABSTAIN", "verdict_after": "PERMIT", "score_delta": -0.5},
                ],
                "structural_floor_fired": False,
                "final_verdict": "PERMIT",
            },
            "PERMIT",
            "raised toward PERMIT",
        ),
        # the structural floor fired but the final verdict is not FORBID
        (
            {
                "stages": [
                    {"verdict_before": "PERMIT", "verdict_after": "ABSTAIN", "score_delta": 0.5}
                ],
                "structural_floor_fired": True,
                "final_verdict": "ABSTAIN",
            },
            "ABSTAIN",
            "structural floor fired",
        ),
        # the witness's final verdict disagrees with the sealed verdict
        (
            {
                "stages": [
                    {"verdict_before": "PERMIT", "verdict_after": "ABSTAIN", "score_delta": 0.5}
                ],
                "structural_floor_fired": False,
                "final_verdict": "ABSTAIN",
            },
            "FORBID",
            "!= sealed verdict",
        ),
        # discontinuous transcript (stage 2 does not start where stage 1 ended)
        (
            {
                "stages": [
                    {"verdict_before": "PERMIT", "verdict_after": "ABSTAIN", "score_delta": 0.5},
                    {"verdict_before": "PERMIT", "verdict_after": "FORBID", "score_delta": 0.5},
                ],
                "structural_floor_fired": False,
                "final_verdict": "FORBID",
            },
            "FORBID",
            "discontinuous",
        ),
    ],
)
def test_forged_witness_fails(witness: dict, sealed_verdict: str, needle: str) -> None:
    bundle, pub = _bundle_dict(_decision_fact(sealed_verdict, witness))
    report = verify_bundle(bundle, pinned_public_key_pem=pub)
    # the forgery was sealed honestly as bytes — chain + signature hold...
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    # ...but the witness invariant catches the lie.
    assert report.witness_present is True
    assert report.witness_valid is False
    assert report.is_valid is False
    assert any(needle in f for f in report.witness_failures), report.witness_failures


# --------------------------------------------------------------------------- #
# 5) witness-absence policy (the not-yet-merged-format hook)
# --------------------------------------------------------------------------- #
def test_no_witness_passes_by_default_but_require_flag_fails() -> None:
    bundle, pub = _bundle_dict(_decision_fact("PERMIT"))  # no witness
    lenient = verify_bundle(bundle, pinned_public_key_pem=pub)
    assert lenient.witness_present is False
    assert lenient.witness_valid is None
    assert lenient.is_valid is True
    strict = verify_bundle(bundle, pinned_public_key_pem=pub, require_witness=True)
    assert strict.is_valid is False


# --------------------------------------------------------------------------- #
# 6) dual ML-DSA co-signature (fail-closed)
# --------------------------------------------------------------------------- #
def _attach_pq_cosignatures(bundle: dict):
    """Sign each record's recomputed record_hash with a fresh ML-DSA-65 key and
    inject the co-signature as the producer is expected to. Returns the PQ pub
    PEM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa

    priv = mldsa.MLDSA65PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    for rec in bundle["records"]:
        msg = rec["record_hash"].encode("ascii")
        rec["pq_signature_b64"] = base64.b64encode(priv.sign(msg)).decode("ascii")
    return pub_pem


@pytest.mark.skipif(not MLDSA_AVAILABLE, reason="no native ML-DSA backend")
def test_dual_pq_cosignature_valid() -> None:
    bundle, pub = _bundle_dict(_decision_fact("FORBID", _valid_witness("FORBID", floor=True)))
    pq_pub = _attach_pq_cosignatures(bundle)
    report = verify_bundle(
        bundle, pinned_public_key_pem=pub, pinned_pq_public_key_pem=pq_pub, require_pq=True
    )
    assert report.pq_present is True
    assert report.pq_valid is True
    assert report.is_valid is True


@pytest.mark.skipif(not MLDSA_AVAILABLE, reason="no native ML-DSA backend")
def test_dual_pq_cosignature_tampered_fails() -> None:
    bundle, pub = _bundle_dict(_decision_fact("FORBID", _valid_witness("FORBID", floor=True)))
    pq_pub = _attach_pq_cosignatures(bundle)
    raw = base64.b64decode(bundle["records"][0]["pq_signature_b64"])
    bundle["records"][0]["pq_signature_b64"] = base64.b64encode(
        bytes([raw[0] ^ 0xFF]) + raw[1:]
    ).decode("ascii")
    report = verify_bundle(
        bundle, pinned_public_key_pem=pub, pinned_pq_public_key_pem=pq_pub
    )
    assert report.pq_present is True
    assert report.pq_valid is False
    assert report.is_valid is False


def test_require_pq_without_cosignature_fails() -> None:
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    report = verify_bundle(bundle, pinned_public_key_pem=pub, require_pq=True)
    assert report.pq_present is False
    assert report.is_valid is False  # required but absent


# --------------------------------------------------------------------------- #
# 7) hostile input never raises — fail closed
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("blob", ["not json at all", "[]", "{}", '{"records": "nope"}', "123"])
def test_malformed_bundle_fails_closed(blob: str) -> None:
    report = verify_bundle(blob, pinned_public_key_pem=b"")
    assert report.is_valid is False


# --------------------------------------------------------------------------- #
# 8) import isolation — the TCB really is tiny
# --------------------------------------------------------------------------- #
def test_verifier_imports_no_engine_code() -> None:
    """Out-of-process: importing the verifier must not pull in the decision
    engine, recognizers, specialists — nor even the producer ledger/bundle. The
    only ``tex.*`` modules loaded are the verifier package itself."""
    probe = (
        "import sys; import tex.verifier.check;"
        "tex_mods = sorted(m for m in sys.modules if m == 'tex' or m.startswith('tex.'));"
        "print('TEXMODS=' + ','.join(tex_mods));"
        "print('CRYPTO=' + str('cryptography' in sys.modules))"
    )
    env = {**os.environ, "PYTHONPATH": str(_SRC)}
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    out = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
    tex_mods = set(filter(None, out["TEXMODS"].split(",")))
    assert tex_mods == {"tex", "tex.verifier", "tex.verifier.check"}, tex_mods
    # belt-and-suspenders: none of the forbidden families snuck in
    forbidden = ("engine", "recognizer", "specialist", "pdp", "router", "crc_gate", "provenance")
    leaks = {m for m in tex_mods if any(k in m for k in forbidden)}
    assert leaks == set(), leaks
    assert out["CRYPTO"] == "True"


# --------------------------------------------------------------------------- #
# 9) CLI exit code is fail-closed
# --------------------------------------------------------------------------- #
def _run_cli(args: list[str]):
    env = {**os.environ, "PYTHONPATH": str(_SRC)}
    return subprocess.run(
        [sys.executable, "-m", "tex.verifier", *args],
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )


def test_cli_valid_and_tampered(tmp_path: Path) -> None:
    bundle, pub = _bundle_dict(_decision_fact("FORBID", _valid_witness("FORBID", floor=True)))
    bundle_path = tmp_path / "bundle.json"
    key_path = tmp_path / "key.pem"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    key_path.write_bytes(pub)

    ok = _run_cli([str(bundle_path), "--pubkey", str(key_path)])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "VALID" in ok.stdout

    # no pin -> INVALID by design (authorship unproven)
    unpinned = _run_cli([str(bundle_path)])
    assert unpinned.returncode == 1
    assert "UNPINNED" in unpinned.stdout

    # tamper the chain -> INVALID, exit 1
    bundle["records"][0]["fact"]["claim"] = "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    bad = _run_cli([str(bundle_path), "--pubkey", str(key_path)])
    assert bad.returncode == 1
    assert "INVALID" in bad.stdout


def test_cli_json_output(tmp_path: Path) -> None:
    bundle, pub = _bundle_dict(_decision_fact("ABSTAIN", _valid_witness("ABSTAIN")))
    bundle_path = tmp_path / "bundle.json"
    key_path = tmp_path / "key.pem"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    key_path.write_bytes(pub)
    res = _run_cli([str(bundle_path), "--pubkey", str(key_path), "--json"])
    assert res.returncode == 0, res.stdout + res.stderr
    payload = json.loads(res.stdout)
    assert payload["is_valid"] is True
    assert payload["witness_valid"] is True
