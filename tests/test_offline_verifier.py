"""
Acceptance tests for the standalone offline verdict checker (``tex.verifier``).

Pins the contract the NIGHT RUN asks for, all fail-closed:

  * a valid bundle minted from a REAL ``SealedFactLedger`` verifies against the
    pinned key — chain intact, signatures valid, witnessed decisions confirmed;
  * a tampered hash chain, a bad signature, and a forged/invalid monotonicity
    witness each FAIL;
  * the checker's trusted computing base imports NO Tex decision-engine code
    (proven both by a source scan and by a clean-subprocess sys.modules check);
  * the dual ECDSA+ML-DSA second-signature hook verifies a real PQ signature
    and fails closed on a bad one;
  * the CLI entry (``python -m tex.verifier``) exits 0 on valid, 1 on tampered.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.evidence import (
    CombinedEvidence,
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.provenance.bundle import export_sealed_fact_bundle
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind
from tex.verifier.check import check_monotonicity_witness, verify_bundle
from tex.verifier.export import (
    portable_bundle_from_ledger,
    portable_bundle_from_sealed_fact_bundle,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"


# --------------------------------------------------------------------------- #
# witnesses
# --------------------------------------------------------------------------- #
def _valid_forbid_witness() -> dict:
    """PERMIT → ABSTAIN (probabilistic) → FORBID (structural floor)."""
    return {
        "base_verdict": "PERMIT",
        "stages": [
            {"stage": "recognizer:bec", "kind": "probabilistic",
             "verdict_in": "PERMIT", "verdict_out": "ABSTAIN",
             "score_delta": 0.42, "structural_floor": False},
            {"stage": "specialist:action_class", "kind": "structural",
             "verdict_in": "ABSTAIN", "verdict_out": "FORBID",
             "score_delta": 0.0, "structural_floor": True},
        ],
        "final_verdict": "FORBID",
        "structural_floor_fired": True,
    }


def _valid_permit_witness() -> dict:
    """No stage moved the verdict; it rests at PERMIT."""
    return {
        "base_verdict": "PERMIT",
        "stages": [
            {"stage": "recognizer:bec", "kind": "probabilistic",
             "verdict_in": "PERMIT", "verdict_out": "PERMIT",
             "score_delta": 0.01, "structural_floor": False},
        ],
        "final_verdict": "PERMIT",
        "structural_floor_fired": False,
    }


# --------------------------------------------------------------------------- #
# fixtures: real ledger -> portable bundle
# --------------------------------------------------------------------------- #
def _decision_fact(*, verdict: str = "FORBID", witness: dict | None = None,
                   claim: str = "verdict sealed") -> SealedFact:
    detail: dict = {"verdict": verdict}
    if witness is not None:
        detail["monotonicity_witness"] = witness
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=str(uuid4()),
        claim=claim,
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        detail=detail,
    )


def _evidence_decision_fact() -> SealedFact:
    """A decision carrying a real composed e-value — exercises the float path
    of canonical_payload through the JSON round-trip."""
    import math
    comps = [
        TexEvidence(
            stream_id="drift", kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID, is_true_e_value=True,
            log_e_value=math.log(2.0), null_hypothesis_id="drift:no_change",
            filtration_id="drift:s", sequentially_predictable=True,
        ),
        TexEvidence(
            stream_id="agent", kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID, is_true_e_value=True,
            log_e_value=math.log(8.0), null_hypothesis_id="agent:on_baseline",
            filtration_id="agent:s", sequentially_predictable=True,
        ),
    ]
    return SealedFact(
        kind=SealedFactKind.DECISION, subject_id=str(uuid4()),
        claim="decision resolved with combined e-value",
        evidence=compose_arithmetic_mean(comps),
        maturity=EvidenceMaturity.RESEARCH_EARLY,
    )


def _ledger(*facts: SealedFact) -> SealedFactLedger:
    led = SealedFactLedger()
    for f in facts:
        led.append(f)
    return led


def _portable(led: SealedFactLedger) -> dict:
    return portable_bundle_from_ledger(led, export_name="exhibit")


def _as_json(bundle: dict) -> str:
    return json.dumps(bundle)


# --------------------------------------------------------------------------- #
# 1) a valid bundle passes
# --------------------------------------------------------------------------- #
def test_valid_bundle_passes_through_json() -> None:
    led = _ledger(
        _decision_fact(verdict="FORBID", witness=_valid_forbid_witness()),
        _decision_fact(verdict="PERMIT", witness=_valid_permit_witness()),
    )
    # serialize + reload to prove the verifier needs only the artifact + the key
    report = verify_bundle(
        _as_json(_portable(led)),
        pinned_public_key_pem=led.public_key_pem,
    )
    assert report.is_valid is True
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    assert report.decisions_total == 2
    assert report.decisions_witnessed == 2
    assert report.fully_witnessed is True
    assert report.witness_violations == ()


def test_valid_bundle_with_evidence_floats_round_trips() -> None:
    led = _ledger(_evidence_decision_fact())
    report = verify_bundle(_as_json(_portable(led)),
                           pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True
    assert report.chain_intact is True


def test_multi_record_chain_verifies() -> None:
    led = _ledger(*[_decision_fact(witness=_valid_forbid_witness())
                    for _ in range(5)])
    report = verify_bundle(_portable(led),  # dict input also accepted
                           pinned_public_key_pem=led.public_key_pem)
    assert report.record_count == 5
    assert report.is_valid is True
    assert report.fully_witnessed is True


def test_bridge_from_main_sealed_fact_bundle_verifies() -> None:
    # Prove compatibility with main's existing export path, not just our bridge.
    led = _ledger(_evidence_decision_fact())
    sfb = export_sealed_fact_bundle(led, export_name="A")
    portable = portable_bundle_from_sealed_fact_bundle(sfb)
    report = verify_bundle(_as_json(portable),
                           pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True
    assert report.chain_intact is True
    assert report.signatures_valid is True


def test_witness_optional_on_main_format_bundle() -> None:
    # A decision with NO witness (today's main format) is valid but not
    # fully_witnessed — the witness check is an additive, optional hook.
    led = _ledger(_decision_fact(witness=None))
    report = verify_bundle(_portable(led), pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True
    assert report.decisions_total == 1
    assert report.decisions_witnessed == 0
    assert report.fully_witnessed is False


def test_garbage_and_empty_bundles_fail_closed() -> None:
    # unparseable input must not raise and must not be valid
    assert verify_bundle("this is not json").is_valid is False
    assert verify_bundle(b"\x00\x01\x02").is_valid is False
    # valid JSON that is NOT an object (number / array / string) must fail
    # closed, not crash with AttributeError
    for non_object in ("5", "[1, 2, 3]", '"hello"', "null"):
        assert verify_bundle(non_object).is_valid is False
    # a parseable but empty bundle proves nothing -> not valid (fail-closed)
    empty = verify_bundle({"bundle_version": "tex-offline-verdict/1", "records": []})
    assert empty.record_count == 0
    assert empty.is_valid is False


# --------------------------------------------------------------------------- #
# 2) a tampered hash chain FAILS
# --------------------------------------------------------------------------- #
def test_tampered_payload_breaks_chain() -> None:
    led = _ledger(_decision_fact(claim="original"),
                  _decision_fact(claim="second"))
    bundle = _portable(led)
    # rewrite the sealed claim but leave the stale hashes — replay must catch it
    bundle["records"][0]["canonical_payload"]["claim"] = "tampered claim"
    report = verify_bundle(_as_json(bundle), pinned_public_key_pem=led.public_key_pem)
    assert report.chain_intact is False
    assert report.chain_break_at == 0
    assert report.is_valid is False


def test_reordered_records_break_chain() -> None:
    led = _ledger(_decision_fact(claim="a"), _decision_fact(claim="b"))
    bundle = _portable(led)
    bundle["records"][0], bundle["records"][1] = (
        bundle["records"][1], bundle["records"][0])
    report = verify_bundle(_as_json(bundle), pinned_public_key_pem=led.public_key_pem)
    assert report.chain_intact is False
    assert report.is_valid is False


def test_tampered_witness_breaks_chain() -> None:
    # The witness lives INSIDE the signed canonical payload, so editing it after
    # sealing breaks the hash — caught by integrity, before semantics.
    led = _ledger(_decision_fact(witness=_valid_forbid_witness()))
    bundle = _portable(led)
    w = bundle["records"][0]["canonical_payload"]["detail"]["monotonicity_witness"]
    w["final_verdict"] = "PERMIT"  # tamper the sealed witness
    report = verify_bundle(_as_json(bundle), pinned_public_key_pem=led.public_key_pem)
    assert report.chain_intact is False
    assert report.is_valid is False


# --------------------------------------------------------------------------- #
# 3) a bad signature FAILS (chain intact, signature wrong)
# --------------------------------------------------------------------------- #
def test_bad_signature_fails_with_chain_intact() -> None:
    led = _ledger(_decision_fact())
    bundle = _portable(led)
    # corrupt ONLY the signature; leave canonical_payload + hashes untouched
    bundle["records"][0]["signatures"][0]["signature_b64"] = base64.b64encode(
        b"\x00" * 64).decode("ascii")
    report = verify_bundle(_as_json(bundle), pinned_public_key_pem=led.public_key_pem)
    assert report.chain_intact is True            # integrity is fine...
    assert report.signatures_valid is False       # ...authenticity is not
    assert report.signature_invalid_at == 0
    assert report.is_valid is False


def test_wrong_pinned_key_fails() -> None:
    led = _ledger(_decision_fact())
    other = SealedFactLedger().public_key_pem
    report = verify_bundle(_portable(led), pinned_public_key_pem=other)
    assert report.key_matches_pin is False
    assert report.signatures_valid is False
    assert report.is_valid is False


def test_attacker_resigned_bundle_caught_by_pin() -> None:
    real = _ledger(_decision_fact(claim="genuine"))
    pinned = real.public_key_pem
    # attacker re-seals the SAME facts with their own key, embeds their own key
    attacker = SealedFactLedger()
    for rec in real.list_all():
        attacker.append(rec.fact)
    forged = _portable(attacker)
    report = verify_bundle(_as_json(forged), pinned_public_key_pem=pinned)
    assert report.key_matches_pin is False
    assert report.signatures_valid is False
    assert report.is_valid is False


def test_unpinned_proves_consistency_not_authorship() -> None:
    led = _ledger(_decision_fact())
    report = verify_bundle(_portable(led))  # no pin
    assert report.pinned is False
    assert report.key_matches_pin is None
    # internally consistent (verifies against the embedded key)...
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.is_valid is True
    # ...but a tamper is still caught even unpinned
    bundle = _portable(led)
    bundle["records"][0]["canonical_payload"]["claim"] = "x"
    assert verify_bundle(_as_json(bundle)).is_valid is False


# --------------------------------------------------------------------------- #
# 4) a forged/invalid witness FAILS (validly signed, but lying)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mutate,expected_code", [
    # a stage raised the verdict toward PERMIT (FORBID -> ABSTAIN)
    (lambda w: w["stages"].append(
        {"stage": "x", "kind": "probabilistic", "verdict_in": "FORBID",
         "verdict_out": "ABSTAIN", "structural_floor": False})
        or w.__setitem__("final_verdict", "ABSTAIN"), "raised_toward_permit"),
    # structural floor fired but the final verdict is not FORBID
    (lambda w: (w.__setitem__("final_verdict", "ABSTAIN"),
                w["stages"][1].__setitem__("verdict_out", "ABSTAIN")),
     "floor_fired_without_forbid"),
    # a PROBABILISTIC stage claims it fired the structural floor
    (lambda w: w["stages"][1].__setitem__("kind", "probabilistic"),
     "probabilistic_fired_floor"),
])
def test_forged_witness_fails(mutate, expected_code) -> None:
    witness = _valid_forbid_witness()
    mutate(witness)
    # seal the LYING witness honestly: valid chain + valid signature
    led = _ledger(_decision_fact(verdict="FORBID", witness=witness))
    report = verify_bundle(_portable(led), pinned_public_key_pem=led.public_key_pem)
    # chain + signature are valid (the lie was sealed as bytes)...
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    # ...but the monotonicity check exposes it.
    assert report.is_valid is False
    assert report.witness_violations
    codes = report.witness_violations[0][1]
    assert any(c.startswith(expected_code) for c in codes), codes


def test_require_witness_flag_fails_on_missing_witness() -> None:
    led = _ledger(_decision_fact(witness=None))
    ok = verify_bundle(_portable(led), pinned_public_key_pem=led.public_key_pem)
    assert ok.is_valid is True  # default: witness optional
    strict = verify_bundle(_portable(led), pinned_public_key_pem=led.public_key_pem,
                           require_witness=True)
    assert strict.is_valid is False
    assert strict.witness_violations[0][1] == ("missing_witness",)


# direct unit coverage of the witness invariant function
def test_check_monotonicity_witness_unit() -> None:
    assert check_monotonicity_witness(_valid_forbid_witness()) == []
    assert check_monotonicity_witness(_valid_permit_witness()) == []
    assert "witness_not_object" in check_monotonicity_witness("nope")
    broken_chain = _valid_forbid_witness()
    broken_chain["stages"][1]["verdict_in"] = "PERMIT"  # != prior verdict_out
    assert any(c.startswith("broken_stage_chain")
               for c in check_monotonicity_witness(broken_chain))
    flag_lie = _valid_forbid_witness()
    flag_lie["structural_floor_fired"] = False  # hides the fired floor
    assert "floor_flag_inconsistent" in check_monotonicity_witness(flag_lie)


# --------------------------------------------------------------------------- #
# 5) the dual ECDSA + ML-DSA second-signature hook
# --------------------------------------------------------------------------- #
def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        mldsa.MLDSA65PrivateKey.generate()
        return mldsa
    except Exception:  # pragma: no cover - depends on cryptography build
        pytest.skip("no native ML-DSA backend (need cryptography >= 48)")


def _dual_sign(bundle: dict, *, corrupt: bool = False) -> bytes:
    """Append a REAL ML-DSA-65 signature over each record_hash. Returns the PEM
    public key to pin. With ``corrupt=True`` the signature is over the wrong
    message, so it must fail closed."""
    mldsa = _mldsa()
    from cryptography.hazmat.primitives import serialization
    sk = mldsa.MLDSA65PrivateKey.generate()
    pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pem_b64 = base64.b64encode(pem).decode("ascii")
    for rec in bundle["records"]:
        msg = (b"not-the-record-hash" if corrupt
               else rec["record_hash"].encode("ascii"))
        sig = sk.sign(msg)
        rec["signatures"].append({
            "algorithm": "ml-dsa-65",
            "signature_b64": base64.b64encode(sig).decode("ascii"),
            "public_key_b64": pem_b64,
        })
    bundle.setdefault("keys", {})["ml-dsa-65"] = pem_b64
    return pem


def test_dual_signature_verifies_when_present() -> None:
    led = _ledger(_decision_fact(witness=_valid_forbid_witness()))
    bundle = _portable(led)
    pq_pem = _dual_sign(bundle)
    report = verify_bundle(
        _as_json(bundle),
        pinned_public_key_pem=led.public_key_pem,
        extra_pins={"ml-dsa-65": pq_pem},
    )
    assert report.is_valid is True
    assert report.pq_present is True
    assert report.pq_all_verified is True
    assert report.pq_invalid is False
    assert report.fully_verified is True


def test_dual_signature_bad_pq_fails_closed() -> None:
    led = _ledger(_decision_fact())
    bundle = _portable(led)
    pq_pem = _dual_sign(bundle, corrupt=True)
    report = verify_bundle(
        _as_json(bundle),
        pinned_public_key_pem=led.public_key_pem,
        extra_pins={"ml-dsa-65": pq_pem},
    )
    # classical path is fine, but the present PQ signature did not verify
    assert report.signatures_valid is True
    assert report.pq_present is True
    assert report.pq_invalid is True
    assert report.is_valid is False  # fail-closed


def test_pq_signature_unpinned_is_not_fully_verified() -> None:
    # A real ML-DSA signature verified only against the bundle's OWN embedded
    # key (no out-of-band pin) is internally consistent — is_valid holds on the
    # pinned ECDSA path — but it must NOT earn fully_verified: it was not
    # anchored to a known key. "a name must deliver its property."
    led = _ledger(_decision_fact(witness=_valid_forbid_witness()))
    bundle = _portable(led)
    _dual_sign(bundle)  # embeds the PQ public key in each signature entry
    report = verify_bundle(
        _as_json(bundle),
        pinned_public_key_pem=led.public_key_pem,  # ECDSA pinned, ML-DSA NOT
    )
    assert report.is_valid is True
    assert report.pq_present is True
    assert report.pq_all_verified is True
    assert report.pq_unpinned is True
    assert report.fully_verified is False


def test_pq_signature_without_backend_is_unverifiable_not_trusted() -> None:
    # A PQ signature whose key the checker cannot resolve is reported honestly
    # as unverifiable: it does NOT flip is_valid (ECDSA still governs) but it
    # does block the stronger fully_verified claim — never silently trusted.
    led = _ledger(_decision_fact())
    bundle = _portable(led)
    for rec in bundle["records"]:
        rec["signatures"].append({
            "algorithm": "ml-dsa-65",
            "signature_b64": base64.b64encode(b"\x00" * 32).decode("ascii"),
            # no public_key_b64, not in keys, and no pq-pin supplied
        })
    report = verify_bundle(_as_json(bundle), pinned_public_key_pem=led.public_key_pem)
    assert report.pq_present is True
    assert report.pq_unverifiable is True
    assert report.pq_invalid is False
    assert report.is_valid is True
    assert report.fully_verified is False


# --------------------------------------------------------------------------- #
# 6) the checker imports NO Tex decision-engine code
# --------------------------------------------------------------------------- #
_BANNED = ("pdp", "engine", "specialist", "recognizer", "router", "crc_gate",
           "hold", "semantic", "agent", "runtime")


def test_check_source_imports_no_tex() -> None:
    import ast
    src = (_SRC / "tex" / "verifier" / "check.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    tex_imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tex_imports += [n.name for n in node.names if n.name.split(".")[0] == "tex"]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "tex":
                tex_imports.append(node.module or "")
    assert tex_imports == [], f"check.py must not import tex.*, found: {tex_imports}"


def test_check_import_pulls_in_no_engine_modules() -> None:
    # Import the checker in a CLEAN subprocess and assert sys.modules contains
    # no Tex engine code — catches transitive imports the source scan cannot.
    code = (
        "import sys, json\n"
        "import tex.verifier.check\n"
        "mods = sorted(m for m in sys.modules if m == 'tex' or m.startswith('tex.'))\n"
        "print(json.dumps(mods))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=env, cwd=str(_REPO_ROOT))
    assert out.returncode == 0, out.stderr
    mods = json.loads(out.stdout.strip().splitlines()[-1])
    assert set(mods) == {"tex", "tex.verifier", "tex.verifier.check"}, mods
    for m in mods:
        assert not any(b in m for b in _BANNED), f"engine module leaked: {m}"


def test_cli_module_pulls_in_no_engine_modules() -> None:
    code = (
        "import sys, json\n"
        "import tex.verifier.__main__\n"
        "leaked = sorted(m for m in sys.modules\n"
        "  if m.startswith('tex.') and m not in "
        "  ('tex.verifier','tex.verifier.check','tex.verifier.__main__'))\n"
        "print(json.dumps(leaked))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=env, cwd=str(_REPO_ROOT))
    assert out.returncode == 0, out.stderr
    leaked = json.loads(out.stdout.strip().splitlines()[-1])
    assert leaked == [], f"CLI leaked engine modules: {leaked}"


# --------------------------------------------------------------------------- #
# 7) the CLI entry point
# --------------------------------------------------------------------------- #
def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    return subprocess.run([sys.executable, "-m", "tex.verifier", *args],
                          capture_output=True, text=True, env=env,
                          cwd=str(_REPO_ROOT))


def test_cli_exit_codes(tmp_path: Path) -> None:
    led = _ledger(_decision_fact(witness=_valid_forbid_witness()))
    bundle = _portable(led)
    bpath = tmp_path / "bundle.json"
    bpath.write_text(_as_json(bundle), encoding="utf-8")
    pin = tmp_path / "tex.pem"
    pin.write_bytes(led.public_key_pem)

    ok = _run_cli([str(bpath), "--pin", str(pin)])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "VALID" in ok.stdout

    # tamper -> exit 1
    bundle["records"][0]["canonical_payload"]["claim"] = "tampered"
    bpath.write_text(_as_json(bundle), encoding="utf-8")
    bad = _run_cli([str(bpath), "--pin", str(pin)])
    assert bad.returncode == 1
    assert "INVALID" in bad.stdout


def test_cli_json_output_and_stdin(tmp_path: Path) -> None:
    led = _ledger(_decision_fact(witness=_valid_forbid_witness()))
    pin = tmp_path / "tex.pem"
    pin.write_bytes(led.public_key_pem)
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    proc = subprocess.run(
        [sys.executable, "-m", "tex.verifier", "-", "--pin", str(pin), "--json"],
        input=_as_json(_portable(led)), capture_output=True, text=True,
        env=env, cwd=str(_REPO_ROOT))
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["is_valid"] is True
    assert payload["fully_witnessed"] is True
