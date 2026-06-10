"""
L2 — Proof-of-Guardrail: verdict-bound attestation tests.

The earnable claim and its falsification (per ROADMAP WAVE 2, L2 row):

  * Fold categorical verdict + policy-bundle digest + decision-input hash
    + prior ledger hash into the composite-attestation ``report_data``.
  * Test-mode composite JWT for FORBID + matching sealed FORBID ⇒ ok=True.
  * Same JWT with sealed_verdict=PERMIT ⇒ ok=False, 'verdict_nonce_mismatch'.
  * forgery=0 over the suite.
  * The verifier MUST check TDX ``report_data``, NOT ``eat_nonce`` — the
    hollow-binding regression (``test_hollow_eat_nonce_binding_is_caught``)
    fails if anyone reverts that.

In ``TEX_TEE_ATTESTATION_MODE=test`` the JWT is unsigned (alg=none); these
tests exercise verifier *logic*. Cryptographic unforgeability of
``report_data`` is RUNTIME-DEPENDENT on real Intel TDX hardware.
"""

from __future__ import annotations

import hashlib

import pytest

from tex.domain.verdict import Verdict
from tex.tee.attestation_client import (
    build_test_mode_composite_jwt,
    verify_attestation,
)
from tex.tee.h100_attestation import collect_gpu_evidence
from tex.tee.tdx_attestation import collect_tdx_evidence
from tex.tee.verdict_binding import (
    build_verdict_bound_test_jwt,
    recompute_expected_nonce,
    report_data_for_nonce,
    verdict_bound_nonce,
    verify_verdict_binding,
)


# Canonical sealed facts reused across tests.
POLICY_DIGEST = hashlib.sha256(b"policy-bundle-v1").hexdigest()
INPUT_HASH = hashlib.sha256(b"decision-input-payload").hexdigest()
PREV_HASH = hashlib.sha256(b"ledger-head-prev").hexdigest()

ALL_VERDICTS = (Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID)


@pytest.fixture(autouse=True)
def _force_test_mode(monkeypatch):
    """Every test runs with TEX_TEE_ATTESTATION_MODE=test."""
    monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "test")
    yield


def _facts(verdict, *, policy=POLICY_DIGEST, inp=INPUT_HASH, prev=PREV_HASH):
    return {
        "sealed_verdict": verdict,
        "policy_bundle_digest": policy,
        "decision_input_sha256": inp,
        "ledger_prev_hash": prev,
    }


# --------------------------------------------------------------------------- #
# verdict_bound_nonce — mirrors decision_bound_nonce (SHA-256[:32])           #
# --------------------------------------------------------------------------- #


class TestVerdictBoundNonce:
    def test_deterministic(self):
        a = verdict_bound_nonce(**_facts(Verdict.FORBID))
        b = verdict_bound_nonce(**_facts(Verdict.FORBID))
        assert a == b

    def test_is_32_lowercase_hex(self):
        n = verdict_bound_nonce(**_facts(Verdict.FORBID))
        assert len(n) == 32
        assert all(c in "0123456789abcdef" for c in n)

    def test_changes_with_verdict(self):
        n = {v: verdict_bound_nonce(**_facts(v)) for v in ALL_VERDICTS}
        assert len(set(n.values())) == 3, "each verdict must yield a distinct nonce"

    def test_changes_with_policy_digest(self):
        a = verdict_bound_nonce(**_facts(Verdict.FORBID))
        b = verdict_bound_nonce(
            **_facts(Verdict.FORBID, policy=hashlib.sha256(b"other-policy").hexdigest())
        )
        assert a != b

    def test_changes_with_input_hash(self):
        a = verdict_bound_nonce(**_facts(Verdict.FORBID))
        b = verdict_bound_nonce(
            **_facts(Verdict.FORBID, inp=hashlib.sha256(b"other-input").hexdigest())
        )
        assert a != b

    def test_changes_with_prev_hash(self):
        a = verdict_bound_nonce(**_facts(Verdict.FORBID))
        b = verdict_bound_nonce(
            **_facts(Verdict.FORBID, prev=hashlib.sha256(b"other-head").hexdigest())
        )
        assert a != b

    def test_genesis_prev_hash_none_is_accepted(self):
        n = verdict_bound_nonce(**_facts(Verdict.FORBID, prev=None))
        assert len(n) == 32

    def test_string_verdict_normalizes(self):
        assert verdict_bound_nonce(**_facts("forbid")) == verdict_bound_nonce(
            **_facts(Verdict.FORBID)
        )

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValueError):
            verdict_bound_nonce(**_facts("MAYBE"))

    def test_blank_digest_rejected(self):
        with pytest.raises(ValueError):
            verdict_bound_nonce(**_facts(Verdict.FORBID, policy=""))

    def test_non_hex_digest_rejected(self):
        with pytest.raises(ValueError):
            verdict_bound_nonce(**_facts(Verdict.FORBID, inp="not-hex-zzz"))

    def test_domain_separated_from_decision_nonce(self):
        # A verdict nonce must never collide with a CrossGuard decision
        # nonce over the same string material.
        from tex.tee.attestation_client import decision_bound_nonce

        assert verdict_bound_nonce(**_facts(Verdict.FORBID)) != decision_bound_nonce(
            "FORBID", POLICY_DIGEST
        )


# --------------------------------------------------------------------------- #
# report_data expansion + recompute_expected_nonce                            #
# --------------------------------------------------------------------------- #


class TestReportData:
    def test_report_data_is_64_bytes(self):
        rd = report_data_for_nonce(verdict_bound_nonce(**_facts(Verdict.FORBID)))
        assert len(rd) == 64

    def test_lower_half_is_sha256_of_upper(self):
        rd = report_data_for_nonce(verdict_bound_nonce(**_facts(Verdict.FORBID)))
        upper, lower = rd[:32], rd[32:]
        assert lower == hashlib.sha256(upper).digest()

    def test_recompute_expected_nonce_is_128_hex(self):
        rd = recompute_expected_nonce(**_facts(Verdict.FORBID))
        assert len(rd) == 128
        assert all(c in "0123456789abcdef" for c in rd)

    def test_recompute_matches_manual_expansion(self):
        nonce = verdict_bound_nonce(**_facts(Verdict.FORBID))
        assert recompute_expected_nonce(**_facts(Verdict.FORBID)) == (
            report_data_for_nonce(nonce).hex()
        )

    def test_matches_ita_user_data_construction(self):
        # Mirror compose_attestation's user_data construction exactly, so a
        # real composed quote would carry the report_data we expect.
        nonce = verdict_bound_nonce(**_facts(Verdict.FORBID))
        upper = bytes.fromhex(nonce.ljust(64, "0"))[:32]
        lower = hashlib.sha256(upper).digest()
        assert recompute_expected_nonce(**_facts(Verdict.FORBID)) == (upper + lower).hex()


# --------------------------------------------------------------------------- #
# Happy path + the verdict-swap adversary                                     #
# --------------------------------------------------------------------------- #


class TestVerifyHappyPath:
    def test_matching_forbid_ok(self):
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        res = verify_verdict_binding(jwt, **_facts(Verdict.FORBID))
        assert res.ok is True
        assert res.reason == "ok_test_mode"
        assert res.bound_verdict == "FORBID"
        assert res.test_mode is True
        assert res.observed_report_data == res.expected_report_data

    @pytest.mark.parametrize("verdict", ALL_VERDICTS)
    def test_each_verdict_self_consistent(self, verdict):
        jwt = build_verdict_bound_test_jwt(**_facts(verdict))
        res = verify_verdict_binding(jwt, **_facts(verdict))
        assert res.ok is True
        assert res.bound_verdict == verdict.value

    def test_accepts_envelope_like_object(self):
        from types import SimpleNamespace

        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        env = SimpleNamespace(ita_jwt=jwt)
        assert verify_verdict_binding(env, **_facts(Verdict.FORBID)).ok is True


class TestVerdictSwapAdversary:
    def test_forbid_token_verified_as_permit_fails(self):
        # The headline case: a real FORBID attestation must not verify as a
        # PERMIT.
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        res = verify_verdict_binding(jwt, **_facts(Verdict.PERMIT))
        assert res.ok is False
        assert res.reason == "verdict_nonce_mismatch"

    @pytest.mark.parametrize("truth", ALL_VERDICTS)
    @pytest.mark.parametrize("claim", ALL_VERDICTS)
    def test_swap_matrix(self, truth, claim):
        jwt = build_verdict_bound_test_jwt(**_facts(truth))
        res = verify_verdict_binding(jwt, **_facts(claim))
        if truth == claim:
            assert res.ok is True
        else:
            assert res.ok is False
            assert res.reason == "verdict_nonce_mismatch"


class TestFieldSensitivity:
    """Flipping any one sealed fact at verify time breaks the binding."""

    def test_wrong_policy_digest_fails(self):
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        res = verify_verdict_binding(
            jwt, **_facts(Verdict.FORBID, policy=hashlib.sha256(b"evil").hexdigest())
        )
        assert res.ok is False and res.reason == "verdict_nonce_mismatch"

    def test_wrong_input_hash_fails(self):
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        res = verify_verdict_binding(
            jwt, **_facts(Verdict.FORBID, inp=hashlib.sha256(b"evil").hexdigest())
        )
        assert res.ok is False and res.reason == "verdict_nonce_mismatch"

    def test_wrong_prev_hash_fails(self):
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        res = verify_verdict_binding(
            jwt, **_facts(Verdict.FORBID, prev=hashlib.sha256(b"evil").hexdigest())
        )
        assert res.ok is False and res.reason == "verdict_nonce_mismatch"

    def test_genesis_vs_nongenesis_distinct(self):
        jwt_genesis = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID, prev=None))
        res = verify_verdict_binding(jwt_genesis, **_facts(Verdict.FORBID))  # prev=PREV
        assert res.ok is False and res.reason == "verdict_nonce_mismatch"


# --------------------------------------------------------------------------- #
# THE BUG FIX — report_data, not eat_nonce                                    #
# --------------------------------------------------------------------------- #


def _forge_hollow_token(*, true_verdict, claimed_verdict):
    """Adversary forges the SOFT echo fields to claim a different verdict.

    Produces a token whose hardware-rooted ``tdx_report_data`` is still
    bound to ``true_verdict`` (the TDX quote signs it; a host cannot
    change it) but whose ``eat_nonce`` is set to ``claimed_verdict``'s
    nonce (a plaintext JSON field a host CAN re-wrap). A verifier that
    keys on ``eat_nonce`` is fooled; one that keys on ``report_data`` is
    not.
    """
    true_rd = report_data_for_nonce(verdict_bound_nonce(**_facts(true_verdict)))
    claimed_nonce = verdict_bound_nonce(**_facts(claimed_verdict))
    # Real hardware report_data bound to the TRUE verdict ...
    tdx_ev = collect_tdx_evidence(user_data=true_rd)
    gpu_ev = collect_gpu_evidence(nonce=true_rd)
    # ... but eat_nonce echoes the CLAIMED verdict.
    return build_test_mode_composite_jwt(
        tdx_evidence=tdx_ev, gpu_evidence=gpu_ev, nonce=claimed_nonce
    )


class TestHollowBindingBugFix:
    def test_old_eat_nonce_verifier_is_fooled(self):
        # Demonstrates WHY the fix is load-bearing: the legacy nonce check
        # (verify_attestation -> _nonce_matches, which consults eat_nonce)
        # ACCEPTS the forged token as the claimed verdict.
        jwt = _forge_hollow_token(
            true_verdict=Verdict.FORBID, claimed_verdict=Verdict.PERMIT
        )
        permit_nonce = verdict_bound_nonce(**_facts(Verdict.PERMIT))
        fooled = verify_attestation(jwt, expected_nonce=permit_nonce)
        assert fooled.ok is True, "eat_nonce check accepts the hollow forgery"

    def test_verdict_binding_verifier_catches_it(self):
        # The fix: verify_verdict_binding gates on tdx_report_data, so the
        # SAME forged token is rejected when claimed as PERMIT.
        jwt = _forge_hollow_token(
            true_verdict=Verdict.FORBID, claimed_verdict=Verdict.PERMIT
        )
        res = verify_verdict_binding(jwt, **_facts(Verdict.PERMIT))
        assert res.ok is False
        assert res.reason == "verdict_nonce_mismatch"

    def test_forged_inconsistent_token_is_accepted_as_no_verdict(self):
        # The forged token's hardware report_data says FORBID but its soft
        # eat_nonce says PERMIT — internally inconsistent. It is rejected
        # as PERMIT (verdict_nonce_mismatch, the report_data gate) AND as
        # FORBID (nonce_mismatch, the consistency gate): accepted as NO
        # verdict. eat_nonce can only ever fail-closed, never forge one.
        jwt = _forge_hollow_token(
            true_verdict=Verdict.FORBID, claimed_verdict=Verdict.PERMIT
        )
        as_permit = verify_verdict_binding(jwt, **_facts(Verdict.PERMIT))
        as_forbid = verify_verdict_binding(jwt, **_facts(Verdict.FORBID))
        assert as_permit.ok is False and as_permit.reason == "verdict_nonce_mismatch"
        assert as_forbid.ok is False and as_forbid.reason == "nonce_mismatch"


# --------------------------------------------------------------------------- #
# Fail-closed posture                                                         #
# --------------------------------------------------------------------------- #


class TestFailClosed:
    def test_missing_tdx_block_rejected(self):
        # A JWT with no tdx block cannot carry a report_data binding.
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        header_b64, payload_b64, _sig = jwt.split(".")
        import base64
        import json

        def _b64d(v):
            return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))

        def _b64e(v):
            return base64.urlsafe_b64encode(v).rstrip(b"=").decode("ascii")

        payload = json.loads(_b64d(payload_b64))
        payload.pop("tdx", None)
        tampered = (
            f"{header_b64}.{_b64e(json.dumps(payload, separators=(',', ':')).encode())}."
        )
        res = verify_verdict_binding(tampered, **_facts(Verdict.FORBID))
        assert res.ok is False and res.reason == "verdict_nonce_mismatch"

    def test_garbage_jwt_rejected(self):
        res = verify_verdict_binding("not-a-jwt", **_facts(Verdict.FORBID))
        assert res.ok is False and res.reason == "parse_error"

    def test_none_jwt_rejected(self):
        from types import SimpleNamespace

        res = verify_verdict_binding(
            SimpleNamespace(ita_jwt=None), **_facts(Verdict.FORBID)
        )
        assert res.ok is False and res.reason == "no_jwt"

    def test_test_mode_token_rejected_in_production(self, monkeypatch):
        # Bound report_data is correct, but an unsigned (alg=none) token
        # must be rejected by the base posture in production.
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "production")
        res = verify_verdict_binding(jwt, **_facts(Verdict.FORBID))
        assert res.ok is False
        assert res.reason == "test_mode_in_prod"

    def test_debuggable_td_rejected(self):
        # Correct binding, but a debuggable TD must fail the base posture.
        jwt = build_verdict_bound_test_jwt(**_facts(Verdict.FORBID))
        import base64
        import json

        header_b64, payload_b64, _sig = jwt.split(".")

        def _b64d(v):
            return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))

        def _b64e(v):
            return base64.urlsafe_b64encode(v).rstrip(b"=").decode("ascii")

        payload = json.loads(_b64d(payload_b64))
        payload["tdx"]["tdx_is_debuggable"] = True
        tampered = (
            f"{header_b64}.{_b64e(json.dumps(payload, separators=(',', ':')).encode())}."
        )
        res = verify_verdict_binding(tampered, **_facts(Verdict.FORBID))
        assert res.ok is False
        assert res.reason == "tdx_debuggable"


# --------------------------------------------------------------------------- #
# forgery = 0 over the suite                                                   #
# --------------------------------------------------------------------------- #


class TestForgeryRateIsZero:
    def test_no_mismatched_binding_ever_accepts(self):
        """Exhaustive grid: only the exact (verdict, policy, input, prev)
        tuple the token was built for may verify. Count every acceptance of
        a mismatched tuple; assert it is exactly zero."""
        policies = [POLICY_DIGEST, hashlib.sha256(b"pol-2").hexdigest()]
        inputs = [INPUT_HASH, hashlib.sha256(b"in-2").hexdigest()]
        prevs = [PREV_HASH, hashlib.sha256(b"prev-2").hexdigest(), None]

        forgeries_accepted = 0
        honest_accepted = 0
        total = 0

        for tv in ALL_VERDICTS:
            true_facts = _facts(tv)
            jwt = build_verdict_bound_test_jwt(**true_facts)
            for cv in ALL_VERDICTS:
                for pol in policies:
                    for inp in inputs:
                        for prev in prevs:
                            total += 1
                            claim = _facts(cv, policy=pol, inp=inp, prev=prev)
                            res = verify_verdict_binding(jwt, **claim)
                            is_honest = claim == true_facts
                            if is_honest:
                                assert res.ok is True
                                honest_accepted += 1
                            elif res.ok:
                                forgeries_accepted += 1

        assert forgeries_accepted == 0, (
            f"{forgeries_accepted} forged bindings accepted out of {total}"
        )
        # Exactly one honest tuple per built token (3 tokens).
        assert honest_accepted == 3
