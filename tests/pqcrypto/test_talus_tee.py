"""
Tests for tex.pqcrypto.talus_tee — 1-round-online threshold ML-DSA with
TEE attestation (TALUS-TEE per arxiv 2603.22109 v2, Mar 24 2026).

The cryptographic core is genuine Mithril running inside the TEE
coordinator. These tests cover:

- The attestation interface (RFC 9334 quote handling)
- Fail-closed default verifier (rejects everything unless explicit allow flag)
- Measurement pinning at verify time
- Attestation freshness window
- Public-key binding via SHA-256(pk) in report_data
- End-to-end sign → verify with both FIPS 204 and TALUS verifiers
- Native BCC+CEF path stubbed (raises NotImplementedError)

Tests requiring the Mithril native extension are skipped if it isn't
loadable.
"""

from __future__ import annotations

import hashlib
import os
import time

import pytest


def _native_available() -> bool:
    try:
        from tex.pqcrypto.threshold_ml_dsa import is_native_available
        return is_native_available()
    except Exception:
        return False


_NATIVE = _native_available()
_requires_native = pytest.mark.skipif(
    not _NATIVE,
    reason="Mithril native extension required for TALUS-TEE tests",
)


# --- Attestation interface tests --------------------------------------------


def test_tee_type_enum_values() -> None:
    from tex.pqcrypto.talus_tee import TeeType

    assert TeeType.SGX_DCAP.value == "intel-sgx-dcap"
    assert TeeType.TDX.value == "intel-tdx"
    assert TeeType.SEV_SNP.value == "amd-sev-snp"
    assert TeeType.NONE_TEST_ONLY.value == "none-test-only"


def test_attestation_quote_dataclass_fields() -> None:
    from tex.pqcrypto.talus_tee import AttestationQuote, TeeType

    q = AttestationQuote(
        tee_type=TeeType.SGX_DCAP,
        quote_bytes=b"\xab" * 16,
        measurement=b"m" * 32,
        report_data=b"r" * 64,
        nonce=b"n" * 32,
        timestamp=1234567890.0,
    )
    assert q.tee_type is TeeType.SGX_DCAP
    assert len(q.measurement) == 32
    assert q.timestamp == 1234567890.0


def test_default_verifier_rejects_production_tee_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a real verifier installed, SGX/TDX/SEV-SNP quotes must reject."""
    from tex.pqcrypto.talus_tee import (
        AttestationQuote,
        TeeType,
        _default_reject_verifier,
    )

    for tee_type in (TeeType.SGX_DCAP, TeeType.TDX, TeeType.SEV_SNP):
        q = AttestationQuote(
            tee_type=tee_type,
            quote_bytes=b"",
            measurement=b"x" * 32,
            report_data=b"x" * 64,
            nonce=b"x" * 32,
            timestamp=time.time(),
        )
        result = _default_reject_verifier(q)
        assert result.is_valid is False
        assert "no production attestation verifier installed" in result.reason


def test_default_verifier_rejects_none_test_only_without_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TEX_TALUS_ALLOW_INSECURE_TEE", raising=False)
    from tex.pqcrypto.talus_tee import (
        AttestationQuote,
        TeeType,
        _default_reject_verifier,
    )

    q = AttestationQuote(
        tee_type=TeeType.NONE_TEST_ONLY,
        quote_bytes=b"",
        measurement=b"x" * 32,
        report_data=b"x" * 64,
        nonce=b"x" * 32,
        timestamp=time.time(),
    )
    result = _default_reject_verifier(q)
    assert result.is_valid is False
    assert "TEX_TALUS_ALLOW_INSECURE_TEE=1" in result.reason


def test_default_verifier_accepts_none_test_only_with_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import (
        AttestationQuote,
        TeeType,
        _default_reject_verifier,
    )

    q = AttestationQuote(
        tee_type=TeeType.NONE_TEST_ONLY,
        quote_bytes=b"",
        measurement=b"\x42" * 32,
        report_data=b"x" * 64,
        nonce=b"x" * 32,
        timestamp=time.time(),
    )
    result = _default_reject_verifier(q)
    assert result.is_valid is True
    assert result.measurement == b"\x42" * 32


def test_install_attestation_verifier_replaces_default() -> None:
    from tex.pqcrypto.talus_tee import (
        AttestationQuote,
        AttestationVerificationResult,
        TeeType,
        _resolve_verifier,
        install_attestation_verifier,
    )

    captured: dict[str, object] = {}

    def fake_sgx(q: AttestationQuote) -> AttestationVerificationResult:
        captured["q"] = q
        return AttestationVerificationResult(
            is_valid=True, reason="fake-sgx-ok", measurement=q.measurement,
            measured_at=q.timestamp,
        )

    install_attestation_verifier(TeeType.SGX_DCAP, fake_sgx)
    resolver = _resolve_verifier(TeeType.SGX_DCAP)
    test_q = AttestationQuote(
        tee_type=TeeType.SGX_DCAP, quote_bytes=b"", measurement=b"x" * 32,
        report_data=b"x" * 64, nonce=b"x" * 32, timestamp=time.time(),
    )
    result = resolver(test_q)
    assert result.is_valid is True
    assert result.reason == "fake-sgx-ok"
    assert captured["q"] is test_q


# --- TalusTeeSdk construction tests ----------------------------------------


@_requires_native
def test_talus_sdk_requires_allow_insecure_flag_for_test_constructor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TEX_TALUS_ALLOW_INSECURE_TEE", raising=False)
    from tex.pqcrypto.talus_tee import TalusTeeSdk
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    sdk = distributed_keygen(t=2, n=3)
    with pytest.raises(RuntimeError, match="TEX_TALUS_ALLOW_INSECURE_TEE=1"):
        TalusTeeSdk.test_only_no_attestation(sdk)


@_requires_native
def test_talus_sdk_constructs_with_insecure_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk, TeeType
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    assert talus.public_key == mithril.public_key
    assert len(talus.measurement) == 32


@_requires_native
def test_talus_sdk_rejects_quote_without_pk_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Per TALUS-TEE §6, the enclave attestation must bind to the threshold
    public key (SHA-256(pk) in the first 32 bytes of report_data). A quote
    that omits or misencodes this binding must be rejected.
    """
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import (
        AttestationQuote,
        TalusTeeSdk,
        TeeType,
    )
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    # Quote with WRONG report_data — does not bind to pk
    bad_quote = AttestationQuote(
        tee_type=TeeType.NONE_TEST_ONLY,
        quote_bytes=b"",
        measurement=b"\x33" * 32,
        report_data=b"\x00" * 64,  # not SHA-256(pk)
        nonce=os.urandom(32),
        timestamp=time.time(),
    )
    with pytest.raises(RuntimeError, match="report_data does not bind"):
        TalusTeeSdk(
            mithril_sdk=mithril,
            tee_type=TeeType.NONE_TEST_ONLY,
            initial_quote=bad_quote,
        )


# --- TALUS-TEE end-to-end signing ------------------------------------------


@_requires_native
def test_talus_online_sign_produces_fips204_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk, verify_talus_signature
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, verify_fips204

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    msg = b"TALUS-TEE 1-round online signing"
    talus_sig = talus.online_sign([0, 1], msg)

    # FIPS 204 ML-DSA-44 size
    assert len(talus_sig.signature) == 2420
    # Verifies under the standard FIPS 204 verifier
    assert verify_fips204(mithril.public_key, msg, talus_sig.signature)
    # Verifies under the TALUS verifier (no measurement pinning)
    assert verify_talus_signature(talus_sig, msg)
    # And under the measurement-pinned variant
    assert verify_talus_signature(talus_sig, msg, talus.measurement)


@_requires_native
def test_talus_verify_rejects_wrong_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk, verify_talus_signature
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    talus_sig = talus.online_sign([0, 1], b"m")
    wrong_measurement = hashlib.sha256(b"different-enclave").digest()
    assert verify_talus_signature(talus_sig, b"m", wrong_measurement) is False


@_requires_native
def test_talus_verify_rejects_tampered_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk, verify_talus_signature
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    talus_sig = talus.online_sign([0, 1], b"original")
    assert verify_talus_signature(talus_sig, b"tampered") is False


@_requires_native
def test_talus_native_bcc_path_raises_not_implemented(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Setting TEX_TALUS_NATIVE_BCC=1 must raise NotImplementedError until
    the TALUS paper authors release reference code (the paper has no
    public implementation as of May 20, 2026).
    """
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    monkeypatch.setenv("TEX_TALUS_NATIVE_BCC", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    with pytest.raises(NotImplementedError, match="BCC\\+CEF"):
        talus.online_sign([0, 1], b"m")


@_requires_native
def test_talus_signature_carries_attestation_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    from tex.pqcrypto.talus_tee import TalusTeeSdk, TeeType
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    sig = talus.online_sign([0, 1], b"m")
    assert sig.tee_type is TeeType.NONE_TEST_ONLY
    assert sig.attestation_measurement == talus.measurement
    assert sig.public_key == mithril.public_key
    assert "mithril-eprint-2026-013" in sig.scheme


@_requires_native
def test_talus_freshness_check_rejects_stale_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A long-running SDK whose attestation has aged past
    ``TEX_TALUS_FRESHNESS_SECONDS`` must refuse to sign.
    """
    monkeypatch.setenv("TEX_TALUS_ALLOW_INSECURE_TEE", "1")
    # 60s minimum freshness
    monkeypatch.setenv("TEX_TALUS_FRESHNESS_SECONDS", "60")
    from tex.pqcrypto.talus_tee import TalusTeeSdk
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    mithril = distributed_keygen(t=2, n=3)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    # Manually rewind attestation timestamp to simulate aging.
    object.__setattr__(talus, "_attestation_timestamp", time.time() - 7200)
    with pytest.raises(RuntimeError, match="stale"):
        talus.online_sign([0, 1], b"m")
