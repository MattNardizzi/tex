# NOTES — L2 TEE attestation: real signed token (track/w3-l2-attestation)

## What changed

L2 (the verdict-bound composite attestation) no longer rides the **test-mode
`alg=none` JWT** path. The capstone now composes a **genuinely signed** Intel
Trust Authority–shaped composite token (a real JWS), and `verify_capstone`
reaches `green` on it through the **real signature path** — not the
`TEX_TEE_ATTESTATION_MODE=test` bypass.

This is standard, off-the-shelf confidential-computing verification (an ITA
composite token is a JWS; you pin the attester's signing key out-of-band and
check the signature). It is **not** a Tex novelty. Tex's value is the
integration — folding the categorical verdict into the TDX `report_data` and
sealing the whole thing into one replayable manifest.

### Concretely

- `tex/tee/attestation_client.py`
  - `build_signed_composite_jwt(...)` — builds a real JWS (`alg != none`,
    default **PS384**, ITA's production algorithm), signs `header.payload`,
    and does **not** set `x-tex-test-mode`. Shares the exact ITA claim shape
    with the test-mode builder via `_composite_claims(...)`.
  - `_sign_signing_input(...)` — signer symmetric with the existing
    `_verify_signature(...)` (PS384/RS256 over RSA, ES256/ES384 over EC).
  - `generate_standin_ita_keypair(...)` — generates a **stand-in** ITA key.
  - The verifier (`verify_attestation` / `_verify_signature`) was **not
    changed** — it already supported PS384/RS256/ES256/ES384 (+ ML-DSA/hybrid).
- `tex/tee/verdict_binding.py`
  - `build_verdict_bound_signed_jwt(...)` — the signed twin of
    `build_verdict_bound_test_jwt(...)`.
  - `VerdictBindingResult` now reports `signature_alg` and a posture-
    independent `signature_verified` (computed by re-checking the JWS against
    the pinned key), so the manifest records the verifier's own output.
- `tex/capstone/{compose,verify,manifest,tamper,flow}.py`
  - Compose generates a stand-in ITA keypair, signs the L2 token, and verifies
    it **under a production posture** (test mode unset) against the pinned
    public key — failing closed if the signature does not validate.
  - The stand-in **public** key is pinned out-of-band in `pins.json` /
    `CapstonePins.ita_public_key_pem` and its digest is sealed into the
    manifest (`PinDigests.ita_public_key_pem_sha256`), exactly like the
    ledger / evidence / voice / log keys.
  - L2 status: `green`, with machine-readable halves
    `{"signature": "green", "hardware_measurement": "runtime_dependent"}`.
  - New tamper-matrix row `forged L2 attestation signature` — a flipped
    signature byte is caught by `L2.signature_invalid`, proving the signature
    is load-bearing (no `alg=none` fallback).
- The test-mode path (`build_test_mode_composite_jwt`,
  `build_verdict_bound_test_jwt`, the `alg=none` verifier gate) was **kept**
  intact for local dev; the capstone simply no longer depends on it.

## What is now REAL (verified by running)

- The L2 token is a real JWS (`alg=PS384`), signed with an asymmetric key.
- Verification goes through the real signature path under a **production**
  posture (`TEX_TEE_ATTESTATION_MODE` unset) — `green` requires
  `l2.ok and not l2.test_mode and l2.signature_verified`.
- Fail-closed, demonstrated: a **wrong** pinned key, **no** pinned key, and a
  **flipped signature byte** each yield `signature_invalid` (unit test
  `test_l2_fails_closed_on_wrong_ita_key`, tamper row
  `tamper_jwt_signature_forged`, and the signed-path smoke check).
- Over-claiming is unconstructible: the manifest validator refuses L2 unless
  `signature_verified=True`, `test_mode=False`, `alg != none`, and the
  hardware half is `runtime_dependent` (tests `_l2_hardware_promoted`,
  `_l2_alg_none`, `_l2_signature_unverified`).

## Honest RESIDUAL — what is still runtime-dependent (`research-early`)

The signature proves **authorship by the holder of the pinned key**. It does
**not** prove that real Intel TDX hardware executed the guardrail. Two
distinct residuals, both labeled in code, manifest caveats, and the demo:

1. **Stand-in key, not Intel's.** Offline, Tex generates an ephemeral
   stand-in keypair and pins its public half. In production the relying party
   pins **Intel's published ITA public key** via `TEX_ITA_PUBLIC_KEY_PEM`
   (or `TEX_ITA_JWKS_PATH`) and Intel holds the private half. Same code path,
   different key — the offline signature attests "the demo composer authored
   this token," the production signature attests "Intel ITA did."
2. **Stub measurements + no hardware-rooted `report_data`.** Off a real TDX
   host, `collect_tdx_evidence`/`collect_gpu_evidence` return dev-stub blobs
   (`is_dev_mode=True`), so `tdx_mrtd`/`tdx_rtmr*` are stub values and the
   verdict-bound `report_data` is **not** signed by a TDX quoting enclave.
   Real MRTD/RTMR and a quote that signs `report_data` need an Intel TDX
   confidential VM at runtime (the M0c probe `tex/tee/_mode_probe.py` reports
   honestly that this host is absent).

So: the **signature path is production-grade and fail-closed today**; the
**hardware root of trust is RUNTIME-DEPENDENT** on Intel TDX + Intel's ITA
key. The L2 manifest entry says exactly this (`status=green`, `halves`,
`runtime_dependent=True`, three verbatim caveats).

## How to run / verify

```sh
# The capstone demo — exit 0 on success (L2 green via the real signature).
PYTHONPATH=src python scripts/capstone_demo.py

# Targeted suites
PYTHONPATH=src python -m pytest tests/tee/ tests/frontier_thread_12_tee/ -q
PYTHONPATH=src python -m pytest tests/capstone/ -q
```

## Promotion path (to drop the residual)

Run on an Intel TDX confidential VM with the ITA Python client installed
(`is_tdx_capable()` true), submit real CPU+GPU evidence via
`compose_attestation`/`_request_ita_composite_token`, and pin **Intel's**
ITA key via `TEX_ITA_PUBLIC_KEY_PEM`. The verifier and the verdict-binding
logic are unchanged; only the key identity and the measurement source move
from stand-in/stub to real — at which point the `hardware_measurement` half
is promotable off `runtime_dependent`.
