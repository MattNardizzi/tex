"""
L2 — Proof-of-Guardrail: verdict-bound composite attestation.

What this adds (the narrow, earnable claim)
-------------------------------------------
Existing TEE code (``tee/attestation_client.py``) attests that *some*
guardrail process ran inside a confidential VM and binds the attestation
nonce to a *decision identifier* (``decision_bound_nonce``, CrossGuard
pattern). That proves **proof-of-execution**, not **proof-of-verdict**:
nothing in the signed quote says *which* PERMIT/ABSTAIN/FORBID came out,
under *which* policy, over *which* input.

This module folds the **categorical verdict** + **policy-bundle digest**
+ **decision-input hash** + **prior ledger hash** into the composite
attestation's own ``report_data`` nonce, so a host-level adversary who
flips the verdict cannot produce a verifier-accepted quote. The verifier
recomputes the expected ``report_data`` from those four sealed facts and
checks it against the **TDX ``report_data``** carried in the quote — the
one field the TDX quoting hardware signs.

Prior art / novelty (re-verify before any customer-facing claim)
----------------------------------------------------------------
Proof-of-Guardrail (arXiv 2603.05786) attests the guardrail **code**;
the open problem it names is "proof-of-execution != proof-of-guardrail
**decision**." Binding the *decision* into ``report_data`` is the narrow
delta here. Citation status: ``UNVERIFIED-FROM-MEMORY`` — not re-fetched
this session; the capability rests on the green benchmark in
``tests/tee/test_verdict_binding.py`` (verdict-swap ⇒ ``ok=False``,
forgery=0 over the suite), never on the citation.

THE BUG THIS FIXES (load-bearing)
---------------------------------
A verifier that checks the **soft echo** nonce — ``nvgpu.eat_nonce`` /
top-level ``eat_nonce`` / ``verifier_nonce`` (what ``attestation_client.
_nonce_matches`` consults) — gives a **hollow** binding: those are
plaintext JSON fields, not covered by the TDX quote's signature over
``report_data``. A host that re-wraps a captured token can set
``eat_nonce`` to any verdict it likes. So this verifier gates on
``tdx.tdx_report_data`` (which mirrors the ``user_data`` submitted to the
TDX quoting enclave), **not** ``eat_nonce``. The regression test
``test_hollow_eat_nonce_binding_is_caught`` shows the old eat_nonce check
is fooled by exactly this forgery while this verifier rejects it.

Maturity
--------
``research-early``. In ``TEX_TEE_ATTESTATION_MODE=test`` the composite
JWT is unsigned (``alg=none``): we exercise **verifier logic** (which
field it consults, monotone fail-closed posture), NOT cryptographic
unforgeability. Unforgeability of ``report_data`` is **RUNTIME-DEPENDENT**
on a real Intel TDX confidential VM whose quote signs ``report_data`` and
on a pinned ITA signing key — neither is present in CI. The name yields
to the property: this is "verdict-bound attestation *logic*," promoted to
a hardware guarantee only on real TDX.

Fail-closed
-----------
Any parse failure, missing TDX block, missing/mismatched ``report_data``,
or failed base attestation posture (debuggable TD, out-of-date TCB, GPU
sub-claim failure, bad signature in production) yields ``ok=False`` with a
stable reason code. Uncertainty resolves to rejection, never acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from tex.domain.verdict import Verdict
from tex.tee.attestation_client import (
    ExpectedMeasurements,
    _parse_jwt,
    build_test_mode_composite_jwt,
    verify_attestation,
)
from tex.tee.composite import CompositeVerificationResult
from tex.tee.h100_attestation import collect_gpu_evidence
from tex.tee.tdx_attestation import TdxEvidence, collect_tdx_evidence


__all__ = [
    "verdict_bound_nonce",
    "recompute_expected_nonce",
    "verify_verdict_binding",
    "report_data_for_nonce",
    "build_verdict_bound_test_jwt",
    "VerdictBindingResult",
]


# Domain-separation prefix. Distinct from ``decision_bound_nonce``'s
# ``"tex|"`` prefix so a decision nonce and a verdict nonce can never
# collide even on identical identifiers. Version it so a future binding
# scheme is unambiguous in the sealed history.
_DOMAIN = "tex-poguard"
_VERSION = "v1"


# --------------------------------------------------------------------------- #
# Nonce derivation (mirrors decision_bound_nonce: SHA-256[:32])               #
# --------------------------------------------------------------------------- #


def _normalize_verdict(sealed_verdict: Verdict | str) -> str:
    """Canonicalize to one of PERMIT/ABSTAIN/FORBID, else raise.

    A blank or unknown verdict is a programming error at the call site,
    not a verification failure — raise rather than silently bind to a
    bogus category (which would let a typo masquerade as a real verdict).
    """
    if isinstance(sealed_verdict, Verdict):
        return sealed_verdict.value
    if not isinstance(sealed_verdict, str) or not sealed_verdict.strip():
        raise ValueError("sealed_verdict must be a Verdict or non-blank string")
    return Verdict.from_str(sealed_verdict).value


def _require_hex(value: str, field: str) -> str:
    """Require a non-blank lowercase-able hex string (a digest)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-blank hex digest")
    stripped = value.strip().lower()
    try:
        bytes.fromhex(stripped)
    except ValueError as exc:
        raise ValueError(f"{field} must be hex, got {value!r}") from exc
    return stripped


def verdict_bound_nonce(
    *,
    sealed_verdict: Verdict | str,
    policy_bundle_digest: str,
    decision_input_sha256: str,
    ledger_prev_hash: str | None,
) -> str:
    """Derive the 32-hex nonce that binds a verdict to its guardrail.

    Mirrors ``decision_bound_nonce`` (``attestation_client.py``): a
    SHA-256 over a domain-separated, ``|``-delimited material string,
    truncated to the first 32 hex chars (the upper 16 bytes), exactly as
    the CrossGuard decision nonce does. The four folded facts are the
    *content* of the guardrail outcome:

      * ``sealed_verdict``        — the categorical PERMIT/ABSTAIN/FORBID,
      * ``policy_bundle_digest``  — *which* policy produced it,
      * ``decision_input_sha256`` — *over which* input,
      * ``ledger_prev_hash``      — the prior sealed-ledger head (``None``
        at genesis), chaining the attestation to the decision history so a
        replayed quote cannot be lifted onto a different ledger position.

    This 32-hex value is the *upper half* of the 64-byte ITA
    ``report_data``; see :func:`report_data_for_nonce`.
    """
    verdict = _normalize_verdict(sealed_verdict)
    policy = _require_hex(policy_bundle_digest, "policy_bundle_digest")
    decision_input = _require_hex(decision_input_sha256, "decision_input_sha256")
    prev = "" if not ledger_prev_hash else _require_hex(ledger_prev_hash, "ledger_prev_hash")

    material = "|".join(
        (_DOMAIN, _VERSION, verdict, policy, decision_input, prev)
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def report_data_for_nonce(nonce_hex: str) -> bytes:
    """Expand a 32-hex nonce into the 64-byte ITA ``report_data``.

    Mirrors ``compose_attestation`` (``attestation_client.py``) and the
    ITA convention documented in ``tdx_attestation.fresh_user_data``: the
    upper 32 bytes are the caller nonce; the lower 32 bytes are
    ``SHA-256(upper)``. The TDX quoting enclave signs these 64 bytes as
    ``report_data``; the JWT surfaces them as ``tdx.tdx_report_data``.
    """
    upper = bytes.fromhex(nonce_hex.ljust(64, "0"))[:32]
    lower = hashlib.sha256(upper).digest()
    return upper + lower


def recompute_expected_nonce(
    *,
    sealed_verdict: Verdict | str,
    policy_bundle_digest: str,
    decision_input_sha256: str,
    ledger_prev_hash: str | None,
) -> str:
    """Verifier-side: the expected ``tdx_report_data`` hex (128 chars).

    Recomputes the 32-hex :func:`verdict_bound_nonce` from the four
    sealed facts and expands it via :func:`report_data_for_nonce` into the
    full 64-byte ``report_data`` (128 hex chars) that an honest quote must
    carry in ``tdx.tdx_report_data``. This is the value
    :func:`verify_verdict_binding` compares against — never ``eat_nonce``.
    """
    nonce = verdict_bound_nonce(
        sealed_verdict=sealed_verdict,
        policy_bundle_digest=policy_bundle_digest,
        decision_input_sha256=decision_input_sha256,
        ledger_prev_hash=ledger_prev_hash,
    )
    return report_data_for_nonce(nonce).hex()


# --------------------------------------------------------------------------- #
# Result                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class VerdictBindingResult:
    """Outcome of verifying a verdict-bound attestation. Fail-closed."""

    ok: bool
    reason: str
    bound_verdict: str | None = None
    expected_report_data: str | None = None
    observed_report_data: str | None = None
    test_mode: bool = False
    attestation: CompositeVerificationResult | None = None


def _vb_fail(
    reason: str,
    *,
    bound_verdict: str | None = None,
    expected_report_data: str | None = None,
    observed_report_data: str | None = None,
    attestation: CompositeVerificationResult | None = None,
) -> VerdictBindingResult:
    return VerdictBindingResult(
        ok=False,
        reason=reason,
        bound_verdict=bound_verdict,
        expected_report_data=expected_report_data,
        observed_report_data=observed_report_data,
        test_mode=False,
        attestation=attestation,
    )


# --------------------------------------------------------------------------- #
# Verifier                                                                    #
# --------------------------------------------------------------------------- #


def _jwt_from(envelope: Any) -> str | None:
    """Accept a raw JWT string or anything carrying ``.ita_jwt`` (e.g.
    ``CompositeAttestationEnvelope``)."""
    if isinstance(envelope, str):
        return envelope
    jwt = getattr(envelope, "ita_jwt", None)
    return jwt if isinstance(jwt, str) else None


def verify_verdict_binding(
    envelope: Any,
    *,
    sealed_verdict: Verdict | str,
    policy_bundle_digest: str,
    decision_input_sha256: str,
    ledger_prev_hash: str | None,
    expected_issuer: str | None = None,
    expected: ExpectedMeasurements | None = None,
) -> VerdictBindingResult:
    """Verify that a composite attestation is bound to exactly this verdict.

    Gates, in order, fail-closed:

      1. Resolve + parse the JWT (envelope or raw string).
      2. **Authoritative binding** — recompute the expected
         ``report_data`` from the four sealed facts and compare it,
         constant-time, against ``tdx.tdx_report_data``. A mismatch (the
         verdict-swap adversary, or a hollow ``eat_nonce`` forgery) ⇒
         ``ok=False, reason='verdict_nonce_mismatch'``. **This is the bug
         fix: it never consults ``eat_nonce``.**
      3. **Base posture** — delegate to ``verify_attestation`` for the
         hardware fail-closed checks (issuer, debuggable TD, TCB status,
         GPU sub-claim, signature in production, expiry).

    On ``eat_nonce`` (the demotion, not a re-introduction of the bug):
    ``verify_attestation`` still runs its legacy ``eat_nonce`` gate. Here
    that gate can **only fail-closed** — it can never *select* or *forge*
    a verdict, because step 2 already decided the binding against the
    hardware-rooted ``report_data`` and runs first. So ``eat_nonce`` is
    demoted from "binding authority" (the hollow bug) to "internal
    consistency check": a token whose soft ``eat_nonce`` contradicts its
    hardware ``report_data`` is accepted as **no** verdict (monotone-safe;
    a signal only lowers).

    Scope/SELF-AUDIT (``research-early``): this wave is test-mode.
    ``build_verdict_bound_test_jwt`` sets ``eat_nonce`` == the verdict
    nonce, so the step-3 gate is satisfied for honest tokens. A production
    verdict-aware composer must do the same (or ``attestation_client``'s
    nonce gate must be made ``report_data``-aware); until a real TDX VM +
    pinned ITA key exist that is ``RUNTIME-DEPENDENT``. ``eat_nonce`` is
    never trusted to choose a verdict at any maturity.

    ``ok=True`` requires *both* the report_data binding and the base
    posture to pass.
    """
    jwt = _jwt_from(envelope)
    if jwt is None:
        return _vb_fail("no_jwt")

    try:
        _header, payload, _signing_input, _signature = _parse_jwt(jwt)
    except Exception:  # noqa: BLE001
        return _vb_fail("parse_error")

    verdict = _normalize_verdict(sealed_verdict)
    expected_report_data = recompute_expected_nonce(
        sealed_verdict=verdict,
        policy_bundle_digest=policy_bundle_digest,
        decision_input_sha256=decision_input_sha256,
        ledger_prev_hash=ledger_prev_hash,
    )

    # --- Step 2: authoritative, hardware-rooted binding ------------------- #
    tdx_block = payload.get("tdx") or {}
    observed = tdx_block.get("tdx_report_data")
    observed_norm = observed.lower() if isinstance(observed, str) else None
    if observed_norm is None or not hmac.compare_digest(
        observed_norm, expected_report_data
    ):
        return _vb_fail(
            "verdict_nonce_mismatch",
            bound_verdict=verdict,
            expected_report_data=expected_report_data,
            observed_report_data=observed_norm,
        )

    # --- Step 3: base hardware posture ----------------------------------- #
    base = verify_attestation(
        jwt,
        expected_issuer=expected_issuer,
        expected_nonce=verdict_bound_nonce(
            sealed_verdict=verdict,
            policy_bundle_digest=policy_bundle_digest,
            decision_input_sha256=decision_input_sha256,
            ledger_prev_hash=ledger_prev_hash,
        ),
        expected=expected,
    )
    if not base.ok:
        return _vb_fail(
            base.reason,
            bound_verdict=verdict,
            expected_report_data=expected_report_data,
            observed_report_data=observed_norm,
            attestation=base,
        )

    return VerdictBindingResult(
        ok=True,
        reason=base.reason,
        bound_verdict=verdict,
        expected_report_data=expected_report_data,
        observed_report_data=observed_norm,
        test_mode=base.test_mode,
        attestation=base,
    )


# --------------------------------------------------------------------------- #
# Test-mode / seam convenience builder                                        #
# --------------------------------------------------------------------------- #


def build_verdict_bound_test_jwt(
    *,
    sealed_verdict: Verdict | str,
    policy_bundle_digest: str,
    decision_input_sha256: str,
    ledger_prev_hash: str | None,
    ttl_seconds: int = 3600,
) -> str:
    """Build a deterministic test-mode composite JWT bound to a verdict.

    For ``TEX_TEE_ATTESTATION_MODE=test`` and the ``commands/
    evaluate_action`` seam's opt-in test path. Sets the dev TDX
    ``user_data`` to the verdict's 64-byte ``report_data`` so an honest
    composer's quote carries the binding the verifier expects. Mirrors the
    upper/lower construction in ``compose_attestation``; produces an
    unsigned (``alg=none``) token — never a production attestation.
    """
    nonce = verdict_bound_nonce(
        sealed_verdict=sealed_verdict,
        policy_bundle_digest=policy_bundle_digest,
        decision_input_sha256=decision_input_sha256,
        ledger_prev_hash=ledger_prev_hash,
    )
    report_data = report_data_for_nonce(nonce)

    tdx_ev: TdxEvidence = collect_tdx_evidence(user_data=report_data)
    gpu_ev = collect_gpu_evidence(nonce=report_data)

    return build_test_mode_composite_jwt(
        tdx_evidence=tdx_ev,
        gpu_evidence=gpu_ev,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
    )
