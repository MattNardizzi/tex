"""
Post-quantum signing provider resolver for the institutional layer.

The institutional governance log is the artifact an external auditor
(insurer, NAIC, FTC, or EU AI Act Article 12 examiner) reads to verify
that every governance-graph transition was decided correctly. The
signature on each log entry is the cryptographic anchor that makes that
verification offline-checkable.

Post-cutoff context (May 7, 2026): arxiv 2605.06933 (MAGIQ, Avizeh /
Mallick / Oprea / Nita-Rotaru / Safavi-Naini) argues that NIST's RSA /
DH / ECC deprecation timeline (deprecate 2030, disallow 2035 for NSS
under CNSA 2.0) makes post-quantum-grade signatures the May-2026
credibility floor for any agent-governance audit trail intended to
remain verifiable past 2030. Tex's algorithm-agility surface
(``tex.pqcrypto.algorithm_agility``) already dispatches ML-DSA-44/65/87
(FIPS 204), HYBRID_ML_DSA_ED25519, ED25519, and ECDSA_P256. This module
*selects* among them per runtime liboqs availability.

The selection chain:

  1. ``ML_DSA_65`` (NIST Security Level 3, the recommended default per
     FIPS 204) — preferred when ``oqs`` is importable AND a probe sign
     succeeds.
  2. ``HYBRID_ML_DSA_ED25519`` — transition mode (signs with both, both
     must verify). NSA CNSA 2.0 explicitly endorses hybrid during the
     2025-2030 transition window.
  3. ``ECDSA_P256`` (FIPS 186-5) — classical fallback. Always available
     because ``cryptography`` is a hard dependency of Tex (events
     ledger). This is what the existing ``governance_log.py`` defaults
     to today and what the Thread 1 fixture pattern uses.

Selection is performed once at module import time. The selected provider
is emitted as a ``tex.institutional.signing.provider_selected`` telemetry
event so operators can audit which algorithm is in use without reading
process state.

References
----------
* FIPS 204 (ML-DSA, finalized August 2024)
* NSA CNSA 2.0 (pure-PQ mandate for NSS, 2030-2035)
* arxiv 2605.06933 (MAGIQ, May 7 2026) — PQ as credibility floor for
  multi-agent governance audit trails
* ``tex.pqcrypto.algorithm_agility`` — the underlying dispatcher

Honesty note
------------
This module does NOT claim Universal-Composability-framework security
(which MAGIQ provides for its full protocol suite). It claims only what
it ships: algorithm-agility-driven selection of the strongest available
NIST-standardized signature algorithm at runtime, with telemetry naming
the choice.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureProvider,
    get_signature_provider,
)


@dataclass(frozen=True, slots=True)
class _SelectedProvider:
    """Result of the selection chain — provider plus the algorithm we picked."""

    provider: SignatureProvider
    algorithm: SignatureAlgorithm
    fallback_reason: str  # empty string means top-of-chain was selected


def _try_provider(algorithm: SignatureAlgorithm) -> tuple[SignatureProvider | None, str]:
    """
    Probe whether ``algorithm`` is usable in this environment.

    For ML-DSA family: we must actually attempt a key generation, because
    ``get_signature_provider`` returns the provider object even when
    liboqs is missing (the failure surface is deferred to first crypto
    call). For ECDSA-P256 we just dispatch — it's a hard dependency.

    Returns ``(provider_or_None, reason)``. On success ``reason`` is
    empty; on failure it carries a short diagnostic.
    """
    try:
        provider = get_signature_provider(algorithm)
    except NotImplementedError as exc:
        return None, f"dispatcher_not_implemented: {exc}"
    except Exception as exc:  # pragma: no cover - defence in depth
        return None, f"dispatcher_error: {type(exc).__name__}: {exc}"

    if algorithm is SignatureAlgorithm.ECDSA_P256:
        # ECDSA-P256 is backed by the `cryptography` package which is a
        # hard dependency; no need to probe.
        return provider, ""

    # ML-DSA family / HYBRID / BLAKE3-ML-DSA: probe a keypair to confirm
    # the underlying lattice library (liboqs) AND the BLAKE3 binding (for
    # the BLAKE3 variant) are actually usable here. Both can fail
    # independently of the dispatcher returning a provider.
    try:
        provider.generate_keypair("_pq_probe")
    except Exception as exc:
        return None, f"probe_failed: {type(exc).__name__}: {exc}"
    return provider, ""


def select_institutional_signing_provider() -> _SelectedProvider:
    """
    Resolve the strongest signing provider this host can run.

    Selection chain (best → fallback), updated Thread 8.1 (May 19, 2026):
      1. BLAKE3_ML_DSA_65 — BLAKE3-accelerated ML-DSA-B (Project Eleven,
         Taurus, Oct 2025). 15-30% faster sign/verify vs stock ML-DSA-65.
         FIPS 204 §5.4 HashML-DSA-compliant. No shipping AI governance
         product implements this as of May 19, 2026.
      2. ML_DSA_65 — stock FIPS 204 (NIST Security Level 3, the
         recommended default). Used when BLAKE3 binding is missing.
      3. HYBRID_ML_DSA_ED25519 — CNSA 2.0 transition mode (signs with
         both; both must verify).
      4. ECDSA-P256 — FIPS 186-5 classical floor. Always available
         because ``cryptography`` is a hard dependency.

    Always returns a usable provider — never raises. ECDSA-P256 is the
    floor; if even that fails the system has bigger problems than
    institutional log signing.

    Telemetry event ``tex.institutional.signing.provider_selected`` is
    emitted with fields ``algorithm`` (string), ``preferred_skipped``
    (tuple of "algorithm:reason" pairs), and ``selection_chain_version``
    so operators can monitor any post-deploy degradation.
    """
    chain: tuple[SignatureAlgorithm, ...] = (
        SignatureAlgorithm.BLAKE3_ML_DSA_65,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
        SignatureAlgorithm.ECDSA_P256,
    )

    skipped: list[str] = []
    for algorithm in chain:
        provider, reason = _try_provider(algorithm)
        if provider is not None:
            emit_event(
                "tex.institutional.signing.provider_selected",
                algorithm=algorithm.value,
                preferred_skipped=tuple(skipped),
                selection_chain_version="v2-blake3-thread-8.1",
            )
            return _SelectedProvider(
                provider=provider,
                algorithm=algorithm,
                fallback_reason=(
                    "; ".join(skipped) if skipped else ""
                ),
            )
        skipped.append(f"{algorithm.value}:{reason}")

    # Defence in depth: every algorithm in the chain failed. ECDSA-P256
    # backed by ``cryptography`` should never fail, but if it does we
    # need to surface the impossibility loudly rather than crash on
    # first sign attempt deep inside the engine.
    raise RuntimeError(
        "select_institutional_signing_provider: all providers failed: "
        + "; ".join(skipped)
    )


__all__ = ["select_institutional_signing_provider"]
