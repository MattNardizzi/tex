"""
PQ-maturity-gated live signer — Wave 2 leap **L10** (``track/wave2-pqlive``).

The narrow claim this module earns (and nothing more)
----------------------------------------------------
Make the **runtime PQ-maturity of Tex's signer a first-class governance signal
that can only ever LOWER a verdict.** When no production-durable ML-DSA backend
is wired, the signer cannot make a post-quantum non-repudiation guarantee, so any
request that *asserts* a PQ-non-repudiation claim resolves to **ABSTAIN** — never
PERMIT. The fact "PQ-durable=false" is surfaced on the routed result and sealed
into the decision it lowered.

This is the L10 *on-ramp* (verdict ``theory-ahead`` in ``ROADMAP.md``). The
North-Star ceiling — threshold/quorum ML-DSA with a formally-earned
Q-Non-Equivocation property (arXiv:2512.00110) — is *not* built here. What is
built and tested here is: (1) a fail-closed maturity probe, (2) a monotone-
lowering ABSTAIN signal gated on that probe, and (3) a real composite
ML-DSA-87 + ECDSA-P384 chain-head sign/verify round-trip, to prove the PQ crypto
is real on this box and not a stand-in.

THE NANOZK TRAP — the #1 risk, and how this module defuses it
-------------------------------------------------------------
The reputation-fatal failure mode (the ``nanozk`` lesson, see CLAUDE.md) is to
label a non-real backend "durable" because *something* on the box can do
ML-DSA. This module is built so that cannot happen:

  * :func:`probe_backend` is a pure function of :func:`ml_dsa.active_backend_id`
    — the id of the backend the **live signer actually dispatches to**. Nothing
    else can raise the maturity.
  * It is **fail-closed by allow-list**: only ids in :data:`_DURABLE_BACKEND_IDS`
    map to DURABLE and only :data:`_RESEARCH_ONLY_BACKEND_IDS` map to
    RESEARCH_ONLY. *Every other value — unknown id, empty string, or ``None`` —
    maps to* :attr:`SignerDurability.NONE`. A backend nobody has reviewed is
    untrusted by construction.
  * The OpenSSL-3.5 CLI shim below (:func:`composite_sign_chain_head`) is a real
    ML-DSA-87 backend, **but it is deliberately NOT the live signer and NOT wired
    into** :func:`ml_dsa.active_backend_id`. Its existence therefore does **not**
    move :func:`probe_backend` off NONE. It exists only to *earn the benchmark*
    that the composite PQ/T crypto is real here — a feasibility proof, never a
    live-maturity upgrade. The regression test
    ``test_cli_shim_does_not_raise_live_maturity`` pins exactly this.

In-environment now: ``requirements.txt`` pins ``cryptography>=48.0.0``, which ships
the native ML-DSA module (FIPS 204 via OpenSSL 3.5), so
:func:`ml_dsa.active_backend_id` returns ``"pyca-cryptography-native"`` ⇒ maturity
DURABLE ⇒ a PQ-non-repudiation claim is HONORED (the signal does not lower the
verdict). On a box without that backend the id is ``None`` ⇒ maturity NONE ⇒ the
claim ABSTAINs. The OpenSSL 3.5 CLI also signs ML-DSA-87, which the round-trip
below exercises.

The capability-vs-use line — READ before reading DURABLE as "PQ-signed"
-----------------------------------------------------------------------
:func:`probe_backend` reports whether a production-durable ML-DSA backend is
**available to the signer** — a capability. It does NOT assert that the live
evidence chain is post-quantum signed: the live ledger signer is ECDSA-P256
(``provenance/ledger.py``). So a DURABLE probe HONORS the claim (the maturity
signal does not lower the verdict) while the bytes actually sealed on the decision
remain ECDSA-P256. Honoring is a statement about backend maturity, never a PQ
property of this epoch's signatures; wiring the live ledger to emit an ML-DSA (or
composite) signature is the separate, larger step this leap does not take.

What a green benchmark here does and does not prove
---------------------------------------------------
  * It proves the maturity probe is fail-closed and allow-list-gated, the ABSTAIN
    signal is monotone-lowering (PERMIT→ABSTAIN only), and that real composite
    ML-DSA-87 + ECDSA-P384 signing/verification runs on this host.
  * It does **not** prove the live evidence chain is post-quantum — see the
    capability-vs-use line above. Maturity of this leap: ``research-early`` until
    its benchmark is a CI default.

Fail-closed to today's behaviour
--------------------------------
  * Absent the opt-in ``request.metadata["pq_non_repudiation"]`` claim, the hook
    is a zero-cost no-op: the routed result is returned byte-for-byte unchanged.
  * The hook only ever demotes a PERMIT to ABSTAIN; FORBID/ABSTAIN pass through
    untouched, and it never fires the deterministic structural floor.
  * Sealing the PQ-durable fact never raises into the request path (fail-closed,
    mirrors ``provenance/decision_seal.seal_decision``).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from tex.domain.evidence import EvidenceMaturity
from tex.pqcrypto import ml_dsa
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind

_logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 1. The maturity ladder + the fail-closed probe (the heart of L10)
# ─────────────────────────────────────────────────────────────────────────────


class SignerDurability(StrEnum):
    """Runtime PQ-maturity of the live signer, worst → best for safety ordering.

    The ordering matters: only :attr:`DURABLE` may *honor* a PQ-non-repudiation
    claim. Everything below it cannot, and so must lower the verdict to ABSTAIN.
    """

    NONE = "none"  # no recognized PQ backend → PQ non-repudiation is unprovable
    RESEARCH_ONLY = "research_only"  # real ML-DSA, research maturity (liboqs)
    DURABLE = "durable"  # FIPS-validated native / KMS-backed ML-DSA


# Allow-list of backend ids that count as production-durable. ``active_backend_id``
# returns ``"pyca-cryptography-native"`` for the pyca >= 48 / OpenSSL >= 3.5 native
# path (the one AWS KMS, MS AD CS and the kernel module-signing patches ship). A
# KMS-backed backend id (e.g. an AWS-KMS ML-DSA provider) JOINS this set *only when
# such a backend is wired and emits a recognized id* — it is not pre-populated with
# a phantom id, because a string nobody emits would be dead surface, not durability.
_DURABLE_BACKEND_IDS: frozenset[str] = frozenset({"pyca-cryptography-native"})

# Real ML-DSA via liboqs, but treated as research-maturity: the PQC libraries are
# far younger than RSA/ECDSA and carry the side-channel / implementation-flaw risk
# that BSI/ANSSI cite when mandating composites (see composite_ml_dsa.py). Real, but
# not yet trusted to *honor* a non-repudiation guarantee on its own.
_RESEARCH_ONLY_BACKEND_IDS: frozenset[str] = frozenset({"liboqs"})


def durability_for_backend_id(backend_id: str | None) -> SignerDurability:
    """Map a backend id to a maturity — **fail-closed**.

    Pure and total. Only explicitly allow-listed ids are recognized; *anything
    else* — ``None``, ``""``, or an unknown/typo'd/future id — maps to
    :attr:`SignerDurability.NONE`. This is the single chokepoint that makes the
    nanozk trap unreachable: a backend that has not been reviewed and allow-listed
    cannot earn DURABLE no matter what it is named.
    """
    if backend_id in _DURABLE_BACKEND_IDS:
        return SignerDurability.DURABLE
    if backend_id in _RESEARCH_ONLY_BACKEND_IDS:
        return SignerDurability.RESEARCH_ONLY
    return SignerDurability.NONE


def probe_backend() -> SignerDurability:
    """Probe the **live** signer's PQ maturity from the backend it dispatches to.

    Reads :func:`tex.pqcrypto.ml_dsa.active_backend_id` — the id of the backend
    the live ``MlDsaProvider`` actually uses — and maps it fail-closed via
    :func:`durability_for_backend_id`. With ``cryptography>=48`` (requirements-
    pinned) the id is ``"pyca-cryptography-native"`` ⇒ :attr:`SignerDurability.DURABLE`;
    on a box with no recognized backend the id is ``None`` ⇒
    :attr:`SignerDurability.NONE`.
    """
    return durability_for_backend_id(ml_dsa.active_backend_id())


# ─────────────────────────────────────────────────────────────────────────────
# 2. The assessment + the monotone-lowering ABSTAIN signal
# ─────────────────────────────────────────────────────────────────────────────

# Opt-in metadata key: a request asserts a PQ-non-repudiation claim by setting a
# truthy ``request.metadata["pq_non_repudiation"]`` (mirrors the struct track's
# opt-in metadata keys — zero-cost no-op when absent).
PQ_CLAIM_METADATA_KEY = "pq_non_repudiation"

# Uncertainty flag raised on the routed result when the claim cannot be honored.
PQ_NON_REPUDIATION_FLAG = "pq_non_repudiation_unavailable"

# Honest maturity for the sealed PQ-durable fact: the signal is real and live, but
# newly wired this wave and not yet a CI-benchmarked default.
_PQ_FACT_MATURITY = EvidenceMaturity.RESEARCH_EARLY


@dataclass(frozen=True, slots=True)
class PQDurabilityAssessment:
    """The sealable verdict-relevant assessment of signer PQ maturity for a request."""

    signer_maturity: SignerDurability
    active_backend_id: str | None
    claim_requested: bool

    @property
    def pq_durable(self) -> bool:
        """True iff the live signer is production-durable (can carry a PQ guarantee)."""
        return self.signer_maturity is SignerDurability.DURABLE

    @property
    def claim_honored(self) -> bool:
        """True iff a PQ-non-repudiation claim was asserted *and* can be honored."""
        return self.claim_requested and self.pq_durable

    @property
    def lowers_verdict(self) -> bool:
        """True iff this assessment must lower a PERMIT to ABSTAIN.

        Exactly: a PQ-non-repudiation claim was asserted but the signer is not
        durable. No claim ⇒ no effect (PQ maturity is irrelevant to this request).
        """
        return self.claim_requested and not self.pq_durable

    def reason(self) -> str:
        backend = self.active_backend_id
        return (
            f"PQ-durable=false: PQ-non-repudiation claim cannot be honored by a "
            f"'{self.signer_maturity.value}' signer "
            f"(ML-DSA backend id: {backend!r}); resolving to ABSTAIN"
        )

    def seal_detail(self) -> dict[str, Any]:
        """Canonical, JSON-native detail block for the sealed PQ-durable fact.

        Carries the real ``None`` backend id (the sealed ``SealedFact.detail`` is
        ``dict[str, Any]``, so JSON ``null`` is the honest encoding of "no backend").
        """
        return {
            "pq_durable": self.pq_durable,
            "signer_maturity": self.signer_maturity.value,
            "ml_dsa_backend_id": self.active_backend_id,
            "pq_non_repudiation_claim_requested": self.claim_requested,
            "pq_non_repudiation_claim_honored": self.claim_honored,
        }

    def finding_metadata(self) -> dict[str, str | int | float | bool]:
        """Scalar-only view of :meth:`seal_detail` for ``Finding.metadata``.

        ``Finding.metadata`` is ``dict[str, str|int|float|bool]`` — it cannot hold
        ``None`` — so the backend id is coerced to the literal string ``"<none>"``
        when absent. The sealed fact keeps the real ``None`` via :meth:`seal_detail`.
        """
        detail = self.seal_detail()
        detail["ml_dsa_backend_id"] = self.active_backend_id or "<none>"
        return detail  # type: ignore[return-value]


def _claim_requested(request: Any) -> bool:
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return False
    return bool(metadata.get(PQ_CLAIM_METADATA_KEY))


def assess(request: Any) -> PQDurabilityAssessment:
    """Assess PQ maturity for ``request`` against the live signer. Pure."""
    backend_id = ml_dsa.active_backend_id()
    return PQDurabilityAssessment(
        signer_maturity=durability_for_backend_id(backend_id),
        active_backend_id=backend_id,
        claim_requested=_claim_requested(request),
    )


def apply_pq_durability_hold(
    *,
    base: Any,
    request: Any,
    decision_ledger: SealedFactLedger | None = None,
) -> Any:
    """Apply the monotone-lowering PQ-maturity signal onto a routed result.

    Opt-in via ``request.metadata["pq_non_repudiation"]``. When (and only when) a
    request asserts a PQ-non-repudiation claim and the live signer is **not**
    durable, demote a **PERMIT** to **ABSTAIN** and surface ``PQ-durable=false``
    on the result (reason + uncertainty flag + finding + ``scores["pq_durable"]``).

    Monotone-lowering invariant — the single guard below: only a PERMIT may be
    demoted. A FORBID or an existing ABSTAIN is returned untouched. A PQ-maturity
    signal never raises a verdict, never relaxes one, and never fires the
    deterministic structural floor.

    Side effect (fail-closed): when ``decision_ledger`` is wired *and* the signal
    fires, the ``PQ-durable=false`` fact is sealed via :func:`seal_pq_durability`.
    An append failure is logged and degrades to "not sealed" — it never propagates
    into the verdict path. When no ledger is wired, nothing is sealed (today's
    behaviour). The returned (possibly demoted) ``RoutingResult`` is rebuilt
    immutably so the determinism fingerprint is preserved.
    """
    # Lazy imports keep pqcrypto/ decoupled from engine/ at module-load time and
    # avoid any import cycle through the PDP (mirrors systemic.probguard).
    from tex.domain.verdict import Verdict

    # Monotone-lowering guard: only a PERMIT may be demoted. This single check is
    # the whole monotonicity invariant for this signal.
    if base.verdict is not Verdict.PERMIT:
        return base

    assessment = assess(request)
    if not assessment.lowers_verdict:
        # No claim, or the signer is durable enough to honor it → no effect.
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reason = assessment.reason()
    reasons = list(base.reasons) + [reason]
    flags = list(base.uncertainty_flags) + [PQ_NON_REPUDIATION_FLAG]
    scores = dict(base.scores)
    scores["pq_durable"] = 0.0
    findings = list(base.findings) + [
        Finding(
            source="pqcrypto.pq_durability",
            rule_name="pq_non_repudiation_unavailable",
            severity=Severity.WARNING,
            message=reason,
            metadata={**assessment.finding_metadata(), "tier": "pq_maturity_hold"},
        )
    ]

    # Seal the PQ-durable=false fact into the decision ledger (fail-closed).
    if decision_ledger is not None:
        seal_pq_durability(decision_ledger, assessment, request)

    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=tuple(reasons),
        findings=tuple(findings),
        scores=scores,
        uncertainty_flags=tuple(flags),
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3. The sealed "PQ-durable=false" fact (mirrors provenance/decision_seal)
# ─────────────────────────────────────────────────────────────────────────────


def build_pq_durability_fact(
    assessment: PQDurabilityAssessment, request: Any
) -> SealedFact:
    """Map an assessment to a ``SealedFact`` recording the PQ-maturity resolution.

    Kind is ``DECISION``: the sealed assertion *is* a verdict resolution — "a
    PQ-non-repudiation claim was resolved to ABSTAIN because the signer is not
    PQ-durable." The ``claim`` names the property explicitly so no reader over-
    reads it, and the ``detail`` carries ``pq_durable=false`` and the active
    backend id. Pure (no I/O).
    """
    request_id = getattr(request, "request_id", None)
    backend = assessment.active_backend_id
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=(str(request_id) if request_id is not None else None),
        claim=(
            f"PQ-non-repudiation claim for request {request_id} resolved to ABSTAIN "
            f"— signer PQ-durable=false (maturity '{assessment.signer_maturity.value}', "
            f"ML-DSA backend id {backend!r}); "
            f"authorship+integrity sealed, PQ guarantee NOT made"
        ),
        maturity=_PQ_FACT_MATURITY,
        detail=assessment.seal_detail(),
    )


def seal_pq_durability(
    ledger: SealedFactLedger | None,
    assessment: PQDurabilityAssessment,
    request: Any,
) -> Any | None:
    """Seal one ``PQ-durable=false`` fact into ``ledger`` and return its PCVR.

    Fail-closed and observation-only (mirrors
    ``provenance/decision_seal.seal_decision``): ``ledger is None`` → no-op,
    return ``None``; an append failure is logged and returns ``None`` — it never
    propagates into the verdict path. Only seals when the assessment actually
    lowered the verdict (a no-op assessment seals nothing).
    """
    if ledger is None or not assessment.lowers_verdict:
        return None
    try:
        return ledger.append(build_pq_durability_fact(assessment, request))
    except Exception:  # pragma: no cover - defensive; a seal must never break a verdict
        _logger.warning(
            "PQ-durability seal failed for request %s; verdict unaffected, fact not sealed",
            getattr(request, "request_id", "?"),
            exc_info=True,
        )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Earn it — a REAL composite ML-DSA-87 + ECDSA-P384 chain-head round-trip.
#
#    The ML-DSA-87 half is signed by the OpenSSL >= 3.5 CLI (real FIPS 204); the
#    ECDSA-P384 half by pyca/cryptography (native). Both halves sign the SAME
#    draft-ietf-lamps-pq-composite-sigs-18 domain-separated binding, reused
#    verbatim from composite_ml_dsa so the wire format matches the production
#    composite. This is a feasibility proof — see the NANOZK-TRAP note: it does
#    NOT change active_backend_id() and so does NOT raise probe_backend().
# ─────────────────────────────────────────────────────────────────────────────

_COMPOSITE_SET = SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384
_OPENSSL_MIN_VERSION: tuple[int, int] = (3, 5)
# OpenSSL's CLI name for the ML-DSA-87 parameter set (see `openssl list
# -signature-algorithms`): the canonical "ML-DSA-87".
_OPENSSL_ML_DSA_87 = "ML-DSA-87"


class OpenSslMlDsaUnavailable(RuntimeError):
    """Raised when no OpenSSL >= 3.5 CLI with ML-DSA-87 is reachable on this host."""


def _parse_openssl_version(text: str) -> tuple[int, int] | None:
    # e.g. "OpenSSL 3.5.0 8 Apr 2025" → (3, 5). LibreSSL (macOS /usr/bin) → None.
    parts = text.split()
    if len(parts) < 2 or parts[0] != "OpenSSL":
        return None
    nums = parts[1].split(".")
    try:
        return (int(nums[0]), int(nums[1]))
    except (ValueError, IndexError):
        return None


def _candidate_openssl_paths() -> list[str]:
    seen: list[str] = []
    for cand in (
        shutil.which("openssl"),
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ):
        if cand and cand not in seen:
            seen.append(cand)
    return seen


def find_openssl_mldsa() -> str | None:
    """Return the path to an ``openssl`` >= 3.5 CLI that exposes ML-DSA-87, or None.

    Fail-closed: a binary is accepted only if BOTH its reported version is >= 3.5
    AND ``ML-DSA-87`` appears in its signature-algorithm list. macOS LibreSSL is
    rejected on the version check.
    """
    for path in _candidate_openssl_paths():
        try:
            ver = subprocess.run(
                [path, "version"], capture_output=True, text=True, timeout=10
            )
            parsed = _parse_openssl_version(ver.stdout.strip())
            if parsed is None or parsed < _OPENSSL_MIN_VERSION:
                continue
            algs = subprocess.run(
                [path, "list", "-signature-algorithms"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if _OPENSSL_ML_DSA_87 in algs.stdout:
                return path
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def openssl_mldsa_available() -> bool:
    """Whether a real OpenSSL-3.5 ML-DSA-87 CLI is reachable for the round-trip."""
    return find_openssl_mldsa() is not None


def _run(args: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=30, **kw)


@dataclass(frozen=True, slots=True)
class CompositeChainHeadKey:
    """A composite ML-DSA-87 + ECDSA-P384 public key for chain-head verification.

    The private material is held only inside the signing call's temp dir / the
    in-process pyca key and never serialised across this boundary; this object
    carries the *public* halves needed to verify.
    """

    ml_dsa_public_pem: bytes
    ecdsa_public_pem: bytes


def _bind(message: bytes) -> bytes:
    # Reuse the production draft-18 binding so the bytes both halves sign match the
    # real composite wire format (not a re-invented stand-in).
    from tex.pqcrypto.composite_ml_dsa import _bind_message

    return _bind_message(message, _COMPOSITE_SET)


def _concat(ml_dsa_part: bytes, classical_part: bytes) -> bytes:
    from tex.pqcrypto.composite_ml_dsa import _concat_length_prefixed

    return _concat_length_prefixed(ml_dsa_part, classical_part)


def _split(blob: bytes, *, label: str) -> tuple[bytes, bytes]:
    from tex.pqcrypto.composite_ml_dsa import _split_length_prefixed

    return _split_length_prefixed(blob, label=label)


def composite_sign_chain_head(
    message: bytes,
) -> tuple[CompositeChainHeadKey, bytes]:
    """Sign ``message`` (an evidence-chain head record) with a fresh composite key.

    Returns ``(public_key, composite_signature)``. The composite signature is the
    length-prefixed concat of the ML-DSA-87 signature (OpenSSL CLI) and the
    ECDSA-P384 signature (pyca), both over the same draft-18 bound message.

    Raises :class:`OpenSslMlDsaUnavailable` if no OpenSSL-3.5 ML-DSA CLI is found
    — it never silently degrades to a non-PQ or stand-in signature.
    """
    openssl = find_openssl_mldsa()
    if openssl is None:
        raise OpenSslMlDsaUnavailable(
            "No OpenSSL >= 3.5 CLI exposing ML-DSA-87 was found on this host; "
            "the composite chain-head round-trip needs a real PQ backend and "
            "will not fabricate one."
        )

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    bound = _bind(message)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        priv_pem = d / "mldsa_priv.pem"
        pub_pem = d / "mldsa_pub.pem"
        msg_path = d / "bound.bin"
        sig_path = d / "mldsa.sig"
        msg_path.write_bytes(bound)

        # ML-DSA-87 keygen + sign via the real OpenSSL FIPS 204 implementation.
        kg = _run([openssl, "genpkey", "-algorithm", _OPENSSL_ML_DSA_87, "-out", str(priv_pem)])
        if kg.returncode != 0:
            raise OpenSslMlDsaUnavailable(f"openssl genpkey failed: {kg.stderr!r}")
        _run([openssl, "pkey", "-in", str(priv_pem), "-pubout", "-out", str(pub_pem)], check=True)
        sign = _run(
            [openssl, "pkeyutl", "-sign", "-inkey", str(priv_pem),
             "-rawin", "-in", str(msg_path), "-out", str(sig_path)]
        )
        if sign.returncode != 0:
            raise OpenSslMlDsaUnavailable(f"openssl ML-DSA sign failed: {sign.stderr!r}")
        ml_dsa_sig = sig_path.read_bytes()
        ml_dsa_pub = pub_pem.read_bytes()

    # ECDSA-P384 half, native via pyca.
    ec_priv = ec.generate_private_key(ec.SECP384R1())
    ecdsa_sig = ec_priv.sign(bound, ec.ECDSA(hashes.SHA384()))
    ecdsa_pub = ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    composite_sig = _concat(ml_dsa_sig, ecdsa_sig)
    return (
        CompositeChainHeadKey(ml_dsa_public_pem=ml_dsa_pub, ecdsa_public_pem=ecdsa_pub),
        composite_sig,
    )


def composite_verify_chain_head(
    message: bytes,
    public_key: CompositeChainHeadKey,
    composite_signature: bytes,
) -> bool:
    """Verify a composite chain-head signature. True **iff BOTH halves verify**.

    Non-separability: the ML-DSA-87 half (OpenSSL CLI) and the ECDSA-P384 half
    (pyca) both sign the same draft-18 bound message, so a single broken or
    swapped half fails the whole verification. Returns False (never raises) on any
    malformed input or cryptographic failure.
    """
    openssl = find_openssl_mldsa()
    if openssl is None:
        return False
    try:
        ml_dsa_sig, ecdsa_sig = _split(composite_signature, label="composite signature")
    except ValueError:
        return False

    bound = _bind(message)

    # ML-DSA-87 half via the OpenSSL CLI.
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        pub_pem = d / "mldsa_pub.pem"
        msg_path = d / "bound.bin"
        sig_path = d / "mldsa.sig"
        pub_pem.write_bytes(public_key.ml_dsa_public_pem)
        msg_path.write_bytes(bound)
        sig_path.write_bytes(ml_dsa_sig)
        verify = _run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub_pem),
             "-rawin", "-in", str(msg_path), "-sigfile", str(sig_path)]
        )
        ml_dsa_ok = verify.returncode == 0

    # ECDSA-P384 half via pyca.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ecdsa_ok = False
    try:
        pub = serialization.load_pem_public_key(public_key.ecdsa_public_pem)
        if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1):
            pub.verify(ecdsa_sig, bound, ec.ECDSA(hashes.SHA384()))
            ecdsa_ok = True
    except (InvalidSignature, ValueError, TypeError):
        ecdsa_ok = False

    return bool(ml_dsa_ok and ecdsa_ok)
