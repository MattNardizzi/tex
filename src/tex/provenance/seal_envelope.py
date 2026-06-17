"""
Crypto-agile dual-signature envelope for sealed-verdict records.

Why this exists
---------------
Every sealed record in ``provenance/ledger.py`` already carries a legacy
ECDSA-P256 signature over its ``record_hash`` (``signature_b64``) — that is
the authorship proof today's verifiers check, and it is left **byte-for-byte
unchanged** by this module. A relying party migrating to post-quantum
signatures, however, needs a *second*, independently verifiable signature
under a PQ scheme, plus an explicit algorithm + version tag so a future
migration does not silently break the chain or let an attacker downgrade a
post-quantum seal back to classical-only.

This module adds exactly that: a **parallel (non-composite) dual signature**.
The same ``record_hash`` is signed by BOTH ECDSA-P256 (today's verifiers) and
ML-DSA-65 (FIPS 204, post-quantum), each as its own self-describing
``SignatureEntry``. Both signatures remain independently checkable — this is
the IETF/NSA-CNSA-2.0 "hybrid during migration" posture, NOT a single combined
composite signature (``draft-ietf-lamps-pq-composite-sigs``), because a
composite blob would break the existing ECDSA-only verifier and prevent
checking the classical signature on its own.

Backend + honesty (RUNTIME-DEPENDENT — re-verify if the crypto stack changes)
-----------------------------------------------------------------------------
The live default signer stays ECDSA-P256. The post-quantum signature comes from
``tex.pqcrypto.ml_dsa.MlDsaProvider``, whose backend is resolved at runtime in
this order:

  1. pyca/cryptography native bindings over OpenSSL ≥ 3.5
     (``cryptography.hazmat.primitives.asymmetric`` ``mldsa``) — present on this
     build (cryptography 49 / Python 3.12), so a real post-quantum signature is
     produced here;
  2. liboqs-python (``oqs``) when pyca lacks the scheme;
  3. neither installed → no real signature; ``MlDsaProvider`` reports no backend
     and dual signing **FAILS CLOSED to ECDSA-only** (``seal_version`` stays 1),
     never a fabricated or place-holder PQ signature.

Whether a post-quantum signature exists is therefore RUNTIME-DEPENDENT on the
backend, not a standing guarantee. The signed primitive (FIPS 204 ML-DSA-65) is
NIST-standardised; the dual-sign *envelope* construction here is a
straightforward engineering composition of two standard signatures — maturity
``research-solid``, not a novel cryptographic claim.

Downgrade / strip resistance
----------------------------
Each ``SignatureEntry`` signs not the bare ``record_hash`` but a
domain-separated message that commits to the seal version AND the ordered set
of algorithms (:func:`envelope_signing_message`). So an adversary who strips
the ML-DSA entry (or edits the declared algorithm set) leaves the surviving
ECDSA envelope signature signed over a message that no longer matches what the
verifier recomputes — the tamper is detected, not merely undeclared. The legacy
``signature_b64`` over the bare ``record_hash`` is preserved alongside, so a
strictly-legacy verifier still gets exactly today's guarantee.

Integrity note
--------------
Nothing in this module enters the hash chain. The chain is
``record_hash = H(payload_sha256, previous_hash)`` and the envelope is computed
*over* ``record_hash`` afterwards — so adding an envelope to a record changes
neither ``payload_sha256`` nor ``record_hash`` nor ``verify_chain``. Old
ECDSA-only bundles (no envelope) and new dual-signed bundles share one chain.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
)

__all__ = [
    "SEAL_VERSION_LEGACY",
    "SEAL_VERSION_DUAL",
    "SignatureEntry",
    "SealEnvelope",
    "EnvelopeVerification",
    "DualSealer",
    "envelope_signing_message",
    "verify_seal_envelope",
]

# Seal versions. v1 == legacy ECDSA-only (no envelope); v2 == dual ECDSA + ML-DSA.
SEAL_VERSION_LEGACY = 1
SEAL_VERSION_DUAL = 2

# The post-quantum algorithm we co-sign with. ML-DSA-65 is the FIPS 204
# Security-Level-3 workhorse (the agility layer's default).
_DEFAULT_PQ_ALGORITHM = SignatureAlgorithm.ML_DSA_65
_ECDSA = SignatureAlgorithm.ECDSA_P256

# Domain-separation prefix for the envelope signing message. Bumping the seal
# version changes the message (the version is interpolated below), so an
# envelope signed at one version can never verify at another.
_DOMAIN_PREFIX = "tex.seal.envelope"


def envelope_signing_message(
    record_hash: str, seal_version: int, algorithms: tuple[str, ...]
) -> bytes:
    """The exact bytes every envelope signature is computed over.

    Commits to the record hash, the seal version, and the *sorted* algorithm
    set, with a domain-separation prefix. Sorting makes the commitment
    order-independent while still binding membership: dropping or adding an
    algorithm changes the message, so a surviving signature fails to verify.

    This is deliberately NOT ``record_hash`` itself — the legacy
    ``signature_b64`` signs the bare ``record_hash`` and must stay distinct so
    the two signatures cannot be confused for one another.
    """
    sorted_algs = ",".join(sorted(algorithms))
    return f"{_DOMAIN_PREFIX}.v{int(seal_version)}|{record_hash}|{sorted_algs}".encode(
        "ascii"
    )


class SignatureEntry(BaseModel):
    """One algorithm's signature over the envelope message — self-describing.

    Carries its own public key (base64) so a multi-algorithm bundle is
    verifiable offline without an out-of-band key for every scheme; the
    verifier still checks each signature against a *pinned* key when one is
    supplied (the embedded key is never the sole basis of trust).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str
    key_id: str
    signature_b64: str
    # base64 of the algorithm-native public key: PEM SPKI for ECDSA-P256,
    # raw FIPS 204 §5.3 bytes for ML-DSA.
    public_key_b64: str


class SealEnvelope(BaseModel):
    """The crypto-agile envelope: a version tag + the declared algorithm set +
    one :class:`SignatureEntry` per algorithm.

    ``algorithms`` is the *declared* ordered set the producer claims it signed
    with; the verifier checks that the entries present match it exactly (an
    independent strip/relabel check) AND that it matches what each signature
    cryptographically committed to via :func:`envelope_signing_message`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seal_version: int = SEAL_VERSION_DUAL
    algorithms: tuple[str, ...]
    signatures: tuple[SignatureEntry, ...]

    @property
    def present_algorithms(self) -> tuple[str, ...]:
        return tuple(e.algorithm for e in self.signatures)


@dataclass(frozen=True, slots=True)
class EnvelopeVerification:
    """Per-envelope verdict — every axis reported so a reader sees exactly what
    held. ``ok`` is the conjunction of all of them."""

    ok: bool
    signatures_valid: bool
    invalid_at: int | None
    # Declared algorithm set == the set actually present in the entries?
    algorithms_match: bool
    # Algorithms whose signature was checked against the embedded key because no
    # pin was supplied (honest "unpinned", not a failure on its own).
    unpinned_algorithms: tuple[str, ...] = field(default=())
    # Algorithms whose embedded public key disagreed with the supplied pin (a
    # substitution attempt; the signature also fails against the pin).
    key_pin_mismatch: tuple[str, ...] = field(default=())


def _provider_for(algorithm: str) -> SignatureProvider | None:
    """Resolve a verification provider for an algorithm string. Lazy imports so
    importing this module never forces ML-DSA backend resolution."""
    if algorithm == _ECDSA.value:
        from tex.events._ecdsa_provider import EcdsaP256Provider

        return EcdsaP256Provider()
    try:
        param = SignatureAlgorithm(algorithm)
    except ValueError:
        return None
    if param in {
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    }:
        from tex.pqcrypto import ml_dsa

        return ml_dsa.MlDsaProvider(parameter_set=param)
    return None


class DualSealer:
    """Produces a :class:`SealEnvelope` over a ``record_hash`` by signing the
    domain-separated message with ECDSA-P256 and (when a PQ backend is present)
    ML-DSA.

    Construct via :meth:`from_ecdsa` so the envelope's ECDSA entry reuses the
    ledger's existing ECDSA identity (one classical key, not two). If no ML-DSA
    backend is available the sealer is **inert** (:attr:`pq_active` is False) and
    the ledger keeps emitting legacy v1 records — fail-closed, never a fake PQ
    signature.
    """

    def __init__(
        self,
        *,
        ecdsa_provider: SignatureProvider,
        ecdsa_key: SignatureKeyPair,
        pq_provider: SignatureProvider | None = None,
        pq_key: SignatureKeyPair | None = None,
        seal_version: int = SEAL_VERSION_DUAL,
    ) -> None:
        self._ecdsa_provider = ecdsa_provider
        self._ecdsa_key = ecdsa_key
        self._pq_provider = pq_provider
        self._pq_key = pq_key
        self._seal_version = int(seal_version)

    # --------------------------------------------------------------- factory
    @classmethod
    def from_ecdsa(
        cls,
        ecdsa_provider: SignatureProvider,
        ecdsa_key: SignatureKeyPair,
        *,
        enable_pq: bool = True,
        pq_algorithm: SignatureAlgorithm = _DEFAULT_PQ_ALGORITHM,
        key_label: str = "tex-seal-pq",
    ) -> "DualSealer":
        """Build a sealer from an existing ECDSA identity, generating a fresh
        ML-DSA keypair when a backend is live and ``enable_pq`` is set.

        ``enable_pq=False`` forces legacy ECDSA-only output (used to produce /
        test backward-compatible v1 bundles, and as an opt-out escape hatch)."""
        pq_provider: SignatureProvider | None = None
        pq_key: SignatureKeyPair | None = None
        if enable_pq:
            try:
                from tex.pqcrypto.ml_dsa import MlDsaProvider, active_backend_id

                if active_backend_id() is not None:
                    prov = MlDsaProvider(parameter_set=pq_algorithm)
                    pq_provider = prov
                    pq_key = prov.generate_keypair(key_label)
            except Exception:  # noqa: BLE001 — any backend failure => stay legacy
                pq_provider = None
                pq_key = None
        return cls(
            ecdsa_provider=ecdsa_provider,
            ecdsa_key=ecdsa_key,
            pq_provider=pq_provider,
            pq_key=pq_key,
        )

    # --------------------------------------------------------------- properties
    @property
    def pq_active(self) -> bool:
        """True iff a post-quantum signature will actually be produced."""
        return self._pq_provider is not None and self._pq_key is not None

    @property
    def algorithms(self) -> tuple[str, ...]:
        algs = [self._ecdsa_key.algorithm.value]
        if self.pq_active:
            assert self._pq_key is not None
            algs.append(self._pq_key.algorithm.value)
        return tuple(algs)

    @property
    def pq_public_key_b64(self) -> str | None:
        if not self.pq_active:
            return None
        assert self._pq_key is not None
        return base64.b64encode(self._pq_key.public_key).decode("ascii")

    @property
    def pq_signing_key_id(self) -> str | None:
        return None if self._pq_key is None else self._pq_key.key_id

    @property
    def pq_algorithm(self) -> str | None:
        return None if self._pq_key is None else self._pq_key.algorithm.value

    # --------------------------------------------------------------- seal
    def seal(self, record_hash: str) -> SealEnvelope | None:
        """Return the dual-signature envelope over ``record_hash``, or ``None``
        when post-quantum signing is inactive (caller then emits a v1 record).

        Only builds an envelope when ≥ 2 algorithms participate — a lone ECDSA
        "envelope" would add nothing over the legacy ``signature_b64`` field."""
        if not self.pq_active:
            return None
        assert self._pq_provider is not None and self._pq_key is not None

        algorithms = self.algorithms
        message = envelope_signing_message(record_hash, self._seal_version, algorithms)

        ecdsa_sig = self._ecdsa_provider.sign(message, self._ecdsa_key)
        pq_sig = self._pq_provider.sign(message, self._pq_key)

        entries = (
            SignatureEntry(
                algorithm=self._ecdsa_key.algorithm.value,
                key_id=self._ecdsa_key.key_id,
                signature_b64=base64.b64encode(ecdsa_sig).decode("ascii"),
                public_key_b64=base64.b64encode(self._ecdsa_key.public_key).decode(
                    "ascii"
                ),
            ),
            SignatureEntry(
                algorithm=self._pq_key.algorithm.value,
                key_id=self._pq_key.key_id,
                signature_b64=base64.b64encode(pq_sig).decode("ascii"),
                public_key_b64=base64.b64encode(self._pq_key.public_key).decode("ascii"),
            ),
        )
        return SealEnvelope(
            seal_version=self._seal_version,
            algorithms=algorithms,
            signatures=entries,
        )


def verify_seal_envelope(
    record_hash: str,
    envelope: SealEnvelope,
    *,
    pinned_keys: dict[str, bytes] | None = None,
) -> EnvelopeVerification:
    """Verify a dual-signature envelope from scratch against a recomputed
    ``record_hash``.

    ``pinned_keys`` maps an algorithm string (e.g. ``"ml-dsa-65"``) to the
    public key bytes a relying party trusts for it (PEM for ECDSA, raw for
    ML-DSA). For any algorithm without a pin, the entry's embedded key is used
    and the algorithm is reported in ``unpinned_algorithms`` — never silently
    treated as trusted. Each signature is verified over
    :func:`envelope_signing_message`, so a stripped/relabelled algorithm set is
    caught both structurally (declared vs present) and cryptographically (the
    surviving signature no longer matches the recomputed message)."""
    pins = pinned_keys or {}

    declared = tuple(envelope.algorithms)
    present = envelope.present_algorithms
    algorithms_match = sorted(declared) == sorted(present)

    # The message is recomputed from the DECLARED set; if an attacker edits the
    # declared set, surviving signatures (made over the original set) fail here.
    message = envelope_signing_message(record_hash, envelope.seal_version, declared)

    unpinned: list[str] = []
    pin_mismatch: list[str] = []
    signatures_valid = True
    invalid_at: int | None = None

    for idx, entry in enumerate(envelope.signatures):
        provider = _provider_for(entry.algorithm)
        try:
            embedded_key = base64.b64decode(entry.public_key_b64.encode("ascii"))
        except Exception:  # noqa: BLE001
            embedded_key = b""

        pinned = pins.get(entry.algorithm)
        if pinned is None:
            verify_key = embedded_key
            unpinned.append(entry.algorithm)
        else:
            verify_key = pinned
            if embedded_key != pinned:
                pin_mismatch.append(entry.algorithm)

        ok = False
        if provider is not None and verify_key:
            try:
                sig = base64.b64decode(entry.signature_b64.encode("ascii"))
                ok = provider.verify(message, sig, verify_key)
            except Exception:  # noqa: BLE001
                ok = False
        if not ok and signatures_valid:
            signatures_valid = False
            invalid_at = idx

    overall = (
        signatures_valid
        and algorithms_match
        and not pin_mismatch
        and len(envelope.signatures) > 0
    )
    return EnvelopeVerification(
        ok=overall,
        signatures_valid=signatures_valid,
        invalid_at=invalid_at,
        algorithms_match=algorithms_match,
        unpinned_algorithms=tuple(unpinned),
        key_pin_mismatch=tuple(pin_mismatch),
    )
