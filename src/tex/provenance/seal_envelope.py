"""
Crypto-agile dual-signature sealer — the post-quantum seal for the ledgers.

What this adds
--------------
Tex seals every verdict (and every behavioural-identity event) into a
hash-chained, signed ledger. The chain proves *integrity*; a per-record
signature proves *authorship*. Historically that signature was ECDSA-P256
only — quantum-vulnerable. This module produces a **crypto-agile envelope**
that signs the *same* ``record_hash`` with more than one algorithm:

  * ECDSA-P256  — kept exactly as-is, so every verifier shipping today still
    works (this is the legacy ``signature_b64``, mirrored into the envelope).
  * ML-DSA-65   — NIST FIPS 204 post-quantum signature, added alongside.

Both signatures cover the identical ``record_hash`` the chain already commits
to, so adding the envelope changes neither ``payload_sha256`` nor
``record_hash``: **the hash chain is byte-for-byte unchanged**, and a legacy
ECDSA-only bundle still verifies. The envelope carries an explicit
``seal_version`` and per-signature algorithm tag, so a future migration can add
or retire an algorithm without breaking the existing chain.

Active ML-DSA backend
---------------------
The ML-DSA signer is obtained from ``tex.pqcrypto.ml_dsa.MlDsaProvider`` via the
algorithm-agility dispatcher. Its backend is resolved at import time, preferring
**pyca/cryptography >= 48 (native, OpenSSL >= 3.5)** and falling back to
**liboqs-python** (``pip install liboqs-python``); see ``tex/pqcrypto/ml_dsa.py``
for the full backend-discovery order and ``active_backend_id()`` to query which
is live. If *no* PQ backend is present, sealing degrades **honestly** to
ECDSA-only (``seal_envelope is None``, logged once at WARNING) rather than
faking a post-quantum signature — the record then reports as not dual-signed and
a PQ-requiring verifier sees ``pq_secured == False``.

Honest limits
-------------
The algorithm tag inside a signature is descriptive metadata, not itself signed.
This is sound because verification dispatches *by* the claimed algorithm against
the *pinned* key of that algorithm: relabelling a signature (an
"algorithm-mismatch") makes the bytes fail to validate under the wrong
algorithm/key, so a tampered tag is caught as a verification failure, never
silently accepted. The signed message is the bare ``record_hash`` (so the
envelope's ECDSA entry stays byte-identical to ``signature_b64`` for backward
compatibility).
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Mapping
from dataclasses import dataclass

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)
from tex.provenance.models import SealEnvelope, SealPublicKey, SealSignature

_logger = logging.getLogger(__name__)

# Bump this when the envelope's algorithm set changes (the migration knob). "2"
# is the first crypto-agile multi-signature seal; "1" was implicit ECDSA-only
# (a record with ``seal_envelope is None``).
SEAL_VERSION_AGILE = "2"

# The default post-quantum algorithm added alongside ECDSA-P256. ML-DSA-65 is
# NIST Security Level 3 — the FIPS 204 workhorse default.
DEFAULT_PQ_ALGORITHM = SignatureAlgorithm.ML_DSA_65

# Algorithms that are NOT post-quantum. Everything else (ml-dsa*, slh-dsa*,
# composites, hybrids) counts as carrying post-quantum protection.
_CLASSICAL_ALGORITHMS = frozenset(
    {SignatureAlgorithm.ECDSA_P256.value, SignatureAlgorithm.ED25519.value}
)


def is_post_quantum_algorithm(algorithm: str) -> bool:
    """True if ``algorithm`` carries post-quantum protection (not purely classical)."""
    return algorithm not in _CLASSICAL_ALGORITHMS


@dataclass(frozen=True, slots=True)
class _Signer:
    """One (provider, key) pair. The key carries its own algorithm tag, which is
    the source of truth for the signature's ``algorithm`` (never guessed)."""

    provider: SignatureProvider
    key: SignatureKeyPair

    @property
    def algorithm_value(self) -> str:
        return self.key.algorithm.value


def make_pq_signer(
    *,
    parameter_set: SignatureAlgorithm = DEFAULT_PQ_ALGORITHM,
    key: SignatureKeyPair | None = None,
    key_label: str = "tex-seal-ml-dsa",
) -> _Signer | None:
    """Build an ML-DSA signer if a post-quantum backend is live; else ``None``.

    Graceful by design: a machine without ``cryptography>=48`` *and* without
    liboqs cannot produce ML-DSA signatures, so we return ``None`` (logged) and
    the caller seals ECDSA-only rather than faking a PQ signature.
    """
    try:
        provider = get_signature_provider(parameter_set)
        signer_key = key or provider.generate_keypair(key_label)
    except Exception as exc:  # noqa: BLE001 — any backend-absent failure → degrade
        _logger.warning(
            "post-quantum seal disabled — no ML-DSA backend available (%s); "
            "sealing ECDSA-only. Install cryptography>=48 or liboqs-python.",
            exc,
        )
        return None
    return _Signer(provider=provider, key=signer_key)


class CryptoAgileSealer:
    """Signs a ``record_hash`` with an ordered set of (provider, key) signers and
    produces a :class:`SealEnvelope`.

    Signer 0 is the **primary** (ECDSA-P256), whose signature mirrors the
    ledger's legacy ``signature_b64`` byte-for-byte (see ``envelope_with_primary``);
    signer 1+ are the post-quantum additions. Stateless and thread-safe for
    signing once constructed (the underlying providers hold no per-call state).
    """

    def __init__(self, signers: list[_Signer]) -> None:
        if not signers:
            raise ValueError("CryptoAgileSealer requires at least one signer")
        self._signers: list[_Signer] = list(signers)

    @classmethod
    def from_primary(
        cls,
        primary_provider: SignatureProvider,
        primary_key: SignatureKeyPair,
        *,
        pq_provider: SignatureProvider | None = None,
        pq_key: SignatureKeyPair | None = None,
        enable_pq: bool = True,
        pq_parameter_set: SignatureAlgorithm = DEFAULT_PQ_ALGORITHM,
        pq_key_label: str = "tex-seal-ml-dsa",
    ) -> "CryptoAgileSealer":
        """Build a sealer from an existing primary (ECDSA) provider+key, adding a
        post-quantum signer when ``enable_pq`` and a PQ backend (or an explicit
        ``pq_provider``+``pq_key``) is available."""
        signers = [_Signer(primary_provider, primary_key)]
        if enable_pq:
            if pq_provider is not None and pq_key is not None:
                signers.append(_Signer(pq_provider, pq_key))
            else:
                pq = make_pq_signer(
                    parameter_set=pq_parameter_set, key=pq_key, key_label=pq_key_label
                )
                if pq is not None:
                    signers.append(pq)
        return cls(signers)

    # ---------------------------------------------------------------- introspect
    @property
    def primary(self) -> _Signer:
        return self._signers[0]

    @property
    def pq_signer(self) -> _Signer | None:
        """The first post-quantum signer, or ``None`` if sealing ECDSA-only."""
        for signer in self._signers[1:]:
            if is_post_quantum_algorithm(signer.algorithm_value):
                return signer
        return None

    @property
    def is_dual(self) -> bool:
        """True when this sealer binds two or more distinct algorithms."""
        return len({s.algorithm_value for s in self._signers}) >= 2

    @property
    def algorithms(self) -> tuple[str, ...]:
        return tuple(s.algorithm_value for s in self._signers)

    @property
    def public_keys(self) -> tuple[SealPublicKey, ...]:
        """One :class:`SealPublicKey` per signer — what a bundle carries so a
        verifier can check each algorithm's signature against a pinned key."""
        return tuple(
            SealPublicKey(
                algorithm=s.algorithm_value,
                key_id=s.key.key_id,
                public_key_b64=base64.b64encode(s.key.public_key).decode("ascii"),
            )
            for s in self._signers
        )

    def pinned_keys(self) -> dict[str, bytes]:
        """``{algorithm: public_key_bytes}`` for this sealer's own keys — the
        convenience pin set for self-verification (ECDSA PEM, ML-DSA raw)."""
        return {s.algorithm_value: s.key.public_key for s in self._signers}

    # ------------------------------------------------------------------- sign
    def sign(self, record_hash_hex: str) -> SealEnvelope:
        """Sign ``record_hash`` with every signer and return the envelope."""
        msg = record_hash_hex.encode("ascii")
        sigs = [self._sign_one(s, msg) for s in self._signers]
        return SealEnvelope(seal_version=SEAL_VERSION_AGILE, signatures=tuple(sigs))

    def envelope_with_primary(
        self, record_hash_hex: str, primary_signature_raw: bytes
    ) -> SealEnvelope:
        """Build the envelope reusing an already-computed primary signature.

        The primary (ECDSA) entry is set from ``primary_signature_raw`` so it is
        byte-identical to the ledger's legacy ``signature_b64`` (ECDSA signing is
        randomised — re-signing would diverge); the post-quantum entries are
        freshly signed over the same ``record_hash``.
        """
        msg = record_hash_hex.encode("ascii")
        primary = self._signers[0]
        sigs = [
            SealSignature(
                algorithm=primary.algorithm_value,
                key_id=primary.key.key_id,
                signature_b64=base64.b64encode(primary_signature_raw).decode("ascii"),
            )
        ]
        sigs.extend(self._sign_one(s, msg) for s in self._signers[1:])
        return SealEnvelope(seal_version=SEAL_VERSION_AGILE, signatures=tuple(sigs))

    @staticmethod
    def _sign_one(signer: _Signer, msg: bytes) -> SealSignature:
        raw = signer.provider.sign(msg, signer.key)
        return SealSignature(
            algorithm=signer.algorithm_value,
            key_id=signer.key.key_id,
            signature_b64=base64.b64encode(raw).decode("ascii"),
        )


# ============================================================================
# Verification
# ============================================================================


@dataclass(frozen=True, slots=True)
class EnvelopeVerification:
    """Result of verifying one envelope against a set of pinned keys.

    ``verified_algorithms`` verified against their pinned key; ``unpinned_algorithms``
    were present but no key was pinned for them (honest "cannot confirm", not a
    tamper); ``mismatch`` is True iff a signature whose algorithm *was* pinned
    failed to validate — a tamper, forgery, or algorithm-mismatch.
    """

    present: bool
    seal_version: str | None
    algorithms: tuple[str, ...]
    verified_algorithms: tuple[str, ...]
    unpinned_algorithms: tuple[str, ...]
    mismatch: bool

    @property
    def ecdsa_verified(self) -> bool:
        return SignatureAlgorithm.ECDSA_P256.value in self.verified_algorithms

    @property
    def pq_verified(self) -> bool:
        """True iff at least one *post-quantum* signature verified against a pin."""
        return any(is_post_quantum_algorithm(a) for a in self.verified_algorithms)

    @property
    def dual_verified(self) -> bool:
        """True iff a classical *and* a post-quantum signature both verified."""
        classical_ok = any(
            not is_post_quantum_algorithm(a) for a in self.verified_algorithms
        )
        return classical_ok and self.pq_verified and not self.mismatch


def verify_envelope(
    record_hash_hex: str,
    envelope: SealEnvelope | None,
    *,
    pinned_keys: Mapping[str, bytes],
) -> EnvelopeVerification:
    """Verify every signature in ``envelope`` against ``pinned_keys``.

    ``pinned_keys`` maps an algorithm value (``"ecdsa-p256"`` / ``"ml-dsa-65"``)
    to the *trusted* public-key bytes for that algorithm. Each signature is
    verified by dispatching the provider for its *claimed* algorithm against the
    pinned key for that algorithm — so a relabelled signature (algorithm-mismatch)
    fails to validate and is reported via ``mismatch``. Verification never trusts
    a key embedded in the bundle; the caller supplies the pins.
    """
    if envelope is None:
        return EnvelopeVerification(
            present=False,
            seal_version=None,
            algorithms=(),
            verified_algorithms=(),
            unpinned_algorithms=(),
            mismatch=False,
        )

    msg = record_hash_hex.encode("ascii")
    verified: list[str] = []
    unpinned: list[str] = []
    mismatch = False
    provider_cache: dict[str, SignatureProvider] = {}

    for sig in envelope.signatures:
        algo = sig.algorithm
        pinned = pinned_keys.get(algo)
        if pinned is None:
            unpinned.append(algo)
            continue
        # Resolve the provider for the CLAIMED algorithm. An unknown/unsupported
        # tag against a pinned key is a mismatch (we cannot honour the claim).
        provider = provider_cache.get(algo)
        if provider is None:
            try:
                provider = get_signature_provider(SignatureAlgorithm(algo))
            except Exception:  # noqa: BLE001 — unknown alg tag on a pinned slot
                mismatch = True
                continue
            provider_cache[algo] = provider
        try:
            raw = base64.b64decode(sig.signature_b64.encode("ascii"))
            ok = provider.verify(msg, raw, pinned)
        except Exception:  # noqa: BLE001 — any verify failure is a non-match
            ok = False
        if ok:
            verified.append(algo)
        else:
            # Pinned algorithm whose signature did not validate: tamper / forgery
            # / algorithm-mismatch. Honest hard failure.
            mismatch = True

    return EnvelopeVerification(
        present=True,
        seal_version=envelope.seal_version,
        algorithms=envelope.algorithms(),
        verified_algorithms=tuple(verified),
        unpinned_algorithms=tuple(unpinned),
        mismatch=mismatch,
    )
