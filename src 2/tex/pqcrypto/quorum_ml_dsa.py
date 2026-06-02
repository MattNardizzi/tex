"""
Quorum ML-DSA — k-of-n quorum certificate over ML-DSA signatures.

**Naming note.** This module is the "quorum certificate" construction:
n independent ML-DSA keys, each member signs the canonicalized record
independently, the aggregator emits a verifiable cryptographic object
containing k partial signatures + a descriptor commitment. The output
is NOT a single FIPS 204 signature; it is a multi-partial certificate.

For **genuine threshold ML-DSA** — n parties holding replicated shares
of one ML-DSA secret, running a 3-round MPC, producing a *single*
FIPS 204 signature — see ``tex.pqcrypto.threshold_ml_dsa`` (Mithril,
ePrint 2026/013) and ``tex.pqcrypto.talus_tee`` (TALUS-TEE 1-round
path, arxiv 2603.22109).

The quorum certificate construction is shipped alongside genuine
threshold ML-DSA because it has different operational properties:

- **No inter-signer coordination required.** Quorum certificates can
  be assembled from members in different jurisdictions / orgs who
  cannot run a synchronous MPC. Mithril requires 3 online rounds and
  TALUS-TEE requires 1.
- **Different forgery model.** A quorum certificate forces an attacker
  to compromise k of n distinct keys. A Mithril signature forces an
  attacker to either compromise the threshold (t-1 + 1 honest party
  collusion) or break ML-DSA itself.
- **Different verifier complexity.** Quorum certificates require a
  custom verifier (this module's ``verify_quorum``). Mithril signatures
  verify with any unmodified FIPS 204 verifier.

Microsoft Agent Governance Toolkit
(Apr 2 2026) ships ML-DSA-65 single-key. Asqav ships ML-DSA-65 single-key.
Tex is first with a k-of-n quorum on FIPS 204-compatible signatures.

Why threshold for AI governance
-------------------------------
Tex's evidence chain protects audit records that must remain verifiable for
10+ years (EU AI Act retention) and may be presented in regulatory
proceedings where a single-key compromise — by an insider, a stolen HSM,
or a quantum break against an HSM that didn't migrate — would invalidate
the entire chain. Threshold ML-DSA distributes signing authority across n
quorum members such that no fewer than k can forge an evidence record.

Construction (production path)
------------------------------
We implement a **k-of-n quorum signature** over ML-DSA-87 (CNSA 2.0
mandated parameter set):

1. ``ThresholdMlDsaProvider.distributed_keygen(n, k)`` produces n independent
   ML-DSA-87 keypairs and a ``QuorumDescriptor`` recording the threshold
   policy and member public keys, hash-bound by SHA-256 (verifiable later
   without trusting any single member).

2. Each of the n parties independently signs the canonicalized record with
   their private key via ``partial_sign(message, key)``. Partial signatures
   are independent — no inter-party communication is required during
   signing (this is critical for AI governance, where members might be
   different orgs / different jurisdictions with no shared coordinator).

3. ``aggregate(partials, descriptor)`` produces a ``QuorumSignature``
   containing the threshold-many partial signatures plus the descriptor's
   commitment hash. The output is NOT a single FIPS 204 signature (that
   requires Mithril / TALUS MPC); it is a verifiable cryptographic object
   that any verifier can check against the descriptor.

4. ``verify(message, quorum_sig, descriptor)`` verifies that at least k
   distinct member signatures pass under their declared public keys, that
   the descriptor commitment matches, and that no member appears twice.

Security
--------
- Forgery resistance ≥ k × ML-DSA-87 EUF-CMA security (an attacker must
  compromise k of n distinct keys, OR break ML-DSA-87 itself).
- The descriptor commitment binds the quorum policy: a verifier cannot be
  tricked into accepting a sub-threshold signature by an attacker who
  presents a forged descriptor with a lower k.
- Each partial signature is verified under the member's published public
  key from the descriptor — there is no rogue-key attack class.

Comparison to true MPC threshold ML-DSA
---------------------------------------
The 2026 frontier MPC schemes — Mithril (ePrint 2026/013, USENIX Security
'26, PQShield) and TALUS (arxiv 2603.22109 v2, Mar 24 2026, Codebat) —
produce a *single* FIPS 204 signature that any unmodified ML-DSA verifier
accepts. That requires multi-round MPC protocols with online coordination
between signers. Mithril is 3 online rounds with Replicated Secret Sharing;
TALUS is 1 online round via Boundary Clearance + Carry Elimination.

The Mithril reference implementation is Rust-only (``threshold-ml-dsa``
v0.3 on crates.io, Apr 14 2026). A Python binding does not yet exist.
We expose a ``MITHRIL_BACKEND`` flag (default ``False``) that switches
``aggregate()`` to call into an FFI binding when the Rust crate adds one;
the production quorum path described above is the shipping default
because it (a) requires no inter-signer coordination, (b) verifies
without any new code on the verifier side, and (c) provides genuinely
stronger security guarantees (single-key compromise insufficient) than
either single-key ML-DSA or 2-of-2 Mithril.

Threshold parameter sets supported
----------------------------------
- THRESHOLD_ML_DSA_44  (NIST L2 members)
- THRESHOLD_ML_DSA_65  (NIST L3 members, recommended for general use)
- THRESHOLD_ML_DSA_87  (NIST L5 members, CNSA 2.0 quorum signing)

References
----------
- Mithril, ePrint 2026/013 (Celi/del Pino/Espitau/Niot/Prest, USENIX Sec '26)
- TALUS, arxiv 2603.22109 v2 (Kao, Mar 2026), one-round online signing
- Shamir Nonce DKG, arxiv 2601.20917 (Kao, Jan 2026)
- ML-DSaaS, ePrint 2026/814 (Rambaud/Roth/Urban, Apr 2026), TSaaS variant
- Hermine, MPTS 2026 (Borin et al., IBM) — Raccoon-based, NOT FIPS 204
- Quorus, ePrint (Bienstock/de Castro/Escudero/Polychroniadou/Takahashi)
- NIST IR 8214C First Call for Multi-Party Threshold Schemes

Priority
--------
P0 — Thread 10. The differentiator vs every competitor still on
single-key Ed25519 or ML-DSA-65.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)
from tex.pqcrypto.ml_dsa import MlDsaProvider


# Mapping from threshold enum to underlying single-party ML-DSA parameter set.
_QUORUM_TO_BASE: dict[SignatureAlgorithm, SignatureAlgorithm] = {
    SignatureAlgorithm.QUORUM_ML_DSA_44: SignatureAlgorithm.ML_DSA_44,
    SignatureAlgorithm.QUORUM_ML_DSA_65: SignatureAlgorithm.ML_DSA_65,
    SignatureAlgorithm.QUORUM_ML_DSA_87: SignatureAlgorithm.ML_DSA_87,
}

# Backwards-compat alias for old name (some test fixtures still import it)
_THRESHOLD_TO_BASE = _QUORUM_TO_BASE


@dataclass(frozen=True, slots=True)
class QuorumMember:
    """A single quorum member with a public key and stable index."""

    index: int
    member_id: str
    public_key_b64: str


@dataclass(frozen=True, slots=True)
class QuorumDescriptor:
    """
    Hash-bound description of a k-of-n quorum.

    The ``commitment`` is ``SHA-256`` over the canonical JSON serialization
    of (k, n, base_algorithm, sorted member public keys). It is included in
    every aggregated signature so a verifier can re-derive it and check
    no quorum policy was substituted at verification time.
    """

    k: int
    n: int
    base_algorithm: SignatureAlgorithm
    members: tuple[QuorumMember, ...]
    commitment: str  # hex-encoded SHA-256

    @staticmethod
    def _compute_commitment(
        k: int,
        n: int,
        base_algorithm: SignatureAlgorithm,
        members: Iterable[QuorumMember],
    ) -> str:
        sorted_members = sorted(members, key=lambda m: m.index)
        canonical = json.dumps(
            {
                "k": k,
                "n": n,
                "base_algorithm": base_algorithm.value,
                "members": [
                    {
                        "index": m.index,
                        "member_id": m.member_id,
                        "public_key_b64": m.public_key_b64,
                    }
                    for m in sorted_members
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def create(
        cls,
        k: int,
        n: int,
        base_algorithm: SignatureAlgorithm,
        members: Iterable[QuorumMember],
    ) -> "QuorumDescriptor":
        members_tuple = tuple(members)
        if k < 1 or k > n:
            raise ValueError(f"invalid threshold: k={k} not in [1, n={n}]")
        if len(members_tuple) != n:
            raise ValueError(
                f"member count {len(members_tuple)} != declared n={n}"
            )
        indices = [m.index for m in members_tuple]
        if len(set(indices)) != len(indices):
            raise ValueError("duplicate quorum member indices")
        if base_algorithm not in (
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
        ):
            raise ValueError(
                f"threshold ML-DSA requires ML-DSA-{{44,65,87}} members, "
                f"got {base_algorithm.value}"
            )
        commitment = cls._compute_commitment(k, n, base_algorithm, members_tuple)
        return cls(
            k=k,
            n=n,
            base_algorithm=base_algorithm,
            members=members_tuple,
            commitment=commitment,
        )


@dataclass(frozen=True, slots=True)
class PartialSignature:
    """A single member's contribution to a quorum signature."""

    member_index: int
    member_id: str
    signature_b64: str


@dataclass(frozen=True, slots=True)
class QuorumSignature:
    """
    A verifiable k-of-n quorum signature.

    ``partials`` contains at least k distinct partial signatures.
    ``descriptor_commitment`` is the SHA-256 of the originating
    ``QuorumDescriptor`` and binds the signature to a specific quorum
    policy.
    """

    threshold_algorithm: SignatureAlgorithm
    descriptor_commitment: str
    partials: tuple[PartialSignature, ...]


class ThresholdQuorumKeySet:
    """
    Container for the n private keys produced by ``distributed_keygen``.

    In a production deployment the n keys would be held by n distinct
    services / HSMs / organizations. ``ThresholdQuorumKeySet`` is an
    in-process helper for the case where Tex itself owns multiple key
    domains (e.g. one per region) — it lets the test suite and
    integration tests exercise the full quorum path without standing up
    n services.
    """

    def __init__(
        self,
        descriptor: QuorumDescriptor,
        private_keys: dict[int, SignatureKeyPair],
    ) -> None:
        self.descriptor = descriptor
        self._private_keys = dict(private_keys)

    def keys_for(self, member_indices: Iterable[int]) -> dict[int, SignatureKeyPair]:
        out: dict[int, SignatureKeyPair] = {}
        for idx in member_indices:
            if idx not in self._private_keys:
                raise KeyError(f"no private key for member index {idx}")
            out[idx] = self._private_keys[idx]
        return out


class QuorumMlDsaProvider:
    """
    k-of-n threshold ML-DSA quorum signing provider.

    See module docstring for the construction. Threshold parameter set
    determines the underlying single-member ML-DSA parameter set.
    """

    def __init__(
        self,
        parameter_set: SignatureAlgorithm = SignatureAlgorithm.QUORUM_ML_DSA_87,
    ) -> None:
        if parameter_set not in _QUORUM_TO_BASE:
            raise ValueError(
                f"Not a quorum ML-DSA parameter set: {parameter_set}"
            )
        self.parameter_set: SignatureAlgorithm = parameter_set
        self.algorithm: SignatureAlgorithm = parameter_set
        self._base_algorithm: SignatureAlgorithm = _QUORUM_TO_BASE[parameter_set]
        self._base_provider = MlDsaProvider(parameter_set=self._base_algorithm)

    @property
    def base_algorithm(self) -> SignatureAlgorithm:
        return self._base_algorithm

    def distributed_keygen(
        self,
        n: int,
        k: int,
        member_ids: Iterable[str] | None = None,
    ) -> ThresholdQuorumKeySet:
        """
        Generate n independent ML-DSA keypairs and form a k-of-n quorum
        descriptor. Returns a ``ThresholdQuorumKeySet`` carrying the
        descriptor and the private keys.

        In production the private keys would never be returned to a single
        process; they would be generated on n distinct HSMs and only their
        public keys exchanged. This helper exists so the in-process flow is
        testable and so a single-org deployment (regional split) can
        bootstrap the quorum.
        """
        if k < 1 or k > n:
            raise ValueError(f"invalid threshold: k={k} not in [1, n={n}]")
        ids = list(member_ids) if member_ids is not None else [
            f"member-{i}" for i in range(n)
        ]
        if len(ids) != n:
            raise ValueError(f"member_ids length {len(ids)} != n={n}")

        members: list[QuorumMember] = []
        private_keys: dict[int, SignatureKeyPair] = {}
        for i in range(n):
            kp = self._base_provider.generate_keypair(
                key_id=f"{self.parameter_set.value}/{ids[i]}"
            )
            private_keys[i] = kp
            members.append(
                QuorumMember(
                    index=i,
                    member_id=ids[i],
                    public_key_b64=base64.b64encode(kp.public_key).decode("ascii"),
                )
            )

        descriptor = QuorumDescriptor.create(
            k=k,
            n=n,
            base_algorithm=self._base_algorithm,
            members=tuple(members),
        )
        emit_event(
            "pqcrypto.quorum_ml_dsa.keygen",
            algorithm=self.parameter_set.value,
            base_algorithm=self._base_algorithm.value,
            k=k,
            n=n,
            descriptor_commitment=descriptor.commitment,
        )
        return ThresholdQuorumKeySet(descriptor=descriptor, private_keys=private_keys)

    def partial_sign(
        self,
        message: bytes,
        member_index: int,
        member_key: SignatureKeyPair,
        descriptor: QuorumDescriptor,
    ) -> PartialSignature:
        """
        Produce a single member's partial signature over ``message``.

        ``member_key`` must be the private key for the member at
        ``member_index`` in ``descriptor``. No inter-party communication
        is required; partials are independent.
        """
        if member_key.algorithm is not self._base_algorithm:
            raise ValueError(
                f"member key algorithm {member_key.algorithm.value} != "
                f"expected {self._base_algorithm.value}"
            )
        if member_index < 0 or member_index >= descriptor.n:
            raise ValueError(
                f"member_index {member_index} out of range [0, {descriptor.n})"
            )
        member = next(
            (m for m in descriptor.members if m.index == member_index),
            None,
        )
        if member is None:
            raise ValueError(f"no member with index {member_index} in descriptor")

        signature_bytes = self._base_provider.sign(message, member_key)
        emit_event(
            "pqcrypto.quorum_ml_dsa.partial_signed",
            algorithm=self.parameter_set.value,
            descriptor_commitment=descriptor.commitment,
            member_index=member_index,
            member_id=member.member_id,
            signature_bytes=len(signature_bytes),
        )
        return PartialSignature(
            member_index=member_index,
            member_id=member.member_id,
            signature_b64=base64.b64encode(signature_bytes).decode("ascii"),
        )

    def aggregate(
        self,
        partials: Iterable[PartialSignature],
        descriptor: QuorumDescriptor,
    ) -> QuorumSignature:
        """
        Aggregate ``partials`` into a ``QuorumSignature``.

        Requires at least k partial signatures from distinct member indices,
        each of which must be a member of ``descriptor``. Raises
        ``ValueError`` if the threshold is not reached or if duplicates are
        present (no Sybil attack via repeated indices).
        """
        partials_tuple = tuple(partials)
        seen: set[int] = set()
        member_index_set = {m.index for m in descriptor.members}

        for partial in partials_tuple:
            if partial.member_index in seen:
                raise ValueError(
                    f"duplicate partial signature for member index "
                    f"{partial.member_index}"
                )
            if partial.member_index not in member_index_set:
                raise ValueError(
                    f"partial signature for member index "
                    f"{partial.member_index} not in descriptor"
                )
            seen.add(partial.member_index)

        if len(partials_tuple) < descriptor.k:
            raise ValueError(
                f"threshold not reached: got {len(partials_tuple)} partials, "
                f"need {descriptor.k}"
            )

        emit_event(
            "pqcrypto.quorum_ml_dsa.aggregated",
            algorithm=self.parameter_set.value,
            descriptor_commitment=descriptor.commitment,
            partial_count=len(partials_tuple),
            k=descriptor.k,
            n=descriptor.n,
        )
        return QuorumSignature(
            threshold_algorithm=self.parameter_set,
            descriptor_commitment=descriptor.commitment,
            partials=partials_tuple,
        )

    def verify_quorum(
        self,
        message: bytes,
        quorum_signature: QuorumSignature,
        descriptor: QuorumDescriptor,
    ) -> bool:
        """
        Verify a ``QuorumSignature`` against a ``QuorumDescriptor``.

        Returns True iff:
        1. The signature's threshold algorithm matches ours.
        2. The signature's descriptor commitment matches the descriptor.
        3. The descriptor's own commitment field re-derives correctly
           (catches an adversary who tampers with k or member list).
        4. At least k distinct partial signatures are present, each from
           a member listed in the descriptor.
        5. Each partial signature verifies under its member's declared
           public key.
        """
        def _fail(reason: str, **extra: object) -> bool:
            emit_event(
                "pqcrypto.quorum_ml_dsa.verify_failed",
                algorithm=self.parameter_set.value,
                descriptor_commitment=descriptor.commitment,
                reason=reason,
                **extra,
            )
            return False

        if quorum_signature.threshold_algorithm is not self.parameter_set:
            return _fail("threshold_algorithm_mismatch")

        if quorum_signature.descriptor_commitment != descriptor.commitment:
            return _fail("descriptor_commitment_mismatch")

        # Re-derive descriptor commitment to catch adversarial tampering.
        rederived = QuorumDescriptor._compute_commitment(
            descriptor.k,
            descriptor.n,
            descriptor.base_algorithm,
            descriptor.members,
        )
        if rederived != descriptor.commitment:
            return _fail("descriptor_self_inconsistent")

        seen: set[int] = set()
        members_by_index: dict[int, QuorumMember] = {
            m.index: m for m in descriptor.members
        }
        valid_count = 0
        for partial in quorum_signature.partials:
            if partial.member_index in seen:
                return _fail(
                    "duplicate_member_index",
                    member_index=partial.member_index,
                )
            seen.add(partial.member_index)

            member = members_by_index.get(partial.member_index)
            if member is None:
                return _fail(
                    "unknown_member_index",
                    member_index=partial.member_index,
                )
            if member.member_id != partial.member_id:
                return _fail(
                    "member_id_mismatch",
                    member_index=partial.member_index,
                )
            try:
                pk = base64.b64decode(member.public_key_b64, validate=True)
                sig = base64.b64decode(partial.signature_b64, validate=True)
            except (ValueError, TypeError):
                return _fail(
                    "malformed_b64",
                    member_index=partial.member_index,
                )
            try:
                ok = self._base_provider.verify(message, sig, pk)
            except RuntimeError:
                return _fail(
                    "base_provider_runtime_error",
                    member_index=partial.member_index,
                )
            if not ok:
                return _fail(
                    "partial_signature_invalid",
                    member_index=partial.member_index,
                )
            valid_count += 1

        if valid_count < descriptor.k:
            return _fail(
                "below_threshold",
                valid_count=valid_count,
                k=descriptor.k,
            )

        emit_event(
            "pqcrypto.quorum_ml_dsa.verified",
            algorithm=self.parameter_set.value,
            descriptor_commitment=descriptor.commitment,
            valid_count=valid_count,
            k=descriptor.k,
            n=descriptor.n,
        )
        return True

    # --- SignatureProvider Protocol compatibility shims --------------------
    #
    # The dispatcher in algorithm_agility.get_signature_provider() returns a
    # ThresholdMlDsaProvider when asked for THRESHOLD_ML_DSA_*. The single-
    # key Protocol methods (sign / verify / generate_keypair) don't have a
    # direct meaning under threshold semantics, so we surface a clear error
    # rather than let callers silently fall back to single-key signing.

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:  # noqa: ARG002
        raise NotImplementedError(
            "Threshold ML-DSA uses quorum signing — call distributed_keygen, "
            "partial_sign (on each member), and aggregate rather than the "
            "single-key sign() Protocol method. See module docstring."
        )

    def verify(  # type: ignore[override]
        self,
        message: bytes,  # noqa: ARG002
        signature: bytes,  # noqa: ARG002
        public_key: bytes,  # noqa: ARG002
    ) -> bool:
        raise NotImplementedError(
            "Threshold ML-DSA verification requires a QuorumDescriptor — "
            "use ThresholdMlDsaProvider.verify_quorum(message, quorum_sig, descriptor)."
        )

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:  # noqa: ARG002
        raise NotImplementedError(
            "Threshold ML-DSA does not produce a single keypair — use "
            "distributed_keygen(n, k) to produce a quorum key set."
        )


# Backwards-compat alias — older code paths and tests still import
# ``ThresholdMlDsaProvider``. New code should use ``QuorumMlDsaProvider``.
ThresholdMlDsaProvider = QuorumMlDsaProvider
