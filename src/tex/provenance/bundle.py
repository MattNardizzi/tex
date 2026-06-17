"""
Offline evidence bundle + standalone verifier — the court-exhibit core.

A ``SealedFactBundle`` is the portable artifact you hand an auditor, a
regulator, or opposing counsel: the sealed Proof-Carrying Verdict Records
(``SealedFactRecord``) from a ``SealedFactLedger``, the public key the ledger
claims to have signed with, and — optionally — the component ``TexEvidence``
snapshots that produced each record's e-value, so the *composition itself* is
replayable. It serializes to plain JSON and carries everything a verifier needs.

``verify_sealed_fact_bundle`` is the standalone verifier. It does NOT import or
need a live ledger, a database, or the Tex runtime — only the bundle, a
**pinned** public key, and a signature provider. It re-derives every claim from
scratch:

  1. **Chain integrity** — recomputes ``payload_sha256`` from each fact's own
     canonical payload and re-links the chain. Any reordering, deletion, or
     tamper (including inside an embedded e-value proof) breaks replay. It never
     trusts the hashes the bundle claims.
  2. **Authorship** — verifies each record's signature against the **pinned**
     key, not the key embedded in the bundle. This is the load-bearing honesty
     point: a self-describing signature only proves *Tex* authored a record if
     you check it against *Tex's known key*. An attacker who re-signs a forged
     bundle with their own key (and embeds their own public key) is caught here,
     because the signature fails against the pin — and ``key_matches_pin`` flags
     the substitution independently.
  3. **Composition replay** — when the components are present, recomputes each
     ``CombinedEvidence`` from them (using the *sealed* combiner) and checks the
     scalar matches. A missing-components record is reported honestly as
     "not recomputable", never silently passed as if it were re-derived.

Post-quantum dual signatures
----------------------------
A bundle produced by a dual-signing ledger additionally carries, per record, a
crypto-agile ``SealEnvelope`` (ECDSA-P256 + ML-DSA-65 over the *same*
``record_hash``) and, at the bundle level, the public keys for each seal
algorithm (``seal_public_keys``). The verifier checks the envelope against
**pinned** keys exactly as it pins the ECDSA key: pass ``pinned_seal_keys`` to
confirm the post-quantum authorship (``pq_secured``). Backward compatible — a
legacy ECDSA-only bundle (no envelopes, no ``seal_public_keys``) verifies
through ``signature_b64`` exactly as before; ``is_valid`` is unchanged by the
post-quantum additions. The chain proves integrity, the ECDSA signature proves
authorship for today's verifiers, the ML-DSA signature proves authorship against
a quantum adversary.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.evidence import (
    TexEvidence,
    compose_arithmetic_mean,
    compose_product_independence,
)
from tex.events._ecdsa_provider import default_signature_provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureProvider
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactRecord, SealPublicKey
from tex.provenance.seal_envelope import is_post_quantum_algorithm, verify_envelope

__all__ = [
    "SealedFactBundle",
    "BundleVerificationReport",
    "export_sealed_fact_bundle",
    "verify_sealed_fact_bundle",
]

_BUNDLE_VERSION = "1"


def _stable_json(obj: object) -> str:
    """The ledger's exact canonical form — must match ``provenance/ledger.py``
    byte-for-byte or recomputed hashes won't line up."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SealedFactBundle(BaseModel):
    """Portable, JSON-serializable export of a sealed-fact chain.

    Frozen. ``components`` is an optional side-store of the ``TexEvidence`` that
    fed each record's ``CombinedEvidence`` — include it to make the composition
    independently replayable; omit it and the verifier still checks the chain
    and the signatures, reporting the proofs as "not recomputable".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_version: str = _BUNDLE_VERSION
    export_name: str = Field(min_length=1, max_length=200)
    exported_at: datetime
    # The ledger's CLAIMED signing identity — never the basis of trust on its
    # own; the verifier checks against a pinned key.
    signing_key_id: str
    public_key_b64: str
    records: tuple[SealedFactRecord, ...]
    components: tuple[TexEvidence, ...] = ()
    # Public keys for each crypto-agile seal algorithm (ECDSA-P256 + ML-DSA-65),
    # so a verifier can check the dual-signature envelope. Empty for a legacy
    # ECDSA-only bundle (the verifier falls back to ``public_key_b64``). Like
    # ``public_key_b64``, these are CLAIMED keys — never trusted on their own; the
    # verifier checks signatures against PINNED keys (see ``verify_sealed_fact_bundle``).
    seal_public_keys: tuple[SealPublicKey, ...] = ()

    def to_json(self) -> str:
        """Serialize to portable JSON (the artifact you ship)."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str) -> "SealedFactBundle":
        """Reconstruct a bundle from its JSON — the verifier's entry point."""
        return cls.model_validate_json(raw)


@dataclass(frozen=True, slots=True)
class BundleVerificationReport:
    """The standalone verifier's verdict — every check reported separately so a
    reader sees exactly what was and wasn't proven."""

    record_count: int
    chain_intact: bool
    chain_break_at: int | None
    signatures_valid: bool
    signature_invalid_at: int | None
    # Did the bundle's claimed public key equal the pinned key?
    key_matches_pin: bool
    # Composition replay over records whose components were in the bundle.
    compositions_checked: int
    compositions_ok: int
    composition_mismatches: tuple[int, ...] = field(default=())
    # Records with an e-value whose components were NOT in the bundle (honest
    # "couldn't re-derive", not a tamper).
    not_recomputable: tuple[int, ...] = field(default=())

    # ---- post-quantum dual-signature checks (additive; never affect is_valid) --
    # Every record carried a two-algorithm seal envelope.
    dual_signed: bool = False
    # Distinct seal-envelope versions and algorithms observed across records.
    seal_versions: tuple[str, ...] = field(default=())
    seal_algorithms: tuple[str, ...] = field(default=())
    # Every record's post-quantum signature verified against the PINNED PQ key.
    # False when no PQ key was pinned (the post-quantum authorship is then
    # unconfirmed, not disproven).
    pq_signatures_valid: bool = False
    pq_signature_invalid_at: int | None = None
    # Did the bundle's CLAIMED PQ public key equal the pinned PQ key? (Same
    # load-bearing pin as ``key_matches_pin``, for the post-quantum key.)
    pq_key_matches_pin: bool = False
    # First record whose envelope had an algorithm-mismatch / failed-but-pinned
    # signature (tamper or forgery in the dual-signature layer).
    envelope_mismatch_at: int | None = None

    @property
    def is_valid(self) -> bool:
        """True iff the chain is intact, every signature verifies against the
        pinned key, the claimed key matched the pin, and no recomputed
        composition disagreed with its seal. ``not_recomputable`` does NOT fail
        validity (a sealed chain is still authentic without the components) —
        check ``fully_replayable`` for that stronger property.

        Defined by the ECDSA-level checks ONLY, so a legacy ECDSA-only bundle is
        as valid as it ever was; the post-quantum properties are reported
        separately (``pq_secured``)."""
        return (
            self.chain_intact
            and self.signatures_valid
            and self.key_matches_pin
            and not self.composition_mismatches
        )

    @property
    def fully_replayable(self) -> bool:
        """True iff ``is_valid`` AND every e-value-bearing record was recomputed
        from its components — the strongest court-exhibit property."""
        return self.is_valid and not self.not_recomputable

    @property
    def pq_secured(self) -> bool:
        """True iff ``is_valid`` AND every record is dual-signed AND every
        post-quantum signature verified against the PINNED PQ key AND the bundle's
        claimed PQ key matched the pin AND no envelope mismatch was found — the
        strongest, quantum-resistant authorship property. Requires the caller to
        pin a post-quantum key via ``pinned_seal_keys``; without it this is
        ``False`` (unconfirmed, never silently asserted)."""
        return (
            self.is_valid
            and self.dual_signed
            and self.pq_signatures_valid
            and self.pq_key_matches_pin
            and self.envelope_mismatch_at is None
        )


def export_sealed_fact_bundle(
    ledger: SealedFactLedger,
    *,
    export_name: str,
    components: tuple[TexEvidence, ...] = (),
    exported_at: datetime | None = None,
) -> SealedFactBundle:
    """Package a ledger's sealed facts (and optionally the component evidence)
    into a portable bundle. ``components`` should be the ``TexEvidence`` that fed
    the records' ``CombinedEvidence`` — include them to make the bundle fully
    replayable offline."""
    return SealedFactBundle(
        export_name=export_name,
        exported_at=exported_at or datetime.now(UTC),
        signing_key_id=ledger.signing_key_id,
        public_key_b64=base64.b64encode(ledger.public_key_pem).decode("ascii"),
        records=ledger.list_all(),
        components=tuple(components),
        # The crypto-agile seal public keys (ECDSA + ML-DSA), when the ledger
        # dual-signs. ``getattr`` keeps the exporter duck-typed for any ledger.
        seal_public_keys=tuple(getattr(ledger, "seal_public_keys", ())),
    )


def verify_sealed_fact_bundle(
    bundle: SealedFactBundle,
    *,
    pinned_public_key_pem: bytes,
    provider: SignatureProvider | None = None,
    pinned_seal_keys: Mapping[str, bytes] | None = None,
) -> BundleVerificationReport:
    """Verify a bundle from scratch, holding only the bundle, a PINNED public
    key, and a signature provider (defaults to ECDSA-P256). Standalone: needs no
    ledger, database, or Tex runtime. See the module docstring for the checks and
    why pinning the key is load-bearing.

    ``pinned_seal_keys`` maps an algorithm value (e.g. ``"ml-dsa-65"``) to its
    *trusted* public-key bytes, enabling verification of the post-quantum
    dual-signature envelope. The ECDSA pin is always ``pinned_public_key_pem``
    (it cannot be weakened via this map). Omit it and the bundle still verifies
    on the ECDSA path (``is_valid``); the report's ``pq_secured`` is then
    ``False`` because the post-quantum authorship was not pinned, never silently
    asserted."""
    provider = provider or default_signature_provider()

    try:
        claimed_key = base64.b64decode(bundle.public_key_b64.encode("ascii"))
    except Exception:  # noqa: BLE001
        claimed_key = b""
    key_matches_pin = bool(claimed_key) and claimed_key == pinned_public_key_pem

    # Envelope pin set: ECDSA pinned to the canonical key (never overridable),
    # plus any post-quantum pins the caller supplied.
    ecdsa_value = SignatureAlgorithm.ECDSA_P256.value
    envelope_pins: dict[str, bytes] = {ecdsa_value: pinned_public_key_pem}
    if pinned_seal_keys:
        for algo, key in pinned_seal_keys.items():
            if algo != ecdsa_value:
                envelope_pins[algo] = key
    pq_pins = {a: k for a, k in envelope_pins.items() if is_post_quantum_algorithm(a)}

    # Load-bearing PQ pin: the bundle's CLAIMED PQ key must equal the pinned one.
    claimed_seal_keys: dict[str, bytes] = {}
    for pk in bundle.seal_public_keys:
        try:
            claimed_seal_keys[pk.algorithm] = base64.b64decode(
                pk.public_key_b64.encode("ascii")
            )
        except Exception:  # noqa: BLE001
            continue
    pq_key_matches_pin = bool(pq_pins) and all(
        claimed_seal_keys.get(algo) == key for algo, key in pq_pins.items()
    )

    comp_by_id: dict[UUID, TexEvidence] = {c.evidence_id: c for c in bundle.components}

    chain_intact = True
    chain_break_at: int | None = None
    signatures_valid = True
    signature_invalid_at: int | None = None
    compositions_checked = 0
    compositions_ok = 0
    mismatches: list[int] = []
    not_recomputable: list[int] = []

    # post-quantum envelope aggregates
    all_dual = len(bundle.records) > 0
    pq_all_valid = True
    pq_signature_invalid_at: int | None = None
    envelope_mismatch_at: int | None = None
    seal_versions_seen: set[str] = set()
    seal_algos_seen: set[str] = set()

    previous_hash: str | None = None
    for idx, rec in enumerate(bundle.records):
        # 1) chain replay — recompute, never trust the claimed hashes
        payload_sha256 = _sha256_hex(_stable_json(rec.fact.canonical_payload()))
        record_hash = _sha256_hex(
            _stable_json(
                {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
            )
        )
        if (
            rec.previous_hash != previous_hash
            or rec.payload_sha256 != payload_sha256
            or rec.record_hash != record_hash
        ):
            chain_intact = False
            chain_break_at = idx
            break

        # 2) authorship — verify over the RECOMPUTED hash against the PINNED key
        try:
            sig = base64.b64decode(rec.signature_b64.encode("ascii"))
            ok = provider.verify(record_hash.encode("ascii"), sig, pinned_public_key_pem)
        except Exception:  # noqa: BLE001
            ok = False
        if not ok and signatures_valid:
            signatures_valid = False
            signature_invalid_at = idx

        previous_hash = rec.record_hash

        # 2b) post-quantum dual signature — verify the crypto-agile envelope over
        #     the RECOMPUTED record_hash against the PINNED seal keys. Additive:
        #     this never changes is_valid (the ECDSA path above owns that).
        env = rec.seal_envelope
        env_res = verify_envelope(record_hash, env, pinned_keys=envelope_pins)
        if env is not None:
            seal_versions_seen.add(env.seal_version)
            seal_algos_seen.update(env.algorithms())
            if not env.is_dual:
                all_dual = False
        else:
            all_dual = False
        if env_res.mismatch and envelope_mismatch_at is None:
            envelope_mismatch_at = idx
        if pq_pins:
            if not env_res.pq_verified:
                pq_all_valid = False
                if pq_signature_invalid_at is None:
                    pq_signature_invalid_at = idx
        else:
            pq_all_valid = False

        # 3) composition replay (when components are present)
        ev = rec.fact.evidence
        if ev is None or ev.combiner == "abstain" or not ev.component_ids:
            continue
        comps = [comp_by_id[cid] for cid in ev.component_ids if cid in comp_by_id]
        if len(comps) != len(ev.component_ids):
            not_recomputable.append(idx)
            continue
        compositions_checked += 1
        if ev.combiner == "product_independence":
            recomputed = compose_product_independence(
                comps, justification=ev.justification or "replay"
            )
        else:
            recomputed = compose_arithmetic_mean(comps)
        if math.isclose(
            recomputed.log_e_value, ev.log_e_value, rel_tol=1e-9, abs_tol=1e-12
        ):
            compositions_ok += 1
        else:
            mismatches.append(idx)

    dual_signed = all_dual and chain_intact and len(bundle.records) > 0
    pq_signatures_valid = (
        pq_all_valid and bool(pq_pins) and chain_intact and len(bundle.records) > 0
    )

    return BundleVerificationReport(
        record_count=len(bundle.records),
        chain_intact=chain_intact,
        chain_break_at=chain_break_at,
        signatures_valid=signatures_valid,
        signature_invalid_at=signature_invalid_at,
        key_matches_pin=key_matches_pin,
        compositions_checked=compositions_checked,
        compositions_ok=compositions_ok,
        composition_mismatches=tuple(mismatches),
        not_recomputable=tuple(not_recomputable),
        dual_signed=dual_signed,
        seal_versions=tuple(sorted(seal_versions_seen)),
        seal_algorithms=tuple(sorted(seal_algos_seen)),
        pq_signatures_valid=pq_signatures_valid,
        pq_signature_invalid_at=pq_signature_invalid_at,
        pq_key_matches_pin=pq_key_matches_pin,
        envelope_mismatch_at=envelope_mismatch_at,
    )
