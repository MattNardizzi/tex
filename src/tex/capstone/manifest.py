"""
The capstone verdict object — one sealed manifest binding one decision to all
eight Wave-2 properties (ROADMAP § THE CAPSTONE).

[Architecture: composition layer over engine + provenance + evidence + voice +
interchange + adversarial — owns NO crypto and NO verdict logic of its own.]

``CapstoneVerdict`` is design (B) from the capstone thread: a **sealed
manifest-of-digests**, not a mega-object. It binds ONE decision's identity
(request_id, content_sha256, determinism_fingerprint, verdict) to the digests,
pins, verification results and maturity labels of each property's artifact,
while the artifacts themselves travel in their NATIVE bundles alongside, each
verified by its own module verifier.

Rejected design (named, per doctrine): (A) one mega-object embedding every
chain record and proof in a single sealed blob. Rejection, specific to this
tree: the three chains verify three different byte disciplines — the evidence
chain recomputes hashes from raw ``payload_json`` strings
(``bench/evidence_bundle.py``), the sealed-fact chain recomputes from
``fact.canonical_payload()`` through pydantic serialization
(``provenance/ledger.py``), and the voice chain hashes its own payload dicts
(``voice/attestation.py``). One blob would have to round-trip all three
byte-exact forever, its canonical bytes would balloon with every artifact, and
a signature over the blob proves only who sealed the blob — it invites
collapsing object-authorship with chain-integrity, the exact confusion the
honesty doctrine bans. The hash CHAIN proves integrity; a signature proves
authorship of one record. Three chains, three pins, native verifiers.

How the manifest becomes ONE object rather than twelve receipts:

1. every artifact file is digest-bound here (sha256 over the file bytes,
   recomputed by the verifier before parsing);
2. the manifest's own canonical-bytes digest is sealed as the FINAL fact of
   the SAME ``SealedFactLedger`` epoch that holds the decision — so the
   verdict's own chain head commits to the manifest, and the manifest commits
   to everything else (the would-be circularity is broken by pinning the
   PRE-seal epoch head + record count here instead of a ledger-file digest);
3. the post-seal checkpoint root is recomputed from the shipped chain's
   record hashes and cosigned by >=3 witnesses — the witnessed root covers
   the sealed manifest too.

Maturity of the COMPOSITION itself: ``research-early`` — the composition is
real and replayable today with test-mode/shim halves honestly labelled
(L1 stand-in, L2 real signature over a stand-in ITA key with the
hardware-measurement half runtime-dependent, L4/L12 certificates
uncertified, L11 entailment half BLOCKED, L12 QIF estimate-only); it is
promoted only as each RUNTIME-DEPENDENT half lands. The per-property ``status`` fields below are
receipts, not hedges: over-claiming combinations are rejected at construction
by the validators in ``CapstoneVerdict`` (the L12 ``Literal[False]`` pattern,
applied at composition level).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "tex.capstone/verdict.v1"

# The chain labels — exactly the three cryptographically separate chains.
CHAIN_SEALED_FACTS = "sealed_fact_ledger"
CHAIN_EVIDENCE = "evidence_records"
CHAIN_VOICE = "voice_attestation"

# Leap -> ROADMAP capstone property index (1..8). Two properties are carried
# by leap pairs (L7+L9 -> 4, L5+L12 -> 8), so indices repeat across leaps but
# the SET over all twelve entries must be exactly {1..8}.
PROPERTY_INDEX: dict[str, int] = {
    "L2": 1,   # attestation-bound to the exact guardrail (real signature)
    "L1": 2,   # ZK-relation proof-carrying (stand-in backend)
    "L10": 3,  # PQ-maturity probed; signal lowers the verdict
    "L7": 4,   # anytime-valid adversary-completeness (with L9)
    "L9": 4,   # anytime-valid drift spine (with L7)
    "L4": 5,   # reversibility x blast-radius floor
    "L3": 6,   # negative-knowledge certificate over the epoch
    "L6": 7,   # witness-cosigned checkpoint (self-hosted witnesses)
    "L5": 8,   # self-governed (with L12)
    "L12": 8,  # robustness + QIF posture of the output (with L5)
    "L8": 8,   # credal hold on the ABSTAIN surface (with L5/L12)
    "L11": 8,  # sealed spoken-proof commitment (with L5/L12)
}

LEAPS: tuple[str, ...] = (
    "L1", "L2", "L3", "L4", "L5", "L6",
    "L7", "L8", "L9", "L10", "L11", "L12",
)

Status = Literal[
    "green",
    "green_test_mode",
    "uncertified",
    "estimate_only",
    "blocked",
    "runtime_dependent",
]

# Phrases banned UNQUALIFIED from prose this module's authors write (titles,
# summaries, the sealed claim). Module-sourced caveats may contain some of
# these words inside negations ("no proven coverage") — those caveats are
# carried VERBATIM and are vetted by the vocabulary test, which strips known
# module constants before scanning. This list guards what WE say.
BANNED_AUTHORED_PHRASES: tuple[str, ...] = (
    "guarantee",
    "proven correct",
    "provable ignorance",
    "never saw",
    "proven complete",
    "post-quantum signed",
    "regulator-grade",
)

# Authored caveat: the one number people will misquote.
TREE_SIZE_CAVEAT = (
    "tree_size counts leaves of EVERY sealed-fact kind (ATTEMPT, DECISION, "
    "ENFORCEMENT, DRIFT, ANSWER) — never cite it as a decision count or an "
    "attempt count"
)

# Authored caveat: applies to all three chains identically.
PIN_CAVEAT = (
    "authorship is UNVERIFIED without the out-of-band pin: the hash chain "
    "proves integrity; a signature proves authorship of one record only "
    "against a pinned key. Three chains, three pins — never collapse them"
)


def stable_json(obj: Any) -> str:
    """The repo's canonical JSON discipline (sort_keys, tight separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex_text(text: str) -> str:
    return sha256_hex_bytes(text.encode("utf-8"))


class ArtifactRef(BaseModel):
    """One digest-bound artifact file carried alongside the manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    filename: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media: Literal["json", "jsonl", "jwt"]
    # Which of the three chains the artifact carries, if any.
    chain: str | None = None


class DecisionIdentity(BaseModel):
    """The ONE decision this capstone object is about."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str = Field(min_length=1)
    verdict: Literal["PERMIT", "ABSTAIN", "FORBID"]
    final_score: float = Field(ge=0.0, le=1.0)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    determinism_fingerprint: str = Field(min_length=1)
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    # Where this decision's facts sit in the sealed epoch.
    attempt_fact_sequence: int = Field(ge=0)
    decision_fact_sequence: int = Field(ge=0)


class EpochBinding(BaseModel):
    """Binds the manifest to the sealed-fact epoch WITHOUT a file digest.

    The ledger bundle cannot be digest-bound here (it contains the sealed
    manifest digest — circular); instead the manifest pins the pre-seal head
    hash + record count, and the sealed ANSWER fact at
    ``sealed_fact_sequence`` carries this manifest's digest back into the
    chain. The offline verifier closes the loop from the bundle side.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_count_pre_seal: int = Field(ge=1)
    epoch_head_hash_pre_seal: str = Field(pattern=r"^[0-9a-f]{64}$")
    # The capstone ANSWER fact is appended at exactly this sequence.
    sealed_fact_sequence: int = Field(ge=1)
    attempt_fact_count: int = Field(ge=0)
    decision_kind_fact_count: int = Field(ge=0)
    tree_size_caveat: str = Field(min_length=1)

    @model_validator(mode="after")
    def _pin_positions(self) -> "EpochBinding":
        if self.sealed_fact_sequence != self.record_count_pre_seal:
            raise ValueError(
                "the capstone fact must be the first record AFTER the "
                "pre-seal epoch (sequence == record_count_pre_seal)"
            )
        if self.tree_size_caveat != TREE_SIZE_CAVEAT:
            raise ValueError("tree_size caveat must be carried verbatim")
        return self


class PinDigests(BaseModel):
    """Digests of the trust anchors. The manifest commits to WHICH keys the
    composition used; trust still comes from the relying party's own
    out-of-band copy of the pins, never from this file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ledger_signing_key_id: str = Field(min_length=1)
    ledger_public_key_pem_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_public_key_b64_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    voice_public_key_b64_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # The L2 composite-attestation signing key the relying party pins
    # out-of-band (Intel Trust Authority's published key in production; a
    # local stand-in in the offline demo). The signed token verifies against
    # THIS key — never one shipped inside the bundle under verification.
    ita_public_key_pem_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    log_name: str = Field(min_length=1)
    log_public_key_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    witness_roster_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    nli_model_id: str = Field(min_length=1)
    pin_caveat: str = Field(min_length=1)

    @model_validator(mode="after")
    def _caveat_verbatim(self) -> "PinDigests":
        if self.pin_caveat != PIN_CAVEAT:
            raise ValueError("pin caveat must be carried verbatim")
        return self


class PropertyAttestation(BaseModel):
    """One leap's machine-readable status inside the composed object.

    ``verification`` is the composition-time snapshot of the LEAP MODULE'S OWN
    verifier output — the capstone never re-implements a verifier, it
    delegates and records. ``caveats`` carry the module's half-specific
    honesty strings VERBATIM.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    leap: str = Field(min_length=2, max_length=3)
    property_index: int = Field(ge=1, le=8)
    title: str = Field(min_length=1, max_length=200)
    scope: Literal["decision", "epoch", "system"]
    status: Status
    runtime_dependent: bool
    maturity: Literal[
        "production", "research_solid", "research_early", "speculative"
    ]
    halves: dict[str, Status] = Field(default_factory=dict)
    caveats: tuple[str, ...] = ()
    verification: dict[str, Any] = Field(default_factory=dict)
    artifacts: tuple[str, ...] = ()
    ledger_sequences: tuple[int, ...] = ()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class CapstoneVerdict(BaseModel):
    """THE composed object. The name is a composition label on purpose: it
    says "the capstone composition of one verdict", not "all eight properties
    proven" — the per-property ``status`` fields say exactly which halves are
    green / test-mode / uncertified / estimate-only / blocked."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["tex.capstone/verdict.v1"] = SCHEMA_VERSION
    created_at: str = Field(min_length=1)
    decision: DecisionIdentity
    epoch: EpochBinding
    pins: PinDigests
    artifacts: tuple[ArtifactRef, ...]
    properties: tuple[PropertyAttestation, ...]
    summary: str = Field(min_length=1, max_length=2000)

    # ------------------------------------------------------------- identity
    def canonical_bytes(self) -> bytes:
        return stable_json(self.model_dump(mode="json")).encode("utf-8")

    def manifest_sha256(self) -> str:
        return sha256_hex_bytes(self.canonical_bytes())

    def property_for(self, leap: str) -> PropertyAttestation:
        for prop in self.properties:
            if prop.leap == leap:
                return prop
        raise KeyError(leap)

    def artifact_for(self, name: str) -> ArtifactRef:
        for ref in self.artifacts:
            if ref.name == name:
                return ref
        raise KeyError(name)

    @property
    def honest_split(self) -> dict[str, tuple[str, ...]]:
        """status -> ("L3", "L11.seal", "L11.entailment", ...) — a leap with
        split halves appears once per half, never collapsed."""
        split: dict[str, list[str]] = {}
        for prop in self.properties:
            if prop.halves:
                for half, status in sorted(prop.halves.items()):
                    split.setdefault(status, []).append(f"{prop.leap}.{half}")
            else:
                split.setdefault(prop.status, []).append(prop.leap)
        return {k: tuple(v) for k, v in sorted(split.items())}

    # ------------------------------------------------- honesty pins (hard)
    @model_validator(mode="after")
    def _enforce_honesty_pins(self) -> "CapstoneVerdict":
        leaps = [p.leap for p in self.properties]
        _require(
            sorted(leaps) == sorted(LEAPS) and len(set(leaps)) == 12,
            "exactly the twelve leaps, once each",
        )
        _require(
            {p.property_index for p in self.properties} == set(range(1, 9)),
            "the twelve leaps must cover exactly the eight capstone properties",
        )
        for prop in self.properties:
            _require(
                PROPERTY_INDEX[prop.leap] == prop.property_index,
                f"{prop.leap}: wrong capstone property index",
            )

        by = {p.leap: p for p in self.properties}

        l1 = by["L1"]
        _require(
            l1.status == "green_test_mode" and l1.runtime_dependent,
            "L1 is a stand-in backend: only green_test_mode + "
            "runtime_dependent is constructible",
        )
        _require(
            l1.verification.get("stand_in") is True
            and l1.verification.get("regulator_grade") is False,
            "L1 verification must carry stand_in=True and "
            "regulator_grade=False verbatim from the arbiter",
        )

        l2 = by["L2"]
        _require(
            l2.status == "green"
            and l2.runtime_dependent
            and l2.halves.get("signature") == "green"
            and l2.halves.get("hardware_measurement") == "runtime_dependent",
            "L2: the verdict-binding signature half is green (a real JWS, "
            "alg != none, verified fail-closed against a pinned key); the "
            "hardware-rooted measurement half stays runtime_dependent — "
            "claiming it green is unconstructible here",
        )
        _require(
            l2.verification.get("test_mode") is False
            and l2.verification.get("signature_verified") is True
            and str(l2.verification.get("alg", "")).lower() not in ("", "none"),
            "L2 verification must carry a real verified signature "
            "(test_mode=False, signature_verified=True, alg != none) — the "
            "alg=none test-mode bypass is unconstructible for the capstone",
        )

        l3 = by["L3"]
        _require(
            l3.scope == "epoch"
            and l3.verification.get("conservation_status") == "GATED-HOLDS",
            "L3 binds an epoch and must record GATED-HOLDS conservation",
        )

        l4 = by["L4"]
        _require(
            l4.halves.get("floor") == "green"
            and l4.halves.get("certificate") == "uncertified"
            and l4.verification.get("certificate", {}).get("certified") is False,
            "L4: the live floor is green; the certificate is uncertified "
            "until a field corpus — certified=True is unconstructible here",
        )

        l5 = by["L5"]
        _require(
            l5.verification.get("ruling_allowed") is False,
            "L5 must record the denied weakening (allowed=False)",
        )

        l6 = by["L6"]
        _require(
            l6.verification.get("federated") is False
            and bool(l6.verification.get("federated_reason")),
            "L6: federated is structurally False this wave and the reason "
            "string must ride along — claiming federation is unconstructible",
        )

        l9 = by["L9"]
        _require(
            l9.verification.get("acted") is True
            and l9.verification.get("anytime_valid") is True,
            "L9 must record an acted, anytime-valid spine step",
        )

        l10 = by["L10"]
        _require(
            l10.halves.get("pq_signing") == "runtime_dependent",
            "L10: the pq_signing half stays runtime_dependent — it is a "
            "property of the runtime, never of this manifest",
        )
        l10_outcome = l10.verification.get("maturity_outcome")
        if l10_outcome == "lowered_to_abstain":
            _require(
                l10.verification.get("pq_durable") is False,
                "L10: a lowered outcome records the non-durable signer it "
                "lowered for — pq_durable=True is unconstructible here",
            )
        elif l10_outcome == "durable_not_lowered":
            # pq_durable=True is constructible ONLY as this coherent record:
            # an honored claim against a durable, named backend. Durability
            # without coherence stays unconstructible, and the offline
            # verifier additionally requires the PERMIT/no-flag decision doc.
            _require(
                l10.verification.get("pq_durable") is True
                and l10.verification.get("claim_honored") is True
                and l10.verification.get("signer_maturity") == "durable"
                and bool(l10.verification.get("active_backend_id"))
                and l10.ledger_sequences == (),
                "L10: a durable outcome is constructible only as the "
                "coherent claim-honored record (durable maturity + named "
                "backend + no sealed-fact claim)",
            )
        else:
            _require(
                False,
                "L10 must record maturity_outcome: 'lowered_to_abstain' "
                "or 'durable_not_lowered'",
            )

        l11 = by["L11"]
        _require(
            l11.halves.get("seal") == "green"
            and l11.halves.get("entailment") == "blocked",
            "L11: only the seal half composes; the entailment half is "
            "BLOCKED (torch/GPU + field corpus)",
        )
        _require(
            l11.verification.get("lambda_hat") is None
            and l11.verification.get("calibrated") is False,
            "L11 seals the ABSENCE of lambda-hat; a calibrated commitment "
            "is unconstructible in this schema",
        )

        l12 = by["L12"]
        cert = l12.verification.get("certificate", {})
        _require(
            l12.halves.get("robustness") == "uncertified"
            and l12.halves.get("qif") == "estimate_only"
            and cert.get("certified") is False
            and cert.get("qif_estimate_only") is True,
            "L12: synthetic-neighborhood robustness stays uncertified and "
            "QIF is a point estimate only — stronger claims are "
            "unconstructible here",
        )

        # Authored-prose vocabulary: what WE write must not over-claim.
        authored = [self.summary] + [p.title for p in self.properties]
        lowered = " ".join(authored).lower()
        for phrase in BANNED_AUTHORED_PHRASES:
            _require(
                phrase not in lowered,
                f"authored prose contains banned unqualified phrase: "
                f"{phrase!r}",
            )
        return self


__all__ = [
    "ArtifactRef",
    "BANNED_AUTHORED_PHRASES",
    "CHAIN_EVIDENCE",
    "CHAIN_SEALED_FACTS",
    "CHAIN_VOICE",
    "CapstoneVerdict",
    "DecisionIdentity",
    "EpochBinding",
    "LEAPS",
    "PIN_CAVEAT",
    "PROPERTY_INDEX",
    "PinDigests",
    "PropertyAttestation",
    "SCHEMA_VERSION",
    "TREE_SIZE_CAVEAT",
    "sha256_hex_bytes",
    "sha256_hex_text",
    "stable_json",
]
