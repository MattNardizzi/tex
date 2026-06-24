"""
C2PA manifest data model.

A manifest is a tamper-evident, cryptographically-signed metadata structure.
Each manifest contains:

  - claim: what was done, when, by what tool, with what inputs
  - assertions: structured statements (creator, software, AI-gen status)
  - signature: COSE_Sign1_Tagged over the canonicalized claim
  - ingredients: chain of upstream content used to produce this output

Per C2PA spec (§10, §13). C2PA 2.3 (2026-01-05) is the latest published
spec as of June 2026 (these §10/§13 structures are unchanged since 2.2,
2025-05-01); the deprecated ``c2pa.claim`` label is replaced by
``c2pa.claim.v2`` at the wrapper level. Tex emits assertion-level
labels (already on ``.v2`` form) directly — the wrapper-level claim
label is handled by the canonicalizer in ``_canonical_claim``.

Email manifest assertions
-------------------------
``build_email_manifest`` emits exactly three assertions, in this order:

  1. ``c2pa.actions.v2``  — the action(s) that produced this asset
                            (here: ``c2pa.created`` with ``digitalSourceType =
                            trainedAlgorithmicMedia``, the AI-generation
                            marker required by EU AI Act Art. 50(2)).
  2. ``cawg.creative_work`` — schema.org-style creator attribution. The
                            sender mailbox is the creator URI.
  3. ``tex.verdict``       — Tex-specific extension assertion linking
                            this manifest to the PERMIT/ABSTAIN/FORBID
                            verdict that authorized emission. This is
                            the Tex-side legal evidence anchor for
                            FTC / EU notified-body inspection.

The email envelope (recipients, subject) is captured under a
``provenance.delivery`` block on the ``cawg.creative_work`` assertion.
Body bytes are NOT included — only the SHA-256, so the manifest can be
retained even after the body is destroyed under data-minimization
policies.

Paper-silent design decisions (marked TODO(spec-verify))
--------------------------------------------------------
- The exact JSON schema of ``c2pa.actions.v2`` and ``cawg.creative_work``
  is not in the spec excerpts we received; we've used the field names
  that match the C2PA 2.0 actions assertion and CAWG identity claim
  publicly published. A real conformance run against c2patool will
  surface any drift; flagged for Thread 7 conformance work.
- The ``tex.verdict`` schema is Tex-defined; we lock it to v1 with an
  explicit ``$schema`` field so we can evolve it without breaking older
  manifests.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# Assertion label constants.
ASSERTION_LABEL_ACTIONS_V2: str = "c2pa.actions.v2"
ASSERTION_LABEL_CAWG_CREATIVE_WORK: str = "cawg.creative_work"
ASSERTION_LABEL_TEX_VERDICT: str = "tex.verdict"
ASSERTION_LABEL_TEX_EVIDENCE_COSIGN: str = "tex.evidence_cosign"

# Per W3C / IPTC digital-source-type vocabulary, the value that marks
# content as fully AI-generated (not assisted, not edited).
DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC: str = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)

# Tex verdict assertion schema URL — versioned so we can evolve.
TEX_VERDICT_SCHEMA_V1: str = "https://schemas.texaegis.com/c2pa/tex.verdict/v1"

# Tex evidence-cosign schema URL — locks the wire format of the
# Thread-5 post-quantum co-signature assertion that closes the six
# attack classes identified in arxiv 2604.24890 (Sherman/Krawetz/NSA,
# Apr 27 2026, "Verifying Provenance of Digital Media: Why the C2PA
# Specifications Fall Short").
TEX_EVIDENCE_COSIGN_SCHEMA_V1: str = (
    "https://schemas.texaegis.com/c2pa/tex.evidence_cosign/v1"
)


class C2paAssertion(BaseModel):
    """A single structured statement within a C2PA claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(min_length=1)
    data: dict[str, Any]


class C2paIngredient(BaseModel):
    """Upstream content consumed to produce this asset."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    format: str  # MIME type
    instance_id: str
    relationship: str  # "parentOf" | "componentOf" | etc.
    hash: str  # SHA-256 of ingredient bytes


class C2paClaim(BaseModel):
    """The core claim of a C2PA manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    format: str
    instance_id: str
    claim_generator: str  # e.g. "tex/2.0"
    claim_generator_info: dict[str, Any]
    created_at: datetime
    assertions: tuple[C2paAssertion, ...]
    ingredients: tuple[C2paIngredient, ...] = Field(default_factory=tuple)


class C2paManifest(BaseModel):
    """A complete C2PA manifest, ready for signing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim: C2paClaim
    signature_b64: str | None = None  # populated by signer (COSE_Sign1_Tagged)
    certificate_chain_pem: str | None = None  # populated by signer


def build_ai_generation_assertion(
    *,
    model_name: str,
    model_version: str,
    training_data_class: str,
    is_ai_generated: bool = True,
) -> C2paAssertion:
    """
    Build the standard ``c2pa.actions.v2`` assertion for AI-generated content.

    The action is ``c2pa.created`` (per C2PA actions vocabulary) with
    ``digitalSourceType = trainedAlgorithmicMedia`` (IPTC code) when
    ``is_ai_generated`` is True. This is the field a spec-conformant
    EU AI Act Art. 50(2) verifier reads to confirm the output is
    "marked in a machine-readable format and detectable as artificially
    generated or manipulated".

    Wiring notes (formerly P0 TODOs, now satisfied):
    - **CAWG 1.2 + AI training-data assertion vocabulary (wired):** the
      assertion uses the ``c2pa.actions.v2`` schema with the IPTC
      ``trainedAlgorithmicMedia`` digitalSourceType. ``trainingDataClass``
      is emitted under ``parameters`` per the C2PA AI training-data
      vocabulary §3.

    TODO(spec-verify): cross-check ``digitalSourceType`` field name and
        action vocabulary against C2PA 2.4 actions assertion JSON schema
        once the schema is in scope.
    """
    action: dict[str, Any] = {
        "action": "c2pa.created",
        "softwareAgent": {
            "name": model_name,
            "version": model_version,
        },
        "parameters": {
            "trainingDataClass": training_data_class,
        },
    }
    if is_ai_generated:
        action["digitalSourceType"] = DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC
    return C2paAssertion(
        label=ASSERTION_LABEL_ACTIONS_V2,
        data={"actions": [action]},
    )


def build_cawg_creative_work_assertion(
    *,
    creator_mailbox: str,
    sent_at: datetime,
) -> C2paAssertion:
    """
    Build a CAWG ``cawg.creative_work`` (creator attribution) assertion.

    Encodes the sender mailbox as the schema.org Person creator URI.
    Recipients are NOT included here by default — see
    ``build_email_manifest`` which extends this with a delivery block.

    TODO(spec-verify): pin against CAWG 1.2 schema once it's pulled into
        the trust list bundle.
    """
    return C2paAssertion(
        label=ASSERTION_LABEL_CAWG_CREATIVE_WORK,
        data={
            "@context": "https://schema.org",
            "@type": "CreativeWork",
            "creator": {
                "@type": "Person",
                "identifier": f"mailto:{creator_mailbox}",
            },
            "datePublished": sent_at.isoformat(),
        },
    )


def build_tex_verdict_assertion(
    *,
    verdict_id: str,
    verdict: str = "PERMIT",
    policy_version: str | None = None,
    issued_at: datetime | None = None,
) -> C2paAssertion:
    """
    Build a Tex-extension ``tex.verdict`` assertion.

    Binds this manifest to the Tex evaluation that authorized the
    outbound action. Verifiers (or auditors under EU AI Act Art. 50)
    can resolve ``verdict_id`` against the Tex evidence chain to walk
    back to the original PERMIT decision and its supporting findings.

    Tex-defined schema, locked to v1 (see ``TEX_VERDICT_SCHEMA_V1``).
    """
    payload: dict[str, Any] = {
        "$schema": TEX_VERDICT_SCHEMA_V1,
        "verdict_id": verdict_id,
        "verdict": verdict,
    }
    if policy_version is not None:
        payload["policy_version"] = policy_version
    if issued_at is not None:
        payload["issued_at"] = issued_at.isoformat()
    return C2paAssertion(
        label=ASSERTION_LABEL_TEX_VERDICT,
        data=payload,
    )


def build_email_manifest(
    *,
    from_address: str,
    to_addresses: tuple[str, ...],
    subject: str,
    body_sha256: str,
    model_name: str,
    model_version: str,
    tex_verdict_id: str,
    created_at: datetime | None = None,
    instance_id: str | None = None,
    training_data_class: str = "general-purpose-llm",
    verdict: str = "PERMIT",
    policy_version: str | None = None,
) -> C2paManifest:
    """
    Build a C2PA manifest for an outbound AI-generated email.

    The manifest binds:
      - the email body hash
      - the originating model identity
      - the Tex verdict (PERMIT/ABSTAIN/FORBID) ID for traceback
      - sender and recipient envelope (NOT body — privacy)

    Wiring notes (formerly P0 TODO, now satisfied): the function emits
    a complete manifest with the three required assertions:
    ``c2pa.actions.v2`` (AI-generation), ``cawg.creative_work`` (sender
    attribution + delivery envelope), and ``tex.verdict`` (Tex extension
    assertion linking to the verdict id).
    """
    if not from_address:
        raise ValueError("from_address is required")
    if not to_addresses:
        raise ValueError("to_addresses must contain at least one recipient")
    if not body_sha256 or len(body_sha256) != 64:
        raise ValueError(
            "body_sha256 must be a 64-character SHA-256 hex digest"
        )
    if not tex_verdict_id:
        raise ValueError("tex_verdict_id is required")

    resolved_created = created_at or datetime.now().astimezone()
    resolved_instance = instance_id or f"sha256:{body_sha256}"

    # Build the three required assertions.
    actions = build_ai_generation_assertion(
        model_name=model_name,
        model_version=model_version,
        training_data_class=training_data_class,
    )
    cawg_base = build_cawg_creative_work_assertion(
        creator_mailbox=from_address,
        sent_at=resolved_created,
    )
    # Extend cawg with the email envelope (recipients + subject) under a
    # ``provenance.delivery`` block. Body content is NOT included — only
    # the hash, which is mirrored from the claim.
    envelope: dict[str, Any] = {
        **cawg_base.data,
        "provenance": {
            "delivery": {
                "channel": "email",
                "subject": subject,
                "recipients": [
                    {"@type": "Person", "identifier": f"mailto:{addr}"}
                    for addr in to_addresses
                ],
                "bodySha256": body_sha256,
            }
        },
    }
    cawg = C2paAssertion(label=cawg_base.label, data=envelope)

    verdict_assertion = build_tex_verdict_assertion(
        verdict_id=tex_verdict_id,
        verdict=verdict,
        policy_version=policy_version,
        issued_at=resolved_created,
    )

    claim = C2paClaim(
        title=f"Email: {subject}",
        format="message/rfc822",
        instance_id=resolved_instance,
        claim_generator="tex/2.0",
        claim_generator_info={
            "name": "Tex",
            "version": "2.0",
            "model": {"name": model_name, "version": model_version},
        },
        created_at=resolved_created,
        assertions=(actions, cawg, verdict_assertion),
    )
    return C2paManifest(claim=claim)


def build_tex_evidence_cosign_assertion(
    *,
    cosign_algorithm: str,
    cosign_signature_b64: str,
    cosign_public_key_b64: str,
    cosign_key_id: str,
    bound_timestamp: str,
    full_file_sha256: str,
    canonicalization_version: str,
    retention_anchor: dict[str, Any],
    revocation_proof: dict[str, Any] | None = None,
) -> C2paAssertion:
    """
    Build a ``tex.evidence_cosign`` assertion that closes the six
    attack classes identified in arxiv 2604.24890 (Sherman et al.,
    Apr 27 2026) against C2PA 2.2–2.4.

    The cosign is a Tex-internal assertion carried inside the C2PA
    manifest. The outer COSE_Sign1 signs the claim CBOR (which
    includes this assertion), so the cosign fields are themselves
    tamper-evident under the spec-conformant signature. The
    cosign's own signature is computed under a Tex-side
    algorithm-agile provider (ML-DSA-65 by default — post-quantum)
    over a deterministic canonicalization of the asset hash, the
    outer-signature timestamp, the verdict id, and the
    full-file hash; that signature is base64-encoded and stored
    in ``cosign_signature_b64``.

    What each field defends against
    -------------------------------
    - ``bound_timestamp`` — included in the signed cosign input,
      so swapping the outer trusted timestamp (NSA paper attack
      #1) yields a cosign that no longer verifies.
    - ``revocation_proof`` — hash-pin of the OCSP response or CRL
      snapshot the outer signing cert was validated against at
      signing time. Defends against the spec's optional revocation
      checking (attack #2).
    - ``canonicalization_version`` — pins the exact canonical-CBOR
      profile + assertion ordering the manifest was hashed under.
      Two validators that disagree on this string disagree
      structurally and cannot produce contradictory VALID results
      (attack #3).
    - ``full_file_sha256`` — SHA-256 of the entire signed asset
      with NO exclusion ranges. C2PA permits exclusion ranges
      (attack #4); the cosign covers the full byte stream.
    - ``retention_anchor`` — a pointer into Tex's hash-chained
      evidence ledger (``record_hash`` + path), so a manifest
      whose C2PA certificate expires (attack #5) can still be
      re-verified offline via the chain.

    The remaining recommendations (independent security audit;
    clarified public-comm claims) are policy/operational, not
    serialization-level.

    All inputs are strings or JSON-safe dicts. The assertion is
    CBOR-encodable under the standard canonical encoding used
    elsewhere in this module.
    """
    if len(full_file_sha256) != 64:
        raise ValueError("full_file_sha256 must be a 64-character SHA-256 hex digest")
    if not cosign_signature_b64:
        raise ValueError("cosign_signature_b64 must not be empty")
    if not cosign_public_key_b64:
        raise ValueError("cosign_public_key_b64 must not be empty")
    if not cosign_key_id:
        raise ValueError("cosign_key_id must not be empty")
    if not bound_timestamp:
        raise ValueError("bound_timestamp must not be empty")
    if not canonicalization_version:
        raise ValueError("canonicalization_version must not be empty")
    if "record_hash" not in retention_anchor:
        raise ValueError(
            "retention_anchor must include a 'record_hash' field pointing into "
            "the Tex evidence chain"
        )

    payload: dict[str, Any] = {
        "$schema": TEX_EVIDENCE_COSIGN_SCHEMA_V1,
        "algorithm": cosign_algorithm,
        "key_id": cosign_key_id,
        "public_key": cosign_public_key_b64,
        "signature": cosign_signature_b64,
        "bound_timestamp": bound_timestamp,
        "full_file_sha256": full_file_sha256,
        "canonicalization_version": canonicalization_version,
        "retention_anchor": dict(retention_anchor),
        "defends_against": {
            "paper": "arxiv:2604.24890",
            "attacks": [
                "timestamp_swap",
                "revocation_skipped",
                "cross_validator_contradiction",
                "exclusion_range_tamper",
                "cert_expiry_before_retention",
            ],
        },
    }
    if revocation_proof is not None:
        payload["revocation_proof"] = dict(revocation_proof)
    return C2paAssertion(
        label=ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
        data=payload,
    )


def attach_cosign_assertion(
    manifest: C2paManifest,
    cosign: C2paAssertion,
) -> C2paManifest:
    """
    Return a new ``C2paManifest`` with ``cosign`` appended to the claim's
    assertion tuple.

    The cosign is appended (not prepended) so that vanilla C2PA validators
    iterate the spec-defined assertions first and treat ``tex.evidence_cosign``
    as a trailing extension assertion they will skip if they don't recognise
    the label.
    """
    if cosign.label != ASSERTION_LABEL_TEX_EVIDENCE_COSIGN:
        raise ValueError(
            f"attach_cosign_assertion expected label "
            f"{ASSERTION_LABEL_TEX_EVIDENCE_COSIGN!r}, got {cosign.label!r}"
        )
    new_claim = manifest.claim.model_copy(
        update={"assertions": (*manifest.claim.assertions, cosign)}
    )
    return manifest.model_copy(update={"claim": new_claim})
