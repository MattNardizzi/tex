"""
C2PA manifest data model.

A manifest is a tamper-evident, cryptographically-signed metadata structure.
Each manifest contains:

  - claim: what was done, when, by what tool, with what inputs
  - assertions: structured statements (creator, software, AI-gen status)
  - signature: COSE_Sign1_Tagged over the canonicalized claim
  - ingredients: chain of upstream content used to produce this output

Per C2PA spec 2.2 (§10, §13). C2PA 2.2 (2025-05-01) is the current
spec; the deprecated ``c2pa.claim`` label is replaced by
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

# Per W3C / IPTC digital-source-type vocabulary, the value that marks
# content as fully AI-generated (not assisted, not edited).
DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC: str = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)

# Tex verdict assertion schema URL — versioned so we can evolve.
TEX_VERDICT_SCHEMA_V1: str = "https://schemas.texaegis.com/c2pa/tex.verdict/v1"


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

    TODO(P0): emit per CAWG 1.2 + C2PA AI training-data assertion vocabulary.
    TODO(spec-verify): cross-check ``digitalSourceType`` field name and
        action vocabulary against C2PA 2.2 actions assertion JSON schema
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

    TODO(P0): emit complete manifest with three assertions:
              c2pa.actions.v2 (AI-gen),
              cawg.creative_work (sender attribution),
              tex.verdict (Tex-specific extension assertion linking to the verdict)
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
            "name": "Tex Aegis",
            "version": "2.0",
            "model": {"name": model_name, "version": model_version},
        },
        created_at=resolved_created,
        assertions=(actions, cawg, verdict_assertion),
    )
    return C2paManifest(claim=claim)
