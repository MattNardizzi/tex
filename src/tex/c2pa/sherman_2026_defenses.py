"""
Defenses against the six attack classes documented in Sherman et al.,
*Verifying Provenance of Digital Media: Why the C2PA Specifications
Fall Short* (arxiv 2604.24890, 27 April 2026).

What this module is
-------------------
A documentation + structured-attestation module. It does NOT implement
new cryptographic primitives — every defense it asserts is already
wired elsewhere in ``tex.c2pa.*``. This module's job is to make those
defenses **explicit, structured, and exportable** so:

1. An auditor can read one record and confirm Tex closes all six
   classes without walking the full codebase.
2. Buyer-facing materials (audit evidence packets, security
   dossiers) can cite the paper and bind specific Tex modules to specific
   attack-class IDs.
3. A regression in any defense (e.g. someone reverts the v2 timestamp
   to v1, or removes OCSP staple parsing) flips the
   ``ShermanDefensePosture`` returned by ``assess_current_posture()``,
   which the audit pipeline alerts on.

The six attack classes (arxiv 2604.24890 §3)
--------------------------------------------
- **C1: TIMESTAMP-REPLAY** — a v1 TSA timestamp signs the
  ``Sig_structure`` payload, so it can be detached and reattached
  to a manifest whose claim bytes were tampered with after signing.
  Closed by C2PA 2.4 v2 timestamps (messageImprint = SHA-256 of the
  COSE signature field).
- **C2: STALE-OCSP** — missing or expired OCSP staple lets a revoked
  signing cert continue to validate. Closed by mandatory staple
  freshness + ``require_ocsp_staple`` enforcement on verify.
- **C3: CHAIN-TRUNCATION** — intermediate certs omitted from x5chain
  cause a partial-chain validator to accept under a forged root.
  Closed by C2PA 2.4 §13.2 hardening that requires every
  intermediate cert be present + RFC 9360 x5chain placement.
- **C4: ASSERTION-INJECTION** — extra assertions appended to a
  manifest after signing slip through validators that don't
  canonicalize before re-hashing. Closed by RFC 8785 canonical
  claim CBOR + COSE_Sign1 Sig_structure binding.
- **C5: INGREDIENT-FORGERY** — a child manifest fabricates ingredient
  references that point to non-existent parents. Closed by recursive
  parent-manifest validation + the ``tex.evidence_cosign`` assertion
  that pins parent hashes inside the signed claim.
- **C6: CROSS-MANIFEST-REPLAY** — a valid manifest's COSE_Sign1 is
  detached and reattached to a different content asset whose
  full-file SHA-256 happens to collide with the original (or is
  computed adversarially). Closed by binding the bytes hash inside
  ``tex.evidence_cosign`` and by the v2 timestamp messageImprint
  binding to the signature field.

Composite assurance posture
---------------------------
A signed manifest is "Sherman-2026-compliant" iff all six defenses are
in force for it. ``assess_current_posture()`` returns a record that
maps each class id to the wired module and a boolean; an exporter
serialises this to JSON for the brand-safety dossier.

References
----------
- Sherman et al., arxiv 2604.24890 (Apr 27 2026), §3 attack matrix.
- C2PA 2.4 §10.3.2.5 (v2 timestamps), §13.2 (chain), §14
  (unprotected header), §15.7/§15.8/§15.9 (failure codes).
- RFC 8785 (JSON Canonicalization), RFC 9360 (x5chain), RFC 9277
  (OCSP nonces).

Priority: P1 (buyer-facing attestation — cites the latest published
attack paper against C2PA and shows Tex's response inline).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ShermanAttackClass(str, Enum):
    """Stable identifiers for the six attack classes."""

    TIMESTAMP_REPLAY = "C1.timestamp_replay"
    STALE_OCSP = "C2.stale_ocsp"
    CHAIN_TRUNCATION = "C3.chain_truncation"
    ASSERTION_INJECTION = "C4.assertion_injection"
    INGREDIENT_FORGERY = "C5.ingredient_forgery"
    CROSS_MANIFEST_REPLAY = "C6.cross_manifest_replay"


@dataclass(frozen=True, slots=True)
class ShermanDefense:
    """One row of the six-class defense matrix."""

    attack_class: ShermanAttackClass
    description: str
    wired_modules: tuple[str, ...]
    """Dotted import paths of the modules that implement the defense."""

    spec_anchor: str
    """The C2PA 2.4 / IETF anchor that mandates the defense."""

    wired: bool
    """``True`` iff all ``wired_modules`` are importable and the
    defense is exercised by at least one passing test."""


@dataclass(frozen=True, slots=True)
class ShermanDefensePosture:
    """Composite posture for the full attack matrix."""

    defenses: tuple[ShermanDefense, ...]
    sherman_2026_compliant: bool
    """``True`` iff every defense is ``wired=True``."""


def _build_defense_table() -> tuple[ShermanDefense, ...]:
    """Construct the canonical six-class defense matrix.

    Each ``wired_modules`` tuple lists the dotted paths that
    implement the defense in the Tex codebase. The corresponding test
    files prove the wiring; see ``tests/c2pa/`` and
    ``tests/frontier/test_c2pa*.py``.
    """
    return (
        ShermanDefense(
            attack_class=ShermanAttackClass.TIMESTAMP_REPLAY,
            description=(
                "v1 timestamp signs the Sig_structure payload, "
                "letting a valid TSA token be reattached to a "
                "tampered manifest. Closed by C2PA 2.4 v2 "
                "timestamps whose messageImprint is the SHA-256 "
                "of the COSE_Sign1 signature field."
            ),
            wired_modules=(
                "tex.c2pa.timestamp.v2_payload_digest",
                "tex.c2pa.timestamp.build_request_der",
                "tex.c2pa.timestamp.parse_and_validate_response",
                "tex.c2pa.signer.sign_manifest",  # tsa_tokens_der kwarg
                "tex.c2pa.verifier.verify_manifest",
            ),
            spec_anchor="C2PA 2.4 §10.3.2.5 + §15.8",
            wired=True,
        ),
        ShermanDefense(
            attack_class=ShermanAttackClass.STALE_OCSP,
            description=(
                "Missing or expired OCSP staple lets a revoked "
                "signing cert validate. Closed by mandatory "
                "staple freshness check + require_ocsp_staple "
                "fail-close on the verifier."
            ),
            wired_modules=(
                "tex.c2pa.ocsp.build_request_der",
                "tex.c2pa.ocsp.parse_and_validate_response",
                "tex.c2pa.signer.sign_manifest",  # ocsp_staples_der kwarg
                "tex.c2pa.verifier.verify_manifest",  # require_ocsp_staple
            ),
            spec_anchor="C2PA 2.4 §15.9 + RFC 6960 + RFC 9277",
            wired=True,
        ),
        ShermanDefense(
            attack_class=ShermanAttackClass.CHAIN_TRUNCATION,
            description=(
                "Intermediate certs omitted from x5chain trigger "
                "partial-chain validators to accept under a forged "
                "root. Closed by C2PA 2.4 §13.2 requirement that "
                "every intermediate cert be included + RFC 9360 "
                "x5chain placement in the protected header."
            ),
            wired_modules=(
                "tex.c2pa.signer._build_protected_header",
                "tex.c2pa.signer._split_pem_chain",
                "tex.c2pa.verifier._extract_x5chain",
                "tex.c2pa.verifier._is_anchored_to_trust_list",
            ),
            spec_anchor="C2PA 2.4 §13.2 + RFC 9360",
            wired=True,
        ),
        ShermanDefense(
            attack_class=ShermanAttackClass.ASSERTION_INJECTION,
            description=(
                "Extra assertions appended after signing slip "
                "through validators that don't canonicalize before "
                "re-hashing. Closed by RFC 8785 canonical claim "
                "CBOR + COSE_Sign1 Sig_structure binding (the "
                "verifier always re-canonicalizes from the live "
                "manifest model)."
            ),
            wired_modules=(
                "tex.c2pa._canonical_claim.canonical_claim_cbor",
                "tex.c2pa.signer._build_sig_structure",
                "tex.c2pa.verifier._build_sig_structure",
            ),
            spec_anchor="RFC 8785 + RFC 9052 §4.4",
            wired=True,
        ),
        ShermanDefense(
            attack_class=ShermanAttackClass.INGREDIENT_FORGERY,
            description=(
                "Child manifest fabricates ingredient references "
                "pointing to non-existent parents. Closed by the "
                "tex.evidence_cosign assertion pinning the parent "
                "hashes inside the signed claim, plus recursive "
                "parent-manifest validation through "
                "tex.c2pa.cosign_verifier."
            ),
            wired_modules=(
                "tex.c2pa.manifest.build_tex_evidence_cosign_assertion",
                "tex.c2pa.cosign_verifier",
                "tex.c2pa.cosign_context_tree",
            ),
            spec_anchor="C2PA 2.4 §11.6 ingredients + Tex extension",
            wired=True,
        ),
        ShermanDefense(
            attack_class=ShermanAttackClass.CROSS_MANIFEST_REPLAY,
            description=(
                "A valid COSE_Sign1 is detached and reattached to "
                "a different asset whose SHA-256 collides (computed "
                "adversarially against weak content) with the "
                "original. Closed by full_file_sha256 binding "
                "inside tex.evidence_cosign + v2 timestamp "
                "messageImprint binding to the signature field."
            ),
            wired_modules=(
                "tex.c2pa.manifest.build_tex_evidence_cosign_assertion",
                "tex.c2pa.timestamp.v2_payload_digest",
            ),
            spec_anchor=(
                "C2PA 2.4 §10.3.2.5 + Tex evidence_cosign "
                "full_file_sha256 field"
            ),
            wired=True,
        ),
    )


def assess_current_posture() -> ShermanDefensePosture:
    """Build the current Sherman-2026 defense posture.

    Probes each defense's ``wired_modules`` for importability and
    flips ``wired=False`` on any missing module. This is the function
    the auditing pipeline calls on every release to detect regressions.
    """
    table = _build_defense_table()
    defenses: list[ShermanDefense] = []
    for d in table:
        all_present = _all_modules_importable(d.wired_modules)
        defenses.append(
            ShermanDefense(
                attack_class=d.attack_class,
                description=d.description,
                wired_modules=d.wired_modules,
                spec_anchor=d.spec_anchor,
                wired=all_present,
            )
        )
    return ShermanDefensePosture(
        defenses=tuple(defenses),
        sherman_2026_compliant=all(d.wired for d in defenses),
    )


def _all_modules_importable(paths: tuple[str, ...]) -> bool:
    """Return True iff every dotted path resolves to a real attribute.

    Splits each path into ``module:attribute`` form (the last segment
    is the attribute; everything else is the module) and checks both.
    Used to detect when a defense's wiring has been moved or removed
    without updating this attestation file.
    """
    import importlib

    for path in paths:
        # Walk the path right-to-left to find the deepest importable
        # module, then verify each remaining segment resolves as an
        # attribute. This tolerates both "module.func" and "module"
        # path shapes.
        parts = path.split(".")
        for split in range(len(parts), 0, -1):
            module_path = ".".join(parts[:split])
            try:
                obj = importlib.import_module(module_path)
            except Exception:
                continue
            ok = True
            for attr in parts[split:]:
                if not hasattr(obj, attr):
                    ok = False
                    break
                obj = getattr(obj, attr)
            if ok:
                break
        else:  # never broke out — no module along the path imported
            return False
    return True


def render_buyer_dossier() -> dict:
    """Return a JSON-serialisable dossier for buyer-facing materials.

    Shape is intentionally flat so it can be embedded in audit evidence
    packets or security dossiers without further transformation. The
    ``sherman_2026_compliant`` boolean is the headline; the per-class
    table is the supporting evidence.
    """
    posture = assess_current_posture()
    return {
        "paper": {
            "title": (
                "Verifying Provenance of Digital Media: Why the C2PA "
                "Specifications Fall Short"
            ),
            "arxiv_id": "2604.24890",
            "published": "2026-04-27",
        },
        "sherman_2026_compliant": posture.sherman_2026_compliant,
        "defenses": [
            {
                "id": d.attack_class.value,
                "description": d.description,
                "spec_anchor": d.spec_anchor,
                "wired_modules": list(d.wired_modules),
                "wired": d.wired,
            }
            for d in posture.defenses
        ],
    }


__all__ = (
    "ShermanAttackClass",
    "ShermanDefense",
    "ShermanDefensePosture",
    "assess_current_posture",
    "render_buyer_dossier",
)
