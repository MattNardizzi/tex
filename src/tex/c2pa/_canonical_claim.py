"""
Canonicalization of a C2PA claim for hashing and signing.

C2PA 2.2 §13.2 specifies the payload field of ``Sig_structure`` as the
"serialized CBOR of the claim document" with detached content mode.
The spec excerpts we received don't enumerate every field of the claim
document at the byte level — to bridge that, Tex canonicalizes via the
already-frozen RFC 8785 JSON canonicalization scheme (``tex.events.
_canonical.canonical_json``) and then encodes the resulting object as
deterministic CBOR.

Why JSON-then-CBOR rather than CBOR-direct?

  - The Tex evidence chain (Thread 2) uses RFC 8785 over JSON. Reusing
    that path means the bytes signed for C2PA and the bytes hashed
    into the Tex evidence chain are derived from the *same* canonical
    intermediate, eliminating drift between the two artifact families.
  - CBOR's deterministic encoding (RFC 8949 §4.2.1) is then a pure
    function of the JSON object. Map keys are sorted bytewise on their
    CBOR-encoded forms — the JSON sort is irrelevant once we re-encode.
  - This is consistent with claim documents that real-world C2PA
    tooling produces: a JSON-shaped object embedded in CBOR.

TODO(spec-verify): once the C2PA 2.2 claim CDDL is in scope, replace
    this helper with a CDDL-conformant CBOR-direct serializer. The
    deliverable boundary is: canonical bytes are byte-for-byte stable
    for a given logical claim across versions.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from tex.c2pa import _cbor
from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paIngredient
from tex.events._canonical import canonical_json


def _claim_to_canonicalizable(claim: C2paClaim) -> dict[str, Any]:
    """Convert a ``C2paClaim`` into a JCS-canonicalizable dict.

    Datetimes become ISO-8601 strings; tuples become lists; pydantic
    models are unrolled to plain dicts.
    """

    def _ass(a: C2paAssertion) -> dict[str, Any]:
        return {"label": a.label, "data": a.data}

    def _ing(i: C2paIngredient) -> dict[str, Any]:
        return {
            "title": i.title,
            "format": i.format,
            "instance_id": i.instance_id,
            "relationship": i.relationship,
            "hash": i.hash,
        }

    return {
        "title": claim.title,
        "format": claim.format,
        "instance_id": claim.instance_id,
        "claim_generator": claim.claim_generator,
        "claim_generator_info": claim.claim_generator_info,
        "created_at": _isoformat(claim.created_at),
        "assertions": [_ass(a) for a in claim.assertions],
        "ingredients": [_ing(i) for i in claim.ingredients],
    }


def _isoformat(dt: datetime) -> str:
    """ISO-8601 with explicit timezone if present."""
    return dt.isoformat()


def canonical_claim_cbor(claim: C2paClaim) -> bytes:
    """
    Return the deterministic CBOR encoding of ``claim``.

    Used as the ``payload`` field of ``Sig_structure`` per C2PA 2.2
    §13.2 (detached content mode).
    """
    obj = _claim_to_canonicalizable(claim)
    # Run through RFC 8785 JCS first to lock the JSON shape, then re-load
    # and re-encode as deterministic CBOR. This pins both
    # representations to the same source of truth.
    jcs = canonical_json(obj)
    reloaded = json.loads(jcs)
    return _cbor.encode(reloaded)
