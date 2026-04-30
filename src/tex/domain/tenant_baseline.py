"""
Tenant-scope content baseline domain models.

This is V11. The agent behavioral evaluator (V10) compares an agent
against its own ledger. The tenant baseline compares an agent's
*outbound content* against everything every agent in the same tenant
has previously released and PERMITted.

The signal Tex adds here is the one nobody else in the market has:
"no agent in your tenant has ever sent content like this before, on
this action type, even though this specific agent looks fine on its
own." It catches drift, hijack, and prompt injection that produces
content the agent has never produced before but other agents in the
tenant have produced — and vice versa.

Design rules mirror the rest of the Tex domain layer:
- frozen Pydantic models with extra='forbid'
- timezone-aware datetimes
- safe to persist, hash, replay
- nothing here knows about HTTP, persistence backends, or model
  providers; the signature scheme is deterministic and dependency-free
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Content signature (a per-content fingerprint we can compare across agents)
# ---------------------------------------------------------------------------


# Number of MinHash bands used to fingerprint a piece of content. 64 bands
# of 32-bit hashes gives ~256 bytes per signature and a stable Jaccard
# estimator with mean error ~12.5%. That is more than enough resolution
# for the "have we seen content like this before in this tenant" signal.
SIGNATURE_BANDS: int = 64

# Length of character shingles used as the underlying token unit. 5 is
# the standard near-duplicate-detection sweet spot — tolerates small
# edits, robust to whitespace and punctuation noise, language-agnostic.
SHINGLE_SIZE: int = 5

# The 64 hash seeds. We pre-pick them as small primes so that the
# signature scheme is fully deterministic and identical across runs,
# processes, and Python interpreter versions.
_HASH_SEEDS: tuple[int, ...] = tuple(
    [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
        137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
    ]
)
assert len(_HASH_SEEDS) == SIGNATURE_BANDS


_NORMALIZER = re.compile(r"\s+")


def _normalize_for_signature(content: str) -> str:
    """
    Normalize content for signature stability.

    We lowercase, collapse runs of whitespace into single spaces, and
    strip leading/trailing whitespace. This is intentionally weaker than
    full text normalization — we want to catch wording drift, not erase
    it. Two pieces of content that differ only in casing or spacing
    should produce identical signatures.
    """
    return _NORMALIZER.sub(" ", content.casefold()).strip()


def _shingles(text: str, *, k: int = SHINGLE_SIZE) -> list[str]:
    """
    Yield overlapping k-character shingles.

    For text shorter than k we return a single shingle of the full text
    so the signature scheme has something to hash. Returning empty here
    would silently produce identical signatures for any short string,
    which is exactly the sort of subtle bug we want to avoid.
    """
    if not text:
        return []
    if len(text) <= k:
        return [text]
    return [text[i : i + k] for i in range(0, len(text) - k + 1)]


def compute_content_signature(content: str) -> tuple[int, ...]:
    """
    Compute a 64-band MinHash signature of `content` as a tuple of ints.

    Pure deterministic function — same input produces identical output
    across runs, processes, machines, and Python versions. The output
    is suitable for inclusion in the determinism fingerprint.

    The signature itself is a tuple of 64 unsigned 32-bit integers.
    """
    normalized = _normalize_for_signature(content)
    shingles = _shingles(normalized)
    if not shingles:
        # Defensive: an empty content string (which the EvaluationRequest
        # validator already rejects) would land here. Returning a stable
        # all-zero signature is correct behavior and keeps the tuple type.
        return tuple(0 for _ in _HASH_SEEDS)

    # Pre-hash each shingle once with SHA-256 and reuse the digest bytes
    # as the entropy source for the 64 band hashes. This is orders of
    # magnitude faster than rehashing per band, and equally deterministic.
    digests: list[bytes] = [
        hashlib.sha256(shingle.encode("utf-8")).digest() for shingle in shingles
    ]

    signature: list[int] = []
    for band_index, seed in enumerate(_HASH_SEEDS):
        # Take 4 bytes from a stable position in the digest, mix with seed.
        offset = (band_index * 4) % 28  # leave headroom in the 32-byte digest
        min_value = 0xFFFFFFFF
        for digest in digests:
            slice_int = int.from_bytes(digest[offset : offset + 4], "big")
            mixed = (slice_int * seed + band_index * 2654435761) & 0xFFFFFFFF
            if mixed < min_value:
                min_value = mixed
        signature.append(min_value)

    return tuple(signature)


def signature_jaccard_similarity(
    a: tuple[int, ...],
    b: tuple[int, ...],
) -> float:
    """
    Estimate Jaccard similarity between two signatures.

    Returns a value in [0.0, 1.0]. 1.0 means identical signatures
    (almost certainly identical normalized content); 0.0 means no
    overlap. Two signatures of different length cannot be compared
    and produce 0.0 — this should never happen in practice because
    SIGNATURE_BANDS is a constant.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    matches = sum(1 for x, y in zip(a, b) if x == y)
    return matches / len(a)


def signature_distance(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    """1.0 - jaccard. Distance, not similarity. Bounded [0.0, 1.0]."""
    return 1.0 - signature_jaccard_similarity(a, b)


def signature_to_hex(signature: tuple[int, ...]) -> str:
    """Stable hex representation. 8 chars per band, no separators."""
    return "".join(f"{value:08x}" for value in signature)


# ---------------------------------------------------------------------------
# Content signature record (what we persist in the tenant baseline)
# ---------------------------------------------------------------------------


class ContentSignatureRecord(BaseModel):
    """
    One PERMITted action contributes one signature record to the tenant.

    The tenant baseline is a rolling collection of these. Each record
    is immutable and auditable — given a tenant_id, action_type, and
    timestamp range, we can reproduce exactly which signatures were in
    the baseline at evaluation time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=200)
    agent_id: UUID
    action_type: str = Field(min_length=1, max_length=100)
    channel: str = Field(min_length=1, max_length=50)
    recipient_domain: str | None = Field(default=None, max_length=255)

    content_sha256: str = Field(min_length=64, max_length=64)
    signature: tuple[int, ...] = Field(min_length=SIGNATURE_BANDS, max_length=SIGNATURE_BANDS)

    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("tenant_id", "action_type", "channel", mode="before")
    @classmethod
    def _normalize_required(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("recipient_domain", mode="before")
    @classmethod
    def _normalize_optional_domain(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("recipient_domain must be a string when provided")
        normalized = value.strip().casefold()
        return normalized or None

    @field_validator("content_sha256", mode="after")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("content_sha256 must be a 64-char lowercase hex digest")
        return normalized

    @field_validator("signature", mode="before")
    @classmethod
    def _coerce_signature(cls, value: Any) -> tuple[int, ...]:
        if isinstance(value, tuple):
            return value
        if isinstance(value, list):
            return tuple(value)
        raise TypeError("signature must be a tuple or list of ints")

    @field_validator("signature", mode="after")
    @classmethod
    def _validate_signature(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(value) != SIGNATURE_BANDS:
            raise ValueError(f"signature must have exactly {SIGNATURE_BANDS} bands")
        for v in value:
            if not isinstance(v, int) or v < 0 or v > 0xFFFFFFFF:
                raise ValueError(
                    "signature bands must be unsigned 32-bit integers"
                )
        return value

    @field_validator("recorded_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware")
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Tenant baseline result (what the evaluator returns)
# ---------------------------------------------------------------------------


class TenantContentBaselineLookup(BaseModel):
    """
    Result of a tenant-baseline lookup for one evaluation.

    The behavioral evaluator folds these fields into its existing signal
    shape — they show up as new deviation components and uncertainty
    flags rather than as a brand-new top-level signal. This is the
    minimum-disruption integration choice: tenant novelty is *behavioral
    drift at tenant scope*, conceptually a peer to per-agent novelty.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=200)
    sample_size: int = Field(
        ge=0,
        description=(
            "Number of tenant signatures considered for this lookup. "
            "Limited to the same action_type and (when configured) recent "
            "window the tenant baseline tracks."
        ),
    )

    # Highest Jaccard similarity to anything in the tenant baseline.
    # 1.0 = exact match, 0.0 = nothing in tenant looks remotely like this.
    max_similarity: float = Field(ge=0.0, le=1.0)
    # Mean Jaccard across all comparisons. Useful for "this content is
    # somewhat novel even at the average" cases.
    mean_similarity: float = Field(ge=0.0, le=1.0)
    # 1 - max_similarity. The headline novelty score.
    novelty_score: float = Field(ge=0.0, le=1.0)

    # Tenant-wide recipient-domain knowledge. We track this because it
    # is the second-most-useful tenant-scope signal: "this agent has
    # never written to acme.example, AND no other agent in the tenant
    # has either" is a much stronger signal than per-agent alone.
    recipient_domain_seen: bool
    recipient_domain_seen_count: int = Field(ge=0)

    # Did the tenant baseline have enough data to draw a confident
    # conclusion. This drives confidence dampening and the cold-start
    # uncertainty flag at tenant scope.
    cold_start: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def extract_recipient_domain(recipient: str | None) -> str | None:
    """
    Lowercase domain extraction shared with the action-ledger and the
    behavioral evaluator. Centralized here so all three see the same
    domain even when callers pass slightly different recipient formats.
    """
    if recipient is None:
        return None
    normalized = recipient.strip().casefold()
    if not normalized:
        return None
    if "@" in normalized:
        return normalized.rsplit("@", 1)[-1] or None
    if "://" in normalized:
        after = normalized.split("://", 1)[-1]
        host = after.split("/", 1)[0]
        return host or None
    return normalized
