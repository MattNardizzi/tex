"""
EvidenceFold — guarded, additive enrichment that never resolves identity.

A discovered agent may also present a self-describing card: an A2A signed
``AgentCard`` (JWS over JCS), an MCP descriptor, a SPIFFE SVID, an Entra Agent
ID beta object. Folding that in is useful — but dangerous if done naively, so
this path is bound by hard rules:

  * It **never resolves identity.** ``source`` / ``external_id`` / ``name`` are
    never read from the card to establish who the agent is. The card is only
    ever attached as evidence on an already-discovered candidate.
  * It **never raises trust.** A verified card does not lower risk or raise
    confidence — it is additive context, nothing more.
  * An unsigned, tamper-failed, untrusted-issuer, oversized, or off-allowlist
    card is a **risk-RAISING** signal: it bumps the risk band up one notch and
    is recorded as evidence. A card that fails its own integrity check is worse
    than no card.
  * Egress is allow-listed and bounded by size; this module never fetches —
    a caller supplies the bytes, and a ``source_url`` is checked against the
    allow-list before it is ever trusted.

Signatures are EdDSA (Ed25519) over the JCS-canonical payload (RFC 8785-style:
sorted keys, compact). Verified offline against an allow-listed issuer key.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from tex.domain.discovery import CandidateAgent, DiscoveryRiskBand

_BAND_ORDER = [
    DiscoveryRiskBand.LOW,
    DiscoveryRiskBand.MEDIUM,
    DiscoveryRiskBand.HIGH,
    DiscoveryRiskBand.CRITICAL,
]


def _raise_band(band: DiscoveryRiskBand) -> DiscoveryRiskBand:
    i = _BAND_ORDER.index(band)
    return _BAND_ORDER[min(i + 1, len(_BAND_ORDER) - 1)]


def _jcs(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CardVerification(StrEnum):
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    TAMPERED = "tampered"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    OVERSIZE = "oversize"
    EGRESS_BLOCKED = "egress_blocked"


@dataclass(frozen=True, slots=True)
class FoldResult:
    candidate: CandidateAgent  # an annotated COPY; identity is never changed
    verification: CardVerification
    risk_raised: bool
    card_type: str

    @property
    def trusted(self) -> bool:
        return self.verification is CardVerification.VERIFIED


class EvidenceFold:
    def __init__(
        self,
        *,
        trusted_issuers: dict[str, str] | None = None,
        egress_allowlist: set[str] | None = None,
        max_bytes: int = 64 * 1024,
    ) -> None:
        # issuer id -> base64 Ed25519 public key (raw 32 bytes).
        self._issuers = dict(trusted_issuers or {})
        self._egress_allowlist = set(egress_allowlist or set())
        self._max_bytes = max_bytes

    def _verify(self, signed_card: dict[str, Any], *, source_url: str | None) -> CardVerification:
        # Egress allow-list (checked before anything in the card is trusted).
        if source_url is not None:
            host = urlparse(source_url).hostname or ""
            if host not in self._egress_allowlist:
                return CardVerification.EGRESS_BLOCKED

        # Size cap.
        try:
            raw = _jcs(signed_card)
        except (TypeError, ValueError):
            return CardVerification.TAMPERED
        if len(raw) > self._max_bytes:
            return CardVerification.OVERSIZE

        payload = signed_card.get("payload")
        issuer = signed_card.get("issuer")
        sig_b64 = signed_card.get("signature_b64")
        if not sig_b64 or payload is None:
            return CardVerification.UNSIGNED
        issuer_key = self._issuers.get(str(issuer))
        if issuer_key is None:
            return CardVerification.UNTRUSTED_ISSUER
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer_key.encode("ascii")))
            pub.verify(base64.b64decode(str(sig_b64).encode("ascii")), _jcs(payload))
            return CardVerification.VERIFIED
        except Exception:  # noqa: BLE001 — any verify failure is tampered, fail-closed
            return CardVerification.TAMPERED

    def fold(
        self,
        candidate: CandidateAgent,
        signed_card: dict[str, Any],
        *,
        card_type: str = "a2a_agent_card",
        source_url: str | None = None,
    ) -> FoldResult:
        verification = self._verify(signed_card, source_url=source_url)
        trusted = verification is CardVerification.VERIFIED

        fold_evidence = {
            "card_type": card_type,
            "verification": verification.value,
            "issuer": signed_card.get("issuer"),
            "source_url": source_url,
            # Identity-bearing fields are recorded as CLAIMS only, never applied.
            "claimed_identity": (signed_card.get("payload") or {}).get("agent_id")
            if isinstance(signed_card.get("payload"), dict)
            else None,
        }
        evidence = dict(candidate.evidence)
        evidence["evidence_fold"] = fold_evidence

        update: dict[str, Any] = {"evidence": evidence}
        risk_raised = False
        if not trusted:
            # A failed card RAISES risk; it never lowers it and never touches
            # confidence (no trust raise on a bad card — or a good one).
            new_band = _raise_band(candidate.risk_band)
            if new_band != candidate.risk_band:
                update["risk_band"] = new_band
                risk_raised = True
            tags = tuple(sorted({*candidate.tags, "evidence_fold_risk"}))
            update["tags"] = tags

        # Identity is NEVER changed: source / external_id / name / confidence
        # are intentionally absent from `update`.
        annotated = candidate.model_copy(update=update)
        return FoldResult(
            candidate=annotated,
            verification=verification,
            risk_raised=risk_raised,
            card_type=card_type,
        )
