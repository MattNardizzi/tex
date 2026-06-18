"""
Opt-in provenance tiers — configuration, never a launch dependency.

The conduit seal FLOOR always works, with zero configuration:

  * **Signing floor:** the C2SP ``tlog-checkpoint`` + Ed25519 ``signed-note``
    (``interchange/gix.py``).
  * **Anchor floor:** the RFC 3161 TSA token whose CMS signature is actually
    verified against a pinned cert (``interchange/external_anchor.py``).

On top of that floor, three tiers can be switched on by configuration. None of
them block launch; each is reported honestly:

  * **ML-DSA seal** — auto-on where a FIPS-204 ML-DSA backend is installed
    (``tex.pqcrypto``), ECDSA/Ed25519 floor otherwise. The receipt format
    already accommodates an ML-DSA-44 ``signed-note`` type as a drop-in with no
    format change, so this upgrades with no receipt-schema change.
  * **Independent witness cosigning** — a C2SP ``tlog-witness`` cosignature.
    This wave it is ``federated=False`` and therefore NOT active: stated
    honestly as aspirational until a real third-party witness (a design
    partner's own auditor) runs. The "you don't have to trust Tex" claim is
    go-to-market, not code, until then.
  * **OpenTimestamps Bitcoin anchoring** — anchors the periodic root to Bitcoin
    via an OpenTimestamps calendar. Off unless a calendar is configured.

Each tier maps to compliance-buyer language (NIST SP 800-53 AU-10/AU-9, EU AI
Act Arts. 10/12/15).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

# Always-on floor (no configuration required).
FLOOR_SIGNING = "ed25519-c2sp-signed-note"
FLOOR_ANCHOR = "rfc3161-tsa-cms-verified"
FLOOR_COMPLIANCE = (
    "NIST SP 800-53 AU-10 (non-repudiation)",
    "EU AI Act Art. 12 (record-keeping / logging)",
)


class ProvenanceTier(StrEnum):
    ML_DSA_SEAL = "ml_dsa_seal"
    WITNESS_COSIGN = "witness_cosign"
    OPENTIMESTAMPS_ANCHOR = "opentimestamps_anchor"


_TIER_COMPLIANCE: dict[ProvenanceTier, tuple[str, ...]] = {
    ProvenanceTier.ML_DSA_SEAL: (
        "FIPS 204 ML-DSA",
        "CNSA 2.0 (quantum-resistant signatures)",
        "EU AI Act Art. 15 (accuracy, robustness & cybersecurity)",
    ),
    ProvenanceTier.WITNESS_COSIGN: (
        "C2SP tlog-witness",
        "NIST SP 800-53 AU-9 (protection of audit information)",
    ),
    ProvenanceTier.OPENTIMESTAMPS_ANCHOR: (
        "OpenTimestamps / Bitcoin anchoring",
        "EU AI Act Art. 12 (tamper-evident record-keeping)",
    ),
}


@dataclass(frozen=True, slots=True)
class TierStatus:
    tier: ProvenanceTier
    requested: bool  # configuration asked for it
    available: bool  # backend / dependency present
    detail: str

    @property
    def active(self) -> bool:
        return self.requested and self.available

    @property
    def compliance(self) -> tuple[str, ...]:
        return _TIER_COMPLIANCE[self.tier]


def ml_dsa_backend_available() -> bool:
    """Real round-trip probe: can we keygen+sign+verify ML-DSA-65? True iff a
    FIPS-204 backend (pyca/cryptography >= 48 or liboqs) is installed."""
    try:
        from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider

        provider = get_signature_provider(SignatureAlgorithm.ML_DSA_65)
        kp = provider.generate_keypair("conduit-tier-probe")
        sig = provider.sign(b"conduit-tier-probe", kp)
        return bool(provider.verify(b"conduit-tier-probe", sig, kp.public_key))
    except Exception:  # noqa: BLE001 — any failure means "not available"
        return False


def _mode(env: dict[str, str], name: str, default: str) -> str:
    return (env.get(name) or default).strip().lower()


@dataclass(frozen=True, slots=True)
class ProvenanceTierConfig:
    """Resolved tier posture. The floor fields are always populated and active;
    the tiers are honest about requested vs available vs active."""

    ml_dsa: TierStatus
    witness: TierStatus
    opentimestamps: TierStatus
    floor_signing: str = FLOOR_SIGNING
    floor_anchor: str = FLOOR_ANCHOR

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ProvenanceTierConfig":
        env = dict(os.environ if env is None else env)

        # ML-DSA: auto (default) | on | off. Auto-on where the backend exists.
        ml_mode = _mode(env, "TEX_CONDUIT_ML_DSA", "auto")
        ml_available = ml_dsa_backend_available()
        ml_requested = ml_mode != "off" if ml_mode == "auto" else ml_mode == "on"
        # In "auto", requested tracks availability; in "on"/"off" it is explicit.
        if ml_mode == "auto":
            ml_requested = ml_available
        ml_detail = (
            "ML-DSA backend present; evidence-chain seals use it. Conduit "
            "checkpoint notes remain Ed25519 (C2SP signed-note); an ML-DSA-44 "
            "signed-note type is a reserved drop-in with no receipt-format change."
            if ml_available
            else "no ML-DSA backend installed — ECDSA/Ed25519 floor in effect."
        )

        # Witness cosigning: federated=False this wave (honest).
        witness_mode = _mode(env, "TEX_CONDUIT_WITNESS_COSIGN", "off")
        witness = TierStatus(
            tier=ProvenanceTier.WITNESS_COSIGN,
            requested=witness_mode == "on",
            available=False,  # gix_witness federated=False until a real witness runs
            detail=(
                "federated=False this wave — aspirational until an independent "
                "third-party witness (e.g. a design partner's auditor) runs. "
                "The 'don't trust Tex' claim is go-to-market until then."
            ),
        )

        # OpenTimestamps: on only if a calendar is configured.
        ots_mode = _mode(env, "TEX_CONDUIT_OPENTIMESTAMPS", "off")
        ots_calendar = (env.get("TEX_CONDUIT_OTS_CALENDAR") or "").strip()
        opentimestamps = TierStatus(
            tier=ProvenanceTier.OPENTIMESTAMPS_ANCHOR,
            requested=ots_mode == "on",
            available=bool(ots_calendar),
            detail=(
                f"OpenTimestamps calendar configured: {ots_calendar}"
                if ots_calendar
                else "no OpenTimestamps calendar configured (TEX_CONDUIT_OTS_CALENDAR unset)."
            ),
        )

        return cls(
            ml_dsa=TierStatus(
                tier=ProvenanceTier.ML_DSA_SEAL,
                requested=ml_requested,
                available=ml_available,
                detail=ml_detail,
            ),
            witness=witness,
            opentimestamps=opentimestamps,
        )

    def active_tiers(self) -> tuple[ProvenanceTier, ...]:
        return tuple(s.tier for s in (self.ml_dsa, self.witness, self.opentimestamps) if s.active)

    def report(self) -> dict:
        return {
            "floor": {
                "signing": self.floor_signing,
                "anchor": self.floor_anchor,
                "always_active": True,
                "compliance": list(FLOOR_COMPLIANCE),
            },
            "tiers": {
                s.tier.value: {
                    "requested": s.requested,
                    "available": s.available,
                    "active": s.active,
                    "detail": s.detail,
                    "compliance": list(s.compliance),
                }
                for s in (self.ml_dsa, self.witness, self.opentimestamps)
            },
        }
