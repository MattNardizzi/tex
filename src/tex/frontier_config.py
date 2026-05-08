"""
Frontier-stack feature-flag configuration.

All scaffolded modules are gated behind these environment variables.
Default: all flags off — existing six-layer pipeline runs untouched.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


@dataclass(frozen=True, slots=True)
class FrontierFlags:
    """Snapshot of all frontier feature flags."""

    pqcrypto: bool          # P0 - ML-DSA signing
    c2pa: bool              # P0 - Content Credentials
    receipts: bool          # P0 - HMAC tool receipts
    zkprov: bool            # P1 - dataset provenance
    nanozk: bool            # P2 - layerwise ZK
    tee: bool               # P2 - GPU attestation
    vet: bool               # P2 - Agent Identity Document
    runtime: bool           # P1 - PlanGuard + ClawGuard + AgentArmor + MAGE + MCPShield
    governance: bool        # P1 - path policies, kernel-MCP, private-data exec, STPA
    interop: bool           # P1 - A2A bus + identity vendors
    compliance: bool        # P0 - regulatory bindings
    pitch: bool             # P0 - dual-ICP pitch surfaces

    @classmethod
    def from_env(cls) -> "FrontierFlags":
        return cls(
            pqcrypto=_flag("TEX_FRONTIER_PQCRYPTO"),
            c2pa=_flag("TEX_FRONTIER_C2PA"),
            receipts=_flag("TEX_FRONTIER_RECEIPTS"),
            zkprov=_flag("TEX_FRONTIER_ZKPROV"),
            nanozk=_flag("TEX_FRONTIER_NANOZK"),
            tee=_flag("TEX_FRONTIER_TEE"),
            vet=_flag("TEX_FRONTIER_VET"),
            runtime=_flag("TEX_FRONTIER_RUNTIME"),
            governance=_flag("TEX_FRONTIER_GOVERNANCE"),
            interop=_flag("TEX_FRONTIER_INTEROP"),
            compliance=_flag("TEX_FRONTIER_COMPLIANCE"),
            pitch=_flag("TEX_FRONTIER_PITCH"),
        )

    def any_enabled(self) -> bool:
        return any(
            (
                self.pqcrypto, self.c2pa, self.receipts, self.zkprov,
                self.nanozk, self.tee, self.vet, self.runtime,
                self.governance, self.interop, self.compliance, self.pitch,
            )
        )
