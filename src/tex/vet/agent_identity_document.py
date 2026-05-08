"""
Agent Identity Document (AID).

A self-signed (and CA-counter-signed) document specifying:
  - The agent's identity (public key)
  - Its model and software-stack measurements
  - The proof systems it uses to verify outputs (TEE / ZK / Web Proofs)
  - Its policy bindings (which compliance regimes it asserts)

Per VET paper. Priority: P2.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AgentIdentityDocument:
    """A passport for an agent."""

    agent_id: str
    public_key: bytes
    model_measurement: str
    software_stack_measurement: str
    supported_proof_systems: tuple[str, ...]
    compliance_assertions: tuple[str, ...]
    self_signature: bytes
    ca_countersignature: bytes | None
