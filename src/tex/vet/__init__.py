"""
VET: Verifiable Execution Traces
================================

Host-independent authentication of agent outputs. Lets a verifier (insurer,
regulator, customer auditor) confirm Tex output is genuine WITHOUT trusting
the host that ran Tex.

Reference
---------
arxiv 2512.15892 — "VET Your Agent: Towards Host-Independent Autonomy via
Verifiable Execution Traces", Grigor, Birnbach, Schroeder de Witt, Martinovic,
Oxford, December 2025.

Three proof systems supported (compositional)
---------------------------------------------
  - TEE proofs (via tex.tee/)
  - Succinct cryptographic proofs (via tex.nanozk/, tex.zkprov/)
  - Web Proofs (notarized TLS transcripts) — typically <3x overhead

Priority
--------
P2 spike — implement after pqcrypto + tee ground floor is in place.
The VET Agent Identity Document (AID) is the headline artifact: a "passport"
for Tex that binds Tex's configuration and the proof systems it uses to
its public identity.
"""

from tex.vet.agent_identity_document import AgentIdentityDocument

__all__ = ["AgentIdentityDocument"]
