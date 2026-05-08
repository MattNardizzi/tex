"""
ZKPROV: Zero-Knowledge Dataset Provenance
==========================================

Cryptographically binds an LLM response to its authorized training datasets
without revealing the dataset contents or model parameters. Sub-3.3-second
end-to-end proof generation for models up to 8B parameters.

Reference
---------
arxiv 2506.20915 — "ZKPROV: A Zero-Knowledge Approach to Dataset Provenance
for Large Language Models", Namazi, Nemecek, Ayday, Dec 2025.

Use case
--------
Enterprise sales unlock for regulated verticals (healthcare, insurance, finance)
where customers must prove a model output was derived from authorized data
without exposing the data itself.

Priority
--------
P1 — ship in days 43-70. After C2PA + ML-DSA + receipts.
"""

from tex.zkprov.commitment import DatasetCommitment
from tex.zkprov.proof import ProvenanceProof, generate_proof, verify_proof

__all__ = [
    "DatasetCommitment",
    "ProvenanceProof",
    "generate_proof",
    "verify_proof",
]
