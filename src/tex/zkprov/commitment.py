"""
Dataset commitment scheme.

A Certificate Authority (CA) signs metadata about authorized datasets:
their content hashes, attribute schemas, and validity windows. The provider
fine-tunes the base model on these authenticated datasets and produces
a compact commitment to the model parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DatasetCommitment:
    """A CA-signed commitment to an authorized dataset."""

    dataset_id: str
    content_root_hash: str  # Merkle root of dataset records
    attribute_schema_hash: str
    issued_at: datetime
    valid_until: datetime
    ca_signature_b64: str
    ca_certificate_pem: str


def issue_commitment(
    *,
    dataset_id: str,
    dataset_records: tuple[bytes, ...],
    attribute_schema: dict,
    ca_signing_key_id: str,
) -> DatasetCommitment:
    """
    TODO(P1): build Merkle tree over dataset records
    TODO(P1): hash schema canonically
    TODO(P1): sign full commitment with CA key (ML-DSA recommended)
    """
    raise NotImplementedError("dataset commitment issuance")
