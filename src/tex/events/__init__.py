"""
[Architecture: Layer 5 (Evidence)] — append-only event ledger with ECDSA-P256 signature provenance

See ARCHITECTURE.md for the full six-layer model.

Events Layer — Append-Only Cryptographic Ledger
================================================

The persistent record of every event in the ecosystem. Each event is:
  - immutable
  - chained (links to upstream event IDs and to the prior ledger entry)
  - cryptographically signed (ECDSA-P256 today, ML-DSA via Thread 4)
  - tagged with a HMAC tool receipt where applicable (tex.receipts; opaque ID for now)

Reference
---------
arxiv 2512.18561 (AAF) — cryptographically verifiable interaction provenance
with quorum-replicated shards. Storage analysis: at N=100 agents, h=8 horizon,
T=10^6 steps the ledger is ≈492 MB and streams at <80 KB/s.

Priority
--------
P0 — the ledger is the system of record.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.events import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

from typing import TYPE_CHECKING

# The light, dependency-free re-exports stay eager: ``event`` and ``exceptions``
# pull only pydantic + stdlib and are the most widely-imported names.
from tex.events.event import Event, genesis_ledger_hash
from tex.events.exceptions import (
    ChainLinkError,
    LedgerAppendError,
    MissingUpstreamError,
    PayloadHashMismatchError,
    RecordHashMismatchError,
    SequenceGapError,
    SignatureVerificationError,
)

# ``crypto_provenance`` and ``ledger`` transitively pull the ecosystem engine
# (networkx/rustworkx/numpy/scipy) and telemetry (starlette). They are loaded
# LAZILY (PEP 562) so that importing this package — or, crucially, the light
# ``tex.events._ecdsa_provider`` submodule the offline ECDSA verifier needs
# (importing a submodule executes this __init__) — does NOT drag that heavy
# chain onto the clean-room verify path. The re-exported names below still
# resolve transparently on first access for every existing caller.
_LAZY_EXPORTS: dict[str, str] = {
    "CryptoProvenance": "crypto_provenance",
    "EventLedger": "ledger",
    "InMemoryLedger": "ledger",
}

if TYPE_CHECKING:  # let type-checkers / IDEs see the real symbols
    from tex.events.crypto_provenance import CryptoProvenance
    from tex.events.ledger import EventLedger, InMemoryLedger


def __getattr__(name: str):
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value  # cache so __getattr__ fires at most once per name
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


__all__ = [
    "Event",
    "EventLedger",
    "InMemoryLedger",
    "CryptoProvenance",
    "genesis_ledger_hash",
    # Exceptions
    "LedgerAppendError",
    "ChainLinkError",
    "MissingUpstreamError",
    "PayloadHashMismatchError",
    "RecordHashMismatchError",
    "SequenceGapError",
    "SignatureVerificationError",
]
