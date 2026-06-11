"""
Tex capstone composition — one sealed verdict object, offline-verifiable,
with a replay-proof tamper matrix.

[Maturity: research-early — the composition is real and replayable today;
its stand-in/test-mode halves are labelled in the manifest and promoted only
as each RUNTIME-DEPENDENT backend lands. See manifest.py for the doctrine.]

Public surface:

- ``CapstoneVerdict`` (manifest.py) — the sealed manifest-of-digests.
- ``compose_capstone`` (compose.py) — module-verifier-delegating composer.
- ``verify_capstone`` / ``CapstonePins`` (verify.py) — the offline verifier.
- ``run_capstone_flow`` (flow.py) — drives the full mixed epoch (demo core).
- ``run_tamper_matrix`` (tamper.py) — the adversary rows, attribution-checked.
"""

from tex.capstone.compose import (
    CapstoneMaterials,
    ComposeResult,
    CompositionError,
    compose_capstone,
)
from tex.capstone.manifest import (
    CapstoneVerdict,
    DecisionIdentity,
    PropertyAttestation,
)
from tex.capstone.verify import (
    CapstonePins,
    CapstoneVerification,
    verify_capstone,
)

__all__ = [
    "CapstoneMaterials",
    "CapstonePins",
    "CapstoneVerdict",
    "CapstoneVerification",
    "ComposeResult",
    "CompositionError",
    "DecisionIdentity",
    "PropertyAttestation",
    "compose_capstone",
    "verify_capstone",
]
