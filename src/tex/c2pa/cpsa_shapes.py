"""
CPSA shapes loader + verifier (Thread 6, Gap 3).

Reads the vendored CPSA output for ``cpsa_models/tex_cosign_v2.scm``
and exposes the canonical execution shapes as Python data so tests
can assert:

  * every expected shape is present (G1–G5 from the .scm file
    docstring), and
  * no unexpected shape is present (which would imply CPSA found
    an attack).

Why vendor the output
---------------------

CPSA is a Haskell tool. Tex's runtime is Python on Render and we
don't want to ship Haskell in CI. Production deployments that want
to re-run CPSA against the .scm file install ``cabal`` and run:

::

    cabal install cpsa
    cpsa cpsa_models/tex_cosign_v2.scm \\
        | cpsashapes \\
        > /tmp/cosign_shapes.txt
    python scripts/parse_cpsa_output.py /tmp/cosign_shapes.txt \\
        > cpsa_models/tex_cosign_v2_shapes.json

The vendored JSON is the build artifact CI checks. The .scm file is
the **source of truth** — any change to the cosign protocol must be
reflected in both.

This module *does not* re-run CPSA. It loads the parsed shapes and
provides assertion helpers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# Default vendored shapes file (repo-root-relative). Tests override.
DEFAULT_SHAPES_PATH: Path = (
    Path(__file__).resolve().parents[3] / "cpsa_models" / "tex_cosign_v2_shapes.json"
)


@dataclass(frozen=True, slots=True)
class CpsaSkeleton:
    """One named skeleton from the CPSA model."""

    name: str
    goals: tuple[str, ...]
    comment: str
    shapes: tuple[dict[str, Any], ...]
    unexpected_shapes: int
    expected_count: int

    @property
    def is_satisfied(self) -> bool:
        """True iff the actual shape count matches expected and no
        unexpected shapes were found."""
        return (
            len(self.shapes) == self.expected_count
            and self.unexpected_shapes == 0
        )


@dataclass(frozen=True, slots=True)
class CpsaShapesBundle:
    """Top-level CPSA-output bundle."""

    model: str
    cpsa_version: str
    generated_at: str
    skeletons: tuple[CpsaSkeleton, ...]
    audit_log: tuple[dict[str, Any], ...]

    @property
    def all_satisfied(self) -> bool:
        return all(s.is_satisfied for s in self.skeletons)

    def skeleton(self, name: str) -> CpsaSkeleton:
        for s in self.skeletons:
            if s.name == name:
                return s
        raise KeyError(f"No CPSA skeleton named {name!r}")

    @property
    def all_goals(self) -> tuple[str, ...]:
        seen: list[str] = []
        for s in self.skeletons:
            for g in s.goals:
                if g not in seen:
                    seen.append(g)
        return tuple(seen)


def load_cpsa_shapes(path: Path | str | None = None) -> CpsaShapesBundle:
    """
    Load the vendored CPSA shapes JSON.

    Raises ``FileNotFoundError`` if the file is missing,
    ``ValueError`` if the schema is malformed.
    """
    resolved = Path(path) if path is not None else DEFAULT_SHAPES_PATH
    if not resolved.exists():
        raise FileNotFoundError(
            f"CPSA shapes file not found at {resolved}. "
            f"Run `cpsa cpsa_models/tex_cosign_v2.scm | cpsashapes` and "
            f"`scripts/parse_cpsa_output.py` to regenerate."
        )
    raw = json.loads(resolved.read_text("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("CPSA shapes JSON must be an object at top level")

    skeletons: list[CpsaSkeleton] = []
    for sk in raw.get("skeletons", []):
        if not isinstance(sk, dict):
            continue
        skeletons.append(
            CpsaSkeleton(
                name=str(sk.get("name", "")),
                goals=tuple(sk.get("goals", [])),
                comment=str(sk.get("comment", "")),
                shapes=tuple(sk.get("shapes", [])),
                unexpected_shapes=int(sk.get("unexpected_shapes", 0)),
                expected_count=int(sk.get("expected_count", 0)),
            )
        )

    return CpsaShapesBundle(
        model=str(raw.get("model", "")),
        cpsa_version=str(raw.get("cpsa_version", "")),
        generated_at=str(raw.get("generated_at", "")),
        skeletons=tuple(skeletons),
        audit_log=tuple(raw.get("audit_log", [])),
    )


def compute_scm_sha256(scm_path: Path | str) -> str:
    """SHA-256 of the CPSA .scm input file — bound into the shapes audit log."""
    p = Path(scm_path)
    return hashlib.sha256(p.read_bytes()).hexdigest()


def model_provenance_assertion_data(
    bundle: CpsaShapesBundle,
    scm_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Build the wire-level data for a ``tex.formal_verification`` C2PA
    assertion that auditors can read to confirm the protocol was
    formally verified.

    Carried in the manifest's outer signature, this gives an offline
    auditor cryptographic evidence that *the protocol the cosign
    implements was the protocol CPSA proved sound*.
    """
    payload: dict[str, Any] = {
        "$schema": "https://schemas.texaegis.com/c2pa/tex.formal_verification/v1",
        "tool": "cpsa",
        "tool_version": bundle.cpsa_version,
        "model": bundle.model,
        "generated_at": bundle.generated_at,
        "all_goals": list(bundle.all_goals),
        "all_satisfied": bundle.all_satisfied,
        "skeletons": [
            {
                "name": s.name,
                "goals": list(s.goals),
                "expected_count": s.expected_count,
                "actual_count": len(s.shapes),
                "unexpected_shapes": s.unexpected_shapes,
                "is_satisfied": s.is_satisfied,
            }
            for s in bundle.skeletons
        ],
        "paper_reference": "arxiv:2604.24890 §Recommendations",
    }
    if scm_path is not None:
        payload["scm_sha256"] = compute_scm_sha256(scm_path)
    return payload


# Constants for the assertion label.
TEX_FORMAL_VERIFICATION_SCHEMA_V1: str = (
    "https://schemas.texaegis.com/c2pa/tex.formal_verification/v1"
)
ASSERTION_LABEL_TEX_FORMAL_VERIFICATION: str = "tex.formal_verification"


__all__ = [
    "CpsaSkeleton",
    "CpsaShapesBundle",
    "load_cpsa_shapes",
    "compute_scm_sha256",
    "model_provenance_assertion_data",
    "DEFAULT_SHAPES_PATH",
    "TEX_FORMAL_VERIFICATION_SCHEMA_V1",
    "ASSERTION_LABEL_TEX_FORMAL_VERIFICATION",
]
