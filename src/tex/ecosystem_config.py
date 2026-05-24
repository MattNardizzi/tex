"""
Ecosystem-layer feature flags.

Extends ``tex.frontier_config`` with the ecosystem-layer flags.

Single source of truth
----------------------
Every ecosystem-layer flag is parsed through :func:`is_flag_on` here.
Modules that need to read the same flag at runtime (notably
``tex.ecosystem.engine`` reading ``TEX_ECOSYSTEM_SYSTEMIC`` on each
``evaluate()``) MUST import :func:`is_flag_on` from this module rather
than re-implementing the parse. Drift between two parsers — for example
the engine defaulting-on while this module defaults-off — was the root
cause of Bug #2 in ``KNOWN_BUGS.md``.

Parse semantics
---------------
* Unset → ``False``. Safety evaluators must be opted *in*, never silently
  on. This matches the post-incident remediation pattern Google Cloud
  published in June 2025 ("enforce all changes to critical binaries to
  be feature-flag protected and disabled by default") and the OWASP-aligned
  fail-safe-defaults principle for security-critical paths.
* Exact string ``"1"`` → ``True``.
* Anything else (``"0"``, ``"true"``, ``"yes"``, ``"on"``, ``""``,
  ``"01"``, ``"1 "``, etc.) → ``False``. Strict equality is a defense
  against typo'd flag values silently enabling expensive or
  partially-tested paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def is_flag_on(name: str) -> bool:
    """Return True iff the environment variable ``name`` is exactly ``"1"``.

    Canonical parser for every ecosystem-layer feature flag. Modules MUST
    NOT re-implement this parse; doing so risks drift in the default
    value across modules (Bug #2 in ``KNOWN_BUGS.md``).
    """
    return os.environ.get(name) == "1"


# Backwards-compatible alias retained for any in-tree callers that still
# reference the underscore-prefixed name. New code should prefer the
# public ``is_flag_on``.
def _flag(name: str) -> bool:
    return is_flag_on(name)


@dataclass(frozen=True, slots=True)
class EcosystemFlags:
    ecosystem: bool       # P0 - top-level ecosystem engine
    ontology: bool        # P0 - type system
    graph: bool           # P0 - temporal knowledge graph
    events: bool          # P0 - append-only ledger
    causal: bool          # P1 - CHIEF + ARM
    institutional: bool   # P1 - Institutional AI governance graph
    drift: bool           # P1 - change-point detection
    intervention: bool    # P1 (skeleton) / P2 (full)
    contracts: bool       # P1 - Agent Behavioral Contracts
    systemic: bool        # P2 - digital twin + risk evaluator

    @classmethod
    def from_env(cls) -> "EcosystemFlags":
        return cls(
            ecosystem=is_flag_on("TEX_ECOSYSTEM"),
            ontology=is_flag_on("TEX_ECOSYSTEM_ONTOLOGY"),
            graph=is_flag_on("TEX_ECOSYSTEM_GRAPH"),
            events=is_flag_on("TEX_ECOSYSTEM_EVENTS"),
            causal=is_flag_on("TEX_ECOSYSTEM_CAUSAL"),
            institutional=is_flag_on("TEX_ECOSYSTEM_INSTITUTIONAL"),
            drift=is_flag_on("TEX_ECOSYSTEM_DRIFT"),
            intervention=is_flag_on("TEX_ECOSYSTEM_INTERVENTION"),
            contracts=is_flag_on("TEX_ECOSYSTEM_CONTRACTS"),
            systemic=is_flag_on("TEX_ECOSYSTEM_SYSTEMIC"),
        )

    def any_enabled(self) -> bool:
        return any(
            (
                self.ecosystem, self.ontology, self.graph, self.events,
                self.causal, self.institutional, self.drift,
                self.intervention, self.contracts, self.systemic,
            )
        )
