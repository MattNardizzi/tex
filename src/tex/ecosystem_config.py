"""
Ecosystem-layer feature flags.

Extends `tex.frontier_config` with the eight ecosystem-layer flags.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


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
            ecosystem=_flag("TEX_ECOSYSTEM"),
            ontology=_flag("TEX_ECOSYSTEM_ONTOLOGY"),
            graph=_flag("TEX_ECOSYSTEM_GRAPH"),
            events=_flag("TEX_ECOSYSTEM_EVENTS"),
            causal=_flag("TEX_ECOSYSTEM_CAUSAL"),
            institutional=_flag("TEX_ECOSYSTEM_INSTITUTIONAL"),
            drift=_flag("TEX_ECOSYSTEM_DRIFT"),
            intervention=_flag("TEX_ECOSYSTEM_INTERVENTION"),
            contracts=_flag("TEX_ECOSYSTEM_CONTRACTS"),
            systemic=_flag("TEX_ECOSYSTEM_SYSTEMIC"),
        )

    def any_enabled(self) -> bool:
        return any(
            (
                self.ecosystem, self.ontology, self.graph, self.events,
                self.causal, self.institutional, self.drift,
                self.intervention, self.contracts, self.systemic,
            )
        )
