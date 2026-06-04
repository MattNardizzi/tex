"""
tex.sim — the Tex sandbox simulator.

A service-virtualized synthetic enterprise AI-agent estate that Tex governs
live. The estate is fake; the governance is real. The fake stops at two seams,
the same two where a real customer's world enters Tex:

  population — the estate's agents enter through the real discovery connectors
               via fixture transports (entra_pages / cloudtrail_records).
  behavior   — those agents act over time, POSTing real-shaped actions to the
               real /evaluate, drawing real PERMIT / ABSTAIN / FORBID verdicts.

Everything above the seams — the PDP, the hash-chained evidence ledger, the
vigil voice, the agent surface — runs untouched. An oracle asserts that the
backend produced what should have happened and that the interface can prove it.

Modules:
  archetype   the shape of a real enterprise (Meridian Financial)
  estate      the deterministic estate generator + wire-shape emitters
  actions     action templates authored to draw real verdicts
  behavior    the clock-driven action driver
  scenarios   smoke / reference / soak tiers
  connectors  wire the estate into the real discovery pipeline
  client      stdlib HTTP client to a running backend
  oracle      the assertions (where it breaks)
  report      the ten-second read
  runner      orchestration
"""

from __future__ import annotations

from tex.sim.estate import Estate, SimAgent, generate_estate

__all__ = ["Estate", "SimAgent", "generate_estate"]
