"""
Epistemic source taxonomy for LLM claims.

Per the NabaOS framework (arxiv 2603.10060), every claim in an LLM response
must be classifiable into exactly one pramana (means of knowledge):

  - PRATYAKSHA: direct tool output (verifiable via receipt)
  - ANUMANA: inference from tool outputs (verifiable via receipt + inference rule)
  - SHABDA: external testimony (verifiable via cited receipt — tool_id + result
            together constitute the citation pointer to the external source)
  - ABHAVA: absence (verifiable via receipt with result_count == 0)
  - UNGROUNDED: opinion, no epistemic backing — must be flagged

Reference
---------
arxiv 2603.10060 — Tool Receipts, Not Zero-Knowledge Proofs (Basu, Mar 2026).
"""

from __future__ import annotations

from enum import Enum


class EpistemicSource(str, Enum):
    """
    Pramana classification for an LLM claim.

    Inherits from ``str`` so values serialize transparently to JSON / pydantic.
    """

    PRATYAKSHA = "pratyaksha"      # direct tool output
    ANUMANA = "anumana"            # inference
    SHABDA = "shabda"              # external testimony
    ABHAVA = "abhava"              # absence / negative result
    UNGROUNDED = "ungrounded"      # ungrounded opinion — flag this
