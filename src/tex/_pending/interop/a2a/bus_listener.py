"""
A2A Bus Listener.

Subscribes to the A2A message bus and adjudicates every agent-to-agent
message. Emits a Tex verdict alongside or in place of the message.

Priority: P1.
"""

from __future__ import annotations


class A2aBusListener:
    def on_message(self, *, from_agent_did: str, to_agent_did: str, message: dict) -> dict:
        """
        TODO(P1): verify sender Agent Card
        TODO(P1): run adjudication pipeline
        TODO(P1): emit verdict (PERMIT/ABSTAIN/FORBID) with evidence chain
        TODO(P1): on FORBID, replace message with redaction notice
        """
        raise NotImplementedError("A2A bus message handler")
