"""
A2A (Agent-to-Agent) Protocol Integration.

Reference
---------
- A2A Protocol v1.2 (Linux Foundation, March 2026)
- Signed Agent Cards (cryptographic identity verification)
- 150+ orgs adopting; PayPal in production; insurance vertical confirmed
- Integration in Azure AI Foundry, Amazon Bedrock AgentCore

Tex positioning
---------------
Tex sits on the A2A bus as a "verdict streaming" service. Every
agent-to-agent message can be adjudicated and tagged with a Tex verdict
(PERMIT/ABSTAIN/FORBID) before delivery to the receiving agent.

Priority: P1.
"""

from tex._pending.interop.a2a.signed_agent_card import SignedAgentCard, verify_agent_card
from tex._pending.interop.a2a.bus_listener import A2aBusListener

__all__ = ["SignedAgentCard", "verify_agent_card", "A2aBusListener"]
