"""
tex-guardrail: Official Python SDK for Tex.

Tex is the gate between AI and the real world. This SDK lets you wire Tex
into any Python agent, framework, or service in a few lines of code.

Quick start
-----------

    from tex_guardrail import TexClient

    tex = TexClient(api_key="...", base_url="https://api.tex.io")

    verdict = tex.evaluate(
        content="Hi Jordan, saw you're hiring for revops...",
        action_type="send_email",
        channel="email",
    )

    if verdict.allowed:
        send_email(...)

Decorator pattern
-----------------

    from tex_guardrail import gate

    @gate(action_type="send_email", channel="email")
    def send_outbound_email(content, recipient):
        smtp.send(to=recipient, body=content)

LangChain integration
---------------------

    from tex_guardrail.integrations.langchain import TexCallbackHandler

    chain.invoke(input, config={"callbacks": [TexCallbackHandler(tex)]})
"""

from tex_guardrail.client import (
    TexClient,
    TexVerdict,
    TexError,
    TexAuthError,
    TexBlocked,
)
from tex_guardrail.decorator import gate

__version__ = "1.0.0"

__all__ = [
    "TexClient",
    "TexVerdict",
    "TexError",
    "TexAuthError",
    "TexBlocked",
    "gate",
    "__version__",
]
