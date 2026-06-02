"""
Run the transparent enforcement proxy as a sidecar:

    # Tex as a separate service (the common case):
    TEX_PDP_MODE=http TEX_PDP_BASE=https://tex.internal \
    TEX_PDP_API_KEY=... python -m tex.pep

    # Tex embedded in the same process (lowest latency):
    TEX_PDP_MODE=inprocess python -m tex.pep

Env:
    TEX_PDP_MODE     "http" (default) or "inprocess"
    TEX_PDP_BASE     PDP base URL (http mode)            default http://127.0.0.1:8080
    TEX_PDP_API_KEY  bearer key for the PDP (http mode)  optional
    TEX_PEP_ENV      environment tag on decisions        default production
    TEX_PEP_TENANT   default tenant when none on header  default default
    TEX_PEP_HOST     bind host                           default 0.0.0.0
    TEX_PEP_PORT     bind port                           default 8088
"""

from __future__ import annotations

import os


def build_app():
    mode = os.environ.get("TEX_PDP_MODE", "http").strip().lower()
    config_env = os.environ.get("TEX_PEP_ENV", "production")
    default_tenant = os.environ.get("TEX_PEP_TENANT", "default")

    from tex.pep.proxy import ProxyConfig, TexEnforcementProxy, build_proxy_app

    config = ProxyConfig(
        environment=config_env,
        default_tenant=default_tenant,
        # Sidecar identity, injected from the pod's downward API by the webhook.
        default_agent_id=os.environ.get("TEX_AGENT_ID") or None,
        default_agent_external_id=os.environ.get("TEX_AGENT") or None,
    )

    if mode == "inprocess":
        from tex.main import build_runtime
        from tex.governance.standing import StandingGovernance
        from tex.pep.decision_client import InProcessDecisionClient

        runtime = build_runtime()
        governance = StandingGovernance(
            agent_registry=runtime.agent_registry,
            evaluate_command=runtime.evaluate_action_command,
            held_sink=runtime.held_decision_sink,
            provenance_engine=runtime.provenance_engine,
        )
        client = InProcessDecisionClient(governance)
        proxy = TexEnforcementProxy(
            decision_client=client, config=config, governance=governance
        )
    else:
        import httpx

        from tex.pep.decision_client import HttpDecisionClient

        base = os.environ.get("TEX_PDP_BASE", "http://127.0.0.1:8080")
        api_key = os.environ.get("TEX_PDP_API_KEY") or None
        client = HttpDecisionClient(
            client=httpx.Client(), base_url=base, api_key=api_key
        )
        proxy = TexEnforcementProxy(decision_client=client, config=config)

    return build_proxy_app(proxy)


def main() -> None:
    import uvicorn

    host = os.environ.get("TEX_PEP_HOST", "0.0.0.0")
    port = int(os.environ.get("TEX_PEP_PORT", "8088"))
    uvicorn.run(build_app(), host=host, port=port)


if __name__ == "__main__":
    main()
