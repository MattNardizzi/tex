"""
Run the transparent enforcement proxy as a sidecar:

    # Tex as a separate service (the common case):
    TEX_PDP_MODE=http TEX_PDP_BASE=https://tex.internal \
    TEX_PDP_API_KEY=... python -m tex.pep

    # Tex embedded in the same process (lowest latency):
    TEX_PDP_MODE=inprocess python -m tex.pep

Env:
    TEX_PDP_MODE       "http" (default) or "inprocess"
    TEX_PDP_BASE       PDP base URL (http mode)            default http://127.0.0.1:8080
    TEX_PDP_API_KEY    bearer key for the PDP (http mode)  optional
    TEX_PEP_ENV        environment tag on decisions        default production
    TEX_PEP_TENANT     default tenant when none on header  default default
    TEX_PEP_HOST       bind host                           default 0.0.0.0
    TEX_PEP_PORT       bind port                           default 8088

Reference-monitor wiring (off by default; opt-in so a bare run stays today's
behaviour):
    TEX_ORIGDST_SOCK   orig_dst UDS path (G7)              default /run/tex/origdst.sock
    TEX_PEP_REQUIRE_DST   "1" => FORBID when no kernel dst (G7)   default off
    TEX_PEP_PERMITS    "1" => mint/verify/consume egress permits (G10)  default off
    TEX_PEP_SEAL       "1" => seal a receipt per decision (G4)   default off
    TEX_PEP_REQUIRE_IDENTITY "1" => require a verified credential (G6)  default off

Permit signing additionally requires ``TEX_PERMIT_SIGNING_SECRET`` in a
production-like env (else minting fails closed and released actions are
refused). See ``tex.enforcement.permit``.
"""

from __future__ import annotations

import os


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def build_app():
    mode = os.environ.get("TEX_PDP_MODE", "http").strip().lower()
    config_env = os.environ.get("TEX_PEP_ENV", "production")
    default_tenant = os.environ.get("TEX_PEP_TENANT", "default")

    from tex.pep.proxy import (
        OrigDstResolver,
        ProxyConfig,
        TexEnforcementProxy,
        build_proxy_app,
    )

    config = ProxyConfig(
        environment=config_env,
        default_tenant=default_tenant,
        # Sidecar identity, injected from the pod's downward API by the webhook.
        default_agent_id=os.environ.get("TEX_AGENT_ID") or None,
        default_agent_external_id=os.environ.get("TEX_AGENT") or None,
        require_verified_dst=_flag("TEX_PEP_REQUIRE_DST"),
        require_identity=_flag("TEX_PEP_REQUIRE_IDENTITY"),
    )

    # G7 — kernel-captured destination loader (Thread T1). Always constructed;
    # at runtime a missing socket degrades to the header fallback (or FORBID when
    # require_verified_dst is set). The loader itself ships in Thread T1.
    origdst = OrigDstResolver(
        os.environ.get("TEX_ORIGDST_SOCK", "/run/tex/origdst.sock")
    )

    # G10 — durable permit subsystem. Opt-in: when off, no egress permits (the
    # capability is built but inert until a deployment turns it on AND provides
    # TEX_PERMIT_SIGNING_SECRET). When on, a missing secret fails closed.
    permit_memory = None
    if _flag("TEX_PEP_PERMITS"):
        from tex.memory.system import MemorySystem

        permit_memory = MemorySystem(tenant_id=default_tenant)

    if mode == "inprocess":
        from tex.governance.standing import StandingGovernance
        from tex.main import build_runtime
        from tex.pep.decision_client import InProcessDecisionClient

        runtime = build_runtime()
        governance = StandingGovernance(
            agent_registry=runtime.agent_registry,
            evaluate_command=runtime.evaluate_action_command,
            held_sink=runtime.held_decision_sink,
            provenance_engine=runtime.provenance_engine,
        )
        client = InProcessDecisionClient(governance)
        client = _maybe_seal(client)
        proxy = TexEnforcementProxy(
            decision_client=client,
            config=config,
            governance=governance,
            origdst=origdst,
            permit_memory=permit_memory,
        )
    else:
        import httpx

        from tex.pep.decision_client import HttpDecisionClient

        base = os.environ.get("TEX_PDP_BASE", "http://127.0.0.1:8080")
        api_key = os.environ.get("TEX_PDP_API_KEY") or None
        client = HttpDecisionClient(
            client=httpx.Client(), base_url=base, api_key=api_key
        )
        client = _maybe_seal(client)
        proxy = TexEnforcementProxy(
            decision_client=client,
            config=config,
            origdst=origdst,
            permit_memory=permit_memory,
        )

    return build_proxy_app(proxy)


def _maybe_seal(client):
    """G4 — wrap the decision client so each decision seals an offline-verifiable
    receipt. Gated (default OFF) and mirrors the caution at ``main.py:878``: an
    in-memory ``SealedFactLedger`` grows one record per decision, so default-on
    is deferred until a durable (Postgres write-through) ledger backs it. When
    off, the client is returned unchanged and the PEP seals nothing — exactly
    today's behaviour."""
    if not _flag("TEX_PEP_SEAL"):
        return client
    from tex.pep.sealing import SealingDecisionClient
    from tex.provenance.ledger import SealedFactLedger

    return SealingDecisionClient(client, SealedFactLedger())


def main() -> None:
    import uvicorn

    host = os.environ.get("TEX_PEP_HOST", "0.0.0.0")
    port = int(os.environ.get("TEX_PEP_PORT", "8088"))
    uvicorn.run(build_app(), host=host, port=port)


if __name__ == "__main__":
    main()
