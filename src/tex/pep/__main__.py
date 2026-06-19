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

Credential brokering (G12) — gate the *credential*, not just the route (off by
default; opt-in so a bare run stays today's behaviour). When on, a released
action gets a fresh, single-use, action-scoped Tex credential minted (reusing
the permit store for single-use/revocation) and injected downstream, and the
agent's standing-credential headers are stripped over an enumerated set
(Authorization + cookie/x-api-key/x-amz-security-token/x-goog-api-key + any
TEX_PEP_BROKER_STRIP_HEADERS) — sole-token-custody over those vectors:
    TEX_PEP_BROKER     "1" => mint+inject a brokered downstream credential
                              (REQUIRES TEX_PEP_PERMITS=1 for the store; minting
                              additionally needs a signing secret — see below)  default off
    TEX_PEP_BROKER_TTL    minted credential TTL (seconds)        default 300
    TEX_PEP_BROKER_AUDIENCE  fixed credential audience id; unset => the resolved
                             recipient host
    TEX_PEP_BROKER_HEADER  request header to inject into          default authorization
    TEX_PEP_BROKER_STRIP_HEADERS  comma-list of EXTRA standing-credential headers
                                  to strip beyond the enumerated set   default none

Brokered credential signing requires ``TEX_AUTHORITY_SIGNING_SECRET`` (or the
shared ``TEX_PERMIT_SIGNING_SECRET``) in a production-like env; with none set,
minting fails closed and a brokered released action is refused. The broker is
PoP-by-default: the agent's identity card must carry an RFC-7800 ``cnf`` key or
the mint fails closed (no weaker bearer token is handed out).

HONEST: the broker gives Tex sole custody of the downstream TOKEN, and strips the
agent's standing-credential headers only over the ENUMERATED set above (an
un-enumerated custom auth header would still egress). It does NOT by itself make
a third-party resource DEMAND a Tex credential — that is resource-side
trust/federation config (RUNTIME-DEPENDENT). See tex.authority.

External-time anchoring (G11) — runs ONLY when TEX_PEP_SEAL is on AND a TSA is
configured (anchoring an un-sealed ledger has nothing to attest):
    TEX_PEP_ANCHOR_TSA_URL  RFC-3161 TSA URL; set => start the AnchorScheduler
    TEX_PEP_ANCHOR_AUTHORITY  human label for the authority (default: the URL)

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
        # G6 anti-replay: this PEP's expected credential audience + whether a
        # credential MUST carry an expiry. Unset leaves aud unchecked (an exp on
        # a card is still honoured).
        pep_audience=os.environ.get("TEX_PEP_AUDIENCE") or None,
        require_credential_expiry=_flag("TEX_PEP_REQUIRE_CRED_EXPIRY"),
        # G12 — credential brokering at the egress call-site (opt-in).
        broker_credentials=_flag("TEX_PEP_BROKER"),
        broker_credential_ttl=int(os.environ.get("TEX_PEP_BROKER_TTL", "300")),
        broker_audience=os.environ.get("TEX_PEP_BROKER_AUDIENCE") or None,
        broker_inject_header=os.environ.get("TEX_PEP_BROKER_HEADER", "authorization"),
        broker_strip_headers=frozenset(
            h.strip().lower()
            for h in os.environ.get("TEX_PEP_BROKER_STRIP_HEADERS", "").split(",")
            if h.strip()
        ),
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

    # G12 — the credential broker reuses the permit store for single-use /
    # revocation, so it is only live when TEX_PEP_PERMITS is also on. Warn loudly
    # if the operator asked to broker but left the store off (the broker would be
    # constructed with no store and stay inert) rather than silently no-op.
    if _flag("TEX_PEP_BROKER") and permit_memory is None:
        import logging

        logging.getLogger(__name__).warning(
            "PEP: TEX_PEP_BROKER=1 but TEX_PEP_PERMITS is off — credential "
            "brokering needs the permit store and will stay INERT. Set "
            "TEX_PEP_PERMITS=1 to activate it."
        )

    # G12 — the IdP source the broker's RFC-8693 exchange path verifies subject
    # assertions against. Optional and RUNTIME-DEPENDENT: only the token-exchange
    # endpoint uses it (the egress mint path binds to the per-request attested
    # identity the PEP already verified, so it needs no IdP source). Unset => no
    # exchange identity source wired.
    identity_source = _maybe_identity_source()

    # G4 — terminal-outcome receipt ledger (gated off by default). The proxy is
    # the single seal site: it seals ONE receipt per request for what actually
    # happened, after the permit gate — so a receipt can never claim "executed"
    # for an action the permit gate refused.
    seal_ledger = _maybe_ledger()

    # G11 — external-time anchoring. The SealedFactLedger's hash chain binds
    # ORDER, never TIME; the AnchorScheduler periodically checkpoints the live
    # ledger's tree-head to an RFC-3161 TSA (off the hot path, fail-soft) so a
    # relying party can prove "an authority that is NOT Tex saw these facts no
    # later than genTime". Built + tested but never STARTED until now. Gated
    # consistently with the seal flag: it only runs when there is a sealed ledger
    # AND a TSA is configured (see _maybe_anchor_scheduler).
    anchor_scheduler = _maybe_anchor_scheduler(seal_ledger)

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
        proxy = TexEnforcementProxy(
            decision_client=client,
            config=config,
            governance=governance,
            origdst=origdst,
            permit_memory=permit_memory,
            seal_ledger=seal_ledger,
            identity_source=identity_source,
        )
    else:
        import httpx

        from tex.pep.decision_client import HttpDecisionClient

        base = os.environ.get("TEX_PDP_BASE", "http://127.0.0.1:8080")
        api_key = os.environ.get("TEX_PDP_API_KEY") or None
        client = HttpDecisionClient(
            client=httpx.Client(), base_url=base, api_key=api_key
        )
        proxy = TexEnforcementProxy(
            decision_client=client,
            config=config,
            origdst=origdst,
            permit_memory=permit_memory,
            seal_ledger=seal_ledger,
            identity_source=identity_source,
        )

    app = build_proxy_app(proxy)
    # Keep a strong reference so the daemon thread is not collected; also lets a
    # health endpoint / test inspect anchor progress (sched.anchor_count, etc.).
    app.state.anchor_scheduler = anchor_scheduler
    return app


def _maybe_identity_source():
    """G12 — the IdP source the broker's RFC-8693 token-exchange path verifies
    subject assertions against. Returns a ``JwksIdentitySource`` configured from
    the operator's trusted-issuer list, or None when unset.

    HONEST: the JWKS *fetch* (OIDC discovery / jwks_uri GET, rotation, caching) is
    a RUNTIME-DEPENDENT shim — this builder does NOT wire a network JWKS provider,
    so an out-of-the-box source has no keys and verifies nothing (fail-closed). A
    deployment supplies a JwksKeyProvider (or a pinned trust bundle); the JWT
    verification crypto is real. Unset (no TEX_PEP_BROKER_TRUSTED_ISSUERS) => None.
    """
    issuers = os.environ.get("TEX_PEP_BROKER_TRUSTED_ISSUERS", "").strip()
    if not issuers:
        return None
    import logging

    from tex.authority.identity_source import JwksIdentitySource

    trusted = {i.strip() for i in issuers.split(",") if i.strip()}
    audiences_raw = os.environ.get("TEX_PEP_BROKER_TRUSTED_AUDIENCES", "").strip()
    audiences = {a.strip() for a in audiences_raw.split(",") if a.strip()} or None
    logging.getLogger(__name__).warning(
        "PEP: G12 JwksIdentitySource configured for issuers %s but NO network "
        "JWKS provider is wired (RUNTIME-DEPENDENT shim) — token exchange will "
        "fail closed until a JwksKeyProvider / pinned trust bundle is supplied.",
        sorted(trusted),
    )
    return JwksIdentitySource(trusted_issuers=trusted, audiences=audiences)


def _maybe_ledger():
    """G4 — the receipt ledger the proxy seals each request's TERMINAL outcome
    into. Gated (default OFF) and mirrors the caution at ``main.py:878``: an
    in-memory ``SealedFactLedger`` grows one record per request, so default-on is
    deferred until a durable (Postgres write-through) ledger backs it. When off,
    returns None and the PEP seals nothing — exactly today's behaviour."""
    if not _flag("TEX_PEP_SEAL"):
        return None
    from tex.provenance.ledger import SealedFactLedger

    return SealedFactLedger()


def _http_poster(timeout: float = 10.0):
    """A timeout-bounded RFC-3161 HTTP poster (stdlib urllib — no httpx import in
    this module). ``(tsa_url, request_der) -> response_der``."""
    import urllib.request

    def poster(url: str, request_der: bytes) -> bytes:
        req = urllib.request.Request(
            url,
            data=request_der,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-set TSA URL
            return resp.read()

    return poster


def _maybe_anchor_scheduler(seal_ledger):
    """G11 — start the background AnchorScheduler on the live enforcement ledger.

    REUSES ``make_rfc3161_anchor`` (the production anchor_fn builder) and
    ``AnchorScheduler`` (built + tested, but until now never STARTED in the PEP).
    Returns the started scheduler, or ``None`` when anchoring is not active.

    Gated consistently with the seal flag: no sealed ledger (TEX_PEP_SEAL off) =>
    nothing to anchor. A sealed ledger but no TSA URL => the chain still proves
    ORDER, just not external TIME; we log that anchoring is idle rather than spin
    a daemon with no authority to call.
    """
    if seal_ledger is None:
        return None
    import logging

    logger = logging.getLogger(__name__)
    tsa_url = os.environ.get("TEX_PEP_ANCHOR_TSA_URL")
    if not tsa_url:
        logger.info(
            "PEP: seal on but TEX_PEP_ANCHOR_TSA_URL unset — ledger proves order, "
            "not external time (G11 anchoring idle)."
        )
        return None

    from tex.discovery.conduit.seal import make_rfc3161_anchor
    from tex.provenance.anchor_scheduler import AnchorScheduler

    authority = os.environ.get("TEX_PEP_ANCHOR_AUTHORITY", tsa_url)
    # A per-process random nonce (the helper binds one nonce for the run; the
    # offline verifier matches it against the TSA response).
    nonce = int.from_bytes(os.urandom(8), "big")
    anchor_fn = make_rfc3161_anchor(
        authority=authority, tsa_url=tsa_url, poster=_http_poster(), nonce=nonce
    )
    sched = AnchorScheduler(seal_ledger, anchor_fn=anchor_fn)
    logger.info("PEP: G11 anchor scheduler started against TSA %s", tsa_url)
    return sched.start()


def main() -> None:
    import uvicorn

    host = os.environ.get("TEX_PEP_HOST", "0.0.0.0")
    port = int(os.environ.get("TEX_PEP_PORT", "8088"))
    uvicorn.run(build_app(), host=host, port=port)


if __name__ == "__main__":
    main()
