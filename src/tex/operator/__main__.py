"""
Run the Tex operator:

    python -m tex.operator

It does two jobs from one process:
  * runs the EnrollmentController (watches namespaces, keeps the scope true);
  * serves the MutatingAdmissionWebhook (/mutate) the API server calls to
    inject the PEP into new pods, plus /scope (the governed set the node
    agents poll) and /healthz.

Env:
    TEX_PDP_BASE        PDP base URL injected into sidecars
                        default http://tex.tex-system.svc.cluster.local:8080
    TEX_PROXY_IMAGE     proxy sidecar image    default ghcr.io/vortexblack/tex:latest
    TEX_INIT_IMAGE      egress-redirect init   default ghcr.io/vortexblack/tex-init:latest
    TEX_PROXY_PORT      sidecar port           default 8088
    TEX_OPERATOR_HOST   bind host              default 0.0.0.0
    TEX_OPERATOR_PORT   bind port (TLS termed by the Service/secret) default 8443
"""

from __future__ import annotations

import os
import threading


def build_app(scope=None):
    from tex.operator.scope import EnrollmentScope
    from tex.operator.webhook import InjectorConfig, build_webhook_app

    scope = scope or EnrollmentScope()
    cfg = InjectorConfig(
        proxy_image=os.environ.get("TEX_PROXY_IMAGE", "ghcr.io/vortexblack/tex:latest"),
        init_image=os.environ.get("TEX_INIT_IMAGE", "ghcr.io/vortexblack/tex-init:latest"),
        proxy_port=int(os.environ.get("TEX_PROXY_PORT", "8088")),
        pdp_base=os.environ.get(
            "TEX_PDP_BASE", "http://tex.tex-system.svc.cluster.local:8080"
        ),
        environment=os.environ.get("TEX_PEP_ENV", "production"),
    )
    app = build_webhook_app(scope, cfg)

    # Expose the governed set for the node agents (the eBPF/ambient route).
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def get_scope(_request):
        return JSONResponse(scope.to_jsonable())

    app.router.routes.append(Route("/scope", get_scope, methods=["GET"]))
    return app, scope


def main() -> None:
    import uvicorn

    app, scope = build_app()

    # Start the namespace watch in the background; the webhook serves in front.
    from tex.operator.controller import EnrollmentController

    controller = EnrollmentController(scope)
    t = threading.Thread(target=controller.run, name="tex-enrollment", daemon=True)
    t.start()

    host = os.environ.get("TEX_OPERATOR_HOST", "0.0.0.0")
    port = int(os.environ.get("TEX_OPERATOR_PORT", "8443"))
    # In-cluster the Service terminates TLS to the API server using the
    # webhook serving cert (mounted secret); uvicorn can also serve TLS via
    # SSL_CERTFILE/SSL_KEYFILE when present.
    certfile = os.environ.get("TEX_WEBHOOK_CERT")
    keyfile = os.environ.get("TEX_WEBHOOK_KEY")
    if certfile and keyfile:
        uvicorn.run(app, host=host, port=port, ssl_certfile=certfile, ssl_keyfile=keyfile)
    else:
        uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
