"""tex.pep.resource — the resource-side (demand) PEP.

A downstream RESOURCE imports this package to DEMAND a Tex-issued capability
token (a TG-PCC) before it acts, and to verify it OFFLINE — no network, no Tex
runtime. The entire package imports ONLY the standard library and
``cryptography``'s Ed25519 primitive, so a resource can pull it in without
loading the Tex app / PDP / proxy / governance stack (see the import-purity
contract in ``verify.py`` and the regression test in
``tests/pep/test_resource_verify.py``).

HONESTY: this is DEMAND-VERIFICATION AT AN IN-PATH RESOURCE, NOT un-bypassable
enforcement; and the verifier shape is PARITY — its only beyond-frontier VALUE
(the ``prov_commit`` integrity-floor re-check) is INHERITED from the taint-gated
MINT (B1+). See the package README.
"""

from __future__ import annotations

from tex.pep.resource.middleware import (
    TexDemandMiddleware,
    asgi_auth_request_app,
    verify_request_headers,
)
from tex.pep.resource.verify import (
    PresentedRequest,
    ResourceCheck,
    canonical_intent_commit,
    verify_capability_token,
    verify_prov_commit_floor,
    verify_tgpcc,
)

__all__ = [
    "PresentedRequest",
    "ResourceCheck",
    "canonical_intent_commit",
    "verify_capability_token",
    "verify_prov_commit_floor",
    "verify_tgpcc",
    "TexDemandMiddleware",
    "asgi_auth_request_app",
    "verify_request_headers",
]
