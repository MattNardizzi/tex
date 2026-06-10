"""
CORS configuration for the Tex API.

The invariant this module exists to enforce
--------------------------------------------
**A wildcard origin (``*``) is NEVER served together with credentials.**

The previous configuration set ``allow_origins=["*"]`` *and*
``allow_credentials=True``. That combination does **not** emit a literal
``Access-Control-Allow-Origin: *``. Under Starlette's ``CORSMiddleware``
(verified against the installed source, ``CORSMiddleware.send``)::

    # If credentials are allowed, then we must respond with the specific
    # origin instead of '*'.
    if self.allow_all_origins and self.allow_credentials:
        self.allow_explicit_origin(headers, origin)   # reflects caller's Origin

i.e. the server *reflects the caller's own ``Origin`` header back* and
adds ``Access-Control-Allow-Credentials: true``. The net effect is that
**any** website a logged-in operator visits can make credentialed
cross-origin calls to Tex and read the responses — a textbook
CSRF / credential-exfiltration hole. Browsers reject literal ``*`` +
credentials precisely to prevent this; the reflect-origin behaviour
quietly re-opens it.

Resolved posture
----------------
Allowed origins come from ``TEX_CORS_ALLOW_ORIGINS`` (comma-separated
exact origins, ``scheme://host[:port]``):

* **Explicit allowlist** → those origins, ``allow_credentials=True``.
  This is the only mode in which credentials are permitted.
* **``TEX_CORS_ALLOW_ORIGINS="*"``** → wildcard is honoured but
  ``allow_credentials`` is forced ``False`` (the only spec-safe wildcard
  mode: a true ``Access-Control-Allow-Origin: *`` with no credentials).
* **Unset** → a safe localhost-dev default
  (``http://localhost:3000`` / ``http://127.0.0.1:3000``) *with*
  credentials, so the bundled dev frontend keeps working while a
  production deployment that forgets to configure origins does **not**
  fall back to "reflect every origin".

``allow_methods`` / ``allow_headers`` remain ``*`` — the security
boundary is the *origin* allowlist, not the method/header lists, and a
permissive method/header set against a closed origin list matches the
prior behaviour with no added risk.
"""

from __future__ import annotations

import logging
import os
from typing import Final

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

_logger = logging.getLogger(__name__)

_ENV_ALLOW_ORIGINS: Final[str] = "TEX_CORS_ALLOW_ORIGINS"
_WILDCARD: Final[str] = "*"

# Safe default when nothing is configured: only the local dev frontend.
# Credentialed, because the dev frontend relies on it — but scoped to
# loopback, so it is inert in any real deployment.
_DEFAULT_DEV_ORIGINS: Final[tuple[str, ...]] = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def resolve_cors_policy(
    raw_env: str | None = None,
) -> tuple[list[str], bool]:
    """
    Resolve ``(allow_origins, allow_credentials)`` from the environment.

    Enforces the one invariant: a wildcard origin never travels with
    credentials. Returns a concrete origin list (never a raw string) plus
    the credentials flag. ``raw_env`` is injectable for testing; when
    ``None`` it is read from ``TEX_CORS_ALLOW_ORIGINS``.
    """
    raw = (raw_env if raw_env is not None else os.environ.get(_ENV_ALLOW_ORIGINS, "")).strip()

    if not raw:
        return list(_DEFAULT_DEV_ORIGINS), True

    origins = [o.strip() for o in raw.split(",") if o.strip()]

    if _WILDCARD in origins:
        # Wildcard requested. Force credentials OFF — the only spec-safe
        # wildcard mode, and the exact thing that closes the reflect-origin
        # hole. An explicit origin alongside "*" is meaningless, so collapse.
        if len(origins) > 1:
            _logger.warning(
                "%s contains '*' alongside explicit origins; collapsing to "
                "wildcard-without-credentials.",
                _ENV_ALLOW_ORIGINS,
            )
        return [_WILDCARD], False

    return origins, True


def configure_cors(app: FastAPI) -> None:
    """Install ``CORSMiddleware`` on ``app`` with the resolved, safe policy."""
    allow_origins, allow_credentials = resolve_cors_policy()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    _logger.info(
        "CORS configured: origins=%s allow_credentials=%s",
        allow_origins,
        allow_credentials,
    )


__all__ = ["configure_cors", "resolve_cors_policy"]
