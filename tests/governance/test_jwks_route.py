"""Tests for GET /.well-known/tex-jwks.json — the public discovery surface that
publishes ONLY Tex's Ed25519 PUBLIC signing key so a remote verifier can check
a Tex-signed capability token offline.

HONESTY: PARITY plumbing (issuance-side asymmetric-verify enablement), NOT
beyond-frontier and NOT in-path enforcement. Default-OFF behind TEX_TGPCC.
"""

from __future__ import annotations

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.governance_standing_routes import build_jwks_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(build_jwks_router())
    return TestClient(app)


def test_jwks_default_off_empty(monkeypatch) -> None:
    """Default boot (TEX_TGPCC unset): the endpoint serves an empty key set —
    no asymmetric key material is exposed by default."""
    monkeypatch.delenv("TEX_TGPCC", raising=False)
    monkeypatch.delenv("TEX_TGPCC_ED25519_SK", raising=False)
    resp = _client().get("/.well-known/tex-jwks.json")
    assert resp.status_code == 200
    assert resp.json() == {"keys": []}


def test_jwks_publishes_public_key_only(monkeypatch) -> None:
    """With the plane on + a pinned key, the JWKS carries exactly the OKP/EdDSA
    PUBLIC key — and NO private material (no ``d`` member, no PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("TEX_TGPCC", "1")
    monkeypatch.setenv(
        "TEX_TGPCC_ED25519_SK",
        base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii"),
    )
    resp = _client().get("/.well-known/tex-jwks.json")
    assert resp.status_code == 200
    doc = resp.json()
    assert len(doc["keys"]) == 1
    key = doc["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert key["use"] == "sig"
    assert key["alg"] == "EdDSA"
    assert key["kid"]  # RFC-7638 thumbprint
    assert "x" in key
    # NEVER private material.
    assert "d" not in key
    assert "PRIVATE" not in resp.text
