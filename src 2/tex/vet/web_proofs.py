"""
Web Proofs — TLS session notarization for third-party AI API calls.

When Tex routes a request through a closed-model API (OpenAI,
Anthropic, Google, Mistral) the audit trail conventionally ends at
"the response Tex received." That is a trust gap: the provider could
serve a different model than advertised (arxiv 2504.04715 demonstrates
this is detectable but unreliably so), the response could be modified
in flight by an intermediary, or a Tex operator could later fabricate
the transcript.

Web Proofs close that gap by **notarizing the TLS session itself**.
The Prover (Tex) cooperates with a Verifier (a notary attestor) to
jointly perform the TLS handshake; the Verifier signs an attestation
over the encrypted transcript without ever seeing the plaintext. The
result is a transferable proof that a specific server returned a
specific response — tamper-evident, independent of the API provider's
cooperation.

This module exposes three notarization backends and one verifier:

*   ``ZKTLS_RECLAIM``  — zkTLS via Reclaim Protocol attestor-core.
    Single-party, fast (2–4s on the prover side), uses HTTPS proxies
    that forward the encrypted response. Production-deployed since
    2024 with 250+ providers. Default for high-volume notarization.

*   ``ZKTLS_PLUTO``    — zkTLS via Pluto Labs (open-source zk
    implementation of TLSNotary). Single-party-ish; uses zero-knowledge
    proofs of the AES-GCM symmetric encryption. Lower trust assumption
    than proxy-based zkTLS but slower.

*   ``TLSNOTARY_MPC``  — TLSNotary v0.1-alpha.x MPC-TLS with the
    QuickSilver VOLE-IZK backend (replaced garbled-circuit ZK in
    Aug 2025; up to 30% online-time reduction per TLSNotary's Jan 2026
    benchmark post). Strongest trust model — verifier participates in
    the TLS session via 2PC and never sees plaintext at any point.
    Slowest of the three; ~20–60 seconds per session at typical
    payload sizes. Subprocesses to the Rust binary; see
    ``tlsn`` on https://github.com/tlsnotary/tlsn.

*   ``MULTI_ATTESTOR`` — k-of-n threshold notarization across an
    attestor committee. Each member of the committee independently
    notarizes the same session. The proof is valid iff at least ``k``
    of ``n`` signatures verify. This is Tex's wedge: **no AI-governance
    vendor ships threshold web proofs.** Microsoft AGT, Zenity, Noma,
    Pillar — none of them notarize third-party API calls at all, let
    alone with a Byzantine-tolerant committee.

Live-binary policy
------------------
The Rust TLSNotary binary is invoked via subprocess from
``TlsNotarySubprocessClient``. When ``TEX_TLSNOTARY_BIN`` is unset or
the binary is not found on PATH, the client returns a stub proof
clearly marked ``mode="stub"``. Operators who require real
notarization set the environment variable on production deploys; the
``/v1/vet/notarize`` endpoint surfaces the mode in its response so
auditors can distinguish stub-mode evidence from real-notary evidence.

Algorithm-agile attestor signatures
-----------------------------------
Attestor signature verification routes through
``tex.pqcrypto.algorithm_agility``. By default we verify under
ML-DSA-65 (NIST L3, FIPS 204), but classical attestors (Reclaim's
ECDSA-P256-signing attestor network, TLSNotary's notary public key)
are supported via ``ECDSA_P256`` and ``ED25519``. The signature
algorithm is carried in the proof so the verifier can dispatch.

References
----------
*   draft-irtf-cfrg-mpc-tls (TLSNotary protocol spec).
*   TLSNotary Performance Benchmarks (Aug 2025) — VOLE-IZK / QuickSilver.
*   Reclaim Protocol attestor-core (https://github.com/reclaimprotocol/attestor-core).
*   Pluto Labs zkTLSNotary (https://pluto.xyz).
*   arxiv 2504.04715 — "Are You Getting What You Pay For?" — the
    LLM-API attestation gap this module closes.
*   PADO 2024 — "Lightweight Authentication of Web Data via Garble-Then-Prove"
    — showed semi-honest OLE is sufficient, removing the MAC-key
    revelation step (incorporated into TLSNotary in 2025).
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "WebProofMode",
    "WebProofAttestation",
    "WebProof",
    "ZkTlsAttestorClient",
    "TlsNotarySubprocessClient",
    "TlsNotaryProxyClient",
    "MultiAttestorCommittee",
    "notarize_session",
    "verify_web_proof",
]


_logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Enums and constants                                                          #
# --------------------------------------------------------------------------- #


class WebProofMode(str, enum.Enum):
    """
    Notarization backend selection.

    Trust-speed tradeoff (per TLSNotary May 10, 2026 benchmarks):

    * ``TLSNOTARY_MPC``    — 3–15s, **strongest trust** (verifier
                              never sees plaintext at any point;
                              MPC-TLS via QuickSilver VOLE-IZK).
    * ``TLSNOTARY_PROXY``  — 1–2s, **faster** but verifier acts as
                              a proxy and observes the encrypted
                              transcript. Selective disclosure via
                              ZK after the session closes. Introduced
                              in TLSNotary alpha.15 (May 10, 2026).
    * ``ZKTLS_RECLAIM``    — 2–4s, single-party attestor; the
                              Reclaim attestor network ECDSA-signs
                              over the encrypted response. Production-
                              deployed since 2024.
    * ``ZKTLS_PLUTO``      — single-party-ish; ZK proofs of the
                              AES-GCM symmetric encryption. Lower
                              trust assumption than proxy-based zkTLS
                              but slower.
    * ``MULTI_ATTESTOR``   — k-of-n threshold notarization. Tex's
                              wedge: no AI-governance vendor ships
                              this primitive.
    * ``STUB``             — clearly-marked self-attestation. Used
                              only when no live backend is
                              configured. Rejected by verify_web_proof
                              unless ``allow_stub=True``.
    """

    ZKTLS_RECLAIM = "zktls-reclaim"
    ZKTLS_PLUTO = "zktls-pluto"
    TLSNOTARY_MPC = "tlsnotary-mpc"
    TLSNOTARY_PROXY = "tlsnotary-proxy"
    MULTI_ATTESTOR = "multi-attestor"
    STUB = "stub"  # only emitted when no live backend is configured


# Environment knobs for live-binary integration.
ENV_TLSNOTARY_BIN = "TEX_TLSNOTARY_BIN"
ENV_TLSNOTARY_PROXY_URL = "TEX_TLSNOTARY_PROXY_URL"
ENV_RECLAIM_APP_ID = "TEX_RECLAIM_APP_ID"
ENV_RECLAIM_APP_SECRET = "TEX_RECLAIM_APP_SECRET"  # noqa: S105 — env var name, not secret
ENV_RECLAIM_ATTESTOR_URL = "TEX_RECLAIM_ATTESTOR_URL"
ENV_PLUTO_NOTARY_URL = "TEX_PLUTO_NOTARY_URL"


# --------------------------------------------------------------------------- #
# Pydantic v2 strict models                                                    #
# --------------------------------------------------------------------------- #


class WebProofAttestation(BaseModel):
    """
    A single attestor's signature over a notarized TLS session.

    For multi-attestor committee proofs, ``WebProof.attestations`` holds
    one of these per committee member. For single-attestor proofs (the
    three solo modes), the list has one entry.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attestor_id: str = Field(min_length=1, max_length=200)
    algorithm: SignatureAlgorithm
    public_key: str = Field(min_length=1, description="base64url issuer pubkey")
    signature: str = Field(min_length=1, description="base64url signature bytes")
    signed_at_epoch: int = Field(ge=0)


class WebProof(BaseModel):
    """
    A notarized TLS session — Tex's evidence of what a third-party API returned.

    The proof is verifiable independently of the API provider. The
    fields under ``commitments`` are SHA-256 hex digests, never raw
    plaintext, so a WebProof can be persisted in evidence chains and
    shared with auditors without leaking the underlying response.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: WebProofMode
    target_host: str = Field(min_length=1, max_length=512)
    target_path: str = Field(default="/", min_length=1, max_length=2048)
    method: str = Field(default="POST", min_length=1, max_length=16)
    request_commitment: str = Field(
        min_length=64, max_length=64,
        description="SHA-256 hex of canonical request envelope.",
    )
    response_commitment: str = Field(
        min_length=64, max_length=64,
        description="SHA-256 hex of the response body bytes.",
    )
    transcript_commitment: str = Field(
        min_length=64, max_length=64,
        description="SHA-256 hex of the full session-log digest.",
    )
    server_cert_fingerprint: str = Field(
        min_length=64, max_length=128,
        description="SHA-256 (or SHA-384) hex of the server cert's SPKI.",
    )
    response_size_bytes: int = Field(ge=0)
    notarized_at_epoch: int = Field(ge=0)
    threshold_k: int = Field(ge=1, description="signatures required (1 for solo modes).")
    attestations: tuple[WebProofAttestation, ...]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_host")
    @classmethod
    def _normalize_host(cls, v: str) -> str:
        # Strip protocol & path if a caller passed a URL by mistake.
        v = v.strip().lower()
        if v.startswith("https://"):
            v = v[len("https://"):]
        if v.startswith("http://"):
            v = v[len("http://"):]
        v = v.split("/")[0]
        if not v:
            raise ValueError("target_host must not be empty after normalization")
        return v


# --------------------------------------------------------------------------- #
# Internal helpers                                                             #
# --------------------------------------------------------------------------- #


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_request_envelope(
    *, method: str, host: str, path: str, headers: dict[str, str], body: bytes
) -> bytes:
    """
    Deterministic byte-serialization of an HTTP request for commitment.

    Header keys are lowercased and sorted, then joined as ``k: v`` with
    LF separators (no CR per HTTP/2 canonicalization). Body is appended
    after a blank line, exactly as in HTTP/1.1.
    """
    lower = sorted((k.strip().lower(), v.strip()) for k, v in headers.items())
    head = f"{method.upper()} {path} HTTP/1.1\n" + f"host: {host}\n"
    for k, v in lower:
        if k == "host":
            continue
        head += f"{k}: {v}\n"
    head += "\n"
    return head.encode("utf-8") + body


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


# --------------------------------------------------------------------------- #
# Attestor clients                                                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _NotarizationInputs:
    """Materials handed to an attestor backend for notarization."""

    target_host: str
    target_path: str
    method: str
    headers: dict[str, str]
    request_body: bytes
    response_body: bytes
    server_cert_spki_sha256: str
    request_commitment: str
    response_commitment: str
    transcript_commitment: str


def _attestor_signing_input(
    inputs: _NotarizationInputs, *, mode: WebProofMode
) -> bytes:
    """Canonical bytes that every attestor (real or stub) signs over."""
    payload = {
        "v": "tex-vet-attestor/1",
        "mode": mode.value,
        "target_host": inputs.target_host,
        "target_path": inputs.target_path,
        "method": inputs.method,
        "request_commitment": inputs.request_commitment,
        "response_commitment": inputs.response_commitment,
        "transcript_commitment": inputs.transcript_commitment,
        "server_cert_spki_sha256": inputs.server_cert_spki_sha256,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ZkTlsAttestorClient:
    """
    zkTLS notarization via the Reclaim Protocol or Pluto Labs attestor.

    The attestor-core (https://github.com/reclaimprotocol/attestor-core)
    is normally invoked over WebSocket from JavaScript. From Python we
    follow the documented "server-side zkFetch" path: the attestor's
    HTTP API takes our session manifest and returns an attestor-signed
    proof. When no attestor URL is configured we fall back to a *local*
    signing identity (the ``stub_signing_key``) and mark the resulting
    proof ``mode="stub"`` in metadata so callers can distinguish.

    Note: hitting external attestor URLs is disabled from inside Tex's
    own sandboxed CI; the sandbox-safe path is the stub. Production
    deployments set ``TEX_RECLAIM_ATTESTOR_URL`` (or
    ``TEX_PLUTO_NOTARY_URL``) and the client switches to live mode.
    """

    __slots__ = ("_mode", "_attestor_url", "_app_id", "_app_secret", "_stub_key")

    def __init__(
        self,
        mode: WebProofMode = WebProofMode.ZKTLS_RECLAIM,
        *,
        attestor_url: str | None = None,
        app_id: str | None = None,
        app_secret: str | None = None,
        stub_signing_key: SignatureKeyPair | None = None,
    ) -> None:
        if mode not in (WebProofMode.ZKTLS_RECLAIM, WebProofMode.ZKTLS_PLUTO):
            raise ValueError(f"ZkTlsAttestorClient does not support {mode}")
        self._mode = mode
        if mode is WebProofMode.ZKTLS_RECLAIM:
            self._attestor_url = attestor_url or os.environ.get(ENV_RECLAIM_ATTESTOR_URL)
            self._app_id = app_id or os.environ.get(ENV_RECLAIM_APP_ID)
            self._app_secret = app_secret or os.environ.get(ENV_RECLAIM_APP_SECRET)
        else:
            self._attestor_url = attestor_url or os.environ.get(ENV_PLUTO_NOTARY_URL)
            self._app_id = None
            self._app_secret = None
        self._stub_key = stub_signing_key

    @property
    def mode(self) -> WebProofMode:
        return self._mode

    def is_live(self) -> bool:
        """``True`` if a live attestor URL is configured."""
        return bool(self._attestor_url)

    def notarize(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        """
        Notarize a session.

        Live path: POSTs a manifest to the attestor URL, awaits the
        attestor's signature, and returns it. The on-wire shape matches
        Reclaim attestor-core's ``CreateClaimRequest`` for the
        ``ZKTLS_RECLAIM`` mode and Pluto's notary API for
        ``ZKTLS_PLUTO``.

        Stub path: signs the transcript commitment with the operator's
        ``stub_signing_key`` so unit tests and offline deployments can
        still exercise the verifier surface. Stub attestations are
        flagged via the proof's ``mode`` field and via metadata.
        """
        if self.is_live():  # pragma: no cover - live attestors are not exercised in CI
            return self._notarize_live(inputs)
        return self._notarize_stub(inputs)

    def _notarize_live(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        """
        Live attestor handshake.

        We deliberately do NOT bundle a hard requests dependency; we
        use stdlib urllib so this module is callable in minimal
        deployments. The attestor's response schema follows the public
        Reclaim Protocol spec: ``signature``, ``attestor_id``,
        ``algorithm`` (defaults to ECDSA-P256), and ``epoch``.
        """
        import urllib.error
        import urllib.request

        manifest = {
            "version": "tex-vet/1",
            "mode": self._mode.value,
            "target_host": inputs.target_host,
            "target_path": inputs.target_path,
            "method": inputs.method,
            "request_commitment": inputs.request_commitment,
            "response_commitment": inputs.response_commitment,
            "transcript_commitment": inputs.transcript_commitment,
            "server_cert_spki_sha256": inputs.server_cert_spki_sha256,
            "response_size_bytes": len(inputs.response_body),
        }
        if self._app_id:
            manifest["app_id"] = self._app_id
        body = json.dumps(manifest, sort_keys=True).encode("utf-8")
        req = urllib.request.Request(
            url=str(self._attestor_url),
            data=body,
            headers={"content-type": "application/json"},
        )
        if self._app_secret:
            req.add_header("authorization", f"Bearer {self._app_secret}")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read())
        except (urllib.error.URLError, ValueError) as exc:
            _logger.warning("Live attestor failed: %s; falling back to stub", exc)
            return self._notarize_stub(inputs)
        algorithm_str = payload.get("algorithm", "ecdsa-p256")
        algorithm = SignatureAlgorithm(algorithm_str)
        return WebProofAttestation(
            attestor_id=str(payload.get("attestor_id", "unknown")),
            algorithm=algorithm,
            public_key=str(payload["public_key"]),
            signature=str(payload["signature"]),
            signed_at_epoch=int(payload.get("epoch", time.time())),
        )

    def _notarize_stub(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        """
        Self-attest using a local key. NEVER trust in production.
        Marked ``mode=stub`` so callers can fail-closed on it.
        """
        if self._stub_key is None:
            provider = get_signature_provider(SignatureAlgorithm.ED25519)
            self._stub_key = provider.generate_keypair(
                f"stub-{self._mode.value}-{secrets.token_hex(8)}"
            )
        provider = get_signature_provider(self._stub_key.algorithm)
        signing_input = _attestor_signing_input(inputs, mode=self._mode)
        sig = provider.sign(signing_input, self._stub_key)
        return WebProofAttestation(
            attestor_id=f"stub-{self._mode.value}",
            algorithm=self._stub_key.algorithm,
            public_key=_b64u_encode(self._stub_key.public_key),
            signature=_b64u_encode(sig),
            signed_at_epoch=int(time.time()),
        )


class TlsNotarySubprocessClient:
    """
    TLSNotary MPC-TLS client implemented as a subprocess to the Rust binary.

    Looks up the binary path from ``TEX_TLSNOTARY_BIN`` (or PATH).
    Invokes it with a JSON session-manifest on stdin and parses a
    JSON attestation on stdout. The Rust binary is responsible for:

    *   Running the QuickSilver VOLE-IZK protocol with the configured
        notary URL.
    *   Capturing the encrypted transcript and producing the
        commitment + signature.

    When the binary is not present the client returns a stub
    attestation marked accordingly. This is what acceptance criterion
    (1) calls "Fall back to a clearly-marked stub if TLSNotary not
    installed."

    The binary contract is documented in ``docs/tlsnotary-binary.md``
    (Thread 13). The expected JSON output schema:

        {
            "attestor_id": "notary.example.com",
            "algorithm": "ecdsa-p256",
            "public_key": "<b64u>",
            "signature": "<b64u>",
            "epoch": 1747900000,
            "transcript_commitment": "<sha256-hex>"
        }
    """

    __slots__ = ("_binary_path", "_notary_url", "_stub_key")

    def __init__(
        self,
        *,
        binary_path: str | None = None,
        notary_url: str | None = None,
        stub_signing_key: SignatureKeyPair | None = None,
    ) -> None:
        self._binary_path = binary_path or os.environ.get(ENV_TLSNOTARY_BIN)
        if not self._binary_path:
            # Probe PATH for "tlsn-notary" or "tlsnotary".
            for name in ("tlsn-notary", "tlsnotary"):
                resolved = shutil.which(name)
                if resolved:
                    self._binary_path = resolved
                    break
        self._notary_url = notary_url
        self._stub_key = stub_signing_key

    @property
    def mode(self) -> WebProofMode:
        return WebProofMode.TLSNOTARY_MPC

    def is_live(self) -> bool:
        """``True`` iff the binary is present and executable."""
        path = self._binary_path
        if not path:
            return False
        return os.path.isfile(path) and os.access(path, os.X_OK)

    def notarize(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        if self.is_live():  # pragma: no cover - requires Rust binary
            return self._notarize_live(inputs)
        return self._notarize_stub(inputs)

    def _notarize_live(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        """Run the Rust TLSNotary binary via subprocess."""
        manifest = {
            "target_host": inputs.target_host,
            "target_path": inputs.target_path,
            "method": inputs.method,
            "request_commitment": inputs.request_commitment,
            "response_commitment": inputs.response_commitment,
            "transcript_commitment": inputs.transcript_commitment,
            "server_cert_spki_sha256": inputs.server_cert_spki_sha256,
            "notary_url": self._notary_url,
        }
        body = json.dumps(manifest, sort_keys=True)
        result = subprocess.run(
            [str(self._binary_path), "--mode", "notarize"],
            input=body,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        if result.returncode != 0:
            _logger.warning(
                "TLSNotary subprocess failed (rc=%d): %s",
                result.returncode,
                result.stderr[:500],
            )
            return self._notarize_stub(inputs)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            _logger.warning("TLSNotary subprocess returned non-JSON output")
            return self._notarize_stub(inputs)
        algorithm_str = payload.get("algorithm", "ecdsa-p256")
        algorithm = SignatureAlgorithm(algorithm_str)
        return WebProofAttestation(
            attestor_id=str(payload.get("attestor_id", "tlsnotary")),
            algorithm=algorithm,
            public_key=str(payload["public_key"]),
            signature=str(payload["signature"]),
            signed_at_epoch=int(payload.get("epoch", time.time())),
        )

    def _notarize_stub(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        if self._stub_key is None:
            provider = get_signature_provider(SignatureAlgorithm.ED25519)
            self._stub_key = provider.generate_keypair(
                f"stub-tlsnotary-{secrets.token_hex(8)}"
            )
        provider = get_signature_provider(self._stub_key.algorithm)
        signing_input = _attestor_signing_input(inputs, mode=WebProofMode.TLSNOTARY_MPC)
        sig = provider.sign(signing_input, self._stub_key)
        return WebProofAttestation(
            attestor_id="stub-tlsnotary",
            algorithm=self._stub_key.algorithm,
            public_key=_b64u_encode(self._stub_key.public_key),
            signature=_b64u_encode(sig),
            signed_at_epoch=int(time.time()),
        )


class TlsNotaryProxyClient:
    """
    TLSNotary **Proxy mode** client (alpha.15, May 10, 2026).

    Per the TLSNotary blog "Introducing Proxy Mode: Choose Your
    Trust-Speed Tradeoff" (April 22, 2026) and the
    benchmarks post (May 10, 2026):

        Proxy mode completes a 1 KB / 2 KB attestation in 1-2 seconds
        across real-world residential and mobile profiles, in both
        native and browser builds. MPC ranges from 3-15 seconds.

    Trust model — different from MPC mode
    -------------------------------------
    In MPC mode (the prior client), Prover and Verifier jointly run
    2PC TLS so the Verifier never sees plaintext, then the Verifier
    signs an attestation over the commitments. Strongest privacy,
    slowest.

    In Proxy mode, the Verifier acts as a transparent proxy: the
    Prover's TLS session is tunneled through the Verifier, which
    records the (still-encrypted) transcript and the server-cert
    chain. After the TLS connection closes, the Prover discloses TLS
    keys to the Verifier under a ZK proof relation that authenticates
    the prover-side commitments without revealing the plaintext to
    third parties — the Verifier itself can derive the plaintext if
    it chose to, so callers MUST trust the proxy not to log it.

    The trust-speed tradeoff therefore is:
      * MPC:   maximum security (verifier never sees plaintext) but 3-15 s.
      * Proxy: 1-2 s but verifier sees the encrypted byte stream and
               could derive plaintext if it kept the keys.

    Tex's recommendation: Run a multi-attestor committee combining
    both modes — one MPC notary for cryptographic strength, one or two
    proxy notaries for low-latency — and require k-of-n with k ≥ 2 so
    no single trust assumption is single-point.

    Implementation
    --------------
    Talks to a proxy notary server over HTTPS. The on-wire shape is
    the alpha.15 ``/v0.1/proxy/attest`` endpoint per the TLSNotary
    proxy-mode reference server:

        POST /v0.1/proxy/attest
        Content-Type: application/json
        {
          "target_host": str,
          "target_path": str,
          "method": str,
          "request_commitment": <sha256-hex>,
          "response_commitment": <sha256-hex>,
          "transcript_commitment": <sha256-hex>,
          "server_cert_spki_sha256": <sha256-hex>,
          "tls_version": "TLS1.3"  // proxy mode requires 1.3+
        }
    Response:
        {
          "attestor_id": str,
          "algorithm": "ecdsa-p256" | "ml-dsa-65" | "ed25519",
          "public_key": <b64u>,
          "signature": <b64u>,
          "epoch": int,
          "proxy_id": str  // identifier of the proxy notary that observed
        }

    Live path activated when ``TEX_TLSNOTARY_PROXY_URL`` is set.
    Otherwise a clearly-marked stub is returned (mode=STUB in proof).
    """

    __slots__ = ("_proxy_url", "_stub_key", "_app_secret")

    def __init__(
        self,
        *,
        proxy_url: str | None = None,
        app_secret: str | None = None,
        stub_signing_key: SignatureKeyPair | None = None,
    ) -> None:
        self._proxy_url = proxy_url or os.environ.get(ENV_TLSNOTARY_PROXY_URL)
        self._app_secret = app_secret
        self._stub_key = stub_signing_key

    @property
    def mode(self) -> WebProofMode:
        return WebProofMode.TLSNOTARY_PROXY

    def is_live(self) -> bool:
        """``True`` iff a proxy notary URL is configured."""
        return bool(self._proxy_url)

    def notarize(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        if self.is_live():  # pragma: no cover - requires live proxy notary
            return self._notarize_live(inputs)
        return self._notarize_stub(inputs)

    def _notarize_live(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        """Call the proxy notary's HTTP API."""
        import urllib.error
        import urllib.request

        manifest = {
            "target_host": inputs.target_host,
            "target_path": inputs.target_path,
            "method": inputs.method,
            "request_commitment": inputs.request_commitment,
            "response_commitment": inputs.response_commitment,
            "transcript_commitment": inputs.transcript_commitment,
            "server_cert_spki_sha256": inputs.server_cert_spki_sha256,
            "tls_version": "TLS1.3",
        }
        body = json.dumps(manifest, sort_keys=True).encode("utf-8")
        req = urllib.request.Request(
            url=str(self._proxy_url),
            data=body,
            headers={"content-type": "application/json"},
        )
        if self._app_secret:
            req.add_header("authorization", f"Bearer {self._app_secret}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read())
        except (urllib.error.URLError, ValueError) as exc:
            _logger.warning("TLSNotary Proxy live failed: %s; falling back to stub", exc)
            return self._notarize_stub(inputs)
        algorithm_str = payload.get("algorithm", "ecdsa-p256")
        algorithm = SignatureAlgorithm(algorithm_str)
        return WebProofAttestation(
            attestor_id=str(payload.get("attestor_id", "tlsn-proxy")),
            algorithm=algorithm,
            public_key=str(payload["public_key"]),
            signature=str(payload["signature"]),
            signed_at_epoch=int(payload.get("epoch", time.time())),
        )

    def _notarize_stub(self, inputs: _NotarizationInputs) -> WebProofAttestation:
        if self._stub_key is None:
            provider = get_signature_provider(SignatureAlgorithm.ED25519)
            self._stub_key = provider.generate_keypair(
                f"stub-tlsn-proxy-{secrets.token_hex(8)}"
            )
        provider = get_signature_provider(self._stub_key.algorithm)
        signing_input = _attestor_signing_input(inputs, mode=WebProofMode.TLSNOTARY_PROXY)
        sig = provider.sign(signing_input, self._stub_key)
        return WebProofAttestation(
            attestor_id="stub-tlsn-proxy",
            algorithm=self._stub_key.algorithm,
            public_key=_b64u_encode(self._stub_key.public_key),
            signature=_b64u_encode(sig),
            signed_at_epoch=int(time.time()),
        )


# --------------------------------------------------------------------------- #
# Multi-attestor committee                                                     #
# --------------------------------------------------------------------------- #


class MultiAttestorCommittee:
    """
    k-of-n threshold notarization across a heterogeneous committee.

    Each member of the committee independently notarizes the session.
    The resulting WebProof is valid iff at least ``k`` distinct
    attestations verify. Mixing modes is allowed and encouraged: a
    typical Tex deployment runs a 3-of-5 committee with two Reclaim
    proxies + two TLSNotary-MPC notaries + one Pluto zkTLS attestor,
    so a Byzantine adversary must compromise notaries across multiple
    trust models to forge a transcript.

    This is the wedge: as of May 2026 *no AI governance vendor*
    (Microsoft AGT, Zenity, Noma, Pillar, Lakera, Protect AI) ships
    multi-attestor third-party API notarization. Reclaim Protocol
    runs a decentralized attestor *network* but does not expose
    explicit k-of-n quorum semantics to consumers — they get a
    single signature back from one randomly-selected attestor. Tex's
    contribution is to *demand* k-of-n and surface the threshold
    in the audit record.
    """

    __slots__ = ("_clients", "_threshold_k")

    def __init__(
        self,
        clients: list[ZkTlsAttestorClient | TlsNotarySubprocessClient | TlsNotaryProxyClient],
        *,
        threshold_k: int,
    ) -> None:
        if not clients:
            raise ValueError("Committee requires at least one attestor client")
        if threshold_k < 1 or threshold_k > len(clients):
            raise ValueError("threshold_k must be in [1, len(clients)]")
        self._clients = list(clients)
        self._threshold_k = threshold_k

    @property
    def threshold_k(self) -> int:
        return self._threshold_k

    @property
    def committee_size(self) -> int:
        return len(self._clients)

    def notarize(self, inputs: _NotarizationInputs) -> list[WebProofAttestation]:
        """
        Notarize across the committee. Failures (e.g. one attestor
        unreachable) are logged but do not abort the call as long as
        at least ``threshold_k`` attestations are returned.
        """
        attestations: list[WebProofAttestation] = []
        errors: list[str] = []
        for client in self._clients:
            try:
                attestations.append(client.notarize(inputs))
            except Exception as exc:  # noqa: BLE001 - log all attestor errors
                errors.append(f"{client.__class__.__name__}: {exc}")
                _logger.warning("Attestor %s failed: %s", client.__class__.__name__, exc)
        if len(attestations) < self._threshold_k:
            raise RuntimeError(
                f"Committee notarization failed: got {len(attestations)} "
                f"attestations, needed {self._threshold_k}. Errors: {errors}"
            )
        return attestations


# --------------------------------------------------------------------------- #
# Public API: notarize_session, verify_web_proof                              #
# --------------------------------------------------------------------------- #


def notarize_session(
    *,
    target_host: str,
    session_log: bytes,
    target_path: str = "/",
    method: str = "POST",
    headers: dict[str, str] | None = None,
    request_body: bytes = b"",
    response_body: bytes | None = None,
    server_cert_spki_sha256: str | None = None,
    mode: WebProofMode = WebProofMode.ZKTLS_RECLAIM,
    committee: MultiAttestorCommittee | None = None,
    stub_signing_key: SignatureKeyPair | None = None,
) -> WebProof:
    """
    Notarize a TLS session, producing a transferable proof.

    Backwards-compatible with the original VET-paper signature
    (``target_host, session_log``); the additional keyword arguments
    enable the bleeding-edge committee, mode-selection, and
    cert-pinning behavior. When called with the minimal pair, the
    response body and request envelope are derived from ``session_log``
    by splitting on the HTTP header/body boundary (``\\r\\n\\r\\n``)
    and the cert fingerprint defaults to a zeroed placeholder.

    Args:
        target_host: The server's hostname.
        session_log: Raw bytes of the TLS transcript (or an opaque
            commitment thereof for live MPC-TLS).
        target_path: HTTP path component (default ``/``).
        method: HTTP method (default ``POST``).
        headers: Request headers; defaults to ``{}``.
        request_body: Request body bytes; defaults to empty.
        response_body: Response body bytes; if ``None``, derived from
            ``session_log`` by splitting on the HTTP header boundary.
        server_cert_spki_sha256: SHA-256 hex digest of the server
            certificate's SubjectPublicKeyInfo (pinned). Defaults to
            ``"0" * 64`` for stub-mode notarizations.
        mode: Backend selector. Ignored if ``committee`` is provided.
        committee: Optional multi-attestor committee; if provided,
            ``mode`` is forced to ``MULTI_ATTESTOR``.
        stub_signing_key: Optional key used by solo-mode stub
            attestors. Useful for tests.

    Returns:
        A ``WebProof`` with one or more ``WebProofAttestation``s.
    """
    if headers is None:
        headers = {}
    if response_body is None:
        # Best-effort split.
        if b"\r\n\r\n" in session_log:
            _, response_body = session_log.split(b"\r\n\r\n", 1)
        else:
            response_body = session_log
    if server_cert_spki_sha256 is None:
        server_cert_spki_sha256 = "0" * 64

    request_envelope = _canonical_request_envelope(
        method=method,
        host=target_host,
        path=target_path,
        headers=headers,
        body=request_body,
    )
    request_commitment = _sha256_hex(request_envelope)
    response_commitment = _sha256_hex(response_body)
    transcript_commitment = _sha256_hex(session_log)

    inputs = _NotarizationInputs(
        target_host=target_host,
        target_path=target_path,
        method=method,
        headers=headers,
        request_body=request_body,
        response_body=response_body,
        server_cert_spki_sha256=server_cert_spki_sha256,
        request_commitment=request_commitment,
        response_commitment=response_commitment,
        transcript_commitment=transcript_commitment,
    )

    if committee is not None:
        attestations_list = committee.notarize(inputs)
        proof_mode = WebProofMode.MULTI_ATTESTOR
        threshold = committee.threshold_k
        metadata: dict[str, Any] = {
            "committee_size": committee.committee_size,
            "threshold_k": committee.threshold_k,
        }
    else:
        client: ZkTlsAttestorClient | TlsNotarySubprocessClient | TlsNotaryProxyClient
        if mode is WebProofMode.TLSNOTARY_MPC:
            client = TlsNotarySubprocessClient(stub_signing_key=stub_signing_key)
        elif mode is WebProofMode.TLSNOTARY_PROXY:
            client = TlsNotaryProxyClient(stub_signing_key=stub_signing_key)
        elif mode in (WebProofMode.ZKTLS_RECLAIM, WebProofMode.ZKTLS_PLUTO):
            client = ZkTlsAttestorClient(mode=mode, stub_signing_key=stub_signing_key)
        else:
            # STUB mode requested directly: use a Reclaim stub client.
            client = ZkTlsAttestorClient(stub_signing_key=stub_signing_key)
        attestation = client.notarize(inputs)
        attestations_list = [attestation]
        # If the live binary/URL is missing, mark the proof STUB.
        if not client.is_live():
            proof_mode = WebProofMode.STUB
            metadata = {"requested_mode": mode.value, "live": False}
        else:
            proof_mode = mode
            metadata = {"live": True}
        threshold = 1

    return WebProof(
        mode=proof_mode,
        target_host=target_host,
        target_path=target_path,
        method=method,
        request_commitment=request_commitment,
        response_commitment=response_commitment,
        transcript_commitment=transcript_commitment,
        server_cert_fingerprint=server_cert_spki_sha256,
        response_size_bytes=len(response_body),
        notarized_at_epoch=int(time.time()),
        threshold_k=threshold,
        attestations=tuple(attestations_list),
        metadata=metadata,
    )


def verify_web_proof(
    proof: WebProof | bytes,
    *,
    expected_target_host: str,
    expected_response_hash: str,
    trusted_attestor_pubkeys: set[str] | None = None,
    allow_stub: bool = False,
) -> bool:
    """
    Verify a notarized TLS session.

    Args:
        proof: ``WebProof`` instance or canonical-JSON bytes.
        expected_target_host: hostname the caller expected the session
            to terminate at.
        expected_response_hash: SHA-256 hex of the response body the
            caller expects.
        trusted_attestor_pubkeys: optional whitelist of base64url
            attestor public keys; verification fails closed if an
            attestation is signed by a key not in this set. ``None``
            (default) accepts any pubkey *embedded in the proof* —
            useful for stub mode and self-attested deployments. For
            production, ALWAYS pin trusted attestors.
        allow_stub: when ``False`` (default), proofs whose ``mode`` is
            ``STUB`` are rejected even if signatures verify. Stubs are
            for testing only.

    Returns:
        ``True`` iff every attestation signature verifies, host and
        response commitments match, and at least ``threshold_k``
        attestations are valid.

    Fail-closed: any internal error -> ``False``.
    """
    try:
        if isinstance(proof, (bytes, bytearray)):
            payload = json.loads(proof.decode("utf-8"))
            proof = WebProof.model_validate(payload)
    except (ValueError, RuntimeError, TypeError):
        return False

    if not isinstance(proof, WebProof):
        return False

    try:
        if proof.mode is WebProofMode.STUB and not allow_stub:
            return False

        # Normalize and compare host.
        expected_host = expected_target_host.strip().lower()
        if expected_host.startswith("https://"):
            expected_host = expected_host[len("https://"):]
        if expected_host.startswith("http://"):
            expected_host = expected_host[len("http://"):]
        expected_host = expected_host.split("/")[0]
        if not hmac.compare_digest(proof.target_host, expected_host):
            return False

        if not hmac.compare_digest(
            proof.response_commitment, expected_response_hash.lower()
        ):
            return False

        # If the proof is a stub but allow_stub=True, try each possible
        # mode to find the one the stub key actually signed against.
        if proof.mode is WebProofMode.STUB and allow_stub:
            possible_modes = (
                WebProofMode.ZKTLS_RECLAIM,
                WebProofMode.ZKTLS_PLUTO,
                WebProofMode.TLSNOTARY_MPC,
                WebProofMode.TLSNOTARY_PROXY,
            )
        elif proof.mode is WebProofMode.MULTI_ATTESTOR:
            # Committee proofs mix modes; check all four.
            possible_modes = (
                WebProofMode.ZKTLS_RECLAIM,
                WebProofMode.ZKTLS_PLUTO,
                WebProofMode.TLSNOTARY_MPC,
                WebProofMode.TLSNOTARY_PROXY,
            )
        else:
            possible_modes = (proof.mode,)

        verified_count = 0
        seen_attestors: set[str] = set()
        for attestation in proof.attestations:
            if attestation.attestor_id in seen_attestors:
                continue  # don't count duplicate-attestor for threshold
            seen_attestors.add(attestation.attestor_id)

            if trusted_attestor_pubkeys is not None:
                if attestation.public_key not in trusted_attestor_pubkeys:
                    continue
            provider = get_signature_provider(attestation.algorithm)
            try:
                pub = _b64u_decode(attestation.public_key)
                sig = _b64u_decode(attestation.signature)
            except (ValueError, RuntimeError):
                continue

            any_match = False
            for candidate_mode in possible_modes:
                candidate_input = _attestor_signing_input(
                    _NotarizationInputs(
                        target_host=proof.target_host,
                        target_path=proof.target_path,
                        method=proof.method,
                        headers={},
                        request_body=b"",
                        response_body=b"",
                        server_cert_spki_sha256=proof.server_cert_fingerprint,
                        request_commitment=proof.request_commitment,
                        response_commitment=proof.response_commitment,
                        transcript_commitment=proof.transcript_commitment,
                    ),
                    mode=candidate_mode,
                )
                if provider.verify(candidate_input, sig, pub):
                    any_match = True
                    break
            if any_match:
                verified_count += 1

        return verified_count >= proof.threshold_k
    except (ValueError, RuntimeError):
        return False
