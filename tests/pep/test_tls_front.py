"""Tests for the TLS-visibility front (G9 — ``tex.pep.tls_front``).

What is covered HERE (macOS-runnable):
  * ClientHello SNI parsing on REAL ClientHello bytes (captured from stdlib ssl)
    and on malformed / no-SNI inputs (fail-soft to None).
  * In-box CA: a minted leaf chains to the CA with the right SAN, and the CA
    private key is never exported (custody is a first-class requirement).
  * Per-connection disposition: terminate iff SNI is pinned to orig_dst AND on
    the allowlist; everything else (no-SNI/ECH, spoofed SNI, pinned-but-not-
    allowlisted, no dst) fails visible with the most-defensible recipient.
  * REAL loopback TLS termination: the front presents the minted leaf, a client
    trusting the in-box CA completes the handshake, and the decrypted MCP
    tools/call reaches the EXISTING proxy.handle() — tool name + args restored,
    channel="mcp" — proving _to_decision needs zero change under MITM.
  * Fail-visible: a non-allowlisted destination is ruled `https_opaque`; on a
    released opaque verdict the raw TCP is spliced to the orig_dst (L4 passthrough,
    no decryption); on a non-released verdict it is refused (fail-closed).

What needs the deploy (NOT covered here): eBPF redirect -> this listener, and the
upstream TLS re-origination against a real pinned upstream. eBPF cannot build on
macOS.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time

import pytest

from tex.pep.decision_client import Decision, DecisionClient, DecisionResult
from tex.pep.proxy import ResolvedDst, TexEnforcementProxy, UpstreamResponse
from tex.pep.tls_front import (
    FAIL_VISIBLE,
    TERMINATE,
    Disposition,
    InBoxCA,
    TlsFront,
    parse_client_hello_sni,
)


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


class _RecordingForwarder:
    def __init__(self):
        self.calls: list[dict] = []

    def send(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return UpstreamResponse(status=200, headers={"content-type": "text/plain"}, body=b"OK-UPSTREAM")


class _CapturingClient(DecisionClient):
    def __init__(self, result: DecisionResult):
        self._result = result
        self.last: Decision | None = None

    def decide(self, decision: Decision) -> DecisionResult:
        self.last = decision
        return self._result


class _FakeResolver:
    def __init__(self, dst: ResolvedDst | None):
        self._dst = dst

    def resolve(self, src_ip, src_port):
        return self._dst


def _permit() -> DecisionResult:
    return DecisionResult(released=True, verdict="PERMIT", reason="ok", decision_id="d1")


def _capture_client_hello(server_name: str) -> bytes:
    """Capture a REAL ClientHello by starting (not completing) a stdlib TLS
    handshake over a socketpair and reading the first record off the wire."""
    a, b = socket.socketpair()
    a.settimeout(2.0)
    b.settimeout(2.0)

    def _client():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.wrap_socket(a, server_hostname=server_name)
        except (ssl.SSLError, OSError):
            pass

    t = threading.Thread(target=_client, daemon=True)
    t.start()
    try:
        data = b.recv(8192)
    finally:
        a.close()
        b.close()
        t.join(timeout=2.0)
    return data


# --------------------------------------------------------------------------- #
# SNI parser                                                                   #
# --------------------------------------------------------------------------- #


def test_parses_sni_from_real_client_hello():
    hello = _capture_client_hello("api.example.com")
    assert parse_client_hello_sni(hello) == "api.example.com"


def test_no_sni_when_server_name_absent():
    # A real ClientHello sent with an IP-literal server_hostname carries NO SNI
    # extension (RFC 6066 forbids IP in SNI) — parser must return None, NOT guess.
    hello = _capture_client_hello("127.0.0.1")
    assert parse_client_hello_sni(hello) is None


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x15\x03\x03\x00\x02\x01\x00",  # alert record, not handshake
        b"\x16\x03\x01\x00\x04\x02\x00\x00\x00",  # handshake but ServerHello (0x02)
        b"\x16\x03\x01\xff\xff\x01\x00\x00\x10garbage-truncated",  # truncated CH
    ],
)
def test_malformed_inputs_fail_soft_to_none(data):
    assert parse_client_hello_sni(data) is None


# --------------------------------------------------------------------------- #
# In-box CA (minting + custody)                                                #
# --------------------------------------------------------------------------- #


def test_minted_leaf_chains_to_ca_with_correct_san():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    ca = InBoxCA.generate()
    cert_pem, key_pem = ca.mint_leaf("api.example")
    leaf = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca.trust_anchor_pem)

    assert leaf.issuer == ca_cert.subject
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert "api.example" in san.value.get_values_for_type(x509.DNSName)
    # The CA's public key verifies the leaf signature => the CA minted it.
    ca_cert.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
    )
    # The leaf key is distinct, per-SNI material returned for the proxy's own ctx.
    assert b"PRIVATE KEY" in key_pem


def test_leaf_cache_is_stable_per_sni():
    ca = InBoxCA.generate()
    assert ca.mint_leaf("api.example") == ca.mint_leaf("api.example")


def test_ca_never_exports_its_private_key():
    ca = InBoxCA.generate()
    anchor = ca.trust_anchor_pem
    assert b"BEGIN CERTIFICATE" in anchor
    assert b"PRIVATE KEY" not in anchor  # the trust anchor is the public cert ONLY
    # No PUBLIC accessor returns the CA private key (custody: it never leaves).
    public_attrs = {n for n in dir(ca) if not n.startswith("_")}
    assert public_attrs == {"generate", "mint_leaf", "server_context_for", "trust_anchor_pem"}


def test_empty_sni_cannot_mint():
    ca = InBoxCA.generate()
    with pytest.raises(ValueError):
        ca.mint_leaf("")


# --------------------------------------------------------------------------- #
# Disposition (terminate vs fail-visible)                                      #
# --------------------------------------------------------------------------- #


def _front(allowlist, dst, host_ips):
    proxy = TexEnforcementProxy(decision_client=_CapturingClient(_permit()))
    return TlsFront(
        proxy=proxy,
        ca=InBoxCA.generate(),
        terminate_allowlist=allowlist,
        origdst=_FakeResolver(dst),
        host_resolver=lambda h: set(host_ips),
    )


def test_terminate_when_pinned_and_allowlisted():
    hello = _capture_client_hello("api.example")
    front = _front({"api.example"}, ResolvedDst("10.0.0.5", 443), {"10.0.0.5"})
    disp = front.disposition(("1.2.3.4", 5), hello)
    assert disp.action == TERMINATE
    assert disp.recipient == "api.example"


def test_fail_visible_when_pinned_but_not_allowlisted():
    hello = _capture_client_hello("api.example")
    front = _front(set(), ResolvedDst("10.0.0.5", 443), {"10.0.0.5"})
    disp = front.disposition(("1.2.3.4", 5), hello)
    assert disp.action == FAIL_VISIBLE
    assert disp.recipient == "api.example"  # trustworthy name, just not terminated


def test_fail_visible_ip_only_when_sni_does_not_pin_to_orig_dst():
    # Agent puts api.example in SNI but the kernel orig_dst is an attacker IP that
    # api.example does NOT resolve to -> do NOT trust the name; rule on the IP.
    hello = _capture_client_hello("api.example")
    front = _front({"api.example"}, ResolvedDst("203.0.113.9", 443), {"10.0.0.5"})
    disp = front.disposition(("1.2.3.4", 5), hello)
    assert disp.action == FAIL_VISIBLE
    assert disp.recipient == "203.0.113.9"  # the kernel-verified IP, not the spoofed name


def test_fail_visible_ip_only_when_no_sni_ech():
    # No readable SNI (ECH cover / IP-literal) -> IP-only floor.
    hello = _capture_client_hello("127.0.0.1")  # carries no SNI
    front = _front({"api.example"}, ResolvedDst("10.0.0.5", 443), {"10.0.0.5"})
    disp = front.disposition(("1.2.3.4", 5), hello)
    assert disp.action == FAIL_VISIBLE
    assert disp.recipient == "10.0.0.5"


def test_fail_visible_no_recipient_when_no_sni_and_no_dst():
    hello = _capture_client_hello("127.0.0.1")
    front = _front({"api.example"}, None, set())
    disp = front.disposition(("1.2.3.4", 5), hello)
    assert disp.action == FAIL_VISIBLE
    assert disp.recipient is None


# --------------------------------------------------------------------------- #
# Real loopback TLS termination (the content-visibility win)                   #
# --------------------------------------------------------------------------- #


def _serve_one(front: TlsFront, server: socket.socket) -> threading.Thread:
    def _serve():
        try:
            conn, peer = server.accept()
        except OSError:
            return
        front.handle_stream(conn, peer)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


def test_termination_decrypts_mcp_toolcall_into_handle():
    ca = InBoxCA.generate()
    client = _CapturingClient(_permit())
    fwd = _RecordingForwarder()
    dst = ResolvedDst("127.0.0.1", 443)
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(dst),
        host_resolver=lambda h: {"127.0.0.1"},
    )
    front = TlsFront(
        proxy=proxy,
        ca=ca,
        terminate_allowlist={"api.example"},
        origdst=_FakeResolver(dst),
        host_resolver=lambda h: {"127.0.0.1"},
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    worker = _serve_one(front, server)

    cctx = ssl.create_default_context(cadata=ca.trust_anchor_pem.decode("ascii"))
    cctx.check_hostname = True
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "ceo@x.com", "body": "secret"}},
        }
    ).encode("utf-8")
    request = (
        b"POST /mcp HTTP/1.1\r\n"
        b"Host: api.example\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    raw = socket.create_connection((host, port), timeout=5.0)
    try:
        tls = cctx.wrap_socket(raw, server_hostname="api.example")
        tls.sendall(request)
        resp = tls.recv(65536)
    finally:
        try:
            tls.close()
        except Exception:
            pass
        server.close()
        worker.join(timeout=5.0)

    assert resp.startswith(b"HTTP/1.1 200")
    assert b"OK-UPSTREAM" in resp
    # The decrypted MCP tools/call reached the EXISTING handle()/_to_decision:
    # tool name -> action_type, args -> content, channel="mcp". No change needed.
    assert client.last is not None
    assert client.last.action_type == "send_email"
    assert client.last.channel == "mcp"
    assert "ceo@x.com" in client.last.content
    assert client.last.recipient == "api.example"
    # Re-originated upstream via the proxy's own forwarder.
    assert fwd.calls and fwd.calls[0]["url"] == "https://127.0.0.1:443/mcp"


def test_termination_handshake_refusal_fails_closed_not_silent_bypass():
    # An agent that pins (refuses our leaf) must NOT slip through: the connection
    # is ruled opaque (sealed audit) and refused, never silently spliced.
    ca = InBoxCA.generate()
    client = _CapturingClient(_permit())
    dst = ResolvedDst("127.0.0.1", 443)
    proxy = TexEnforcementProxy(
        decision_client=client, origdst=_FakeResolver(dst), host_resolver=lambda h: {"127.0.0.1"}
    )
    front = TlsFront(
        proxy=proxy, ca=ca, terminate_allowlist={"api.example"},
        origdst=_FakeResolver(dst), host_resolver=lambda h: {"127.0.0.1"},
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    worker = _serve_one(front, server)

    # A client that does NOT trust the in-box CA -> the handshake fails (pinning).
    cctx = ssl.create_default_context()  # system trust only; rejects our leaf
    cctx.check_hostname = True
    raw = socket.create_connection((host, port), timeout=5.0)
    try:
        # wrap_socket runs the handshake (do_handshake_on_connect default), which
        # the pinning client rejects with an unknown-CA alert.
        with pytest.raises((ssl.SSLError, OSError)):
            cctx.wrap_socket(raw, server_hostname="api.example")
    finally:
        raw.close()
        server.close()
        worker.join(timeout=5.0)

    # The opaque connection was RULED (and would be sealed) — never permitted-by-default.
    assert client.last is not None
    assert client.last.action_type == "https_opaque"


# --------------------------------------------------------------------------- #
# Fail-visible L4 splice (opaque PERMIT) and refusal (opaque non-PERMIT)       #
# --------------------------------------------------------------------------- #


def test_opaque_permit_splices_raw_tcp_to_orig_dst():
    # An echo "upstream" stands in for the real destination.
    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(("127.0.0.1", 0))
    up.listen(1)
    up_host, up_port = up.getsockname()

    def _echo():
        try:
            conn, _ = up.accept()
        except OSError:
            return
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=_echo, daemon=True).start()

    dst = ResolvedDst(up_host, up_port)
    proxy = TexEnforcementProxy(
        decision_client=_CapturingClient(_permit()),  # opaque verdict PERMITs
        origdst=_FakeResolver(dst),
    )
    front = TlsFront(
        proxy=proxy,
        ca=InBoxCA.generate(),
        terminate_allowlist=set(),  # nothing allowlisted -> fail-visible path
        origdst=_FakeResolver(dst),
        host_resolver=lambda h: {up_host},  # pins api.example to the echo upstream IP
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    worker = _serve_one(front, server)

    hello = _capture_client_hello("api.example")  # pinned, not allowlisted -> opaque PERMIT -> splice
    cli = socket.create_connection((host, port), timeout=5.0)
    cli.settimeout(5.0)
    got = b""
    try:
        cli.sendall(hello + b"OPAQUE-PAYLOAD")
        deadline = time.monotonic() + 5.0
        while b"OPAQUE-PAYLOAD" not in got and time.monotonic() < deadline:
            try:
                chunk = cli.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            got += chunk
    finally:
        cli.close()
        server.close()
        up.close()
        worker.join(timeout=5.0)

    # The raw bytes were spliced to the orig_dst and echoed back — never decrypted.
    assert b"OPAQUE-PAYLOAD" in got
    assert proxy._decide.last.action_type == "https_opaque"


def test_opaque_non_permit_refuses_without_splicing():
    forbid = DecisionResult(released=False, verdict="FORBID", reason="opaque to forbidden host")
    dst = ResolvedDst("10.0.0.9", 443)
    proxy = TexEnforcementProxy(decision_client=_CapturingClient(forbid), origdst=_FakeResolver(dst))
    front = TlsFront(
        proxy=proxy, ca=InBoxCA.generate(), terminate_allowlist=set(),
        origdst=_FakeResolver(dst), host_resolver=lambda h: {"10.0.0.9"},
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    worker = _serve_one(front, server)

    hello = _capture_client_hello("api.example")
    cli = socket.create_connection((host, port), timeout=5.0)
    cli.settimeout(5.0)
    try:
        cli.sendall(hello + b"SHOULD-NOT-EGRESS")
        # The front refuses with no backend: the client sees EOF (b"") or a reset
        # (RST when the socket is closed with our unread bytes still buffered).
        # Either way nothing was forwarded/echoed — a fail-closed refusal.
        try:
            leftover = cli.recv(4096)
        except ConnectionResetError:
            leftover = b""
    finally:
        cli.close()
        server.close()
        worker.join(timeout=5.0)

    assert leftover == b""  # connection refused/closed, nothing forwarded
    # It WAS ruled (opaque), and since the verdict was not released it was never
    # spliced — an explicit fail-closed refusal, not a silent bypass.
    assert proxy._decide.last.action_type == "https_opaque"
