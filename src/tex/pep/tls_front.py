"""
TLS content-visibility front for the enforcement proxy (G9).

This is the scoped, custody-disciplined in-box MITM terminator the design doc
(``docs/blueprint/exec-layer/tls-visibility.md``) recommends. It sits in front of
the EXISTING ``TexEnforcementProxy.handle(...)`` and, per connection:

  1. Peek the ClientHello (``MSG_PEEK`` — never consumes it) and read the SNI.
  2. Resolve the real destination from the kernel orig_dst loader
     (``OrigDstResolver``, keyed by the agent's source ``ip:port``).
  3. Pin SNI to orig_dst: trust the hostname ONLY if it DNS-resolves to the
     kernel-observed orig_dst IP. ECH (no/cover SNI), a spoofed SNI, or a name
     that resolves elsewhere is NOT trusted — we fall to the IP-only floor.
  4. Terminate IFF the pinned SNI is on the configured ``terminate_allowlist``,
     using an in-box CA whose private key lives ONLY here (never in the agent
     container). After termination the decrypted HTTP/MCP request flows through
     the IDENTICAL ``proxy.handle(...)`` the plaintext path uses — ``_to_decision``
     restores tool + args, ``channel="mcp"``, filtered discovery — UNCHANGED. The
     upstream re-origination is the proxy's existing forwarder (httpx speaks TLS
     to ``https://<orig_dst_ip>:port``), so this module owns ONLY the agent-facing
     TLS server side.
  5. Otherwise FAIL VISIBLE, never silent: rule the connection as
     ``proxy.rule_opaque(...)`` → ``action_type="https_opaque"`` on the
     SNI-pinned-to-orig_dst recipient, so the PDP can ABSTAIN on un-inspectable
     content. On a released opaque verdict we splice the TCP straight through to
     the kernel-verified orig_dst (honest L4 passthrough — we never decrypt);
     otherwise we refuse (close = fail-closed). A handshake the agent refuses
     under termination (suspected cert-pinning) routes here too — fail-closed,
     never a silent bypass.

What this does NOT buy (read the design doc §5 too):
  * SNI-allowlisting is not DLP. Argument-level inspection returns ONLY on the
    terminated path; the opaque/L4 path knows WHERE, never WHAT.
  * MITM does not cover cert-pinned / agent-controlled-trust upstreams — those
    fail-closed to the opaque verdict, never slip by uninspected.
  * ECH (RFC 9849) blinds the SNI; the floor then degrades to orig_dst IP only.
  * Sealing this as "content observed via MITM-termination at the proxy" is the
    honest claim — never "proved the agent's intent". The trust is exactly the
    trust in the termination, no more.

Crypto/TLS reuse (per the thread's ground rules): the in-box CA and leaf minting
use ``cryptography``; the agent-facing handshake uses the stdlib ``ssl`` module.
The ONLY thing hand-parsed is the SNI field of the ClientHello — that is reading
a wire structure (RFC 8446 §4.1.2 / RFC 6066 §3), not implementing crypto, and is
required because we must read the SNI to decide whether to terminate BEFORE any
handshake (the ssl module cannot peek SNI without owning the handshake).

Maturity: ``research-early``. The pure units (SNI parse, leaf minting + custody,
disposition / SNI-pin / allowlist, the opaque fail-visible verdict) and the
real-loopback termination path are unit/integration-tested here. The full
deploy E2E — eBPF redirect → this listener → upstream TLS, and the L4 splice
against a live upstream — needs the Linux node (eBPF cannot build on macOS).
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from tex.pep.proxy import ResolvedDst, _default_host_ips

if TYPE_CHECKING:
    from tex.pep.decision_client import DecisionResult
    from tex.pep.proxy import OrigDstResolver, TexEnforcementProxy, UpstreamResponse

__all__ = [
    "parse_client_hello_sni",
    "InBoxCA",
    "Disposition",
    "TlsFront",
    "TERMINATE",
    "FAIL_VISIBLE",
]

logger = logging.getLogger(__name__)

TERMINATE = "terminate"
FAIL_VISIBLE = "fail_visible"

# Defensive caps.
_DEFAULT_PEEK_BYTES = 8192
_DEFAULT_IO_TIMEOUT = 30.0
_DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024


# --------------------------------------------------------------------------- #
# ClientHello SNI parser (wire-format read, not crypto)                        #
# --------------------------------------------------------------------------- #


def parse_client_hello_sni(data: bytes) -> str | None:
    """Extract the SNI host_name from a TLS ClientHello record.

    Returns the lowercased hostname, or ``None`` when there is no readable SNI:
    a non-handshake / non-ClientHello record, a truncated buffer, an SNI absent
    (ECH cover or a client that sends none), or any malformed field. Fail-soft by
    construction — a ``None`` makes the caller fall to the IP-only floor, never to
    a silent trust of an unparsed name.

    Structure (RFC 8446 §4.1.2, RFC 6066 §3): TLS record header (type=0x16
    handshake, 2-byte version, 2-byte length) → handshake header (type=0x01
    ClientHello, 3-byte length) → client_version(2) random(32) session_id
    cipher_suites compression_methods extensions; the server_name extension
    (type 0x0000) holds a server_name_list of (name_type, name) pairs, host_name
    being name_type 0x00. Single-record ClientHello assumed (the overwhelmingly
    common case; a fragmented ClientHello yields ``None`` → IP-only floor).
    """
    try:
        if len(data) < 5 or data[0] != 0x16:  # 0x16 = handshake content type
            return None
        rec_len = int.from_bytes(data[3:5], "big")
        body = data[5 : 5 + rec_len]
        if len(body) < 4 or body[0] != 0x01:  # 0x01 = ClientHello
            return None
        pos = 4  # skip handshake type(1) + length(3)
        pos += 2 + 32  # client_version + random
        if pos >= len(body):
            return None
        sid_len = body[pos]
        pos += 1 + sid_len
        if pos + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(body):
            return None
        cm_len = body[pos]
        pos += 1 + cm_len
        if pos + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
            pos += 4
            ext_data = body[pos : pos + ext_len]
            pos += ext_len
            if ext_type == 0x0000:  # server_name
                return _parse_sni_extension(ext_data)
        return None
    except (IndexError, ValueError):
        return None


def _parse_sni_extension(ext: bytes) -> str | None:
    if len(ext) < 2:
        return None
    list_len = int.from_bytes(ext[0:2], "big")
    pos = 2
    end = min(len(ext), 2 + list_len)
    while pos + 3 <= end:
        name_type = ext[pos]
        name_len = int.from_bytes(ext[pos + 1 : pos + 3], "big")
        pos += 3
        name = ext[pos : pos + name_len]
        pos += name_len
        if name_type == 0x00:  # host_name
            try:
                return name.decode("ascii").strip().lower() or None
            except UnicodeDecodeError:
                try:
                    return name.decode("utf-8").strip().lower() or None
                except UnicodeDecodeError:
                    return None
    return None


# --------------------------------------------------------------------------- #
# In-box CA — custody is a first-class requirement, not a footnote             #
# --------------------------------------------------------------------------- #


class InBoxCA:
    """A certificate authority used ONLY to mint short-lived per-SNI leaf certs
    for connections the proxy terminates.

    CUSTODY (the serious one, per design doc §2/Approach 2): the agent is the
    adversary and its sandbox trust store now trusts this CA. So the CA *private
    key* lives ONLY here, in the proxy's process memory. The agent's trust store
    receives ONLY :attr:`trust_anchor_pem` (the public CA cert). There is
    deliberately NO method on this object that returns the CA private key — a leak
    would forge a leaf for ANY domain the agent trusts (whole-sandbox TLS
    impersonation). Leaf minting happens here, server-side; only the leaf cert
    (public) reaches the agent during the handshake.
    """

    __slots__ = ("_ca_cert", "_ca_key", "_leaf_ttl_seconds", "_leaf_cache", "_ctx_cache", "_lock")

    def __init__(self, ca_cert: object, ca_key: object, *, leaf_ttl_seconds: int = 3600) -> None:
        self._ca_cert = ca_cert
        self._ca_key = ca_key  # NEVER exported — see class docstring.
        self._leaf_ttl_seconds = leaf_ttl_seconds
        self._leaf_cache: dict[str, tuple[bytes, bytes]] = {}
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    @classmethod
    def generate(
        cls,
        *,
        common_name: str = "Tex In-Box MITM CA",
        validity_days: int = 3650,
        leaf_ttl_seconds: int = 3600,
    ) -> "InBoxCA":
        """Generate a fresh EC P-256 CA in memory. The private key never leaves
        this process."""
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(cert, key, leaf_ttl_seconds=leaf_ttl_seconds)

    @property
    def trust_anchor_pem(self) -> bytes:
        """The PUBLIC CA cert, PEM-encoded — the ONLY material that goes into the
        agent's trust store. Carries no private key."""
        from cryptography.hazmat.primitives import serialization

        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def mint_leaf(self, sni: str) -> tuple[bytes, bytes]:
        """Mint (or return a cached) leaf cert + key for ``sni``, signed by the CA.

        Returns ``(cert_pem, key_pem)`` — the leaf key is per-SNI, short-lived, and
        distinct from the CA key. SAN is the hostname (or the IP, for an IP-literal
        SNI). Raises ``ValueError`` on an empty SNI (we never mint a wildcard."""
        host = (sni or "").strip().lower()
        if not host:
            raise ValueError("cannot mint a leaf without an SNI hostname")
        with self._lock:
            cached = self._leaf_cache.get(host)
        if cached is not None:
            return cached

        import ipaddress
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        try:
            san: object = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(seconds=self._leaf_ttl_seconds))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self._lock:
            self._leaf_cache[host] = (cert_pem, key_pem)
        return cert_pem, key_pem

    def server_context_for(self, sni: str) -> ssl.SSLContext:
        """An ``ssl.SSLContext`` (server side) presenting the minted leaf for
        ``sni``. Cached per SNI.

        ``ssl.load_cert_chain`` has no in-memory form, so the leaf is written to
        0600 temp files, loaded, and immediately unlinked. Only the LEAF key (not
        the CA key) ever touches disk, briefly, in the proxy's own tmpdir.
        """
        with self._lock:
            ctx = self._ctx_cache.get(sni)
        if ctx is not None:
            return ctx

        import os
        import tempfile

        cert_pem, key_pem = self.mint_leaf(sni)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certfd, certpath = tempfile.mkstemp(suffix=".pem")
        keyfd, keypath = tempfile.mkstemp(suffix=".pem")
        try:
            os.fchmod(keyfd, 0o600)
            os.write(certfd, cert_pem)
            os.write(keyfd, key_pem)
            os.close(certfd)
            os.close(keyfd)
            certfd = keyfd = -1
            ctx.load_cert_chain(certfile=certpath, keyfile=keypath)
        finally:
            for fd in (certfd, keyfd):
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            for path in (certpath, keypath):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        with self._lock:
            self._ctx_cache[sni] = ctx
        return ctx


# --------------------------------------------------------------------------- #
# Per-connection disposition                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Disposition:
    """The decision for one connection, BEFORE any handshake.

    ``action`` is :data:`TERMINATE` or :data:`FAIL_VISIBLE`. ``recipient`` is the
    most-defensible name to rule on: the pinned SNI when it is trustworthy, else
    the kernel orig_dst IP, else ``None`` (no SNI and no verified dst). ``dst`` is
    the kernel-verified orig_dst (or ``None``). ``reason`` is for the audit log.
    """

    action: str
    sni: str | None
    dst: "ResolvedDst | None"
    recipient: str | None
    reason: str


class TlsFront:
    """The TLS-visibility front. Construct with the proxy it fronts, an in-box CA,
    and the terminate-allowlist; optionally the orig_dst resolver and a DNS
    resolver for the SNI pin (defaults to system DNS)."""

    def __init__(
        self,
        *,
        proxy: "TexEnforcementProxy",
        ca: InBoxCA,
        terminate_allowlist: "set[str] | frozenset[str] | tuple[str, ...]",
        origdst: "OrigDstResolver | None" = None,
        host_resolver: "Callable[[str], set[str]] | None" = None,
        peek_bytes: int = _DEFAULT_PEEK_BYTES,
        io_timeout: float = _DEFAULT_IO_TIMEOUT,
        max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
    ) -> None:
        self._proxy = proxy
        self._ca = ca
        # Lowercased; an entry beginning with "." is a suffix match (".foo.com").
        self._allow = frozenset(h.strip().lower() for h in terminate_allowlist if h.strip())
        self._origdst = origdst
        self._host_resolver = host_resolver or _default_host_ips
        self._peek_bytes = peek_bytes
        self._io_timeout = io_timeout
        self._max_request_bytes = max_request_bytes
        self._stop = threading.Event()
        self._srv: socket.socket | None = None

    # ------------------------------------------------------------------ decision

    def _allows(self, host: str | None) -> bool:
        if not host:
            return False
        if host in self._allow:
            return True
        return any(a.startswith(".") and host.endswith(a) for a in self._allow)

    def _host_ips(self, host: str) -> set[str]:
        try:
            return set(self._host_resolver(host))
        except Exception:  # noqa: BLE001 — a resolver fault must not fail open
            logger.warning("tls_front: host resolve raised for %r", host, exc_info=True)
            return set()

    def disposition(
        self, peer: tuple[str, int] | None, client_hello: bytes
    ) -> Disposition:
        """Decide TERMINATE vs FAIL_VISIBLE for one connection (no handshake yet).

        Terminate IFF the SNI is present, pins to the kernel orig_dst IP, AND is
        on the terminate-allowlist. Everything else fails visible — ECH/no SNI, a
        SNI that does not resolve to the orig_dst (spoof), or a pinned-but-not-
        allowlisted host — and we rule it as ``https_opaque`` rather than trust an
        unverifiable name.
        """
        sni = parse_client_hello_sni(client_hello)
        dst: "ResolvedDst | None" = None
        if self._origdst is not None and peer is not None and peer[0] and peer[1]:
            try:
                dst = self._origdst.resolve(str(peer[0]), int(peer[1]))
            except Exception:  # noqa: BLE001 — a resolver fault degrades to IP-only
                logger.warning("tls_front: orig_dst resolve raised for %s", peer, exc_info=True)
                dst = None

        pinned = bool(sni) and dst is not None and dst.ip in self._host_ips(sni)  # type: ignore[arg-type]

        if pinned and self._allows(sni):
            return Disposition(
                TERMINATE, sni, dst, sni, "SNI pinned to orig_dst and on terminate-allowlist"
            )

        if pinned:
            recipient, reason = sni, "SNI pinned to orig_dst but not on terminate-allowlist"
        elif dst is not None:
            recipient = dst.ip
            reason = (
                "no SNI (ECH?) -> IP-only floor"
                if not sni
                else "SNI did not pin to orig_dst (spoof?) -> IP-only floor"
            )
        else:
            recipient, reason = None, "no SNI and no kernel-verified orig_dst"
        return Disposition(FAIL_VISIBLE, sni, dst, recipient, reason)

    # ------------------------------------------------------------------ serving

    def handle_stream(self, client_sock: socket.socket, peer: tuple[str, int] | None) -> None:
        """Drive one accepted connection end-to-end. Never raises."""
        try:
            client_sock.settimeout(self._io_timeout)
            hello = self._peek_client_hello(client_sock)
            disp = self.disposition(peer, hello)
            logger.info(
                "tls_front: peer=%s sni=%r dst=%s -> %s (%s)",
                peer, disp.sni, disp.dst, disp.action, disp.reason,
            )
            if disp.action == TERMINATE:
                self._terminate(client_sock, disp, peer)
            else:
                self._fail_visible(client_sock, disp)
        except Exception:  # noqa: BLE001 — a per-connection bug must not kill the server
            logger.warning("tls_front: connection handling failed", exc_info=True)
            _safe_close(client_sock)

    def _peek_client_hello(self, sock: socket.socket) -> bytes:
        """Read the ClientHello WITHOUT consuming it (``MSG_PEEK``), so the same
        bytes remain for ``ssl.wrap_socket`` (terminate) or the upstream splice
        (fail-visible)."""
        try:
            return sock.recv(self._peek_bytes, socket.MSG_PEEK)
        except OSError:
            return b""

    def _terminate(
        self, client_sock: socket.socket, disp: Disposition, peer: tuple[str, int] | None
    ) -> None:
        assert disp.sni is not None  # TERMINATE implies a pinned SNI
        try:
            ctx = self._ca.server_context_for(disp.sni)
            tls = ctx.wrap_socket(client_sock, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            # The agent refused our forged leaf — almost always cert/key pinning.
            # Do NOT fall back to a silent L4 bypass: a pinned upstream Tex cannot
            # inspect must be ruled (and sealed) as opaque, fail-closed. We have no
            # usable plaintext and the agent's TLS is half-broken, so we refuse
            # (close) rather than splice — never a silent escape.
            logger.info(
                "tls_front: termination handshake failed for %r (%s) -> fail-closed opaque",
                disp.sni, exc,
            )
            self._proxy.rule_opaque(recipient=disp.recipient)
            _safe_close(client_sock)
            return

        try:
            method, path, headers, body = _read_http_request(
                tls, self._io_timeout, self._max_request_bytes
            )
        except (OSError, ValueError) as exc:
            logger.info("tls_front: could not read decrypted request: %s", exc)
            _safe_close(tls)
            return

        # The decrypted request flows through the EXISTING handle() unchanged:
        # _to_decision restores tool + args, channel="mcp", and the proxy's own
        # forwarder re-originates TLS upstream on PERMIT.
        try:
            resp = self._proxy.handle(
                method=method, path=path, headers=headers, body=body, peer=peer
            )
            _write_http_response(tls, resp)
        except Exception:  # noqa: BLE001
            logger.warning("tls_front: terminated request handling failed", exc_info=True)
        finally:
            _safe_close(tls)

    def _fail_visible(self, client_sock: socket.socket, disp: Disposition) -> None:
        result: "DecisionResult" = self._proxy.rule_opaque(recipient=disp.recipient)
        if result.released and disp.dst is not None:
            # PERMIT on the opaque destination: splice the raw TCP straight through
            # to the kernel-verified orig_dst. We never decrypt — honest L4
            # passthrough. The peeked ClientHello is still buffered (MSG_PEEK did
            # not consume it), so it is forwarded as the first upstream bytes.
            self._splice(client_sock, disp.dst)
        else:
            # ABSTAIN / FORBID, or no verified dst to splice to: refuse. Closing
            # the socket with no backend is fail-closed — never a silent bypass.
            logger.info(
                "tls_front: opaque verdict not released (or no dst) -> refused (%s)",
                disp.reason,
            )
            _safe_close(client_sock)

    def _splice(self, client_sock: socket.socket, dst: "ResolvedDst") -> None:
        try:
            upstream = socket.create_connection((dst.ip, dst.port), timeout=self._io_timeout)
        except OSError as exc:
            logger.info("tls_front: opaque splice connect to %s:%s failed: %s", dst.ip, dst.port, exc)
            _safe_close(client_sock)
            return
        _pump_bidirectional(client_sock, upstream)

    def serve_forever(self, host: str = "0.0.0.0", port: int = 8443) -> None:
        """Accept loop: one daemon thread per connection. Blocks until
        :meth:`stop`. (Deploy wiring; the per-connection logic above is what the
        unit/integration tests exercise.)"""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(128)
        self._srv = srv
        logger.info("tls_front: listening on %s:%s (terminate-allowlist=%s)", host, port, sorted(self._allow))
        while not self._stop.is_set():
            try:
                conn, peer = srv.accept()
            except OSError:
                break
            threading.Thread(
                target=self.handle_stream, args=(conn, peer), name="tex-tls-front-conn", daemon=True
            ).start()

    def stop(self) -> None:
        self._stop.set()
        srv = self._srv
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Wire helpers (HTTP over the terminated stream; raw TCP pump)                 #
# --------------------------------------------------------------------------- #

_STATUS_REASON = {200: "OK", 403: "Forbidden", 502: "Bad Gateway"}


def _read_http_request(
    sock: ssl.SSLSocket, timeout: float, max_bytes: int
) -> tuple[str, str, dict[str, str], bytes]:
    """Read one HTTP/1.1 request off the terminated TLS stream → (method, target,
    headers, body). Reading a wire format, not crypto."""
    sock.settimeout(timeout)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > max_bytes:
            raise ValueError("request headers exceed cap")
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise ValueError("empty request")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) < 2:
        raise ValueError("malformed request line")
    method, target = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        k, _, v = line.partition(b":")
        headers[k.decode("latin-1").strip()] = v.decode("latin-1").strip()
    body = bytearray(rest)
    cl = headers.get("Content-Length") or headers.get("content-length")
    if cl is not None:
        try:
            n = int(cl)
        except ValueError:
            n = 0
        while len(body) < n:
            if len(body) > max_bytes:
                raise ValueError("request body exceeds cap")
            chunk = sock.recv(min(4096, n - len(body)))
            if not chunk:
                break
            body += chunk
    return method, target, headers, bytes(body)


def _write_http_response(sock: ssl.SSLSocket, resp: "UpstreamResponse") -> None:
    reason = _STATUS_REASON.get(resp.status, "OK")
    out = bytearray()
    out += f"HTTP/1.1 {resp.status} {reason}\r\n".encode("latin-1")
    headers = {k: v for k, v in resp.headers.items() if k.lower() not in {"transfer-encoding", "content-length"}}
    headers["content-length"] = str(len(resp.body))
    for k, v in headers.items():
        out += f"{k}: {v}\r\n".encode("latin-1")
    out += b"\r\n"
    out += resp.body
    sock.sendall(bytes(out))


def _pump_bidirectional(a: socket.socket, b: socket.socket) -> None:
    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=copy, args=(a, b), daemon=True)
    t2 = threading.Thread(target=copy, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    _safe_close(a)
    _safe_close(b)


def _safe_close(sock: object) -> None:
    try:
        sock.close()  # type: ignore[attr-defined]
    except OSError:
        pass
