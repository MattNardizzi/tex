# Tex Kernel-Floor PEP

The deepest enforcement point: a transparent eBPF data plane that governs
**every** agent's egress with zero per-agent integration — including an agent
that spawned seconds ago. The wire is the kernel.

This directory is a **deploy artifact**, not part of the Python package. It is
compiled against the target kernel at deploy time. It speaks the same fixed
contract as every Tex PEP: call the PDP, obey the verdict.

## What is mediated

| Path | Hook | Program | Covers |
|---|---|---|---|
| TCP / connected UDP (v4) | `cgroup/connect4` | `tex_connect4` | TCP, QUIC sockets that `connect()` |
| TCP / connected UDP (v6) | `cgroup/connect6` | `tex_connect6` | the v6 equivalent |
| UNconnected UDP (v4) | `cgroup/sendmsg4` | `tex_sendmsg4` | QUIC/HTTP3/DNS on unconnected sockets |
| UNconnected UDP (v6) | `cgroup/sendmsg6` | `tex_sendmsg6` | the v6 equivalent |
| orig-dst recovery | `sockops` | `tex_sock_ops` | re-keys the stash for the proxy |
| io_uring egress | Tetragon | `deploy/tracingpolicy.yaml` | backstop (post-commit kill) |

A `connect()` on a UDP socket fires the cgroup connect hook too, so connected
UDP/QUIC is covered by `connect4/6` (which branch on socket type: a connected
UDP socket is routed to the UDP proxy or fail-closed, like `sendmsg4/6`, since
`sockops` cannot re-key a UDP flow). The `sendmsg4/6` hooks specifically catch
**unconnected** UDP that never calls `connect()`. Either way, mediating UDP
needs `TEX_UDP_PROXY_PORT` — without it, non-FORBID UDP is dropped.

## How it works

```
agent connect()  ──cgroup/connect4|6 (eBPF)──┐
                                              │  known FORBID dst?  ── yes ─► refuse in-kernel (µs, fail-closed)
                                              │  otherwise:
                                              │     stash real dst by socket cookie
                                              └────► rewrite dst to the tex-proxy (127.0.0.1:8088 / [::1]:8088)
                                                          │
   tex_sock_ops (ACTIVE_ESTABLISHED) ◄────────── handshake completes; src port now bound
        │  re-key stash: src(ip:port) -> real dst   into src_to_orig
        ▼
   tex-proxy accept()s, reads peer = agent src(ip:port), asks the loader's UDS:
        "{src_ip, src_port, family}" ─► "{ip, port}"  (the real upstream)
        POST /v1/govern/decide  ── released? ─► forward upstream   else ─► 403 (hold → the voice)
```

- **Inline fast-block** (`verdict_cache`, `verdict_cache6`): the agent warms
  in-kernel maps from `GET {PDP}/v1/govern/forbid-set` every 30s. The
  highest-confidence denials never reach userspace — the connect/sendmsg is
  refused before a packet leaves. Absence from the cache is **never** permit; it
  means "decide at the proxy."
- **Transparent redirect**: everything else is rewritten to the local
  enforcement proxy, the agent unaware.
- **Fail-closed for UDP**: connectionless UDP cannot be faithfully mediated
  without a UDP proxy. A non-FORBID datagram is **dropped (EPERM)**, not allowed
  out, unless `TEX_UDP_PROXY_PORT` is set (redirect) or `TEX_ALLOW_DNS=1` carves
  out UDP/53 (operator accepts the DNS-tunnel residual risk).

Why cgroup-attach: attaching under governed workload cgroups makes cgroup
membership the governance boundary — no per-process allowlist, and a new process
inside a governed cgroup is covered the instant it makes an egress call.

## orig-dst recovery — the keystone for the proxy

After the connect hook rewrites the destination to the proxy, the proxy
`accept()`s a connection whose **socket cookie differs** from the agent's client
socket, so the cookie-keyed stash is unreachable to it. What the proxy *can*
observe on the accepted socket is the peer 4-tuple — the agent's source ip:port.

So `tex_sock_ops` fires at `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` (by which point
the source port **is** bound — it is not yet at connect time) and re-keys the
real destination under the agent's **source 4-tuple** into `src_to_orig`. The Go
loader serves lookups from that map over a UDS. This mirrors Cilium's
cookie-keyed `sockops` storage, adapted for cross-process recovery by source
tuple rather than an in-process `getsockopt(SO_ORIGINAL_DST)` emulation (which
cannot bridge the cookie gap to a separate proxy process either).

On loopback to the single proxy destination, the agent's `(src_ip, src_port)` is
unique among simultaneously-live flows, so the source tuple identifies the flow.

### UDS contract (T2's proxy is the client)

- **socket path**: env `TEX_ORIGDST_SOCK` (default `/run/tex/origdst.sock`)
- **request** (newline-terminated JSON):
  `{"src_ip":"<agent src ip>","src_port":<int>,"family":4|6}`
- **response** (newline-terminated JSON):
  `{"ip":"<orig dst ip>","port":<int>}` **or** `{"error":"not_found"}`

A `not_found` is fail-closed: the proxy must NOT forward a flow whose original
destination it cannot recover.

## Files

- `bpf/tex_redirect.bpf.c` — the CO-RE eBPF programs (connect4/6, sendmsg4/6,
  sockops) + maps.
- `agent/main.go` — loads/attaches them (cilium/ebpf), configures the proxy
  targets, warms the verdict caches from the PDP, serves orig-dst over the UDS.
- `Makefile` — `make build` (needs clang/llvm, libbpf, bpftool, Go ≥ 1.22).
- `Dockerfile` — multi-stage build to a distroless runtime image.
- `deploy/daemonset.yaml` — one pod/node: the agent + the `python -m tex.pep`
  proxy as a sidecar.
- `deploy/configmap.yaml` — cgroup root + PDP base URL.
- `deploy/tracingpolicy.yaml` — optional Tetragon backstops: the connect()
  kill-based defense-in-depth **and** the io_uring egress backstop (G3).

## Configuration (loader env)

| Env | Default | Meaning |
|---|---|---|
| `TEX_CGROUP` | `/sys/fs/cgroup` | governed cgroup root to attach under |
| `TEX_PROXY_ADDR` | `127.0.0.1:8088` | v4 proxy target (also the shared TCP port) |
| `TEX_PROXY6_IP` | `::1` | v6 proxy IP (shares `TEX_PROXY_ADDR`'s port) |
| `TEX_UDP_PROXY_PORT` | _(unset)_ | UDP proxy port; **unset ⇒ fail-closed** for non-FORBID UDP |
| `TEX_ALLOW_DNS` | _(unset)_ | `1` ⇒ let UDP/53 flow untouched (accepts DNS-tunnel risk) |
| `TEX_ORIGDST_SOCK` | `/run/tex/origdst.sock` | UDS path the proxy queries for orig-dst |
| `TEX_PDP_BASE` | `http://127.0.0.1:8080` | PDP base URL |
| `TEX_PDP_API_KEY` | _(unset)_ | bearer token for the forbid-set fetch |

## Build & deploy

```bash
make build                          # on a Linux host with the eBPF toolchain
docker build -t ghcr.io/vortexblack/tex-kernel-pep:latest .
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/daemonset.yaml
kubectl apply -f deploy/tracingpolicy.yaml   # if running Tetragon
```

`make build` runs `make vmlinux bpf generate` then `go build`. The eBPF object
**cannot** compile on macOS (no `vmlinux.h`/libbpf/`bpf2go`); build it on a
Linux node with clang/llvm ≥ 14, libbpf headers, and bpftool. The Dockerfile
does exactly this in a `golang:1.22-bookworm` stage.

## Requirements

- Linux kernel ≥ 5.10 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE.
- `cgroup/connect4` and `cgroup/connect6` attach (kernel ≥ 4.17/4.18),
  `cgroup/sendmsg4|6` (≥ 4.18), and `bpf_sock_addr->sk` reads in the sendmsg
  hooks (≥ 5.3). `sockops` ACTIVE_ESTABLISHED is long-supported.
- The io_uring backstop needs Tetragon and a kernel where the io_uring syscalls
  resolve; it is **post-commit kill, not pre-dispatch** (see the policy header).
- The DaemonSet runs privileged with `/sys/fs/bpf` and `/sys/fs/cgroup`
  mounted. TLS-encrypted *intent* capture (uprobes on userspace SSL) is a
  separate eBPF program on the AgentSight pattern; this redirector enforces at
  the connection boundary and hands the request to the proxy for the decision.

## Honest gaps

- **UDP orig-dst is best-effort.** `sendmsg4/6` stashes by source tuple only
  when the socket's source port is already bound; an unconnected socket's very
  first datagram can't be keyed (autobind happens during the send) and the proxy
  lookup misses → fail-closed. Fully transparent multi-destination UDP also
  needs the proxy to rewrite replies via a `recvmsg` hook — out of scope here.
- **io_uring backstop is blunt.** Blocking `io_uring_setup` prevents ring-based
  egress structurally but also denies legitimate io_uring (e.g. disk I/O) to
  governed workloads; opcode-surgical blocking is kernel/Tetragon-version
  dependent and deliberately not shipped. See the policy header.
- **v4-mapped over v6.** A v4 destination reached over a v6 socket is keyed in
  `verdict_cache6` in `::ffff:a.b.c.d` form; the loader warms both forms.

## The contract (do not break)

The kernel PEP and the proxy depend only on:
- `GET  /v1/govern/forbid-set` → `{ "forbid": [ { "ip": "...", "port": N } ] }`
- `POST /v1/govern/decide`      → `{ "released": bool, "verdict": "...", ... }`
- the orig-dst UDS above.

Everything else about the PDP can change freely.
