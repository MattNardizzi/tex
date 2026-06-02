# Tex Kernel-Floor PEP

The deepest enforcement point: a transparent eBPF data plane that governs
**every** agent's egress with zero per-agent integration — including an agent
that spawned seconds ago. The wire is the kernel.

This directory is a **deploy artifact**, not part of the Python package. It is
compiled against the target kernel at deploy time. It speaks the same fixed
contract as every Tex PEP: call the PDP, obey the verdict.

## How it works

```
agent connect()  ──cgroup/connect4 (eBPF)──┐
                                            │  known FORBID dst?  ── yes ─► refuse in-kernel (µs, fail-closed)
                                            │  otherwise:
                                            │     stash real dst by socket cookie
                                            └────► rewrite dst to 127.0.0.1:8088 (tex-proxy)
                                                          │
                                            tex-proxy recovers real dst, maps the request,
                                            POST /v1/govern/decide  ── released? ─► forward upstream
                                                                                   else ─► 403 (hold → the voice)
```

- **Inline fast-block** (`verdict_cache`): the agent warms an in-kernel map
  from `GET {PDP}/v1/govern/forbid-set` every 30s. The highest-confidence
  denials never reach userspace — connect() is refused before a packet leaves.
  Absence from the cache is **never** permit; it means "decide at the proxy."
- **Transparent redirect** (`cgroup/connect4`): everything else is rewritten to
  the local enforcement proxy, with the original destination stashed by socket
  cookie so the proxy forwards upstream on PERMIT. The agent is unaware.

Why cgroup-attach: attaching the program under governed workload cgroups makes
cgroup membership the governance boundary — no per-process allowlist, and a new
process inside a governed cgroup is covered the instant it calls connect().

## Files

- `bpf/tex_redirect.bpf.c` — the CO-RE eBPF program.
- `agent/main.go` — loads/attaches it (cilium/ebpf), configures the proxy
  target, pins the orig-dst map, warms the verdict cache from the PDP.
- `Makefile` — `make build` (needs clang/llvm, libbpf, bpftool, Go ≥ 1.22).
- `Dockerfile` — multi-stage build to a distroless runtime image.
- `deploy/daemonset.yaml` — one pod/node: the agent + the `python -m tex.pep`
  proxy as a sidecar.
- `deploy/configmap.yaml` — cgroup root + PDP base URL.
- `deploy/tracingpolicy.yaml` — optional Tetragon kill-based backstop for
  clusters already running Tetragon.

## Build & deploy

```bash
make build                          # on a host with the eBPF toolchain
docker build -t ghcr.io/vortexblack/tex-kernel-pep:latest .
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/daemonset.yaml
```

## Requirements

- Linux kernel ≥ 5.10 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE.
- `cgroup/connect4` attach support (kernel ≥ 4.17; v6 via a sibling
  `cgroup/connect6` program, same shape).
- The DaemonSet runs privileged with `/sys/fs/bpf` and `/sys/fs/cgroup`
  mounted. TLS-encrypted *intent* capture (uprobes on userspace SSL) is a
  separate eBPF program on the AgentSight pattern; this redirector enforces at
  the connection boundary and hands the request to the proxy for the decision.

## The contract (do not break)

The kernel PEP and the proxy depend only on:
- `GET  /v1/govern/forbid-set` → `{ "forbid": [ { "ip": "...", "port": N } ] }`
- `POST /v1/govern/decide`      → `{ "released": bool, "verdict": "...", ... }`

Everything else about the PDP can change freely.
