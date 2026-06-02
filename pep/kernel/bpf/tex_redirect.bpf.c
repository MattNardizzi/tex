// SPDX-License-Identifier: Apache-2.0
//
// tex_redirect.bpf.c — the kernel-floor PEP.
//
// Two jobs, both at cgroup/connect time, for any process in a governed
// cgroup, with zero changes to the agent:
//
//   1. INLINE FAST-BLOCK (microseconds, fail-closed for the hot set).
//      A verdict_cache map, kept warm by the userspace agent from the PDP,
//      maps destination (ip,port) -> verdict. If the destination is a known
//      FORBID, the connect() is refused in-kernel before a packet leaves.
//      This is the floor's floor: the highest-confidence denials never even
//      reach userspace.
//
//   2. TRANSPARENT REDIRECT (the synchronous semantic path).
//      Every other governed connect() is rewritten to the local Tex
//      enforcement proxy (127.0.0.1:proxy_port). The original destination is
//      stashed in orig_dst keyed by the socket cookie, so the proxy recovers
//      it and forwards upstream on PERMIT. The agent thinks it connected to
//      the real endpoint; it connected to Tex.
//
// This is the answer to "even the second new ones are added": the hook fires
// on any process that calls connect() inside a governed cgroup, including one
// that spawned moments ago. There is no per-agent integration — the wire is
// the kernel.
//
// CO-RE: compile once with clang -target bpf against vmlinux.h; runs on any
// modern kernel via BTF. Loaded/attached by ../agent (cilium/ebpf).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#define AF_INET 2

// Verdicts mirrored from the PDP (domain/verdict.py). Only FORBID is acted on
// in-kernel; PERMIT/ABSTAIN flow through the redirect to the proxy, which runs
// the full two-tier decision. Absence from the cache is NOT permit — it is
// "ask the proxy."
#define TEX_FORBID 2

// ---- Configuration, set once by the loader at attach time ---------------- //
struct tex_config {
    __u32 proxy_ip4;    // network byte order; typically 127.0.0.1
    __u16 proxy_port;   // network byte order; the local proxy
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tex_config);
} config SEC(".maps");

// ---- Verdict cache: destination -> verdict (PDP-warmed) ------------------ //
struct dst_key {
    __u32 ip4;     // network byte order
    __u16 port;    // network byte order
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dst_key);
    __type(value, __u8);   // verdict
} verdict_cache SEC(".maps");

// ---- Original destination stash: sock cookie -> real dst ----------------- //
// The proxy recovers the true upstream from here (the redirect overwrote it).
struct orig_dst_val {
    __u32 ip4;
    __u16 port;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);    // bpf_get_socket_cookie
    __type(value, struct orig_dst_val);
} orig_dst SEC(".maps");

// The cgroup this program is attached to IS the governance boundary: the
// loader attaches it only under governed pod/workload cgroups. So reaching
// this code already means "governed" — no extra membership check needed.

SEC("cgroup/connect4")
int tex_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET)
        return 1; // allow non-IPv4 to proceed untouched (v6 handled separately)

    __u32 ckey = 0;
    struct tex_config *cfg = bpf_map_lookup_elem(&config, &ckey);
    if (!cfg)
        return 1; // not configured yet: do not interfere

    __u32 dst_ip = ctx->user_ip4;        // network byte order
    __u16 dst_port = (__u16)ctx->user_port; // network byte order

    // Never redirect traffic already destined for the proxy itself, or the
    // agent would loop the proxy's own upstream call straight back in.
    if (dst_ip == cfg->proxy_ip4 && dst_port == cfg->proxy_port)
        return 1;

    // 1) Inline fast-block: known FORBID destinations die here.
    struct dst_key dk = {};
    dk.ip4 = dst_ip;
    dk.port = dst_port;
    __u8 *v = bpf_map_lookup_elem(&verdict_cache, &dk);
    if (v && *v == TEX_FORBID) {
        // Refuse the connect. EPERM bubbles up to the caller; fail-closed.
        return 0;
    }

    // 2) Transparent redirect: stash the real dst, rewrite to the proxy.
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst_val od = {};
    od.ip4 = dst_ip;
    od.port = dst_port;
    bpf_map_update_elem(&orig_dst, &cookie, &od, BPF_ANY);

    ctx->user_ip4 = cfg->proxy_ip4;
    ctx->user_port = cfg->proxy_port;
    return 1; // allow the (now redirected) connect to proceed
}
