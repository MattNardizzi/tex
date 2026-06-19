// SPDX-License-Identifier: Apache-2.0
//
// tex_redirect.bpf.c — the kernel-floor PEP.
//
// Goal: every egress path an agent in a governed cgroup can take is mediated,
// with zero changes to the agent. Five programs cover the surface:
//
//   tex_connect4   cgroup/connect4   TCP + connected-UDP/QUIC over IPv4
//   tex_connect6   cgroup/connect6   TCP + connected-UDP/QUIC over IPv6
//   tex_sendmsg4   cgroup/sendmsg4   UNconnected UDP over IPv4 (QUIC/HTTP3/DNS)
//   tex_sendmsg6   cgroup/sendmsg6   UNconnected UDP over IPv6
//   tex_sock_ops   sockops           re-keys the orig-dst stash so the proxy
//                                     (a separate process) can recover it
//
// Each connect/sendmsg program does two jobs at the syscall boundary, for any
// process in a governed cgroup, including one that spawned moments ago:
//
//   1. INLINE FAST-BLOCK (microseconds, fail-closed for the hot set).
//      A per-family verdict cache (verdict_cache / verdict_cache6), kept warm by
//      the userspace agent from the PDP, maps destination -> verdict. A known
//      FORBID destination is refused in-kernel before a packet leaves. This is
//      the floor's floor: the highest-confidence denials never reach userspace.
//
//   2. TRANSPARENT REDIRECT (the synchronous semantic path).
//      Every other governed egress is rewritten to the local Tex enforcement
//      proxy. The original destination is stashed (see orig-dst recovery below)
//      so the proxy recovers it and forwards upstream on PERMIT. The agent
//      thinks it reached the real endpoint; it reached Tex.
//
// FAIL-CLOSED is the invariant: absence from the verdict cache is NEVER permit.
// For TCP, "the rest" can always be redirected to the proxy (a real TCP
// connection survives a sockaddr rewrite). For UNconnected UDP, faithful
// mediation needs a UDP proxy; if none is configured the datagram is dropped
// (EPERM), not allowed — see tex_sendmsg4.
//
// ---- orig-dst recovery (the keystone T2 depends on) --------------------- //
//
// The hard part: after connect4/connect6 rewrites the destination to the proxy,
// the proxy accept()s a connection whose *socket cookie differs* from the
// agent's client socket, so a cookie-keyed stash is unreachable to the proxy.
// What the proxy CAN observe on the accepted socket is the peer 4-tuple — the
// agent's source ip:port (getpeername()).
//
// So we stash the real dst by cookie at connect time (orig_dst), then at
// sockops BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB — by which point the source port
// IS bound (it is not yet bound at connect time) — we re-key it under the
// agent's source 4-tuple into src_to_orig, which the userspace loader serves
// over a UDS to the proxy. This mirrors Cilium's cookie-keyed sockops storage,
// adapted for cross-process recovery via the source tuple rather than an
// in-process getsockopt(SO_ORIGINAL_DST) emulation (which cannot bridge the
// cookie gap to a separate proxy process either).
//
// On loopback to the single proxy dst, the agent's (src_ip, src_port) is unique
// among simultaneously-live flows, so the source tuple identifies the flow.
//
// CO-RE: compile once with clang -target bpf against vmlinux.h; runs on any
// modern kernel via BTF. Loaded/attached by ../agent (cilium/ebpf).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#define AF_INET  2
#define AF_INET6 10

// Stable UAPI value (4); guarded in case the BTF-generated vmlinux.h omits the
// anonymous sock_ops op enum.
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4
#endif

// Socket types (enum sock_type); guarded for the same reason.
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

// Verdicts mirrored from the PDP (domain/verdict.py). Only FORBID is acted on
// in-kernel; PERMIT/ABSTAIN flow through the redirect to the proxy, which runs
// the full two-tier decision. Absence from the cache is NOT permit — it is
// "ask the proxy."
#define TEX_FORBID 2

// ---- Configuration, set once by the loader at attach time ---------------- //
// Layout is fixed: the Go loader's texConfig mirrors it byte-for-byte. All
// addresses/ports are network byte order. Append-only — connect4 reads
// proxy_ip4/proxy_port at the original offsets.
struct tex_config {
    __u32 proxy_ip4;        // v4 proxy, network byte order; typically 127.0.0.1
    __u16 proxy_port;       // TCP+UDP proxy port, network byte order
    __u16 udp_proxy_port;   // UDP proxy port, network byte order; 0 => no UDP
                            // proxy => fail-closed for non-FORBID UDP
    __u32 proxy_ip6[4];     // v6 proxy, network byte order; typically ::1
    __u8  allow_dns;        // 1 => let UDP/53 flow untouched (accepts the
                            // DNS-tunnel residual risk); 0 => strict
    __u8  _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tex_config);
} tex_cfg SEC(".maps"); // NB: not "config" — collides with a typedef in some kernels' vmlinux.h

// ---- Verdict caches: destination -> verdict (PDP-warmed) ----------------- //
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

// 128-bit-keyed v6 forbid set. A v4 destination reached over a v6 socket
// (::ffff:a.b.c.d) is keyed here in v4-mapped form; the loader warms both forms.
struct dst6_key {
    __u32 ip6[4];  // network byte order
    __u16 port;    // network byte order
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dst6_key);
    __type(value, __u8);   // verdict
} verdict_cache6 SEC(".maps");

// ---- orig-dst values: family-tagged, v6-capable (v4 lives in ip[0]) ------ //
struct orig_dst_val {
    __u32 ip[4];   // network byte order; v4 in ip[0]
    __u16 port;    // network byte order
    __u8  family;  // 4 or 6
    __u8  _pad;
};

// Internal scratch: socket cookie -> real dst. Written by connect4/connect6,
// read+deleted by tex_sock_ops, which re-keys it under the source tuple. The
// proxy does NOT read this map (it can't see the cookie); it reads src_to_orig.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);    // bpf_get_socket_cookie
    __type(value, struct orig_dst_val);
} orig_dst SEC(".maps");

// Proxy-facing keystone: source 4-tuple -> real dst. The userspace loader
// serves lookups from this map over the UDS (TEX_ORIGDST_SOCK). Written by
// tex_sock_ops (TCP) and tex_sendmsg4/6 (UDP).
struct src_key {
    __u8  family;     // 4 or 6
    __u8  _pad[3];
    __u32 src_ip[4];  // network byte order; v4 in src_ip[0]
    __u16 src_port;   // network byte order
    __u16 _pad2;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct src_key);
    __type(value, struct orig_dst_val);
} src_to_orig SEC(".maps");

// The cgroup this program is attached to IS the governance boundary: the loader
// attaches it only under governed pod/workload cgroups. So reaching this code
// already means "governed" — no extra membership check needed.

// ====================== IPv4 connect (TCP + connected UDP) =============== //
// connect() fires this hook for SOCK_DGRAM too, so a UDP socket that calls
// connect() (e.g. some QUIC stacks) is mediated here, not by sendmsg4. TCP and
// connected-UDP need DIFFERENT handling: TCP rides the cookie-stash → sockops
// re-key path; connected UDP cannot (sockops has no UDP established callback and
// connected sends carry no sockaddr for sendmsg4 to see), so it redirects to the
// UDP proxy and stashes by source tuple inline (best-effort, like sendmsg4).
SEC("cgroup/connect4")
int tex_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET)
        return 1; // allow non-IPv4 to proceed untouched (v6 handled separately)

    __u32 ckey = 0;
    struct tex_config *cfg = bpf_map_lookup_elem(&tex_cfg, &ckey);
    if (!cfg)
        return 1; // not configured yet: do not interfere

    __u32 dst_ip = ctx->user_ip4;           // network byte order
    __u16 dst_port = (__u16)ctx->user_port; // network byte order

    // Never redirect traffic already destined for the proxy itself, or the
    // agent would loop the proxy's own upstream call straight back in.
    if (dst_ip == cfg->proxy_ip4 &&
        (dst_port == cfg->proxy_port || dst_port == cfg->udp_proxy_port))
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

    if (ctx->type == SOCK_DGRAM) {
        // Connected UDP: route to the UDP proxy or fail closed; stash by source
        // tuple here because sockops will not re-key a UDP flow.
        if (cfg->udp_proxy_port == 0)
            return 0; // fail-closed drop
        struct bpf_sock *sk = ctx->sk;
        if (sk && sk->src_port != 0) {
            struct src_key skey = {};
            skey.family = 4;
            skey.src_ip[0] = sk->src_ip4;
            skey.src_port = bpf_htons((__u16)sk->src_port);
            struct orig_dst_val od = {};
            od.ip[0] = dst_ip;
            od.port = dst_port;
            od.family = 4;
            bpf_map_update_elem(&src_to_orig, &skey, &od, BPF_ANY);
        }
        ctx->user_ip4 = cfg->proxy_ip4;
        ctx->user_port = cfg->udp_proxy_port;
        return 1;
    }

    // 2) TCP transparent redirect: stash the real dst by cookie, rewrite to
    //    proxy. tex_sock_ops re-keys it under the source tuple at established.
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst_val od = {};
    od.ip[0] = dst_ip;
    od.port = dst_port;
    od.family = 4;
    bpf_map_update_elem(&orig_dst, &cookie, &od, BPF_ANY);

    ctx->user_ip4 = cfg->proxy_ip4;
    ctx->user_port = cfg->proxy_port;
    return 1; // allow the (now redirected) connect to proceed
}

// ====================== IPv6 connect (TCP + connected UDP) =============== //
SEC("cgroup/connect6")
int tex_connect6(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET6)
        return 1; // allow non-IPv6 to proceed untouched

    __u32 ckey = 0;
    struct tex_config *cfg = bpf_map_lookup_elem(&tex_cfg, &ckey);
    if (!cfg)
        return 1;

    __u16 dst_port = (__u16)ctx->user_port; // network byte order

    // Avoid looping the proxy's own upstream call back in (proxy is ::1).
    if (ctx->user_ip6[0] == cfg->proxy_ip6[0] &&
        ctx->user_ip6[1] == cfg->proxy_ip6[1] &&
        ctx->user_ip6[2] == cfg->proxy_ip6[2] &&
        ctx->user_ip6[3] == cfg->proxy_ip6[3] &&
        (dst_port == cfg->proxy_port || dst_port == cfg->udp_proxy_port))
        return 1;

    // 1) Inline fast-block: known FORBID v6 destinations die here.
    struct dst6_key dk = {};
    dk.ip6[0] = ctx->user_ip6[0];
    dk.ip6[1] = ctx->user_ip6[1];
    dk.ip6[2] = ctx->user_ip6[2];
    dk.ip6[3] = ctx->user_ip6[3];
    dk.port = dst_port;
    __u8 *v = bpf_map_lookup_elem(&verdict_cache6, &dk);
    if (v && *v == TEX_FORBID)
        return 0; // fail-closed

    if (ctx->type == SOCK_DGRAM) {
        // Connected UDP over v6: UDP proxy or fail closed; stash by src tuple
        // (sockops will not re-key a UDP flow).
        if (cfg->udp_proxy_port == 0)
            return 0; // fail-closed drop
        struct bpf_sock *sk = ctx->sk;
        if (sk && sk->src_port != 0) {
            struct src_key skey = {};
            skey.family = 6;
            skey.src_ip[0] = sk->src_ip6[0];
            skey.src_ip[1] = sk->src_ip6[1];
            skey.src_ip[2] = sk->src_ip6[2];
            skey.src_ip[3] = sk->src_ip6[3];
            skey.src_port = bpf_htons((__u16)sk->src_port);
            struct orig_dst_val od = {};
            od.ip[0] = ctx->user_ip6[0];
            od.ip[1] = ctx->user_ip6[1];
            od.ip[2] = ctx->user_ip6[2];
            od.ip[3] = ctx->user_ip6[3];
            od.port = dst_port;
            od.family = 6;
            bpf_map_update_elem(&src_to_orig, &skey, &od, BPF_ANY);
        }
        ctx->user_ip6[0] = cfg->proxy_ip6[0];
        ctx->user_ip6[1] = cfg->proxy_ip6[1];
        ctx->user_ip6[2] = cfg->proxy_ip6[2];
        ctx->user_ip6[3] = cfg->proxy_ip6[3];
        ctx->user_port = cfg->udp_proxy_port;
        return 1;
    }

    // 2) TCP transparent redirect: stash the real dst by cookie, rewrite to
    //    proxy. tex_sock_ops re-keys it under the source tuple at established.
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst_val od = {};
    od.ip[0] = ctx->user_ip6[0];
    od.ip[1] = ctx->user_ip6[1];
    od.ip[2] = ctx->user_ip6[2];
    od.ip[3] = ctx->user_ip6[3];
    od.port = dst_port;
    od.family = 6;
    bpf_map_update_elem(&orig_dst, &cookie, &od, BPF_ANY);

    ctx->user_ip6[0] = cfg->proxy_ip6[0];
    ctx->user_ip6[1] = cfg->proxy_ip6[1];
    ctx->user_ip6[2] = cfg->proxy_ip6[2];
    ctx->user_ip6[3] = cfg->proxy_ip6[3];
    ctx->user_port = cfg->proxy_port;
    return 1;
}

// ====================== UNconnected UDP egress (v4) ====================== //
// Covers QUIC/HTTP3/DNS that send() on an UNconnected UDP socket. (A UDP socket
// that called connect() already went through tex_connect4 — connect() fires the
// cgroup connect hook for SOCK_DGRAM too.)
//
// Honest limits of sockaddr rewrite for UDP: a datagram CAN be redirected to a
// UDP proxy by rewriting (user_ip4, user_port). But UDP is connectionless — one
// socket may send to many destinations — so per-datagram orig-dst recovery is
// best-effort: we key src_to_orig by the socket's source tuple, which only
// works once the source port is bound (the kernel auto-binds on first send; an
// unbound socket's first datagram can't be keyed and the proxy lookup misses →
// fail-closed at the proxy). For multi-destination sockets the proxy must also
// rewrite replies via a recvmsg hook to be fully transparent; that is out of
// scope for this redirector.
SEC("cgroup/sendmsg4")
int tex_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET)
        return 1;

    __u32 ckey = 0;
    struct tex_config *cfg = bpf_map_lookup_elem(&tex_cfg, &ckey);
    if (!cfg)
        return 1;

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = (__u16)ctx->user_port;

    // Already headed for the proxy: leave it alone.
    if (dst_ip == cfg->proxy_ip4 &&
        (dst_port == cfg->udp_proxy_port || dst_port == cfg->proxy_port))
        return 1;

    // 1) Inline fast-block: known FORBID destinations die here (EPERM).
    struct dst_key dk = {};
    dk.ip4 = dst_ip;
    dk.port = dst_port;
    __u8 *v = bpf_map_lookup_elem(&verdict_cache, &dk);
    if (v && *v == TEX_FORBID)
        return 0; // drop the datagram, fail-closed

    // Optional DNS carve-out: let UDP/53 flow untouched if the operator accepts
    // the residual DNS-tunnel exfil risk (off by default).
    if (cfg->allow_dns && dst_port == bpf_htons(53))
        return 1;

    // 2) Redirect to the UDP proxy if one is configured; otherwise FAIL CLOSED.
    //    We cannot faithfully mediate connectionless UDP without a UDP proxy, so
    //    a non-FORBID datagram is dropped rather than allowed out unmediated.
    if (cfg->udp_proxy_port == 0)
        return 0; // fail-closed drop (EPERM)

    // Best-effort orig-dst stash by source tuple (needs the src port bound).
    // Load ctx->sk once: the verifier tracks the single null-check, whereas
    // re-reading ctx->sk yields a fresh nullable pointer each time.
    struct bpf_sock *sk = ctx->sk;
    if (sk && sk->src_port != 0) {
        struct src_key skey = {};
        skey.family = 4;
        skey.src_ip[0] = sk->src_ip4;                 // network byte order
        skey.src_port = bpf_htons((__u16)sk->src_port); // sk->src_port host order
        struct orig_dst_val od = {};
        od.ip[0] = dst_ip;
        od.port = dst_port;
        od.family = 4;
        bpf_map_update_elem(&src_to_orig, &skey, &od, BPF_ANY);
    }

    ctx->user_ip4 = cfg->proxy_ip4;
    ctx->user_port = cfg->udp_proxy_port;
    return 1;
}

// ====================== UNconnected UDP egress (v6) ====================== //
SEC("cgroup/sendmsg6")
int tex_sendmsg6(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET6)
        return 1;

    __u32 ckey = 0;
    struct tex_config *cfg = bpf_map_lookup_elem(&tex_cfg, &ckey);
    if (!cfg)
        return 1;

    __u16 dst_port = (__u16)ctx->user_port;

    if (ctx->user_ip6[0] == cfg->proxy_ip6[0] &&
        ctx->user_ip6[1] == cfg->proxy_ip6[1] &&
        ctx->user_ip6[2] == cfg->proxy_ip6[2] &&
        ctx->user_ip6[3] == cfg->proxy_ip6[3] &&
        (dst_port == cfg->udp_proxy_port || dst_port == cfg->proxy_port))
        return 1;

    // 1) Inline fast-block.
    struct dst6_key dk = {};
    dk.ip6[0] = ctx->user_ip6[0];
    dk.ip6[1] = ctx->user_ip6[1];
    dk.ip6[2] = ctx->user_ip6[2];
    dk.ip6[3] = ctx->user_ip6[3];
    dk.port = dst_port;
    __u8 *v = bpf_map_lookup_elem(&verdict_cache6, &dk);
    if (v && *v == TEX_FORBID)
        return 0;

    if (cfg->allow_dns && dst_port == bpf_htons(53))
        return 1;

    // 2) Redirect if a UDP proxy is configured; otherwise fail-closed.
    if (cfg->udp_proxy_port == 0)
        return 0;

    struct bpf_sock *sk = ctx->sk;
    if (sk && sk->src_port != 0) {
        struct src_key skey = {};
        skey.family = 6;
        skey.src_ip[0] = sk->src_ip6[0];
        skey.src_ip[1] = sk->src_ip6[1];
        skey.src_ip[2] = sk->src_ip6[2];
        skey.src_ip[3] = sk->src_ip6[3];
        skey.src_port = bpf_htons((__u16)sk->src_port);
        struct orig_dst_val od = {};
        od.ip[0] = ctx->user_ip6[0];
        od.ip[1] = ctx->user_ip6[1];
        od.ip[2] = ctx->user_ip6[2];
        od.ip[3] = ctx->user_ip6[3];
        od.port = dst_port;
        od.family = 6;
        bpf_map_update_elem(&src_to_orig, &skey, &od, BPF_ANY);
    }

    ctx->user_ip6[0] = cfg->proxy_ip6[0];
    ctx->user_ip6[1] = cfg->proxy_ip6[1];
    ctx->user_ip6[2] = cfg->proxy_ip6[2];
    ctx->user_ip6[3] = cfg->proxy_ip6[3];
    ctx->user_port = cfg->proxy_port;
    return 1;
}

// ====================== orig-dst re-key (the keystone) =================== //
// At ACTIVE_ESTABLISHED the agent's source port is bound (it was not at connect
// time). Re-key the cookie-stashed real dst under the source 4-tuple — the one
// thing the proxy can observe on its accepted socket via getpeername(). This is
// what makes G7 recoverable across the process boundary.
//
// skops byte order (kernel quirk, confirmed against the docs): local_ip4/ip6
// and remote_port are NETWORK order, but local_port is HOST order — so we
// bpf_htons() it to keep src_to_orig uniformly network order.
SEC("sockops")
int tex_sock_ops(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(skops);
    struct orig_dst_val *od = bpf_map_lookup_elem(&orig_dst, &cookie);
    if (!od)
        return 0; // not one of ours (not redirected) — leave it alone

    // Copy the looked-up value to the stack before re-inserting (the
    // conservative pattern: update from a stack value, not a map-value pointer).
    struct orig_dst_val val = *od;

    struct src_key sk = {};
    if (skops->family == AF_INET6) {
        sk.family = 6;
        sk.src_ip[0] = skops->local_ip6[0];
        sk.src_ip[1] = skops->local_ip6[1];
        sk.src_ip[2] = skops->local_ip6[2];
        sk.src_ip[3] = skops->local_ip6[3];
    } else {
        sk.family = 4;
        sk.src_ip[0] = skops->local_ip4;            // network byte order
    }
    sk.src_port = bpf_htons((__u16)skops->local_port); // local_port is HOST order

    bpf_map_update_elem(&src_to_orig, &sk, &val, BPF_ANY);
    // Re-keyed: drop the cookie entry so the scratch map self-bounds.
    bpf_map_delete_elem(&orig_dst, &cookie);
    return 0;
}
