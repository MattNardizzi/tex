// SPDX-License-Identifier: GPL-2.0
//
// tex_lsm_local — the LOCAL-action in-kernel enforcement leg.
//
// This is the SEPARATE, GPL-licensed object foretold by the note in
// tex_redirect.bpf.c (~line 569): the kernel requires BPF-LSM programs to carry
// a GPL-compatible license, and a single .o has ONE license section, so the LSM
// programs CANNOT live in the Apache-2.0 tex_redirect object without taking down
// the whole egress floor. They live here instead, in their own object with its
// own bpf2go target and its own loader (../localpep), so the working 5-program
// egress floor is never at risk.
//
// What it does: extends Tex's in-kernel floor from the NETWORK plane
// (tex_redirect: connect/sendmsg -> EPERM) to the LOCAL/non-network irreversible
// action class — file delete (unlink), and in later slices exec + truncating
// writes. A FORBID verdict from the live PDP is enforced here as a real -EPERM
// returned by the kernel's LSM Mandatory-Access-Control hook, BEFORE the effect
// is committed, against the KERNEL-RESOLVED object (no TOCTOU window), even for
// a fully compromised agent userspace issuing raw syscalls, even for root.
//
// Scope model (S1 = forbid-set, mirrors the egress TEX_FORBID_AUTOFEED model):
//   * Only ENROLLED cgroups are governed (tex_enrolled_cgroups). A process whose
//     cgroup is not enrolled is NEVER affected — so the rest of the host host is
//     untouched and the kill-switch is "clear the enrolled set" (instant, total).
//   * Within an enrolled cgroup, an action is denied iff (cgroup_id, inode) is in
//     tex_local_deny — warmed by the loader from the PDP's destination-attributable
//     FORBID verdicts. Default within an enrolled cgroup is ALLOW (forbid-set), so
//     legitimate work is not broken (low false-deny). The stronger default-deny
//     capability model for a designated protected set is a later slice.
//
// Honest edges (kept in sync with the residual-bypass ledger):
//   * Governs only enrolled cgroups; an agent outside the enrolled cgroup is
//     ungoverned (completeness-of-mediation = cgroup membership is the boundary).
//   * Per-agent identity == one-agent-per-cgroup granularity.
//   * Forbid-set blocks only targets the PDP has ruled FORBID; targets never sent
//     to the PDP are not blocked by this slice (closed by the capability slice).
//   * Holds against a compromised agent userspace (L3, in-kernel); does NOT hold
//     against a rooted host / compromised kernel or loader (L4) — out of scope.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TEX_EPERM 1 /* return -TEX_EPERM == -EPERM */

// (cgroup_id, inode) -> 1 means: the enrolled agent in this cgroup is FORBIDDEN
// from the irreversible op on this inode. Mirrors the C struct byte-for-byte in
// ../localpep (localKey).
struct tex_local_key {
	__u64 cgroup_id;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, struct tex_local_key);
	__type(value, __u8);
} tex_local_deny SEC(".maps");

// cgroup_id -> 1 means: this cgroup is governed by the local PEP. Empty map =
// nothing governed = bit-for-bit inert (the default-OFF / kill-switch state).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} tex_enrolled_cgroups SEC(".maps");

// Verdict decision shared by every local hook. Fail-OPEN for non-enrolled
// cgroups (so the host is untouched); within an enrolled cgroup, deny iff the
// resolved inode is in the forbid-set.
static __always_inline int tex_local_verdict(__u64 ino)
{
	__u64 cg = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tex_enrolled_cgroups, &cg))
		return 0; /* not governed */
	struct tex_local_key k = {};
	k.cgroup_id = cg;
	k.ino = ino;
	if (bpf_map_lookup_elem(&tex_local_deny, &k))
		return -TEX_EPERM; /* FORBID: block the irreversible op in-kernel */
	return 0;
}

// security_inode_unlink(struct inode *dir, struct dentry *dentry)
SEC("lsm/inode_unlink")
int BPF_PROG(tex_inode_unlink, struct inode *dir, struct dentry *victim, int ret)
{
	if (ret) /* preserve any prior LSM denial (chaining) */
		return ret;
	__u64 ino = BPF_CORE_READ(victim, d_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_path_unlink(const struct path *dir, struct dentry *dentry) — the
// path-based hook (CONFIG_SECURITY_PATH); fires alongside inode_unlink. Having
// both closes the gap where a kernel/config routes a delete through only one.
SEC("lsm/path_unlink")
int BPF_PROG(tex_path_unlink, const struct path *dir, struct dentry *victim, int ret)
{
	if (ret)
		return ret;
	__u64 ino = BPF_CORE_READ(victim, d_inode, i_ino);
	return tex_local_verdict(ino);
}
