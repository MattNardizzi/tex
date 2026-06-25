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
#define TEX_FMODE_WRITE 0x2 /* FMODE_WRITE (include/linux/fs.h) */
#define TEX_MAY_WRITE 0x2 /* MAY_WRITE (include/linux/fs.h) */
#define TEX_MAY_APPEND 0x8 /* MAY_APPEND */
#define TEX_PROT_WRITE 0x2 /* PROT_WRITE (include/uapi/asm-generic/mman-common.h) */
#define TEX_MAP_SHARED 0x1 /* MAP_SHARED (include/uapi/asm-generic/mman-common.h) */

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

// ===== S4 breadth: the rest of the irreversible local-action class ========= //
// Blocking unlink alone is not enough — an attacker who cannot delete a file can
// still destroy it by zeroing its contents (truncate / open(O_TRUNC)) or by
// renaming another file over it. And executing a forbidden binary is itself an
// irreversible local action (the address space is replaced). These hooks close
// that gap so a FORBID genuinely stops the irreversible action, not just delete.

// security_path_truncate(const struct path *path) — truncate(2) AND the O_TRUNC
// leg of open(2) both reach do_truncate -> security_path_truncate here
// (CONFIG_SECURITY_PATH=y). Zeroing a forbidden file is as irreversible as
// deleting it.
SEC("lsm/path_truncate")
int BPF_PROG(tex_path_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;
	__u64 ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_file_truncate(struct file *file) — ftruncate(2) on an already-open fd
// (a path that does not pass through path_truncate).
SEC("lsm/file_truncate")
int BPF_PROG(tex_file_truncate, struct file *file, int ret)
{
	if (ret)
		return ret;
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_inode_rename(old_dir, old_dentry, new_dir, new_dentry) — block when
// the MOVED file (old) or the OVERWRITE target (new) is a forbidden inode.
// rename-onto unlinks the target's inode as part of the operation (irreversible);
// move-away evades a path-locked policy. new_dentry may have no inode (pure move
// to a fresh name) -> CO-RE read yields 0, which is never in the forbid-set, so
// that case is correctly NOT denied.
SEC("lsm/inode_rename")
int BPF_PROG(tex_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;
	__u64 old_ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
	int v = tex_local_verdict(old_ino);
	if (v)
		return v;
	__u64 new_ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);
	return tex_local_verdict(new_ino);
}

// security_file_open(struct file *file) — the keystone of immutability. Deny any
// WRITE-intent open of a forbidden inode. This single hook closes the entire
// content-mutation surface that per-syscall hooks would otherwise have to chase:
//   * plain write(2)/pwrite(2) overwrite (no truncate, no unlink — just clobber),
//   * mmap(MAP_SHARED) + memory-store corruption (the store emits NO syscall, but
//     it REQUIRES a writable fd, which is denied here),
//   * open(O_TRUNC) content-zeroing (O_TRUNC implies write intent).
// Read-only opens are allowed (the agent may still READ a protected file), so a
// forbidden inode becomes immutable-but-readable for the enrolled agent. A
// writable fd opened BEFORE the forbid is added is caught by tex_file_permission
// below (which re-checks every write(2)-class access), so the pre-opened-fd
// WRITE window is closed (ledger B14). HONEST EDGE: a writable MAP_SHARED mapping
// established BEFORE the forbid is NOT closed — a memory store through it emits no
// syscall, so no LSM hook fires (ledger B15, irreducible at the LSM layer). New
// shared-writable mappings are denied at acquisition by tex_file_open (needs a
// writable fd) + tex_mmap_file below.
SEC("lsm/file_open")
int BPF_PROG(tex_file_open, struct file *file, int ret)
{
	if (ret)
		return ret;
	unsigned int fmode = BPF_CORE_READ(file, f_mode);
	if (!(fmode & TEX_FMODE_WRITE))
		return 0; /* read-only open is permitted */
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_bprm_check_security(struct linux_binprm *bprm) — execve(2)/execveat(2).
// Block executing a forbidden binary; the subject is the resolved program file's
// inode. The exec is denied before the address space is replaced.
SEC("lsm/bprm_check_security")
int BPF_PROG(tex_bprm_check, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	__u64 ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_file_permission(struct file *file, int mask) — fires on every read/
// write access to an already-open file. Denying MAY_WRITE/MAY_APPEND here closes
// ledger B14: a writable fd opened BEFORE the forbid was added (when the open was
// still permitted) cannot WRITE through it afterward — every write re-checks the
// LIVE forbid-set against the kernel-resolved inode. Read/exec-only access stays
// allowed (immutable-but-readable preserved). The map lookup is paid only inside
// an enrolled cgroup, since tex_local_verdict gates on enrollment first.
SEC("lsm/file_permission")
int BPF_PROG(tex_file_permission, struct file *file, int mask, int ret)
{
	if (ret)
		return ret;
	if (!(mask & (TEX_MAY_WRITE | TEX_MAY_APPEND)))
		return 0; /* read/exec-only access is permitted */
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	return tex_local_verdict(ino);
}

// security_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
// unsigned long flags) — deny establishing a NEW writable+shared mapping of a
// forbidden inode (only MAP_SHARED|PROT_WRITE can write back to the file; private
// mappings are copy-on-write and never corrupt it). This closes the mmap-ACQUIRE
// path as defence-in-depth on top of tex_file_open (which already denies the
// writable fd a shared-writable mapping requires). HONEST EDGE it does NOT close:
// a mapping established BEFORE the forbid — those PTEs already exist and a store
// through them emits no syscall, so nothing fires (ledger B15, irreducible at the
// LSM layer; mitigated by warming forbids BEFORE the agent maps the file).
SEC("lsm/mmap_file")
int BPF_PROG(tex_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags, int ret)
{
	if (ret)
		return ret;
	if (file == NULL)
		return 0; /* anonymous mapping — no file to protect */
	if (!((prot & TEX_PROT_WRITE) && (flags & TEX_MAP_SHARED)))
		return 0; /* only a shared+writable mapping can corrupt the file */
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	return tex_local_verdict(ino);
}
