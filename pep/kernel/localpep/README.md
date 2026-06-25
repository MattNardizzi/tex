# tex-local-pep — in-kernel LOCAL-action enforcement leg

Extends Tex's in-kernel floor from the network plane (`tex_redirect`: egress
`connect`/`sendmsg` → EPERM) to the **local/non-network irreversible action
class**. A FORBID from the live PDP is enforced here as a real `-EPERM` returned
by the kernel's BPF-LSM Mandatory-Access-Control hooks — *before* the effect is
committed, against the kernel-resolved object (no TOCTOU window), even for a
fully-compromised agent userspace issuing raw syscalls, even for root.

A forbidden inode becomes **immutable + undeletable + inexecutable, but still
readable**, for the enrolled agent. Hooks: `inode_unlink`/`path_unlink` (delete),
`path_truncate`/`file_truncate` (truncate/`O_TRUNC`/ftruncate),
`file_open(FMODE_WRITE)` (the keystone — closes write-overwrite + the no-syscall
`mmap(MAP_SHARED)` hole at the write-intent open), `inode_rename` (move-away +
overwrite-onto), `bprm_check_security` (exec).

## How it binds to the live verdict (one verdict, two PEPs)
The PDP's `StandingGovernance.decide()` warms a per-`(agent, resource)`
`LocalForbidSource` on a resource-attributable local-action FORBID (gated, additive
— `local_forbid_sink`). The source exports an **HMAC-signed** set; this loader
(`serve`) **verifies the HMAC at the enforcement point** before warming the
in-kernel `(cgroup_id, inode)` deny map. The loader is the privilege-separated
enforcer: a compromised agent in the enrolled cgroup cannot reach the maps, and
cannot forge or strip a signed set without `TEX_LOCAL_PEP_SECRET`.

## DEPLOY PREREQUISITES (honest edges — see the residual-bypass ledger)
- **Linux + `bpf` in the active LSM list** (`lsm=...,bpf` boot param + reboot;
  check `cat /sys/kernel/security/lsm`). **Not on Render or macOS** — this governs
  the *agent fleet host*, not the Tex control plane (Render stays decide+prove).
- **Run governed agents UNPRIVILEGED + cgroup-delegated** so they cannot rewrite
  `cgroup.procs` to escape the enrolled cgroup (ledger B10). This is the single
  load-bearing deploy rule: a *root* agent can move itself out of the governed
  cgroup, which trends toward L4 (below). An unprivileged agent provably cannot.

## THREAT MODEL — what this DOES and does NOT defend (no overclaim)
Enforcement holds against an adversary up to **L3 — a fully compromised agent
USERSPACE** in the enrolled cgroup: raw syscalls (bypass libc/SDK), TOCTOU
path-swaps (defeated — the hook matches the kernel-resolved inode), hardlink/
symlink/`/proc/self/fd` tricks, `renameat2(RENAME_EXCHANGE)`, `copy_file_range`/
`FICLONE`, `io_uring` ops (incl. async io_wq offload), and `write(2)`-class writes
through a fd opened before the forbid (all proven blocked). **One honest residual
WITHIN L3 (ledger B15):** a writable `MAP_SHARED` mapping established BEFORE the
forbid lands lets a *syscall-free* memory store corrupt the file afterward — no
LSM hook can observe a CPU store, so this is irreducible at the LSM layer. New
shared-writable mappings ARE denied at acquisition (`file_open` needs a writable
fd + `mmap_file`); the residual is only a pre-existing mapping, mitigated by
warming forbids BEFORE the agent maps the file (born into a pre-warmed cgroup).
It does **NOT** defend **L4 — a rooted host / compromised kernel, or a compromise
of the loader process itself**. The loader writes the verdict maps with CAP_BPF/
CAP_MAC_ADMIN; root owns the kernel and can detach the programs or clear the maps.
Closing L4 requires a hardware root of trust (measured boot + remote attestation /
a TEE), a separate program **not** claimed here. "Un-bypassable" in this README
always means *relative to L3 and the residual-bypass ledger*, never absolute.

## ACTIVATE (outward step (b) — the genuinely dangerous one)
This can deny legitimate production work fleet-wide. Do it deliberately, per host:
1. Ensure `bpf` is in the active LSM list (above).
2. `make -C pep/kernel lsm-build` → the `tex-local-pep` binary.
3. Set `TEX_LOCAL_PEP_SECRET` (shared with the PDP) and point at the PDP feed:
   `tex-local-pep serve --feed https://<pdp>/v1/govern/local-forbid-set \
      --secret-env TEX_LOCAL_PEP_SECRET --agent <agent_id>=/sys/fs/cgroup/<path> --poll`
4. On the PDP, wire `StandingGovernance(local_forbid_sink=<source>.feed_from_decision)`
   (i.e. set `TEX_LOCAL_PEP`). Until this is wired the source stays empty.

## REVERSE / KILL-SWITCH (proven ~22-27µs under load)
- **Instant, total, in place:** `kill -USR1 <serve pid>` → `Disarm` un-enrolls every
  cgroup; enforcement is off immediately, hooks stay attached (re-arm is instant).
- **Full teardown:** `kill -INT <serve pid>` → detaches every LSM hook.
- **Stop warming:** unset `TEX_LOCAL_PEP` on the PDP (the sink goes inert; existing
  denies TTL-expire). Default is OFF — unwired is byte-for-byte unchanged.

## REVERSE outward step (a) — the merge-to-main
A merge is **prod-inert** (flag-gated default-OFF; the kernel leg does not even run
on Render). To undo it anyway: `git revert -m 1 <merge-commit>` (the code carries no
default behavior, so the revert is mechanical).

## Test (root, on a kernel with `bpf` LSM)
    make -C pep/kernel lsm-vm-test
    # or: TEX_BYPASS_CORPUS=$PWD/tests/enforcement/bypass_corpus/corpus.jsonl \
    #       sudo <prebuilt localpep.test> -test.v
