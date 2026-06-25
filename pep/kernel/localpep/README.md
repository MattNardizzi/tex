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
  `cgroup.procs` to escape the enrolled cgroup (ledger B10).
- **Warm forbids BEFORE the agent acts** (born into a pre-warmed governed cgroup)
  so there is no writable-fd-opened-before-the-forbid window (ledger B14).

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
