# REPRODUCE — the kernel `rm → EPERM` demo, by hand

What you will see: a shell enrolled as a governed agent can **read** a file
but cannot delete, truncate, overwrite, rename, or execute it. `rm` comes
back `Operation not permitted` — a real `-EPERM` from the kernel's BPF-LSM
hooks, not an alert after the fact — and the file is intact afterward.

Honest time budget: **~30–35 minutes including VM provision** (most of it is
the VM image download and one reboot). On a Linux box that already has `bpf`
in its active LSM list, it is closer to 10 minutes. A scripted one-command
demo is coming; these are the exact manual steps in the meantime.

## 0. A machine that can load BPF-LSM

You need Linux with BTF (`/sys/kernel/btf/vmlinux`), cgroup-v2, clang ≥ 14,
Go ≥ 1.22, and root. macOS cannot load eBPF — use the Lima VM template
committed in this repo (Ubuntu 24.04, works on Apple silicon and x86):

```bash
brew install lima            # if you don't have it
cd tex/pep/kernel
limactl create --name tex-ebpf hack/tex-ebpf.lima.yaml
limactl start tex-ebpf
limactl shell tex-ebpf
```

On your own Linux host, any distro with kernel ≥ 5.15 + BTF works.

## 1. Put `bpf` in the active LSM list (one-time; needs a reboot)

```bash
cat /sys/kernel/security/lsm
```

If the list does not contain `bpf`, add it to the kernel command line. On
Ubuntu, take the list you just printed and append `,bpf`:

```bash
sudo sed -i 's/^GRUB_CMDLINE_LINUX="/&lsm=landlock,lockdown,yama,integrity,apparmor,bpf /' /etc/default/grub
sudo update-grub && sudo reboot
```

(Use *your* printed list plus `,bpf` — the line above is Ubuntu 24.04's
default. After reboot, `cat /sys/kernel/security/lsm` must show `bpf`.)

## 2. Build the enforcer

Inside the VM (or on your Linux host):

```bash
git clone https://github.com/MattNardizzi/tex && cd tex
make -C pep/kernel lsm-build      # produces pep/kernel/tex-local-pep
```

## 3. Stage a target file, a cgroup, and a signed FORBID feed

The enforcer only warms the in-kernel deny map from an **HMAC-signed**
verdict set — a compromised agent can't forge or strip a FORBID. Stage a
payroll file, an agent cgroup, and a signed feed that forbids the agent from
touching the file:

```bash
sudo mkdir -p /sys/fs/cgroup/texdemo
mkdir -p /tmp/tex_e2e
printf 'ACCT  NAME      SALARY\n0001  A. Ghost  $180,000\n0002  B. Real   $165,000\n' > /tmp/tex_e2e/payroll.db

export TEX_LOCAL_PEP_SECRET=texdemo-local-secret
python3 - <<'EOF'
import hmac, hashlib, json, os
secret = os.environ["TEX_LOCAL_PEP_SECRET"].encode()
canon = '{"epoch":1,"forbid":[{"agent_id":"ghost-agent","path":"/tmp/tex_e2e/payroll.db"}],"tenant":"acme"}'
sig = hmac.new(secret, canon.encode(), hashlib.sha256).hexdigest()
open("/tmp/tex_e2e/feed.json", "w").write(json.dumps({"set_canonical": canon, "sig": sig}))
print("feed.json written, sig", sig[:16], "…")
EOF
```

(In a live deployment the feed is the PDP's `/v1/govern/local-forbid-set`
endpoint and the FORBID arrives from a real decision; the file feed is the
same code path with the transport removed.)

## 4. Start the enforcer

```bash
sudo TEX_LOCAL_PEP_SECRET="$TEX_LOCAL_PEP_SECRET" ./pep/kernel/tex-local-pep serve \
  --feed /tmp/tex_e2e/feed.json --secret-env TEX_LOCAL_PEP_SECRET \
  --agent ghost-agent=/sys/fs/cgroup/texdemo
```

Leave it running (or background it with `nohup … &`). It verifies the HMAC,
resolves the path to its inode, and warms the `(cgroup, inode)` deny map.

## 5. Become the governed agent and try to destroy the file

In a second shell:

```bash
echo $$ | sudo tee /sys/fs/cgroup/texdemo/cgroup.procs   # enroll this shell as the agent
cat /tmp/tex_e2e/payroll.db                              # read: allowed
rm /tmp/tex_e2e/payroll.db                               # destroy: denied by the kernel
ls -la /tmp/tex_e2e/payroll.db                           # the file is intact
```

Expected output of the `rm`:

```
rm: cannot remove '/tmp/tex_e2e/payroll.db': Operation not permitted
```

The deny is at the kernel-resolved inode, so the usual escapes fail too:
TOCTOU path swaps, hardlinks/symlinks, `/proc/self/fd`,
`renameat2(RENAME_EXCHANGE)`, `copy_file_range`, `io_uring` ops, raw
syscalls that bypass libc, and `O_TRUNC`/`ftruncate` — the behavior tests
pin each of these (`make -C pep/kernel lsm-vm-test` runs them as root
against the live kernel).

Demo note: `sudo tee` into `cgroup.procs` is a convenience for *this* demo.
The load-bearing deploy rule is the opposite — run governed agents
**unprivileged and cgroup-delegated**, born into a pre-warmed cgroup, so
they cannot re-write `cgroup.procs` to escape.

## 6. Kill switch (proven ~22–27µs under load)

```bash
sudo kill -USR1 "$(pgrep -f 'tex-local-pep serve')"   # disarm: enforcement off instantly, hooks stay attached
sudo kill -INT  "$(pgrep -f 'tex-local-pep serve')"   # full teardown: detaches every LSM hook
```

## What this does — and does not — defend

Enforcement holds against an adversary up to **L3 — a fully compromised
agent userspace** in the enrolled cgroup. It does **not** defend **L4 — a
rooted host / compromised kernel, or a compromise of the loader process
itself**: root owns the kernel and can detach the programs. There is one
honest residual *within* L3 (a writable `MAP_SHARED` mapping established
before the forbid lands). The full threat model and the residual-bypass
ledger are in [pep/kernel/localpep/README.md](pep/kernel/localpep/README.md)
— read that before relying on this for anything real. Zero production
deployments today.
