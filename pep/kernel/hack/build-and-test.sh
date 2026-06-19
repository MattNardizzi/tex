#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-and-test.sh — build + load + verifier + behavior tests for the kernel
# floor, run inside a Linux VM against the running kernel's BTF.
#
# Two modes:
#
#   1. HOST mode (default, run from macOS/host via `make vm-test`):
#      copies pep/kernel from the read-only host mount into a writable dir inside
#      the Lima VM `tex-ebpf`, then re-invokes itself there with --in-vm.
#
#   2. IN-VM mode (`--in-vm`, run inside the VM):
#      guards on BTF, builds the object + agent, then runs the kernel-half Go
#      tests as root (sudo) behind the `linux_ebpf_vm` build tag.
#
# Honest by construction: it FAILS loudly on a verifier rejection or a behavior
# regression, and SKIPs (does not fake-pass) when prerequisites are missing.
#
# Env:
#   TEX_VM        Lima VM name              (default: tex-ebpf)
#   KERNEL_SRC    host path to pep/kernel   (default: this script's ../)
#   VM_BUILD_DIR  writable dir inside VM    (default: ~/kbuild)
#   GO_TEST_RUN   -run filter for go test   (default: empty = all)

set -euo pipefail

TEX_VM="${TEX_VM:-tex-ebpf}"
VM_BUILD_DIR="${VM_BUILD_DIR:-\$HOME/kbuild}"
GO_TEST_RUN="${GO_TEST_RUN:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_SRC="${KERNEL_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)}"

log()  { printf '\033[1;36m[vm-test]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[vm-test] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }
skip() { printf '\033[1;33m[vm-test] SKIP:\033[0m %s\n' "$*" >&2; exit 0; }

run_in_vm() {
  log "VM=$TEX_VM  KERNEL_SRC=$KERNEL_SRC"
  command -v limactl >/dev/null 2>&1 || fail "limactl not found on host (install Lima)"
  limactl list 2>/dev/null | grep -qE "^${TEX_VM}\b.*Running" \
    || fail "Lima VM '$TEX_VM' is not Running (limactl start $TEX_VM)"

  # Copy the kernel dir from the RO host mount into a writable dir in the VM,
  # then re-run this script there. The host home is mounted at the same path
  # inside the VM (read-only), so KERNEL_SRC resolves on both sides.
  limactl shell "$TEX_VM" -- bash -lc "
    set -euo pipefail
    rm -rf $VM_BUILD_DIR
    cp -r '$KERNEL_SRC' $VM_BUILD_DIR
    cd $VM_BUILD_DIR
    GO_TEST_RUN='$GO_TEST_RUN' hack/build-and-test.sh --in-vm
  "
}

run_in_vm_local() {
  log "in-VM: $(uname -m) kernel $(uname -r)"

  # 1) BTF guard — CO-RE relocation needs the running kernel's BTF.
  [ -r /sys/kernel/btf/vmlinux ] || skip "/sys/kernel/btf/vmlinux missing (kernel without CONFIG_DEBUG_INFO_BTF)"
  log "BTF present: $(stat -c%s /sys/kernel/btf/vmlinux) bytes"

  for t in clang go bpftool; do
    command -v "$t" >/dev/null 2>&1 || fail "toolchain missing: $t"
  done

  # 2) Build: vmlinux.h -> object -> bpf2go bindings -> agent binary.
  log "make arch-info"
  make arch-info
  log "make vmlinux bpf generate"
  make vmlinux bpf generate
  log "go build agent"
  ( cd agent && CGO_ENABLED=0 go build -o ../tex-kernel-pep . )
  log "agent built: $(stat -c%s tex-kernel-pep) bytes"

  # 3) Kernel-half tests as root (load + verifier + behavior). The tests are
  #    gated behind -tags linux_ebpf_vm so they only ever run here.
  local runflag=()
  [ -n "$GO_TEST_RUN" ] && runflag=(-run "$GO_TEST_RUN")
  log "go test -tags linux_ebpf_vm (as root)${GO_TEST_RUN:+ -run $GO_TEST_RUN}"
  # Preserve GOCACHE/GOPATH for root by passing the env through sudo -E and a
  # GOFLAGS-friendly cache dir; -p 1 keeps cgroup attach serialized.
  sudo -E env "PATH=$PATH" GOFLAGS="" \
    go test -tags linux_ebpf_vm -v -p 1 -count=1 "${runflag[@]}" ./agent
  log "all kernel-floor tests passed"
}

case "${1:-}" in
  --in-vm) run_in_vm_local ;;
  "")      run_in_vm ;;
  *)       fail "unknown arg: $1 (use --in-vm or no args)" ;;
esac
