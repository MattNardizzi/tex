// SPDX-License-Identifier: Apache-2.0
//
//go:build linux_ebpf_vm

// load_test.go — kernel-half load + verifier + attach tests for the floor.
//
// These run ONLY in a Linux VM as root (the verifier needs the running kernel's
// BTF and CAP_BPF/CAP_NET_ADMIN to attach cgroup hooks). They are gated behind
// the `linux_ebpf_vm` build tag so a plain `go test ./...` on a dev host (or in
// CI without a kernel) never tries to load eBPF. Run them via:
//
//	make vm-test            # copies into the VM, builds, runs as root
//	# or directly inside the VM, as root, after `make generate`:
//	sudo go test -tags linux_ebpf_vm ./agent -run TestLoad -v
//
// What is asserted here (the load floor):
//   - the bpf2go-embedded object loads and ALL FIVE programs pass the verifier;
//   - each program AttachCgroup()s to a throwaway cgroup-v2 directory with the
//     correct attach type (connect4/6, sendmsg4/6, sockops).
//
// behavior_test.go asserts the in-kernel ENFORCEMENT (FORBID block, redirect +
// orig-dst recovery, UDP fail-closed) against a child run in the governed cgroup.

package main

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// requireRoot skips the test when not uid 0 — attaching cgroup programs needs
// privilege, and the failure mode (EPERM) is environmental, not a code defect.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("kernel-floor tests require root (cgroup attach + bpf load); rerun under sudo")
	}
}

// loadObjs loads the embedded CO-RE object WITHOUT pinning (tests are
// self-contained and repeatable; the production loader pins under /sys/fs/bpf).
// It fails the test (not skips) on a verifier rejection — a rejection is a real
// regression in the BPF source, exactly what these tests exist to catch.
func loadObjs(t *testing.T) *texRedirectObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	objs := &texRedirectObjects{}
	if err := loadTexRedirectObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Print the full verifier log — this is the actionable artifact a
			// human needs if a program is rejected.
			t.Fatalf("VERIFIER REJECTED a program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return objs
}

// newGovernedCgroup makes a throwaway cgroup-v2 dir under the unified root and
// returns its path; it is removed on cleanup. Attaching the floor's hooks here
// makes membership of THIS cgroup the governance boundary, exactly as in prod.
func newGovernedCgroup(t *testing.T) string {
	t.Helper()
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(root + "/cgroup.controllers"); err != nil {
		t.Skipf("no cgroup-v2 unified hierarchy at %s: %v", root, err)
	}
	dir, err := os.MkdirTemp(root, "textest-")
	if err != nil {
		t.Fatalf("create throwaway cgroup: %v", err)
	}
	t.Cleanup(func() {
		// Move any stragglers back to root, then rmdir. A leaf cgroup with no
		// procs is removable via rmdir(2).
		_ = os.Remove(dir)
	})
	return dir
}

// TestLoadVerifierPassesAllPrograms asserts the embedded object loads and every
// one of the five programs passed the in-kernel verifier (a successful
// loadTexRedirectObjects means each SEC()'d program verified).
func TestLoadVerifierPassesAllPrograms(t *testing.T) {
	requireRoot(t)
	objs := loadObjs(t)

	progs := map[string]*ebpf.Program{
		"tex_connect4": objs.TexConnect4,
		"tex_connect6": objs.TexConnect6,
		"tex_sendmsg4": objs.TexSendmsg4,
		"tex_sendmsg6": objs.TexSendmsg6,
		"tex_sock_ops": objs.TexSockOps,
	}
	if len(progs) != 5 {
		t.Fatalf("expected 5 programs, have %d", len(progs))
	}
	for name, p := range progs {
		if p == nil {
			t.Errorf("program %s is nil after load (verifier did not accept it)", name)
			continue
		}
		// FD validity is a second, independent confirmation the program is live.
		if p.FD() < 0 {
			t.Errorf("program %s has invalid fd %d", name, p.FD())
		}
		t.Logf("verifier PASS: %s (fd=%d)", name, p.FD())
	}
}

// TestAttachCgroupAllHooks asserts each program attaches to a throwaway
// cgroup-v2 dir with its correct attach type. This exercises the same
// link.AttachCgroup path the production loader uses in agent/main.go.
func TestAttachCgroupAllHooks(t *testing.T) {
	requireRoot(t)
	objs := loadObjs(t)
	cg := newGovernedCgroup(t)

	specs := []struct {
		name   string
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{"cgroup/connect4", ebpf.AttachCGroupInet4Connect, objs.TexConnect4},
		{"cgroup/connect6", ebpf.AttachCGroupInet6Connect, objs.TexConnect6},
		{"cgroup/sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, objs.TexSendmsg4},
		{"cgroup/sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, objs.TexSendmsg6},
		{"sockops", ebpf.AttachCGroupSockOps, objs.TexSockOps},
	}
	for _, s := range specs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cg,
			Attach:  s.attach,
			Program: s.prog,
		})
		if err != nil {
			t.Errorf("AttachCgroup %s at %s: %v", s.name, cg, err)
			continue
		}
		t.Cleanup(func() { l.Close() })
		t.Logf("attached %s -> %s", s.name, cg)
	}
}
