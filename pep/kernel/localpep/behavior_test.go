// SPDX-License-Identifier: Apache-2.0
//
// Behavior tests for the BPF-LSM local-action enforcement leg. Run as root,
// against the running kernel's BTF, inside the Lima VM (see ../hack). These are
// internal-fixture tests (labeled as such in the contract): they drive a REAL
// child process that joins the governed cgroup and issues a REAL unlink(2); the
// child observes the in-kernel -EPERM. They are necessary but not sufficient for
// DoD-E1 — the non-harness real-process proof is the cmd binary + a separate
// agent process (see the loop log).
package localpep

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// Probe child: if TEX_PROBE_UNLINK is set, this binary joins the cgroup named by
// TEX_PROBE_CGROUP (if any), attempts unlink(TEX_PROBE_UNLINK), and exits with
// 0 on success or 100+errno on failure. Runs BEFORE any test via TestMain.
func TestMain(m *testing.M) {
	if target := os.Getenv("TEX_PROBE_UNLINK"); target != "" {
		if cg := os.Getenv("TEX_PROBE_CGROUP"); cg != "" {
			if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"),
				[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
				os.Stderr.WriteString("probe: join cgroup failed: " + err.Error() + "\n")
				os.Exit(200)
			}
		}
		err := syscall.Unlink(target)
		if err == nil {
			os.Exit(0) // deleted
		}
		if errno, ok := err.(syscall.Errno); ok {
			os.Exit(100 + int(errno))
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// runProbe re-execs this test binary in probe mode and returns its exit code.
// exit 0 = deleted; 100+EPERM(1) = 101 = blocked in-kernel.
func runProbe(t *testing.T, cgroupPath, target string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "TEX_PROBE_UNLINK="+target)
	if cgroupPath != "" {
		cmd.Env = append(cmd.Env, "TEX_PROBE_CGROUP="+cgroupPath)
	}
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatalf("probe exec failed: %v", err)
	return -1
}

const blockedEPERM = 100 + int(syscall.EPERM) // 101

func mkCgroup(t *testing.T) string {
	t.Helper()
	path := filepath.Join("/sys/fs/cgroup", "tex_test_"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("mkdir cgroup %s: %v (is cgroup v2 mounted?)", path, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func writeFile(t *testing.T, path, content string) uint64 {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	ino, err := InodeOf(path)
	if err != nil {
		t.Fatalf("inode %s: %v", path, err)
	}
	return ino
}

func TestLocalActionEnforcement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	cg := mkCgroup(t)
	dir := t.TempDir()
	forbidden := filepath.Join(dir, "payroll.db")
	control := filepath.Join(dir, "scratch.tmp")
	fIno := writeFile(t, forbidden, "irreversible")
	_ = writeFile(t, control, "fine to delete")

	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()

	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := l.Forbid(cgID, fIno); err != nil {
		t.Fatalf("forbid: %v", err)
	}

	// 1) The governed agent's delete of the forbidden file is BLOCKED in-kernel.
	if code := runProbe(t, cg, forbidden); code != blockedEPERM {
		t.Fatalf("forbidden unlink: want blocked(EPERM)=%d, got exit %d", blockedEPERM, code)
	}
	if _, err := os.Stat(forbidden); err != nil {
		t.Fatalf("forbidden file must survive the blocked unlink, stat err: %v", err)
	}

	// 2) Control file (not forbidden) deletes fine — no false-deny.
	if code := runProbe(t, cg, control); code != 0 {
		t.Fatalf("control unlink: want deleted(0), got exit %d", code)
	}

	// 3) Scoping: the SAME forbidden inode, deleted by a process NOT in the
	//    enrolled cgroup, succeeds — enforcement is per-agent, not global.
	scope := filepath.Join(dir, "other-agent.db")
	sIno := writeFile(t, scope, "other agent's file")
	// forbid it ONLY for the enrolled cgroup; a non-enrolled probe must still delete it.
	if err := l.Forbid(cgID, sIno); err != nil {
		t.Fatalf("forbid scope: %v", err)
	}
	if code := runProbe(t, "" /* no cgroup join */, scope); code != 0 {
		t.Fatalf("non-enrolled unlink: want deleted(0), got exit %d (scoping leaked!)", code)
	}

	// 4) Kill-switch: Disarm un-enrolls all; the previously-forbidden delete now
	//    succeeds — reversibility proven, hooks still attached.
	cleared, err := l.Disarm()
	if err != nil || cleared != 1 {
		t.Fatalf("disarm: cleared=%d err=%v (want 1, nil)", cleared, err)
	}
	if code := runProbe(t, cg, forbidden); code != 0 {
		t.Fatalf("after kill-switch, forbidden unlink: want deleted(0), got exit %d", code)
	}
}
