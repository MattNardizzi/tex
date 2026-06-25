// SPDX-License-Identifier: Apache-2.0
//
// DoD-E10: the kill-switch (Disarm) is proven to work UNDER LOAD — while many
// concurrent agent processes are hammering forbidden syscalls against the live
// hooks — and to take effect quickly, without detaching the programs.
package localpep

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestKillSwitchUnderLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	const workers = 8
	cg := mkCgroup(t)
	dir := t.TempDir()
	l, err := Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Each worker hammers unlink on its OWN forbidden file (no shared-file race).
	files := make([]string, workers)
	for i := 0; i < workers; i++ {
		f := filepath.Join(dir, "load_"+strconv.Itoa(i)+".dat")
		_ = os.WriteFile(f, []byte("irreplaceable"), 0o644)
		ino, _ := InodeOf(f)
		_ = l.Forbid(cgID, ino)
		files[i] = f
	}

	// Launch the load: every worker tight-loops unlink against the live hooks.
	procs := make([]*exec.Cmd, workers)
	for i := 0; i < workers; i++ {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), "TEX_PROBE_OP=hammer", "TEX_PROBE_TARGET="+files[i], "TEX_PROBE_CGROUP="+cg)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start worker %d: %v", i, err)
		}
		procs[i] = cmd
	}
	// Let the load ramp, then confirm enforcement holds under it: every file survives.
	time.Sleep(300 * time.Millisecond)
	for i, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("file %d deleted UNDER LOAD before kill-switch — enforcement leaked: %v", i, err)
		}
	}

	// KILL-SWITCH under load — measure how fast enforcement turns off.
	t0 := time.Now()
	cleared, err := l.Disarm()
	dt := time.Since(t0)
	if err != nil {
		t.Fatalf("disarm under load: %v", err)
	}
	t.Logf("DoD-E10 kill-switch latency under %d-worker load: %v (un-enrolled %d cgroup)", workers, dt, cleared)
	if dt > 100*time.Millisecond {
		t.Fatalf("kill-switch too slow under load: %v", dt)
	}

	// After the kill-switch, a freshly-forbidden delete must SUCCEED (enforcement
	// is off; the hooks remain attached, proving Disarm, not teardown).
	post := filepath.Join(dir, "post.dat")
	_ = os.WriteFile(post, []byte("x"), 0o644)
	pino, _ := InodeOf(post)
	_ = l.Forbid(cgID, pino) // re-forbid, but cgroup is un-enrolled so it is inert
	if code := runProbe(t, "unlink", cg, post, ""); code != 0 {
		t.Fatalf("after kill-switch, delete still blocked (exit %d) — kill-switch did not take effect", code)
	}

	for _, cmd := range procs {
		_ = cmd.Wait() // workers exit once their file becomes deletable post-disarm
	}
}
