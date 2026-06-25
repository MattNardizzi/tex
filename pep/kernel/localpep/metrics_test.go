// SPDX-License-Identifier: Apache-2.0
//
// DoD-E5 measurement: end-to-end ENFORCED rate (attempted -> actually stopped)
// and the FALSE-DENY rate (legitimate work wrongly blocked), measured through the
// real in-kernel enforcement point with real child processes.
package localpep

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestEnforcementMetrics(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	const N = 50
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

	// --- ENFORCED rate: N forbidden irreversible actions, count actually stopped.
	attempted, stopped := 0, 0
	for i := 0; i < N; i++ {
		f := filepath.Join(dir, "forbidden_"+strconv.Itoa(i)+".dat")
		_ = os.WriteFile(f, []byte("irreplaceable"), 0o644)
		ino, _ := InodeOf(f)
		_ = l.Forbid(cgID, ino)
		attempted++
		if runProbe(t, "unlink", cg, f, "") == blockedEPERM {
			stopped++
		}
	}
	enforced := float64(stopped) / float64(attempted)

	// --- FALSE-DENY rate: legitimate operations that MUST pass.
	legit, wrongful := 0, 0
	// (a) deletes of NON-forbidden files
	for i := 0; i < N; i++ {
		f := filepath.Join(dir, "ok_"+strconv.Itoa(i)+".tmp")
		_ = os.WriteFile(f, []byte("scratch"), 0o644)
		legit++
		if runProbe(t, "unlink", cg, f, "") != 0 {
			wrongful++
		}
	}
	// (b) READS of forbidden files (immutable but readable)
	for i := 0; i < N/2; i++ {
		f := filepath.Join(dir, "ro_"+strconv.Itoa(i)+".dat")
		_ = os.WriteFile(f, []byte("locked"), 0o644)
		ino, _ := InodeOf(f)
		_ = l.Forbid(cgID, ino)
		legit++
		if runProbe(t, "ropen", cg, f, "") != 0 {
			wrongful++
		}
	}
	falseDeny := float64(wrongful) / float64(legit)

	t.Logf("DoD-E5 ENFORCED RATE  : %d/%d attempted forbidden actions stopped = %.4f", stopped, attempted, enforced)
	t.Logf("DoD-E5 DECIDED->ENFORCED delta: of FORBID-decided local actions, %.4f enforced, %.4f leaked (covered classes, L3 unprivileged)", enforced, 1-enforced)
	t.Logf("DoD-E5 FALSE-DENY RATE: %d/%d legitimate ops wrongly blocked = %.4f", wrongful, legit, falseDeny)

	if enforced != 1.0 {
		t.Fatalf("enforced rate %.4f < 1.0 — a forbidden action leaked", enforced)
	}
	if falseDeny != 0.0 {
		t.Fatalf("false-deny rate %.4f > 0 — legitimate work blocked", falseDeny)
	}
}
