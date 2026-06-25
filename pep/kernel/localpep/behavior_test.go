// SPDX-License-Identifier: Apache-2.0
//
// Behavior tests for the BPF-LSM local-action enforcement leg. Run as root,
// against the running kernel's BTF, inside the Lima VM (see ../hack). These are
// internal-fixture tests (labeled as such in the contract): they drive a REAL
// child process that joins the governed cgroup and issues a REAL syscall; the
// child observes the in-kernel -EPERM. They are necessary but not sufficient for
// DoD-E1 — the non-harness real-process proof is the cmd binary + a separate
// agent process (see the loop log).
package localpep

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// unlinkatVia issues unlinkat(2) through an explicit dirfd — the *at()-family
// path the seccomp-notify literature flags as a TOCTOU surface, here proven
// harmless because the LSM hook matches the kernel-resolved inode, not a path.
func unlinkatVia(dirfd int, name string) error {
	return unix.Unlinkat(dirfd, name, 0)
}

// Probe child: re-exec of the test binary. If TEX_PROBE_OP is set, it joins the
// cgroup named by TEX_PROBE_CGROUP (if any) and performs the op against
// TEX_PROBE_TARGET, exiting 0 on success or 100+errno on a blocked syscall. This
// drives a REAL syscall from a REAL separate process, exactly like a compromised
// agent would.
func TestMain(m *testing.M) {
	if op := os.Getenv("TEX_PROBE_OP"); op != "" {
		os.Exit(runProbeChild(op, os.Getenv("TEX_PROBE_TARGET"), os.Getenv("TEX_PROBE_SRC")))
	}
	os.Exit(m.Run())
}

func runProbeChild(op, target, src string) int {
	// cgroup_escape deliberately leaves the enrolled cgroup for the root cgroup
	// (the B10 completeness boundary). Every other op joins the enrolled cgroup.
	joinCg := os.Getenv("TEX_PROBE_CGROUP")
	if op == "cgroup_escape" {
		joinCg = "/sys/fs/cgroup" // root cgroup — un-enrolled
	}
	if joinCg != "" {
		if err := os.WriteFile(filepath.Join(joinCg, "cgroup.procs"),
			[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			os.Stderr.WriteString("probe: join cgroup failed: " + err.Error() + "\n")
			return 200
		}
	}
	var err error
	switch op {
	case "hardlink": // alias the forbidden inode elsewhere, then delete the alias
		alias := target + ".hl"
		if lerr := syscall.Link(target, alias); lerr != nil {
			err = lerr
			break
		}
		err = syscall.Unlink(alias) // same inode -> must be blocked
	case "procfd": // resolve via an O_PATH dirfd + unlinkat (path-canonicalization trick)
		dir := filepath.Dir(target)
		var dfd int
		dfd, err = syscall.Open(dir, syscall.O_PATH|syscall.O_DIRECTORY, 0)
		if err != nil {
			break
		}
		err = unlinkatVia(dfd, filepath.Base(target))
		syscall.Close(dfd)
	case "mmap_write": // requires a writable fd (denied at open) -> closes the mmap hole
		var fd int
		fd, err = syscall.Open(target, syscall.O_RDWR, 0)
		if err == nil {
			syscall.Close(fd)
		}
	case "cgroup_escape": // un-enrolled (root cgroup) delete — B10, root-only residual
		err = syscall.Unlink(target)
	case "unlink":
		err = syscall.Unlink(target)
	case "truncate":
		err = syscall.Truncate(target, 0)
	case "otrunc":
		var fd int
		fd, err = syscall.Open(target, syscall.O_WRONLY|syscall.O_TRUNC, 0)
		if err == nil {
			syscall.Close(fd)
		}
	case "ftruncate":
		var fd int
		fd, err = syscall.Open(target, syscall.O_WRONLY, 0)
		if err != nil {
			break
		}
		err = syscall.Ftruncate(fd, 0)
		syscall.Close(fd)
	case "rename_from": // move the forbidden file away
		err = syscall.Rename(target, target+".moved")
	case "rename_onto": // overwrite the forbidden file with src
		err = syscall.Rename(src, target)
	case "write": // plain overwrite (no truncate, no unlink) — clobber contents
		var fd int
		fd, err = syscall.Open(target, syscall.O_WRONLY, 0)
		if err == nil {
			_, werr := syscall.Write(fd, []byte("CORRUPTED-BY-ATTACKER"))
			syscall.Close(fd)
			err = werr
		}
	case "preopen_write": // B14: open a writable fd BEFORE the forbid, then write
		// AFTER it — the write must be blocked by lsm/file_permission. Synchronizes
		// with the test over stdout("READY")/stdin so the forbid lands between the
		// open and the write.
		var fd int
		fd, err = syscall.Open(target, syscall.O_RDWR, 0) // pre-forbid: permitted
		if err != nil {
			break
		}
		os.Stdout.WriteString("READY\n")
		var one [1]byte
		_, _ = os.Stdin.Read(one[:]) // block until the test has added the forbid
		_, err = syscall.Write(fd, []byte("LATE-WRITE-AFTER-FORBID"))
		syscall.Close(fd)
	case "mmap_after_forbid": // open O_RDWR BEFORE forbid, mmap shared+writable AFTER
		// it — tex_mmap_file must deny ACQUIRING the mapping post-forbid.
		var fd int
		fd, err = syscall.Open(target, syscall.O_RDWR, 0)
		if err != nil {
			break
		}
		os.Stdout.WriteString("READY\n")
		var one [1]byte
		_, _ = os.Stdin.Read(one[:])
		_, err = unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		syscall.Close(fd)
	case "mmap_store_preforbid": // B15 RESIDUAL: map shared+writable BEFORE the
		// forbid, store through it AFTER — a syscall-free store no LSM hook sees.
		var fd int
		fd, err = syscall.Open(target, syscall.O_RDWR, 0)
		if err != nil {
			break
		}
		var b []byte
		b, err = unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		syscall.Close(fd) // the mapping survives the fd close
		if err != nil {
			break
		}
		os.Stdout.WriteString("READY\n")
		var one [1]byte
		_, _ = os.Stdin.Read(one[:])
		copy(b, []byte("PWNED")) // short marker that fits within the file (writeback won't extend EOF)
		err = unix.Msync(b, unix.MS_SYNC)
	case "hammer": // tight unlink loop until deleted or exhausted — used for load
		for i := 0; i < 500000; i++ {
			e := syscall.Unlink(target)
			if e == nil {
				err = nil
				break
			}
			err = e
		}
	case "ropen": // read-only open — MUST be allowed (immutable but readable)
		var fd int
		fd, err = syscall.Open(target, syscall.O_RDONLY, 0)
		if err == nil {
			syscall.Close(fd)
		}
	case "exec": // replace the address space with the forbidden binary
		err = syscall.Exec(target, []string{target}, os.Environ())
		// only returns on failure
	default:
		os.Stderr.WriteString("probe: unknown op " + op + "\n")
		return 201
	}
	if err == nil {
		return 0 // op succeeded
	}
	if errno, ok := err.(syscall.Errno); ok {
		return 100 + int(errno)
	}
	return 1
}

// runProbe re-execs this test binary in probe mode and returns its exit code.
// 0 = op succeeded; 100+EPERM(1) = 101 = blocked in-kernel.
func runProbe(t *testing.T, op, cgroupPath, target, src string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "TEX_PROBE_OP="+op, "TEX_PROBE_TARGET="+target)
	if cgroupPath != "" {
		cmd.Env = append(cmd.Env, "TEX_PROBE_CGROUP="+cgroupPath)
	}
	if src != "" {
		cmd.Env = append(cmd.Env, "TEX_PROBE_SRC="+src)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("probe exec failed: %v", err)
	}
	return 0
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

// S1: the core unlink block + scoping + default-OFF + kill-switch.
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

	if code := runProbe(t, "unlink", cg, forbidden, ""); code != blockedEPERM {
		t.Fatalf("forbidden unlink: want blocked(EPERM)=%d, got exit %d", blockedEPERM, code)
	}
	if _, err := os.Stat(forbidden); err != nil {
		t.Fatalf("forbidden file must survive the blocked unlink, stat err: %v", err)
	}
	if code := runProbe(t, "unlink", cg, control, ""); code != 0 {
		t.Fatalf("control unlink: want deleted(0), got exit %d", code)
	}

	// Scoping: a process NOT in the enrolled cgroup can delete the same inode.
	scope := filepath.Join(dir, "other-agent.db")
	sIno := writeFile(t, scope, "other agent's file")
	if err := l.Forbid(cgID, sIno); err != nil {
		t.Fatalf("forbid scope: %v", err)
	}
	if code := runProbe(t, "unlink", "", scope, ""); code != 0 {
		t.Fatalf("non-enrolled unlink: want deleted(0), got exit %d (scoping leaked!)", code)
	}

	// Kill-switch reverses live.
	cleared, err := l.Disarm()
	if err != nil || cleared != 1 {
		t.Fatalf("disarm: cleared=%d err=%v (want 1, nil)", cleared, err)
	}
	if code := runProbe(t, "unlink", cg, forbidden, ""); code != 0 {
		t.Fatalf("after kill-switch, forbidden unlink: want deleted(0), got exit %d", code)
	}
}

// S4: the full irreversible-action class — a FORBID must stop truncate, O_TRUNC,
// ftruncate, rename-away, rename-onto, and exec, not just unlink. Each blocked op
// must leave the file's CONTENT intact (the point of "irreversible").
func TestS4BreadthEnforcement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	cg := mkCgroup(t)
	dir := t.TempDir()

	const payload = "PAYROLL-RECORDS-IRREPLACEABLE"
	target := filepath.Join(dir, "ledger.db")
	tIno := writeFile(t, target, payload)

	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := l.Forbid(cgID, tIno); err != nil {
		t.Fatalf("forbid: %v", err)
	}

	contentIntact := func(t *testing.T, op string) {
		t.Helper()
		b, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("%s: target unreadable after blocked op (destroyed?): %v", op, err)
		}
		if string(b) != payload {
			t.Fatalf("%s: target CONTENT changed (want %q, got %q) — irreversible loss!", op, payload, string(b))
		}
	}

	// truncate(2)
	if code := runProbe(t, "truncate", cg, target, ""); code != blockedEPERM {
		t.Fatalf("truncate: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "truncate")

	// open(O_TRUNC) — the `: > file` content-destroy
	if code := runProbe(t, "otrunc", cg, target, ""); code != blockedEPERM {
		t.Fatalf("O_TRUNC open: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "otrunc")

	// ftruncate(2) on an open fd
	if code := runProbe(t, "ftruncate", cg, target, ""); code != blockedEPERM {
		t.Fatalf("ftruncate: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "ftruncate")

	// plain write-overwrite (no truncate) — denied at the write-intent open, so
	// the entire write/mmap-write content-mutation surface is closed.
	if code := runProbe(t, "write", cg, target, ""); code != blockedEPERM {
		t.Fatalf("write-overwrite: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "write")

	// read-only open MUST still succeed — the inode is immutable but readable
	// (proves no false-deny on legitimate reads).
	if code := runProbe(t, "ropen", cg, target, ""); code != 0 {
		t.Fatalf("read-only open: want allowed(0), got %d (over-block on reads)", code)
	}

	// rename-away: moving the forbidden inode is denied (path-lock evasion)
	if code := runProbe(t, "rename_from", cg, target, ""); code != blockedEPERM {
		t.Fatalf("rename-away: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "rename_from")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("rename-away: target moved despite block: %v", err)
	}

	// rename-onto: overwriting the forbidden inode is denied (it would unlink it)
	src := filepath.Join(dir, "attacker.tmp")
	_ = writeFile(t, src, "attacker payload")
	if code := runProbe(t, "rename_onto", cg, target, src); code != blockedEPERM {
		t.Fatalf("rename-onto: want blocked(%d), got %d", blockedEPERM, code)
	}
	contentIntact(t, "rename_onto")

	// exec: executing a forbidden binary is denied before the address space flips
	bin := filepath.Join(dir, "payload.bin")
	if err := copyFile("/bin/true", bin, 0o755); err != nil {
		t.Fatalf("stage exec binary: %v", err)
	}
	bIno, _ := InodeOf(bin)
	if err := l.Forbid(cgID, bIno); err != nil {
		t.Fatalf("forbid bin: %v", err)
	}
	if code := runProbe(t, "exec", cg, bin, ""); code != blockedEPERM {
		t.Fatalf("exec forbidden binary: want blocked(%d), got %d", blockedEPERM, code)
	}
	// control: a NON-forbidden copy of the same binary execs fine (no false-deny)
	okBin := filepath.Join(dir, "ok.bin")
	if err := copyFile("/bin/true", okBin, 0o755); err != nil {
		t.Fatalf("stage ok binary: %v", err)
	}
	if code := runProbe(t, "exec", cg, okBin, ""); code != 0 {
		t.Fatalf("non-forbidden exec: want ok(0), got %d (false-deny)", code)
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

// TestB14PreOpenedFdWriteBlocked closes ledger B14: a writable fd opened BEFORE
// the forbid is added cannot write through it after — lsm/file_permission
// re-checks every write against the live forbid-set.
func TestB14PreOpenedFdWriteBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	cg := mkCgroup(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "ledger.db")
	ino := writeFile(t, target, "ORIGINAL-LEDGER")

	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Launch the probe; it opens a writable fd (still permitted) and waits.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"TEX_PROBE_OP=preopen_write", "TEX_PROBE_TARGET="+target, "TEX_PROBE_CGROUP="+cg)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe: %v", err)
	}
	// Wait until the fd is open, THEN forbid (so the open predates the forbid).
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.Contains(line, "READY") {
		t.Fatalf("probe did not open the fd (got %q)", line)
	}
	if err := l.Forbid(cgID, ino); err != nil {
		t.Fatalf("forbid: %v", err)
	}
	_, _ = stdin.Write([]byte("go\n")) // release the late write

	code := 0
	if werr := cmd.Wait(); werr != nil {
		if ee, ok := werr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("probe wait: %v", werr)
		}
	}
	if code != blockedEPERM {
		t.Fatalf("pre-opened fd write: want blocked(EPERM)=%d, got exit %d", blockedEPERM, code)
	}
	b, _ := os.ReadFile(target)
	if strings.Contains(string(b), "LATE-WRITE") {
		t.Fatalf("B14 LEAK: write reached the file through a pre-opened fd: %q", string(b))
	}
}

// runSyncedProbe launches a probe that opens a resource, prints READY, and waits
// on stdin; the test runs betweenReadyAndGo (e.g. adds the forbid) in that gap,
// then releases the probe. Returns the probe's exit code.
func runSyncedProbe(t *testing.T, op, cg, target string, betweenReadyAndGo func()) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "TEX_PROBE_OP="+op, "TEX_PROBE_TARGET="+target, "TEX_PROBE_CGROUP="+cg)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe %s: %v", op, err)
	}
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.Contains(line, "READY") {
		t.Fatalf("probe %s not READY (got %q)", op, line)
	}
	betweenReadyAndGo()
	_, _ = stdin.Write([]byte("go\n"))
	if werr := cmd.Wait(); werr != nil {
		if ee, ok := werr.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("probe %s wait: %v", op, werr)
	}
	return 0
}

// TestMmapAcquireAfterForbidBlocked: tex_mmap_file denies ACQUIRING a new shared+
// writable mapping of a forbidden inode (here via an fd opened pre-forbid, mapped
// post-forbid). This closes the mmap-acquisition path.
func TestMmapAcquireAfterForbidBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	cg := mkCgroup(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "ledger.db")
	ino := writeFile(t, target, "ORIGINAL")
	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code := runSyncedProbe(t, "mmap_after_forbid", cg, target, func() {
		if e := l.Forbid(cgID, ino); e != nil {
			t.Fatalf("forbid: %v", e)
		}
	})
	if code != blockedEPERM {
		t.Fatalf("mmap-shared-writable acquire after forbid: want blocked(EPERM)=%d, got exit %d", blockedEPERM, code)
	}
}

// TestB15PreForbidMmapStoreResidual PINS a KNOWN-OPEN, honestly-ledgered residual
// (B15): a writable MAP_SHARED mapping established BEFORE the forbid lands lets a
// syscall-free memory store corrupt the file afterward. No LSM hook can see a CPU
// store, so this is irreducible at the LSM layer (closing it needs PTE write-
// protection / a different mechanism). The test asserts the store SUCCEEDS so the
// gap can never be silently re-claimed as "closed" by an overclaim. Mitigation:
// warm forbids BEFORE the agent maps the file (born into a pre-warmed cgroup).
func TestB15PreForbidMmapStoreResidual(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	cg := mkCgroup(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "ledger.db")
	ino := writeFile(t, target, "ORIGINAL-LEDGER-CONTENT-PADDED-LONG-ENOUGH")
	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code := runSyncedProbe(t, "mmap_store_preforbid", cg, target, func() {
		if e := l.Forbid(cgID, ino); e != nil {
			t.Fatalf("forbid: %v", e)
		}
	})
	b, _ := os.ReadFile(target)
	corrupted := strings.HasPrefix(string(b), "PWNED")
	if code == 0 && corrupted {
		return // residual confirmed present + honestly ledgered (B15) — expected
	}
	t.Fatalf("B15 residual changed: probe exit=%d corrupted=%v. If the store is now "+
		"BLOCKED this is GOOD — close B15 in the ledger and flip this test; do not "+
		"leave the ledger overclaiming.", code, corrupted)
}
