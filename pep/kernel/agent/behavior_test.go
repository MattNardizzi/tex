// SPDX-License-Identifier: Apache-2.0
//
//go:build linux_ebpf_vm

// behavior_test.go — in-kernel ENFORCEMENT tests for the floor.
//
// Root-only, Linux-VM-only (build tag linux_ebpf_vm), same as load_test.go.
// These prove the hooks actually DO their job at the syscall boundary against a
// real child process placed inside a governed cgroup-v2 directory:
//
//	(a) FORBID block      — a dst written FORBID into verdict_cache is refused
//	                        in-kernel (connect fails) for a child in the cgroup.
//	(b) redirect + recover — a non-FORBID dst is rewritten to the local proxy
//	                        port AND the orig-dst is recoverable over the
//	                        src-tuple map (the keystone the proxy queries).
//	(c) UDP fail-closed   — with udp_proxy_port unset, a UDP sendmsg is dropped.
//
// The child is THIS test binary re-exec'd with TEX_TEST_CHILD set (see
// TestMain): it joins the governed cgroup by writing its own pid to
// cgroup.procs, then performs one controlled syscall and reports the errno via
// exit code. Running the syscall in a separate process is what makes the cgroup
// attach actually mediate it — the parent test process is NOT in the cgroup.

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Child-mode exit codes (errno-ish, kept small & distinct from Go's defaults).
const (
	childOK          = 0  // syscall succeeded
	childRefused     = 10 // ECONNREFUSED
	childPerm        = 11 // EPERM / EACCES (fail-closed drop)
	childOtherErr    = 12 // some other error (printed to stderr)
	childBadArgs     = 13
	childUnreachable = 14 // ENETUNREACH / EHOSTUNREACH
)

// TestMain dispatches: when TEX_TEST_CHILD is set we are the re-exec'd child and
// run the requested syscall instead of the test suite.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TEX_TEST_CHILD"); mode != "" {
		os.Exit(runChild(mode))
	}
	os.Exit(m.Run())
}

// runChild performs one syscall described by env and returns an exit code that
// classifies the resulting errno. It is invoked in a process already joined to
// the governed cgroup (the parent wrote our pid to cgroup.procs before exec).
func runChild(mode string) int {
	dst := os.Getenv("TEX_TEST_DST") // "ip:port"
	switch mode {
	case "connect_tcp":
		return childConnectTCP(dst)
	case "sendto_udp":
		return childSendUDP(dst)
	default:
		fmt.Fprintf(os.Stderr, "child: unknown mode %q\n", mode)
		return childBadArgs
	}
}

func classifyErrno(err error) int {
	if err == nil {
		return childOK
	}
	var se syscall.Errno
	if !errnoOf(err, &se) {
		fmt.Fprintf(os.Stderr, "child: non-errno error: %v\n", err)
		return childOtherErr
	}
	switch se {
	case syscall.ECONNREFUSED:
		return childRefused
	case syscall.EPERM, syscall.EACCES:
		return childPerm
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
		return childUnreachable
	default:
		fmt.Fprintf(os.Stderr, "child: errno=%d (%v)\n", int(se), se)
		return childOtherErr
	}
}

// errnoOf unwraps a (possibly wrapped) syscall.Errno.
func errnoOf(err error, out *syscall.Errno) bool {
	for err != nil {
		if se, ok := err.(syscall.Errno); ok {
			*out = se
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			continue
		}
		return false
	}
	return false
}

func childConnectTCP(dst string) int {
	// A short timeout so a redirect to a dead port returns promptly rather than
	// hanging the test; the cgroup hook fires synchronously at connect().
	c, err := net.DialTimeout("tcp", dst, 2*time.Second)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok {
			return classifyErrno(ne.Err)
		}
		return classifyErrno(err)
	}
	_ = c.Close()
	return childOK
}

func childSendUDP(dst string) int {
	// Use an UNCONNECTED UDP socket so the sendmsg4 hook (not connect4) mediates
	// the datagram: build the socket by hand and sendto() the destination.
	udpAddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return childBadArgs
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return classifyErrno(err)
	}
	defer syscall.Close(fd)
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], udpAddr.IP.To4())
	sa.Port = udpAddr.Port
	// Sendto on an unconnected UDP socket triggers cgroup/sendmsg4. A
	// fail-closed drop surfaces as EPERM from sendto(2).
	if err := syscall.Sendto(fd, []byte("tex-probe"), 0, &sa); err != nil {
		return classifyErrno(err)
	}
	return childOK
}

// ---- shared harness ------------------------------------------------------- //

// loopbackProxyPort is the fake "tex-proxy" TCP port the redirect test points
// the config at; we run a real listener there so a redirected connect SUCCEEDS
// (proving the rewrite landed) and recover the orig-dst the proxy would query.
const loopbackProxyPort = 18088

// attachAll loads the object, writes a config map, and attaches all five hooks
// to a fresh governed cgroup. Returns the cgroup path and the loaded objects.
func attachAll(t *testing.T, cfg texConfig) (string, *texRedirectObjects) {
	t.Helper()
	objs := loadObjs(t)
	if err := objs.TexCfg.Put(uint32(0), cfg); err != nil {
		t.Fatalf("write config map: %v", err)
	}
	cg := newGovernedCgroup(t)
	specs := []struct {
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, objs.TexConnect4},
		{ebpf.AttachCGroupInet6Connect, objs.TexConnect6},
		{ebpf.AttachCGroupUDP4Sendmsg, objs.TexSendmsg4},
		{ebpf.AttachCGroupUDP6Sendmsg, objs.TexSendmsg6},
		{ebpf.AttachCGroupSockOps, objs.TexSockOps},
	}
	for _, s := range specs {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cg, Attach: s.attach, Program: s.prog})
		if err != nil {
			t.Fatalf("attach at %s: %v", cg, err)
		}
		t.Cleanup(func() { l.Close() })
	}
	return cg, objs
}

// runInCgroup re-execs this test binary as a child that (1) joins cgroup cg by
// writing its own pid to cgroup.procs, then (2) runs the named syscall mode
// against dst. Returns the child's classified exit code.
func runInCgroup(t *testing.T, cg, mode, dst string) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		"TEX_TEST_CHILD="+mode,
		"TEX_TEST_DST="+dst,
	)
	cmd.Stderr = os.Stderr
	// Join the cgroup via CgroupFD on the child's clone (kernel >= 5.7). This is
	// race-free: the child starts already inside the governed cgroup, so its very
	// first syscall is mediated. Fallback below for older kernels.
	if joinViaClone(cmd, cg) {
		// joined at clone time
	} else if err := writeProcsAfterStart(t, cmd, cg); err != nil {
		t.Fatalf("place child in cgroup: %v", err)
	}
	err = cmd.Run()
	if err == nil {
		return childOK
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatalf("run child: %v", err)
	return -1
}

// joinViaClone uses clone3 CLONE_INTO_CGROUP via SysProcAttr.CgroupFD when the
// kernel supports it, so the child is born inside the cgroup. Returns false if
// unsupported (caller falls back to writing cgroup.procs).
func joinViaClone(cmd *exec.Cmd, cg string) bool {
	f, err := os.Open(cg)
	if err != nil {
		return false
	}
	// NOTE: we intentionally leak f until the command runs; close after.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(f.Fd()),
	}
	// Keep f alive past Run by stashing it on the cmd via a closure in Cancel.
	cmd.Cancel = func() error { f.Close(); return nil }
	// Best-effort close after the process exits is handled by the GC/Cancel; the
	// fd is dup'd into the child at clone, so an early close after Start is fine.
	return true
}

// writeProcsAfterStart is the pre-5.7 fallback: start the child stopped-ish and
// write its pid into cgroup.procs. We approximate by starting then immediately
// writing the pid; a tiny window exists but the child's blocking step is the
// syscall under test, which it reaches after this returns.
func writeProcsAfterStart(t *testing.T, cmd *exec.Cmd, cg string) error {
	t.Helper()
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	return os.WriteFile(cg+"/cgroup.procs", []byte(strconv.Itoa(pid)), 0)
}

// ---- (a) FORBID is blocked in-kernel -------------------------------------- //

func TestForbidBlockedInKernel(t *testing.T) {
	requireRoot(t)
	// Config: a real proxy port (so non-forbidden traffic could redirect), but
	// this test forbids the dst outright so it should die before redirect.
	cfg := texConfig{
		ProxyIP4:  ipToBE(net.ParseIP("127.0.0.1")),
		ProxyPort: htons(loopbackProxyPort),
	}
	cg, objs := attachAll(t, cfg)

	// Forbid 127.0.0.2:9 (discard-ish; an address we control on loopback).
	const forbidIP = "127.0.0.2"
	const forbidPort = 9
	k := dstKey{IP4: ipToBE(net.ParseIP(forbidIP)), Port: htons(forbidPort)}
	if err := objs.VerdictCache.Put(k, verdictForbid); err != nil {
		t.Fatalf("write FORBID entry: %v", err)
	}

	dst := net.JoinHostPort(forbidIP, strconv.Itoa(forbidPort))
	code := runInCgroup(t, cg, "connect_tcp", dst)

	// The connect hook returns 0 for a FORBID dst => the kernel refuses the
	// connect. cilium/the kernel surfaces a cgroup connect deny as EPERM (most
	// kernels) or ECONNREFUSED; either is a successful in-kernel block.
	switch code {
	case childPerm, childRefused:
		t.Logf("FORBID dst blocked in-kernel (child exit %d = %s)", code, codeName(code))
	case childOK:
		t.Fatalf("FORBID dst was NOT blocked: child connect succeeded (exit 0)")
	default:
		t.Fatalf("FORBID block: unexpected child exit %d (%s); expected EPERM/ECONNREFUSED",
			code, codeName(code))
	}
}

// ---- (b) non-FORBID redirect + orig-dst recovery -------------------------- //

func TestRedirectAndOrigDstRecovery(t *testing.T) {
	requireRoot(t)

	// Stand up a real TCP listener on the proxy port. A redirected connect will
	// land here and SUCCEED — proving the dst rewrite happened — and the
	// accepted peer's src tuple is what we feed to the orig-dst lookup.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(loopbackProxyPort)))
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		srcIP   string
		srcPort int
	}
	gotCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ra := c.RemoteAddr().(*net.TCPAddr) // the agent's src tuple
		gotCh <- accepted{srcIP: ra.IP.String(), srcPort: ra.Port}
		// Drain briefly so the child's Dial completes cleanly.
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()

	cfg := texConfig{
		ProxyIP4:  ipToBE(net.ParseIP("127.0.0.1")),
		ProxyPort: htons(loopbackProxyPort),
	}
	cg, objs := attachAll(t, cfg)

	// The REAL upstream the child thinks it is reaching. Not forbidden, so it is
	// redirected. Pick a non-loopback-ish but routable-on-lo target; the connect
	// never actually reaches it because the dst is rewritten to the proxy.
	const realIP = "203.0.113.7" // TEST-NET-3, guaranteed not live
	const realPort = 443
	realDst := net.JoinHostPort(realIP, strconv.Itoa(realPort))

	code := runInCgroup(t, cg, "connect_tcp", realDst)
	if code != childOK {
		t.Fatalf("redirected connect did not succeed: child exit %d (%s) — the rewrite to the proxy should have made this connect land on our listener",
			code, codeName(code))
	}

	var got accepted
	select {
	case got = <-gotCh:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy listener never accepted a redirected connection")
	}
	t.Logf("redirect landed on proxy from src %s:%d", got.srcIP, got.srcPort)

	// Now the keystone: the proxy would query the loader's UDS with this src
	// tuple to recover the real upstream. We call lookupOrigDst directly against
	// the live src_to_orig map (sockops re-keyed it at ACTIVE_ESTABLISHED).
	// Retry briefly: sockops fires asynchronously right after the handshake.
	var resp origDstResp
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp = lookupOrigDst(objs.SrcToOrig, origDstReq{
			SrcIP:   got.srcIP,
			SrcPort: got.srcPort,
			Family:  4,
		})
		if resp.Error == "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp.Error != "" {
		t.Fatalf("orig-dst NOT recovered for src %s:%d: %q (sockops should have re-keyed src_to_orig)",
			got.srcIP, got.srcPort, resp.Error)
	}
	if resp.IP != realIP || resp.Port != realPort {
		t.Fatalf("orig-dst MISMATCH: got %s:%d, want %s:%d", resp.IP, resp.Port, realIP, realPort)
	}
	t.Logf("orig-dst recovered correctly: %s:%d -> %s:%d", got.srcIP, got.srcPort, resp.IP, resp.Port)
}

// ---- (c) UDP fail-closed when no UDP proxy is configured ------------------ //

func TestUDPFailClosedWithoutProxy(t *testing.T) {
	requireRoot(t)
	// udp_proxy_port unset (0) => sendmsg4 drops non-FORBID UDP (fail-closed).
	cfg := texConfig{
		ProxyIP4:     ipToBE(net.ParseIP("127.0.0.1")),
		ProxyPort:    htons(loopbackProxyPort),
		UDPProxyPort: 0, // the point of the test
	}
	cg, _ := attachAll(t, cfg)

	// Any non-forbidden UDP dst; the datagram should be dropped (EPERM) because
	// there is no UDP proxy to faithfully mediate connectionless UDP.
	const udpIP = "203.0.113.9"
	const udpPort = 4242
	dst := net.JoinHostPort(udpIP, strconv.Itoa(udpPort))

	code := runInCgroup(t, cg, "sendto_udp", dst)
	switch code {
	case childPerm:
		t.Logf("UDP fail-closed: sendto dropped with EPERM (child exit %d)", code)
	case childOK:
		t.Fatalf("UDP was NOT fail-closed: sendto succeeded with no UDP proxy configured")
	default:
		t.Fatalf("UDP fail-closed: unexpected child exit %d (%s); expected EPERM", code, codeName(code))
	}
}

func codeName(c int) string {
	switch c {
	case childOK:
		return "OK"
	case childRefused:
		return "ECONNREFUSED"
	case childPerm:
		return "EPERM/EACCES"
	case childOtherErr:
		return "other-error"
	case childBadArgs:
		return "bad-args"
	case childUnreachable:
		return "ENETUNREACH/EHOSTUNREACH"
	default:
		return "exit=" + strconv.Itoa(c)
	}
}

// silence unused-import vetting if strings is not referenced in some build perms.
var _ = strings.TrimSpace
