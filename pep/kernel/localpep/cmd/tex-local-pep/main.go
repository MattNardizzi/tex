// SPDX-License-Identifier: Apache-2.0
//
// tex-local-pep — the local-action enforcement loader binary. Loads + attaches
// the GPL BPF-LSM hooks, enrolls an agent cgroup, warms the in-kernel forbid-set
// from FORBID verdicts, and holds the LSM links alive. Used for the real-process
// end-to-end proof and the manual kill-switch demo (S1); the live-PDP feed and
// permit verification are wired in later slices.
//
// Default-OFF: with no --enroll/--forbid the process attaches the hooks but
// governs nobody (maps empty) — bit-for-bit inert.
//
//	arm   --cgroup <cgroup2-path> --forbid <file> [--forbid <file> ...]
//	      attaches, enrolls the cgroup, forbids each file's inode, then blocks.
//	      SIGUSR1 -> kill-switch (Disarm: un-enroll all, instant, governs no one).
//	      SIGINT/SIGTERM -> full teardown (detach).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tex.systems/pep/kernel/localpep"
)

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 || os.Args[1] != "arm" {
		fmt.Fprintln(os.Stderr, "usage: tex-local-pep arm --cgroup <path> [--forbid <file> ...]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("arm", flag.ExitOnError)
	cgroup := fs.String("cgroup", "", "cgroup v2 directory path of the agent to govern")
	var forbid multiFlag
	fs.Var(&forbid, "forbid", "file path to forbid (delete) for the enrolled cgroup; repeatable")
	_ = fs.Parse(os.Args[2:])

	l, err := localpep.Open()
	if err != nil {
		log.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	log.Printf("tex-local-pep: LSM hooks attached (governing nobody yet)")

	var cgID uint64
	if *cgroup != "" {
		cgID, err = l.Enroll(*cgroup)
		if err != nil {
			log.Fatalf("enroll %s: %v", *cgroup, err)
		}
		log.Printf("enrolled cgroup %s (id=%d)", *cgroup, cgID)
		for _, f := range forbid {
			ino, err := localpep.InodeOf(f)
			if err != nil {
				log.Fatalf("resolve %s: %v", f, err)
			}
			if err := l.Forbid(cgID, ino); err != nil {
				log.Fatalf("forbid %s: %v", f, err)
			}
			log.Printf("FORBID delete: %s (inode=%d) for cgroup %d", f, ino, cgID)
		}
	}
	n, _ := l.EnrolledCount()
	log.Printf("ARMED: %d cgroup(s) governed. SIGUSR1=kill-switch, SIGINT=teardown.", n)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	for s := range sig {
		switch s {
		case syscall.SIGUSR1:
			cleared, err := l.Disarm()
			if err != nil {
				log.Printf("kill-switch error: %v", err)
				continue
			}
			log.Printf("KILL-SWITCH: disarmed, %d cgroup(s) un-enrolled, host now ungoverned", cleared)
		default:
			log.Printf("teardown on %s", s)
			return
		}
	}
}
