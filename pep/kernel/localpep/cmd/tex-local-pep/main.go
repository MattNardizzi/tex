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
	"strings"
	"syscall"
	"time"

	"tex.systems/pep/kernel/localpep"
)

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "arm":
		runArm()
	case "serve":
		runServe()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  tex-local-pep arm   --cgroup <path> [--forbid <file> ...]")
	fmt.Fprintln(os.Stderr, "  tex-local-pep serve --feed <file|url> --secret-env <ENV> --agent id=/cgroup/path [--agent ...] [--poll]")
	os.Exit(2)
}

// runServe consumes the HMAC-signed local-forbid-set the live PDP emits
// (LocalForbidSource.signed_response), verifies it, and warms the in-kernel deny
// map — the loader is the privilege-separated enforcement component the agent
// cannot reach. SIGUSR1 = kill-switch; SIGINT = teardown.
func runServe() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	feed := fs.String("feed", "", "signed local-forbid-set source (file path or http(s) URL)")
	secretEnv := fs.String("secret-env", "TEX_LOCAL_PEP_SECRET", "env var holding the shared HMAC secret")
	poll := fs.Bool("poll", false, "keep polling the feed (else apply once and hold)")
	apiKeyEnv := fs.String("api-key-env", "", "env var holding the x-tex-api-key the PDP feed route requires (optional)")
	var agents multiFlag
	fs.Var(&agents, "agent", "agent_id=/cgroup/v2/path mapping; repeatable")
	_ = fs.Parse(os.Args[2:])

	secret := os.Getenv(*secretEnv)
	if *feed == "" || secret == "" {
		log.Fatalf("serve: --feed and a non-empty $%s are required", *secretEnv)
	}
	apiKey := ""
	if *apiKeyEnv != "" {
		apiKey = os.Getenv(*apiKeyEnv)
	}
	agentCgroup := map[string]string{}
	for _, a := range agents {
		id, path, ok := strings.Cut(a, "=")
		if !ok {
			log.Fatalf("serve: bad --agent %q (want id=/cgroup/path)", a)
		}
		agentCgroup[id] = path
	}

	l, err := localpep.Open()
	if err != nil {
		log.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	log.Printf("tex-local-pep serve: LSM hooks attached; consuming %s", *feed)

	epoch, applied, skipped, err := l.PollFeed(*feed, []byte(secret), agentCgroup, 0, apiKey)
	if err != nil {
		log.Fatalf("apply feed: %v", err)
	}
	log.Printf("APPLIED feed epoch=%d: %d forbids warmed, %d skipped", epoch, applied, skipped)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGUSR1 {
				cleared, _ := l.Disarm()
				log.Printf("KILL-SWITCH: disarmed, %d cgroup(s) un-enrolled", cleared)
				continue
			}
			log.Printf("teardown on %s", s)
			return
		case <-ticker.C:
			if !*poll {
				continue
			}
			e, a, sk, perr := l.PollFeed(*feed, []byte(secret), agentCgroup, epoch, apiKey)
			if perr != nil {
				log.Printf("poll: %v (keeping existing denies — revoke-wins)", perr)
				continue
			}
			if e != epoch || a > 0 {
				log.Printf("re-applied feed epoch=%d: %d warmed, %d skipped", e, a, sk)
				epoch = e
			}
		}
	}
}

func runArm() {
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
