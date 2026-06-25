// SPDX-License-Identifier: Apache-2.0
//
// Frozen bypass-corpus runner. Reads the version-controlled corpus
// (tests/enforcement/bypass_corpus/corpus.jsonl), arms the local-action PEP, and
// drives each named bypass from a REAL re-exec'd child issuing the REAL syscall.
// `blocked` cases must fail-closed (+ content intact); `allowed` controls must
// succeed (no false-deny); `open` cases are known ledgered residuals — recorded,
// not failed. Run as root with `bpf` in the active LSM list.
package localpep

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type corpusCase struct {
	ID              string `json:"id"`
	Ledger          string `json:"ledger"`
	Op              string `json:"op"`
	Target          string `json:"target"` // "file" | "binary"
	Expect          string `json:"expect"` // "blocked" | "allowed" | "open"
	ContentSurvives bool   `json:"content_survives"`
	Adversary       string `json:"adversary"`
	Note            string `json:"note"`
}

func findCorpus(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("TEX_BYPASS_CORPUS"); p != "" {
		return p
	}
	// walk up from cwd looking for the canonical corpus
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "tests", "enforcement", "bypass_corpus", "corpus.jsonl")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("corpus.jsonl not found (set TEX_BYPASS_CORPUS); skipping")
	return ""
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	f, err := os.Open(findCorpus(t))
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()
	var cases []corpusCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		var c corpusCase
		if err := json.Unmarshal(line, &c); err != nil {
			t.Fatalf("parse corpus line %q: %v", string(line), err)
		}
		cases = append(cases, c)
	}
	return cases
}

func TestBypassCorpus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (BPF-LSM attach)")
	}
	const payload = "FROZEN-CORPUS-IRREPLACEABLE-PAYLOAD"
	cases := loadCorpus(t)
	if len(cases) == 0 {
		t.Fatal("empty corpus")
	}

	cg := mkCgroup(t)
	l, err := Open()
	if err != nil {
		t.Fatalf("open loader: %v", err)
	}
	defer l.Close()
	cgID, err := l.Enroll(cg)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	var nBlocked, nAllowed, nResidual int
	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, c.ID+".dat")
			if c.Target == "binary" {
				if err := copyFile("/bin/true", target, 0o755); err != nil {
					t.Fatalf("stage binary: %v", err)
				}
			} else {
				if err := os.WriteFile(target, []byte(payload), 0o644); err != nil {
					t.Fatalf("stage file: %v", err)
				}
			}
			ino, err := InodeOf(target)
			if err != nil {
				t.Fatalf("inode: %v", err)
			}
			if err := l.Forbid(cgID, ino); err != nil {
				t.Fatalf("forbid: %v", err)
			}
			defer l.Unforbid(cgID, ino)

			src := ""
			if c.Op == "rename_onto" {
				src = filepath.Join(dir, "attacker.src")
				_ = os.WriteFile(src, []byte("attacker"), 0o644)
			}
			code := runProbe(t, c.Op, cg, target, src)

			switch c.Expect {
			case "blocked":
				if code != blockedEPERM {
					t.Fatalf("[%s %s] expected BLOCKED(EPERM=%d), got exit %d — BYPASS! (%s)",
						c.ID, c.Ledger, blockedEPERM, code, c.Note)
				}
				if c.Target == "file" && c.ContentSurvives {
					b, err := os.ReadFile(target)
					if err != nil || string(b) != payload {
						t.Fatalf("[%s] blocked but content not intact (err=%v) — irreversible loss", c.ID, err)
					}
				}
				nBlocked++
			case "allowed":
				if code != 0 {
					t.Fatalf("[%s] control expected ALLOWED(0), got %d — false-deny on legitimate op", c.ID, code)
				}
				nAllowed++
			case "open":
				// Known, ledgered residual — record honestly, do not fail.
				t.Logf("RESIDUAL [%s %s] adversary=%s outcome=exit%d — %s", c.ID, c.Ledger, c.Adversary, code, c.Note)
				nResidual++
			default:
				t.Fatalf("[%s] unknown expect=%q", c.ID, c.Expect)
			}
		})
	}
	t.Logf("BYPASS CORPUS: %d blocked(fail-closed), %d allowed-controls, %d ledgered-residuals (of %d cases)",
		nBlocked, nAllowed, nResidual, len(cases))
}
