# Enforcement bypass corpus (frozen, monotone-growing)

This directory is the **frozen, version-controlled, monotone-growing** corpus of named
bypass attempts against Tex's local-action enforcement leg (the BPF-LSM PEP in
`pep/kernel/`). It is the canonical adversarial reference the independent verifier
re-runs at every gate.

## Rules (binding)
- **Each `expect:"blocked"` case MUST fail-closed** (the forbidden action does not happen).
  For content-mutation ops, the file's content must also survive intact.
- **`expect:"allowed"` cases are controls** — they must SUCCEED (proving no false-deny on
  legitimate work, e.g. reading an immutable file).
- **`expect:"open"` cases are KNOWN, LEDGERED residuals** — the runner records their outcome
  honestly and does NOT fail; each carries its `ledger` id and the deploy/research step to
  close it. This prevents silent truncation: a residual is surfaced, never hidden.
- **The corpus may only GROW.** Removing or weakening a `blocked` case (or flipping it to
  `open` to make a run pass) is an automatic verifier FAIL. New bypass classes are appended.

## Schema (`corpus.jsonl`, one JSON object per line)
`id` · `ledger` (residual-ledger row in `ENFORCEMENT_LAYER_LOOP.md`) · `op` (the probe op) ·
`target` (`file`|`binary`) · `expect` (`blocked`|`allowed`|`open`) · `content_survives` ·
`adversary` (L0..L4) · `note`.

## Runner
`pep/kernel/localpep/bypass_corpus_test.go` (`TestBypassCorpus`) reads this file (path via
`TEX_BYPASS_CORPUS`, else discovered by walking up from the test cwd), arms the loader,
enrolls a cgroup, and drives each case from a REAL re-exec'd child process issuing the REAL
syscall. Run as root on a kernel with `bpf` in the active LSM list:

    TEX_BYPASS_CORPUS=$PWD/tests/enforcement/bypass_corpus/corpus.jsonl \
      sudo <prebuilt localpep.test> -test.run=TestBypassCorpus -test.v
