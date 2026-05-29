# Tex Audit — Index

> Generated: 2026-05-27
> All claims in this audit are derived from `grep` and AST analysis of the source code.
> No claims from any documentation file (existing or deleted) were used as input.

## Contents

```
audit/
├── 00_INDEX.md                              ← this file
├── EXECUTIVE_SUMMARY.md                     ← headline numbers, action plan
│
├── canonical/                               ← documents derived purely from code
│   ├── ARCHITECTURE.md                      ← what Tex actually is
│   └── README.md                            ← the README that ships at repo root
│
├── orphans/
│   ├── ORPHAN_REGISTRY.md                   ← every file's wiring status
│   ├── code_evidence_registry.json          ← machine-readable per-file verdicts
│   └── build_code_evidence_registry.py      ← re-runnable analyzer
│
└── contradictions/
    └── CONTRADICTIONS.md                    ← contradictions between code and its own docstrings
```

## Methodology

1. AST-parse every `.py` file in `src/tex/`, `tests/`, `scripts/`, `sdks/`.
2. Build a directed import graph. For each file, record what it imports. Add transitive edges through `__init__.py` files because importing `tex.X.Y` triggers `tex.X.__init__.py` loading.
3. BFS-reach from `src/tex/main.py` → the **WIRED** set.
4. BFS-reach from every test file → the **TEST_REACHABLE** set.
5. BFS-reach from every script/SDK file → the **SCRIPT_REACHABLE** set.
6. Classify each file by which reachable sets it appears in.

## Key facts

| | |
|---|---|
| Total `src/tex/` Python files | 462 |
| WIRED (reachable from main.py) | 377 |
| TEST_ONLY | 47 |
| TEST_AND_SCRIPT_ONLY | 9 |
| FULL_ORPHAN | 29 |

## Re-running the analysis

```bash
cd audit/orphans
python3 build_code_evidence_registry.py
```

The script writes `code_evidence_registry.json` with the full per-file verdict.
