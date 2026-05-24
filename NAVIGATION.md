# NAVIGATION

Read this first. It tells you which doc answers which question. The
goal of the documentation system is **transparency** — nothing buried,
nothing assumed, every claim verifiable, every package mapped.

---

## The documents

| File | What it is | When to read |
|---|---|---|
| **`README.md`** | Top-of-repo overview, quickstart, smoke test, honest state | First time in the repo; setting up locally |
| **`NAVIGATION.md`** | This file — the doc map | When you forget which doc does what |
| **`TIER_OWNERSHIP.md`** | Every subpackage tagged with dev tier (A/B/C/D) + capability tier | When you change a file and need to know its blast radius |
| **`CAPABILITY_TIERS.md`** | The five capability tiers defined precisely (Discovery, Identity, Monitoring, Governance, Evidence) | When you need the product-facing view of what Tex does |
| **`MODULES.md`** | Per-subpackage cards (purpose, key files, public interface, verify) for Tier A/B packages | When you don't know what a package actually does |
| **`RUNBOOKS.md`** | Procedures for the common change scenarios | When you changed something and want to know what to test |
| **`STUB_REGISTRY.md`** | Every unfinished site with "blocks current claim?" column | When triaging what to finish next |
| **`KNOWN_BUGS.md`** | Verified defects with sev rating, reproduction, fix | Day-one onboarding; before any demo |
| **`CLAIMS_CURRENT.md`** | Claims that hold up today — outreach copy must not exceed this | Prepping a pitch, customer call, blog post |
| **`CLAIMS_HISTORY.md`** | Historical per-thread log of when each capability landed | Writing release notes; build-log narrative |
| **`CLAIMS_ASPIRATIONAL.md`** | Claims tied to unfinished work; not yet defensible | Roadmap planning; deciding what to finish next |
| **`FRONTIER_GTM.md`** | Active dual-ICP go-to-market positioning | When prepping outreach by buyer type |
| **`FRONTIER_ROADMAP.md`** | Forward-looking technical roadmap | When planning the next thread of work |
| **`docs/history/`** | Archived per-thread development logs | Tracing why a decision was made |

Plus the tool:

| File | What it does |
|---|---|
| **`scripts/audit.py`** | CLI navigation tool. Run `python scripts/audit.py <package>` for full context on any subpackage |

---

## When to read what — by situation

| Situation | Read |
|---|---|
| New to this repo | `README.md` → `NAVIGATION.md` → `TIER_OWNERSHIP.md` |
| Something broke and I don't know where | `RUNBOOKS.md` → Runbook 4 ("Something broke...") |
| I changed a file and want to know what to test | `RUNBOOKS.md` → Runbook 1 or 2 |
| I want to know what's in a package | `python scripts/audit.py <package>` |
| I want to know what's still unfinished | `STUB_REGISTRY.md` |
| I want to know what bugs to expect | `KNOWN_BUGS.md` |
| I want to know if a demo path is shippable | `RUNBOOKS.md` → Runbook 5 |
| I added a new package | `RUNBOOKS.md` → Runbook 6 |
| Prepping outreach copy | `CLAIMS_CURRENT.md` + `FRONTIER_GTM.md` |
| Roadmap planning | `CLAIMS_ASPIRATIONAL.md` + `STUB_REGISTRY.md` |
| Understanding the buyer-facing structure | `CAPABILITY_TIERS.md` |

---

## Quick commands

```bash
# Get full context on any package
python scripts/audit.py engine
python scripts/audit.py pitch

# List everything
python scripts/audit.py --list

# Just Tier A packages
python scripts/audit.py --tier A

# Just Execution Governance packages (the capability tier)
python scripts/audit.py --capability E/G

# Where's all the unfinished work?
python scripts/audit.py --stub-summary

# Find tier-violation imports (Tier A → Tier C/D)
python scripts/audit.py --check-deps

# CI gate: fail if any package lacks a tier assignment
python scripts/audit.py --check-categorization

# All P1 TODOs (not enumerated in STUB_REGISTRY.md)
python scripts/audit.py --list-p1

# Refresh data after code changes
python scripts/audit.py --rebuild-data
```

---

## Maintenance rules

These docs are only valuable if they stay current. When code changes:

| If you... | Then update... |
|---|---|
| Add a new subpackage | `TIER_OWNERSHIP.md` + (if A/B) `MODULES.md` |
| Finish a stub | `STUB_REGISTRY.md` (remove entry) |
| Land a new capability | `CLAIMS_CURRENT.md` (add entry) + `CLAIMS_ASPIRATIONAL.md` (remove if moved) |
| Discover a defect | `KNOWN_BUGS.md` (add entry with verification status) |
| Fix a defect | `KNOWN_BUGS.md` (move to Resolved) |
| Change a package's behavior | the `MODULES.md` card for that package |
| Reorganize the tree | all of the above + run `python scripts/audit.py --rebuild-data` |

Stale docs are worse than no docs. If you don't have time to update,
at least add a `STALE:` marker to the section that's out of date.

---

## Current state (as of May 2026 audit)

**Codebase:**
- 45 active subpackages, ~453 Python files, ~133K LOC across `src/tex/`
- 202 test files, **~3,653 tests passing on a clean install in ~3 minutes**
- 23 failures (22 missing optional crypto deps, 1 real product bug)
- 1 collection error (broken parametrize — `KNOWN_BUGS.md` Bug #1)

**Tiers:**
- **Dev Tier A:** 14 packages, ~50K LOC — product core
- **Dev Tier B:** 3 packages (api, pitch, discovery) — buyer-facing
- **Dev Tier C:** 27 packages, ~63K LOC — R&D / future-proofing
- **Dev Tier D:** compliance (mixed) + `_pending/interop/` (stubs)

**Capability distribution:**
- **Execution Governance** (E/G): 12 packages — the decision pipeline
- **Evidence / Recording** (E/R): 12 packages — signed artifacts
- **Monitoring / Observability** (M/O): 5 packages
- **Identity / Access** (I/A): 3 packages
- **Discovery / Inventory** (D/I): 1 package + IFC overlap
- **Cross-cutting kernel:** 13 packages

**Stubs and unfinished work:**
- 30 `NotImplementedError` sites (down from 36 after moving `interop/` to `_pending/`)
- 67 P0 TODOs (but many are stale `[done]` tags; needs cleanup pass)
- 111 P1 TODOs

**Known bugs:** 8 documented in `KNOWN_BUGS.md` (3 Sev 1, 4 Sev 2, 1 Sev 3).

**Architectural debt:** 17 Tier A → Tier C dependency violations
(`python scripts/audit.py --check-deps`). Some are legitimate (evidence
signing through pqcrypto); some indicate mis-tiered packages.

---

## What this system replaces

Before this documentation pass, a typical change to Tex looked like:

1. Make the change.
2. Spend 4 hours running every test, looking at every file, trying to
   figure out what blast radius the change had.
3. Maybe miss something, ship a regression.
4. Repeat.

After:

1. Make the change.
2. Look up the file in `TIER_OWNERSHIP.md` → know the tier.
3. Run the matching runbook from `RUNBOOKS.md` → 1-15 minutes.
4. Done.

The 4-hour audit cost was being paid because there was no map. The map
now exists. Use it.
