# Thread 2 changelog

Thread 2 — Fix the test suite on a clean install. Per Section 14 of the
TEX — CANONICAL TRUTH DOCUMENT (May 22, 2026), this thread's objective
is to make `pip install -e .` work on a fresh machine and the full test
suite go green.

Date: May 22, 2026.

---

## 1. What this thread changed

### 1.1 `pyproject.toml` — relaxed Python version pin

- `requires-python = ">=3.12"` → `requires-python = ">=3.11"`.
- `[tool.ruff] target-version = "py312"` → `"py311"` (kept in lockstep
  to prevent 3.12-only syntax from sneaking into the codebase via
  future PRs that wouldn't get caught by ruff).
- `[tool.mypy] python_version = "3.12"` → `"3.11"` (same reason —
  internal consistency).

**Why this is safe:** verified by `ast.parse(..., feature_version=(3, 11))`
against **every** `.py` file in the repo:
- 463 files under `src/` parse cleanly under 3.11 grammar.
- 234 files under `tests/` parse cleanly under 3.11 grammar.
- 0 failures total. No PEP 695 type parameter syntax, no f-string quote
  reuse, no `type X = ...` aliases — none of the syntactic features
  introduced in Python 3.12 are used anywhere.
- Stdlib API usage: `from datetime import UTC` and `from enum import
  StrEnum` are the most recent stdlib features used, both introduced
  in 3.11. Compatible with `>=3.11`.

Script used for verification: `/home/claude/check_311_compat.py`
(out-of-tree; provided in the chat trace for re-running).

### 1.2 `KNOWN_BUGS.md` — Bug #1 moved to Resolved

Marked Bug #1 (Broken parametrize in kernel MCP test) `✅ RESOLVED`
inline, following the established pattern from Bug #2. Added a brief
pointer in the `## Resolved` section.

The fix had already shipped in the codebase before this thread opened:
`tests/governance/test_kernel_mcp.py:351` is `("sk_test_example_key",
"stripe_key")` — a proper 2-tuple. Collection of the test module
succeeds.

**Note on canonical-doc accuracy:** TEX_CANONICAL.md Section 17 row 4
prescribed the second tuple member as `"openai_anthropic"`. The fix
that actually shipped used `"stripe_key"`, which is the correct family
name for `sk_test_*` keys per Stripe API documentation. The follow-on
coverage gap that fix exposed (`stripe_key` family not in
`_SECRET_PATTERNS`) is already documented as Resolved under "Stripe
key family detection gap (May 21, 2026)". This thread updated the Bug
#1 entry to reflect what was actually fixed, not what the canonical
doc prescribed.

---

## 2. What this thread did NOT change

Per the canonical doc's Section 5 ("missing dependencies in
`pyproject.toml`") — this thread did **not** touch the dependencies
list. Thread 1's changelog already reported that the deps were
already present:

> ### 3.1 `requirements.txt` sync with `pyproject.toml`
> `requirements.txt` was missing `pyasn1`, `pyasn1_modules`, and
> `blake3` — even though `pyproject.toml` had them.

I re-verified Thread 1's claim against the live snapshot:
- `pyproject.toml` `[project.dependencies]` contains `blake3>=0.4.1`,
  `pyasn1>=0.6.0`, `pyasn1_modules>=0.4.0`.
- `pyproject.toml` `[project.optional-dependencies.postgres]` contains
  `psycopg[binary]>=3.1.0` and `asyncpg>=0.29.0`.
- `requirements.txt` lists `psycopg[binary]>=3.1.0`, `asyncpg>=0.29.0`,
  `pyasn1>=0.6.0`, `pyasn1_modules>=0.4.0`, `blake3>=0.4.1`.

The canonical doc was written from a pre-Thread-1 snapshot. Section 5
is therefore stale — Thread 1 closed that gap, this thread had no
deps work to do.

The canonical doc's Stale Documentation Map (Section 18) should add
an explicit note that `pyproject.toml` Section 5 ("EVERY DEPENDENCY")
overstates the gap; Thread 1's changelog Section 3.1 is the
authoritative record of what was actually missing and where.

---

## 3. Verification

### 3.1 Clean-install simulation

In a fresh Python 3.12.3 venv:
```bash
python3 -m venv .test_venv
.test_venv/bin/pip install -e ".[dev,postgres]"
```

**Result:** install succeeded. Versions resolved (as of May 22, 2026):
- `cryptography-48.0.0` (native ML-DSA enabled)
- `fastapi-0.136.1`, `pydantic-2.13.4`, `starlette-1.0.1`
- `pytest-9.0.3`, `pytest-asyncio-1.3.0`
- `asyncpg-0.31.0`, `psycopg-3.3.4`, `psycopg-binary-3.3.4`
- `blake3-1.0.8`, `pyasn1-0.6.3`, `pyasn1_modules-0.4.2`
- `openai-2.38.0`, `numpy-2.4.6`, `networkx-3.6.1`

### 3.2 Test collection

```bash
.test_venv/bin/python -m pytest --collect-only -q
```
**Result:** `3957 tests collected in 3.62s`. **Zero collection
errors.** Compares against the canonical-doc-reported `~3,845 tests
/ 9 failures (dep gap)` from the pre-Thread-1 snapshot. Codebase
test count has grown to 3957 since the doc was written.

### 3.3 Full test run

```bash
.test_venv/bin/python -m pytest -q
```

**Result: 3907 passed, 49 skipped, 1 failed** in 115.92s.

The single failure is `tests/causal/test_chief_fast_attribute.py::
test_fast_attribute_under_5ms_p99` — a p99 latency test with a 5ms
threshold. It **passes in isolation** (verified in this thread: each
call clocks ~4ms). It fails under full-suite shared-CPU contention on
this sandbox.

This is the same failure Thread 1's changelog documented at the end
of Section 4: *"environment-bound (shared-VM CPU contention) — it
passes when run in isolation. Not a Thread 1 regression."* The same
description applies here: it is not a Thread 2 regression either.

The canonical doc's threshold ("0 failures") cannot be met on a
shared-CPU sandbox for this test alone. On dedicated hardware (or
when run in isolation), the threshold is met. Two clean ways to
address this longer-term, neither in this thread's scope:
- Raise the threshold to something like 10–15ms p99 to absorb
  CI/sandbox jitter.
- Add a `@pytest.mark.timing` marker and skip it under
  `PYTEST_DISABLE_TIMING=1` in noisy environments.

Recommend the timing-marker approach; it preserves the perf assertion
as a real signal on perf-tracking hardware without breaking CI on
contended runners.

### 3.4 Skipped tests

49 skipped. Spot-checked: pre-existing skips (poseidon-hash gated
behind `[zk]` extra, Mithril Rust binding gated on Linux x86-64,
liboqs-gated paths). None are Thread 2's responsibility.

---

## 4. Net result against the canonical doc's Section 14 acceptance
   criteria for Thread 2

| Acceptance criterion | Status |
|---|---|
| `pip install -e .` in fresh venv installs all deps | ✅ (with `[postgres]` extra, matching `requirements.txt`) |
| `pytest tests/` returns 0 failures | ⚠️ 1 environment-bound perf-test failure on shared-CPU; passes in isolation. Same env-noise pattern Thread 1 documented. |
| KNOWN_BUGS Bug #1 in Resolved section | ✅ |
| Python version pin justified or relaxed | ✅ relaxed `>=3.12` → `>=3.11` after AST-verifying 463 src + 234 test files |

---

## 5. Issues surfaced but explicitly NOT fixed in this thread

These are real, but they belong to other threads or to future work.
I'm flagging them so they don't get re-discovered on the next audit:

### 5.1 `tex.db.arcade_leaderboard_repo` couples to `asyncpg` at import time

Line 45: `import asyncpg`. This is a **top-level** import. Because
`tex.main` transitively imports this module via
`tex.api.arcade_leaderboard`, installing Tex without the `[postgres]`
extra makes `import tex.main` fail outright with
`ModuleNotFoundError: No module named 'asyncpg'`.

This contradicts the canonical doc's claim in Section 4 that
*"Runtime falls back to in-memory mode when `DATABASE_URL` unset."*
The fallback only works for **store implementations** that check
`DATABASE_URL` lazily. The leaderboard repo doesn't — its `asyncpg`
import runs unconditionally at module load.

The right fix is one of:
- Guard the import: `try: import asyncpg; except ImportError:
  asyncpg = None` and raise informatively only when the repo is
  actually constructed.
- Move the import into the function(s) that need it (lazy import).

This is a code change to a runtime module, not a packaging fix, so
out of Thread 2 scope. Recommend folding it into **Thread 8**
(documentation cleanup sweep) since it's a single defensive-import
edit that pairs with the broader "treat `[postgres]` as truly
optional" claim. Alternatively, change `requirements.txt` and the
`all` extra to make Postgres unconditional — but the doc framing
treats it as optional, so the import is the thing that should bend.

### 5.2 `poseidon-hash` `[zk]` extra has a hard install conflict

The pyproject already documents this: `poseidon-hash 0.1.4` declares
`pytest~=7.1.2` as a runtime dependency, conflicting with the dev dep
on `pytest>=8.2.0`. Tex carries `poseidon-hash` in `[zk]` with an
operator workaround (`pip install -e ".[zk]" --no-deps poseidon-hash`).

I confirmed this is still reproducible. The pyproject already
documents the workaround in a comment. No action needed in Thread 2.
The right place to address this is either upstream (file an issue
asking them to drop the pinned `pytest` runtime dep, which is
clearly wrong — pytest is a test-only dep for that package) or
swap to a different Poseidon implementation. Not Thread 2's call.

### 5.3 Canonical doc Section 5 / Section 17 row 4 are stale

The canonical doc says `pyproject.toml` is missing `pyasn1`,
`pyasn1_modules`, `blake3`, `psycopg`, `asyncpg`. It isn't —
Thread 1 closed that, and these were partially in place before
Thread 1 too. The doc's Section 5 captures a pre-Thread-1 state.

This was a documentation drift that didn't surface as a code
problem in this thread, but it caused 30 minutes of "wait, is the
doc right or is the repo?" investigation at the top of this thread.
Surface this to Matthew for the eventual canonical-doc
reconciliation (rule #7 of the document's preamble).

---

## 6. What this thread did NOT do (out of scope per Section 14)

Strictly per the canonical doc's "stay in your lane" rule:

- ❌ Did not touch any source code under `src/tex/` (Thread 2 is a
  packaging/test-infra thread).
- ❌ Did not touch the `tex.io` references (Thread 1).
- ❌ Did not wire C2PA emission or the digital twin (Thread 5).
- ❌ Did not fix the `enforce_tenant_match` multi-tenant gap
  (Thread 3).
- ❌ Did not add pitch HTTP routes (Thread 4).
- ❌ Did not fix the jailbreak recognizers or evidence-bundle slice
  verifier (Thread 6).
- ❌ Did not wire the EcosystemEngine (Thread 7).
- ❌ Did not sweep stale `TODO(P0)` markers (Thread 8).
- ❌ Did not fix the VET cert pinning or ZKPROV regulator_grade
  default (Thread 9).
- ❌ Did not address the `tex.db.arcade_leaderboard_repo` top-level
  `asyncpg` import (flagged in §5.1 above for a future thread).

---

## 7. Files changed in this thread

```
pyproject.toml                        # 3 lines: requires-python, ruff.target-version, mypy.python_version
KNOWN_BUGS.md                         # Bug #1 reformatted to "✅ RESOLVED" + Resolved-section pointer
THREAD_2_CHANGELOG.md                 # this file
```
