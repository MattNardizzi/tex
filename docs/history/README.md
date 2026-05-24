# docs/history

Archive of per-thread development logs. Not operational.

These were moved out of the repo root on 2026-05-21 to make the operational docs
(NAVIGATION, TIER_OWNERSHIP, MODULES, RUNBOOKS, STUB_REGISTRY, KNOWN_BUGS) visible.

## What's in here

- **`COMMIT_MSG_thread_*.txt`** — commit-message drafts from each build thread.
- **`FRONTIER_DELTA_thread_*.md`** — per-thread "what changed and why" deltas.
- **`V*_*.md`** — version milestone notes (V9 through V18).

## When to read these

- You're trying to remember why a decision was made — grep here for the topic.
- You're writing a release note and want to summarize a version arc.
- You're onboarding a new collaborator and want to point at the build history.

## When NOT to read these

- You're trying to understand the current state of the system. Use the
  operational docs at the repo root instead.
- You're trying to figure out what's broken. Use `KNOWN_BUGS.md`.
- You're trying to find unfinished work. Use `STUB_REGISTRY.md`.

The historical files are immutable. Don't edit them. If something here is wrong
or outdated, fix it in the corresponding operational doc, not here.
