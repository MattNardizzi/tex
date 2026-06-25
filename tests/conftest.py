"""
Shared pytest configuration for Tex.

Key behaviors enforced here:

1. The semantic provider is forced off for the entire test session so tests
   are deterministic and do not make real network calls. Individual tests
   that want to exercise provider-specific code paths must construct the
   provider themselves; they should not rely on ambient environment state.

2. Evidence writes are redirected to a per-session temp file so running
   the suite never pollutes the project's evidence store.

3. ``get_settings`` is cached with ``lru_cache``. We clear that cache at
   session start so the test environment overrides take effect even when a
   previous import already filled the cache.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

# Thread 4 (May 2026): the ``import tex.ecosystem`` workaround that
# previously sat here was removed once the underlying circular import
# (``tex.events.crypto_provenance`` <-> ``tex.ecosystem.engine``) was
# broken by moving ``CryptoProvenance`` to TYPE_CHECKING in
# ``ecosystem/engine.py`` and ``events/ledger.py``. See
# THREAD_4_CHANGELOG.md.


@pytest.fixture(scope="session", autouse=True)
def _disable_semantic_provider_for_tests(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """
    Force deterministic test behavior:
    - no semantic provider (fallback only)
    - semantic fallback allowed
    - evidence path pointed at a throwaway temp directory
    """
    session_dir: Path = tmp_path_factory.mktemp("tex-test-evidence")
    evidence_path = session_dir / "evidence.jsonl"

    prior: dict[str, str | None] = {
        "TEX_SEMANTIC_PROVIDER": os.environ.get("TEX_SEMANTIC_PROVIDER"),
        "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
        "TEX_ALLOW_SEMANTIC_FALLBACK": os.environ.get("TEX_ALLOW_SEMANTIC_FALLBACK"),
        "TEX_EVIDENCE_PATH": os.environ.get("TEX_EVIDENCE_PATH"),
        "TEX_DISCOVERY_DEMO_SEED": os.environ.get("TEX_DISCOVERY_DEMO_SEED"),
    }

    os.environ.pop("TEX_SEMANTIC_PROVIDER", None)
    os.environ.pop("OPENAI_API_KEY", None)
    os.environ["TEX_ALLOW_SEMANTIC_FALLBACK"] = "true"
    os.environ["TEX_EVIDENCE_PATH"] = str(evidence_path)
    # Discovery connectors expose the documented "empty by default" surface to
    # tests; the first-run demo seed (Entra/OCSF fixtures) is suppressed so
    # exact-count discovery assertions are not polluted by demo agents. Tests
    # that want the seed set TEX_DISCOVERY_DEMO_SEED=1 explicitly.
    os.environ["TEX_DISCOVERY_DEMO_SEED"] = "0"

    # Clear cached settings so the new env vars take effect if anything
    # imported tex.config before this fixture ran.
    from tex.config import get_settings

    get_settings.cache_clear()

    yield

    # Restore prior environment so we leave the process state clean.
    for key, value in prior.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_action_cadence_tracker() -> Iterator[None]:
    """Isolate the autonomous-attack cadence circuit-breaker per test.

    The breaker keeps a process-wide, history-accumulating tracker singleton (it
    must, to measure an agent's action rate across requests). Reset it before and
    after every test so cadence state from one test can never leak into the next
    and trip a false ABSTAIN/FORBID. Within a single test, accumulation is
    preserved — that is what the breaker's own tests exercise.
    """
    from tex.deterministic.cadence import _reset_default_cadence_tracker

    _reset_default_cadence_tracker()
    yield
    _reset_default_cadence_tracker()


@pytest.fixture(autouse=True)
def _reset_value_budget_tracker() -> Iterator[None]:
    """Isolate the ledgered value-class budget tracker per test.

    The budget keeps a process-wide, cumulative tracker singleton (it must, to
    sum a lineage's confidentiality-class movement across requests and restarts).
    Reset it before and after every test so budget state from one test can never
    leak into the next and trip a false ABSTAIN/FORBID. Within a single test,
    accumulation is preserved — that is what the budget's own tests exercise.
    """
    from tex.deterministic.value_budget import _reset_default_budget_tracker

    _reset_default_budget_tracker()
    yield
    _reset_default_budget_tracker()


@pytest.fixture
def evidence_path(tmp_path: Path) -> Path:
    """Per-test evidence path so concurrent tests do not share state."""
    return tmp_path / "evidence.jsonl"


@pytest.fixture
def runtime(evidence_path: Path):
    """
    Build a fresh in-process Tex runtime for one test.

    Imported lazily so that ``_disable_semantic_provider_for_tests`` has
    already reset the settings cache before build_runtime runs.
    """
    from tex.main import build_runtime

    return build_runtime(evidence_path=evidence_path)
