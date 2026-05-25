"""
Regression tests for KNOWN_BUGS.md Bug #4 (kernel-MCP secret patterns).

The historic defect: the outbound-secret pattern library only recognized
Stripe *live* secret keys (``sk_live_*`` / ``rk_live_*``). Test-mode keys
(``sk_test_*``), publishable keys (``pk_*``), and webhook signing secrets
(``whsec_*``) were never flagged, even though leaking any of them is
either credential-equivalent (test-mode in CI environments connected to
real Connect accounts, webhook secrets) or tenant-identifying
(publishable keys).

Resolution: a unified ``stripe_key`` family covers the secret /
restricted / publishable cross-product of test / live modes per
docs.stripe.com/keys (verified May 2026). A separate
``stripe_webhook_secret`` family covers ``whsec_*`` because its rotation
path is distinct.

Note on fixtures
----------------
The string literals below intentionally use the form
``<prefix>_NOTREALKEY_<padding>``. GitHub's push-protection scanner
flags any value matching Stripe's real-key character distribution,
even inside test files, and even when the value is Stripe's own
published documentation example. Using an obviously-synthetic body
with the ``NOTREALKEY`` sentinel:

  1. Exercises the same regex code path under test (the detector
     keys on the ``sk_*`` / ``rk_*`` / ``pk_*`` / ``whsec_*`` prefix
     family plus minimum length, not on the body content).
  2. Cannot be mistaken for a real credential by any scanner,
     CI auditor, or human reader.
  3. Survives a clone-and-grep secret audit cleanly.

If you add new Stripe fixture keys, keep the ``NOTREALKEY`` token
in the body.
"""

from __future__ import annotations

import pytest

from tex.governance.kernel_mcp.syscall_gate import _scan_outbound_secrets


# Synthetic Stripe-shaped fixtures. Each body is the literal token
# "NOTREALKEY" repeated to reach the minimum length the detector regex
# requires (24 chars after the prefix). These match Stripe's documented
# prefix families (sk_live_, sk_test_, rk_live_, rk_test_, pk_live_,
# pk_test_, whsec_) without resembling any real-key character
# distribution.
_STRIPE_SK_LIVE        = "sk_live_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_SK_TEST        = "sk_test_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_RK_LIVE        = "rk_live_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_RK_TEST        = "rk_test_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_PK_LIVE        = "pk_live_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_PK_TEST        = "pk_test_NOTREALKEYNOTREALKEYNOTREALKEY"
_STRIPE_WEBHOOK_SECRET = "whsec_NOTREALKEYNOTREALKEYNOTREALKEY"


class TestStripeKeyFamilyCoverage:
    """Every Stripe-issued credential shape Stripe documents in 2026
    must surface under exactly one of two families:
    ``stripe_key`` (the API key universe) or ``stripe_webhook_secret``
    (the webhook signing secret universe).
    """

    @pytest.mark.parametrize(
        "key",
        [
            # Secret keys
            _STRIPE_SK_LIVE,
            _STRIPE_SK_TEST,
            # Restricted keys (Stripe's current best-practice for prod)
            _STRIPE_RK_LIVE,
            _STRIPE_RK_TEST,
            # Publishable keys
            _STRIPE_PK_LIVE,
            _STRIPE_PK_TEST,
        ],
    )
    def test_real_format_keys_detected(self, key: str) -> None:
        hits = _scan_outbound_secrets(key)
        assert "stripe_key" in hits, (
            f"{key!r} was not detected as a stripe_key (hits={hits})"
        )

    def test_placeholder_fixture_detected(self) -> None:
        """The canonical CI placeholder must also fire — this is the
        exact fixture the test_kernel_mcp.py parametrize lists, and
        the original Bug #4 reproducer.
        """
        assert "stripe_key" in _scan_outbound_secrets("sk_test_example_key")

    def test_webhook_secret_distinct_family(self) -> None:
        hits = _scan_outbound_secrets(_STRIPE_WEBHOOK_SECRET)
        assert "stripe_webhook_secret" in hits
        # Important: a whsec_ must NOT also match stripe_key, because the
        # remediation path differs (rotate the webhook endpoint, not the
        # API key). Different families means a clean signal to the
        # operator about *which* credential leaked.
        assert "stripe_key" not in hits


class TestStripeKeyFalsePositives:
    """Defensive false-positive checks. The prefix itself is a reserved
    Stripe namespace, so even short matches are intentional — but we
    must not mis-fire on adjacent OpenAI / Anthropic keys (``sk-``,
    dash not underscore) or on bare prefixes that appear in
    documentation prose.
    """

    @pytest.mark.parametrize(
        "text",
        [
            # OpenAI key shape (dash, not underscore) — must NOT match stripe_key
            "sk-NOTREALKEYNOTREALKEYNOTREALKEYNOTREALKEY",
            # Anthropic key shape
            "sk-ant-NOTREALKEYNOTREALKEYNOTREALKEYNOTREALKEY",
            # Bare prefix only, with no body
            "see sk_test_ above for an example",
            # Generic prose mentioning Stripe
            "Stripe keys begin with sk or pk.",
        ],
    )
    def test_does_not_misfire(self, text: str) -> None:
        hits = _scan_outbound_secrets(text)
        assert "stripe_key" not in hits, (
            f"{text!r} should not match stripe_key (hits={hits})"
        )

    def test_openai_key_still_detected_under_its_own_family(self) -> None:
        # Belt-and-suspenders: re-confirm that the openai_anthropic
        # detector still fires on its native format after the Stripe
        # pattern change.
        hits = _scan_outbound_secrets("sk-ant-NOTREALKEYNOTREALKEYNOTREALKEYNOTREALKEY")
        assert "openai_anthropic" in hits


class TestNoSilentRenameRegression:
    """Defensive: the historic name ``stripe_live`` must not be the
    *only* surfaced family for a live key. If a future refactor brings
    it back as a name, that's fine — but the canonical ``stripe_key``
    family must remain present so downstream alert routing keyed on
    that string keeps working.
    """

    def test_live_key_surfaces_under_unified_family(self) -> None:
        hits = _scan_outbound_secrets(_STRIPE_SK_LIVE)
        assert "stripe_key" in hits