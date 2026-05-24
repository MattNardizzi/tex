"""
_pending — code that is not part of the active product.

Files in this directory:
  - exist but are not imported by anything in src/tex/.
  - do not appear in the audit tool's package list.
  - are not subject to tier-categorization checks.
  - may contain NotImplementedError stubs without blocking anything.

When to restore something here:
  - Move the directory back to src/tex/.
  - Add the package to TIER_MAP and CAP_TIER_MAP in scripts/audit.py.
  - Add a row to TIER_OWNERSHIP.md.
  - Run: python scripts/audit.py --rebuild-data
  - Run: python scripts/audit.py --check-categorization (must pass)
  - Add tests under tests/<package>/.

Current contents (as of 2026-05-21):
  - interop/  Microsoft, Okta, Ping, NIST, A2A integration stubs.
              Moved here because current Tex Aegis GTM (VP Marketing at
              AI-SDR-using SaaS) does not require these integrations.
              Restore when an integration push lands on the roadmap.
"""
