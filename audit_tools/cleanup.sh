#!/usr/bin/env bash
# cleanup.sh -- Phase 8a fossil deletion.
#
# Removes stale CLAIM artifacts that this blueprint supersedes. Every file below
# was verified to be a prior audit/registry/stored-number artifact whose numbers
# DISAGREE with the code-derived truth in TEX_SYSTEM.md / index.json (e.g. the
# fossil EXECUTIVE_SUMMARY claims 462 files / 377 WIRED / 29 orphans; the
# code-derived truth is 524 files / 439 wired / 0 ISOLATED, and the fossil's
# "enforcement/ + path_policy never wired" claim is now FALSE in code).
#
# Run from the repo root. Review before executing.
set -euo pipefail

echo "Removing fossil audit/registry artifacts (superseded by TEX_SYSTEM.md + index.json)..."

# --- prior audit folder: stale counts, orphan/contradiction registries -------
git rm -r --quiet --ignore-unmatch audit/

# (defensive: if the above globbed away, remove the individual fossils)
git rm --quiet --ignore-unmatch audit/EXECUTIVE_SUMMARY.md            || true
git rm --quiet --ignore-unmatch audit/00_INDEX.md                     || true
git rm --quiet --ignore-unmatch audit/contradictions/CONTRADICTIONS.md|| true
git rm --quiet --ignore-unmatch audit/orphans/ORPHAN_REGISTRY.md      || true
git rm --quiet --ignore-unmatch audit/orphans/code_evidence_registry.json || true
git rm --quiet --ignore-unmatch audit/orphans/build_code_evidence_registry.py || true
git rm --quiet --ignore-unmatch audit/canonical/README.md             || true
git rm --quiet --ignore-unmatch audit/canonical/ARCHITECTURE.md       || true

echo "Done. KEPT (genuine external/deploy docs, not system claims):"
echo "  - deploy/helm/tex/README.md   (Helm chart docs)"
echo "  - tex-frontend/README.md      (frontend app docs)"
echo "  - vendor/mithril/*            (third-party)"
echo
echo "REVIEW (prior hand-authored layer docs under docs/ — superseded by"
echo "TEX_SYSTEM.md; remove only if you no longer want them as design notes):"
echo "  docs/BEHAVIORAL_PROVENANCE.md docs/layers/LAYER_*.md docs/layers/CROSS_CUTTING_*.md"
echo "  # To remove: git rm -r docs/"
