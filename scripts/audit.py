#!/usr/bin/env python3
"""
Tex audit navigator.

Quick package context, dependency mapping, stub listing, and audit-slice
test commands. The tool that turns "4-hour audit" into "30-second lookup."

Every package carries two tags:
  - dev tier (A/B/C/D) — engineering blast radius
  - capability tier (D/I, I/A, M/O, E/G, E/R, kernel) — product-facing view

Usage:
    python scripts/audit.py <package>            Show full context for one package
    python scripts/audit.py --list               List all packages with both tiers
    python scripts/audit.py --tier A             Filter by dev tier
    python scripts/audit.py --capability E/G     Filter by capability tier
    python scripts/audit.py --stub-summary       Stub counts by package
    python scripts/audit.py --list-p1            Enumerate all P1 TODOs
    python scripts/audit.py --check-deps         Find Tier A files importing Tier C/D
    python scripts/audit.py --check-categorization  CI gate: every package tagged
    python scripts/audit.py --rebuild-data       Regenerate the data file from source

The script reads `scripts/_audit_data.json` (auto-rebuilds if missing).
Tier maps are in TIER_MAP and CAP_TIER_MAP below — keep them in sync with
TIER_OWNERSHIP.md and CAPABILITY_TIERS.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = Path(__file__).resolve().parent / "_audit_data.json"
SRC_BASE = ROOT / "src" / "tex"
TESTS_BASE = ROOT / "tests"

# Dev tier assignments. Keep in sync with TIER_OWNERSHIP.md.
# Engineering blast radius: what to run when this changes.
TIER_MAP = {
    # Dev Tier A — Product core
    "engine": "A",
    "specialists": "A",
    "agent": "A",
    "commands": "A",
    "domain": "A",
    "evidence": "A",
    "retrieval": "A",
    "semantic": "A",
    "deterministic": "A",
    "contracts": "A",
    "learning": "A",
    "memory": "A",
    "stores": "A",
    "governance": "A",
    # api is split: core auth/routes/guardrail/schemas are A, rest B. Tagged B.
    "api": "B",
    # Dev Tier B — Buyer surfaces
    "pitch": "B",
    "discovery": "B",
    # Dev Tier C — Frontier R&D
    "nanozk": "C",
    "pqcrypto": "C",
    "vet": "C",
    "zkprov": "C",
    "tee": "C",
    "c2pa": "C",
    "causal": "C",
    "ecosystem": "C",
    "intervention": "C",
    "systemic": "C",
    "pcas": "C",
    "runtime": "C",
    "safeflow": "C",
    "adversarial": "C",
    "institutional": "C",
    "drift": "C",
    "camel": "C",
    "receipts": "C",
    "ontology": "C",
    "graph": "C",
    "events": "C",
    "enforcement": "C",
    "observability": "C",
    "proofs": "C",
    "bench": "C",
    "db": "C",
    "policies": "C",
    # Dev Tier D — stubs
    "compliance": "D",  # mixed — Article 50 is real, most others are stubs
    # Note: `interop` was moved to src/tex/_pending/interop/ on 2026-05-21.
    # When restoring (e.g., for a Microsoft / Okta / Ping integration push),
    # move it back to src/tex/interop/ and uncomment the line below.
    # "interop": "D",
}

# Capability tier assignments. Keep in sync with CAPABILITY_TIERS.md.
# Buyer-facing view: what this contributes to the product.
# Values: D/I, I/A, M/O, E/G, E/R, kernel.
# Some packages span two — the second is noted in parens but the primary
# tier is what's stored here.
CAP_TIER_MAP = {
    # Execution Governance (the decision pipeline + content adjudication)
    "engine": "E/G",
    "specialists": "E/G",
    "retrieval": "E/G",
    "semantic": "E/G",
    "deterministic": "E/G",
    "contracts": "E/G",
    "governance": "E/G",  # IFC partly D/I; tag E/G as primary
    "intervention": "E/G",
    "pcas": "E/G",
    "runtime": "E/G",
    "safeflow": "E/G",
    "camel": "E/G",
    # Evidence / Recording (signed artifacts, compliance, post-decision proof)
    "evidence": "E/R",
    "c2pa": "E/R",
    "pqcrypto": "E/R",
    "zkprov": "E/R",
    "tee": "E/R",
    "nanozk": "E/R",
    "events": "E/R",
    "receipts": "E/R",
    "compliance": "E/R",
    "pitch": "E/R",
    "institutional": "E/R",
    # Monitoring / Observability (passive watch, drift, learning, systemic)
    "learning": "M/O",  # calibration portion overlaps E/G
    "observability": "M/O",
    "drift": "M/O",
    "systemic": "M/O",
    "causal": "M/O",
    # Identity / Access
    "agent": "I/A",  # behavioral_evaluator portion overlaps E/G
    "vet": "I/A",
    "enforcement": "I/A",
    # `interop` was moved to src/tex/_pending/. Restore if integration push returns.
    # Discovery / Inventory
    "discovery": "D/I",
    # Cross-cutting kernel infrastructure
    "domain": "kernel",
    "commands": "kernel",
    "memory": "kernel",
    "stores": "kernel",
    "db": "kernel",
    "api": "kernel",
    "ontology": "kernel",
    "policies": "kernel",
    "graph": "kernel",
    "ecosystem": "kernel",
    "bench": "kernel",
    "adversarial": "kernel",
    "proofs": "kernel",
}

# Full names for the capability tier abbreviations.
CAP_TIER_FULL = {
    "D/I": "Discovery / Inventory",
    "I/A": "Identity / Access",
    "M/O": "Monitoring / Observability",
    "E/G": "Execution Governance",
    "E/R": "Evidence / Recording",
    "kernel": "Cross-cutting kernel",
}

# Test slices per tier. Kept here for quick recall.
TIER_A_SLICE = (
    "pytest tests/specialists tests/contracts tests/governance tests/intervention "
    "tests/test_agent_governance.py tests/test_api.py tests/test_v16_hardening.py "
    "tests/test_calibration_safety.py tests/test_deterministic.py -q"
)
TIER_B_SLICE = (
    "pytest tests/test_api.py tests/test_governance_history_routes.py "
    "tests/test_discovery_routes.py tests/frontier/test_pitch.py "
    "tests/test_c2pa_http_routes.py tests/vet/test_vet_routes.py "
    "tests/zkprov/test_routes.py -q"
)


# ---------------------------------------------------------------------------
# Data loading + rebuild
# ---------------------------------------------------------------------------

def load_data() -> dict:
    if not DATA_FILE.exists():
        print(f"[!] {DATA_FILE} missing — rebuilding...", file=sys.stderr)
        rebuild_data()
    with DATA_FILE.open() as fh:
        return json.load(fh)


def rebuild_data() -> None:
    """Walk the source tree and regenerate _audit_data.json."""
    p0_re = re.compile(r"TODO\s*\(?\s*P0\s*\)?[:\s]?\s*(.+)", re.IGNORECASE)
    p1_re = re.compile(r"TODO\s*\(?\s*P1\s*\)?[:\s]?\s*(.+)", re.IGNORECASE)
    nie_re = re.compile(r"raise\s+NotImplementedError")
    import_re = re.compile(r"from\s+tex\.(\w+)|import\s+tex\.(\w+)")

    if not SRC_BASE.exists():
        print(f"[!] {SRC_BASE} not found — run from repo root", file=sys.stderr)
        sys.exit(1)

    packages = sorted(
        p.name for p in SRC_BASE.iterdir()
        if p.is_dir() and not p.name.startswith("_")
    )
    data: dict[str, dict] = {pkg: {
        "files": 0, "loc": 0,
        "p0_sites": [], "p1_sites": [], "nie_sites": [],
        "imports": [], "imported_by": [], "tests": [],
        "exports": [], "docstring": "",
    } for pkg in packages}

    imports: dict[str, set] = {pkg: set() for pkg in packages}
    imported_by: dict[str, set] = {pkg: set() for pkg in packages}

    for pkg in packages:
        d = SRC_BASE / pkg
        for path in d.rglob("*.py"):
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue
            data[pkg]["files"] += 1
            data[pkg]["loc"] += content.count("\n")
            for i, line in enumerate(content.splitlines(), 1):
                if nie_re.search(line):
                    data[pkg]["nie_sites"].append(f"{path.relative_to(ROOT)}:{i}")
                m = p0_re.search(line)
                if m:
                    data[pkg]["p0_sites"].append({
                        "file": str(path.relative_to(ROOT)),
                        "line": i,
                        "text": m.group(1)[:150].strip(),
                    })
                m = p1_re.search(line)
                if m:
                    data[pkg]["p1_sites"].append({
                        "file": str(path.relative_to(ROOT)),
                        "line": i,
                        "text": m.group(1)[:150].strip(),
                    })
            for m in import_re.finditer(content):
                other = m.group(1) or m.group(2)
                if other and other in data and other != pkg:
                    imports[pkg].add(other)
                    imported_by[other].add(pkg)

        # docstring + __all__ from __init__.py
        init = d / "__init__.py"
        if init.exists():
            try:
                content = init.read_text(errors="ignore")
                m = re.match(r'^\s*(?:"""(.+?)"""|\'\'\'(.+?)\'\'\')',
                             content, re.DOTALL)
                if m:
                    data[pkg]["docstring"] = (m.group(1) or m.group(2)).strip().split("\n")[0][:120]
                am = re.search(r"__all__\s*=\s*\[(.*?)\]", content, re.DOTALL)
                if am:
                    data[pkg]["exports"] = re.findall(r'["\']([^"\']+)["\']', am.group(1))
            except Exception:
                pass

    # Test mapping
    if TESTS_BASE.exists():
        for path in TESTS_BASE.rglob("test_*.py"):
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue
            counts: dict[str, int] = {}
            for m in import_re.finditer(content):
                pkg = m.group(1) or m.group(2)
                if pkg in data:
                    counts[pkg] = counts.get(pkg, 0) + 1
            if counts:
                top = max(counts.items(), key=lambda x: x[1])[0]
                rel = str(path.relative_to(ROOT))
                if rel not in data[top]["tests"]:
                    data[top]["tests"].append(rel)

    # Finalize import edges
    for pkg in data:
        data[pkg]["imports"] = sorted(imports[pkg])
        data[pkg]["imported_by"] = sorted(imported_by[pkg])
        data[pkg]["tests"].sort()

    DATA_FILE.parent.mkdir(exist_ok=True)
    DATA_FILE.write_text(json.dumps(data, indent=2))
    print(f"[ok] wrote {DATA_FILE} with {len(data)} packages")
    print(f"     total NIE: {sum(len(d['nie_sites']) for d in data.values())}")
    print(f"     total P0:  {sum(len(d['p0_sites']) for d in data.values())}")
    print(f"     total P1:  {sum(len(d['p1_sites']) for d in data.values())}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def show_package(pkg: str, data: dict) -> int:
    if pkg not in data:
        print(f"[!] unknown package: {pkg}")
        print(f"    available: {', '.join(sorted(data))}")
        return 2

    info = data[pkg]
    tier = TIER_MAP.get(pkg, "?")
    cap = CAP_TIER_MAP.get(pkg, "?")
    cap_full = CAP_TIER_FULL.get(cap, cap)

    print(f"\n{'=' * 70}")
    print(f"  {pkg}    [dev {tier}]  [cap {cap} — {cap_full}]")
    print(f"{'=' * 70}")
    if info["docstring"]:
        print(f"  {info['docstring']}")
    print()
    print(f"  files: {info['files']}    loc: {info['loc']}")
    print(f"  stubs: {len(info['nie_sites'])} NIE, "
          f"{len(info['p0_sites'])} P0 TODO, "
          f"{len(info['p1_sites'])} P1 TODO")

    if info["exports"]:
        ex = info["exports"]
        shown = ", ".join(ex[:10])
        more = f" (+{len(ex)-10} more)" if len(ex) > 10 else ""
        print(f"\n  public interface ({len(ex)} exports):")
        print(f"    {shown}{more}")

    if info["imports"]:
        print(f"\n  imports from:")
        print(f"    {', '.join(info['imports'])}")

    if info["imported_by"]:
        print(f"\n  imported by (blast radius):")
        print(f"    {', '.join(info['imported_by'])}")

    if info["tests"]:
        print(f"\n  test files ({len(info['tests'])}):")
        for t in info["tests"][:8]:
            print(f"    {t}")
        if len(info["tests"]) > 8:
            print(f"    ... +{len(info['tests'])-8} more")

    print(f"\n  recommended audit slice:")
    if tier == "A":
        print(f"    # Tier A — full slice")
        print(f"    {TIER_A_SLICE}")
    elif tier == "B":
        print(f"    # Tier B — surface slice")
        print(f"    {TIER_B_SLICE}")
    elif tier == "C":
        if info["tests"]:
            test_dirs = sorted({os.path.dirname(t) for t in info["tests"] if "/" in t})
            print(f"    pytest {' '.join(test_dirs)} -q")
        else:
            print(f"    # no tests directly mapped — run frontier suite")
            print(f"    pytest tests/frontier -q")
    elif tier == "D":
        print(f"    # Tier D — stub area; finish stub first, then promote tier")

    if info["p0_sites"]:
        print(f"\n  P0 TODOs ({len(info['p0_sites'])}):")
        for site in info["p0_sites"][:10]:
            print(f"    {site['file']}:{site['line']}")
            print(f"      {site['text']}")
        if len(info["p0_sites"]) > 10:
            print(f"    ... +{len(info['p0_sites'])-10} more")

    if info["nie_sites"]:
        print(f"\n  NotImplementedError sites ({len(info['nie_sites'])}):")
        for s in info["nie_sites"][:10]:
            print(f"    {s}")
        if len(info["nie_sites"]) > 10:
            print(f"    ... +{len(info['nie_sites'])-10} more")

    # Cross-reference KNOWN_BUGS.md
    known_bugs_file = ROOT / "KNOWN_BUGS.md"
    if known_bugs_file.exists():
        bugs_content = known_bugs_file.read_text()
        # Split into per-bug sections, then scan each for this package name.
        sections = re.split(r"\n## Bug #", bugs_content)
        mentions = []
        pkg_pat = re.compile(
            rf"(?:src/tex/{re.escape(pkg)}/|`{re.escape(pkg)}/`|tex\.{re.escape(pkg)}\b)"
        )
        for sec in sections[1:]:  # first split is preamble
            m_num = re.match(r"(\d+)", sec)
            if m_num and pkg_pat.search(sec):
                mentions.append(m_num.group(1))
        if mentions:
            print(f"\n  known bugs touching this package: "
                  f"#{', #'.join(sorted(set(mentions), key=int))}")
            print(f"    see KNOWN_BUGS.md")

    print()
    return 0


def list_packages(data: dict, tier_filter: str | None = None,
                  cap_filter: str | None = None) -> int:
    print(f"\n  {'package':<20} {'dev':>3} {'cap':>6} {'files':>6} {'loc':>8} "
          f"{'NIE':>4} {'P0':>4} {'P1':>4}")
    print(f"  {'-'*20} {'-'*3} {'-'*6} {'-'*6} {'-'*8} "
          f"{'-'*4} {'-'*4} {'-'*4}")
    total_files = total_loc = total_nie = total_p0 = total_p1 = 0
    for pkg in sorted(data):
        info = data[pkg]
        tier = TIER_MAP.get(pkg, "?")
        cap = CAP_TIER_MAP.get(pkg, "?")
        if tier_filter and tier != tier_filter:
            continue
        if cap_filter and cap != cap_filter:
            continue
        nie = len(info["nie_sites"])
        p0 = len(info["p0_sites"])
        p1 = len(info["p1_sites"])
        print(f"  {pkg:<20} {tier:>3} {cap:>6} {info['files']:>6} {info['loc']:>8} "
              f"{nie:>4} {p0:>4} {p1:>4}")
        total_files += info["files"]
        total_loc += info["loc"]
        total_nie += nie
        total_p0 += p0
        total_p1 += p1
    print(f"  {'-'*20} {'-'*3} {'-'*6} {'-'*6} {'-'*8} "
          f"{'-'*4} {'-'*4} {'-'*4}")
    label_parts = []
    if tier_filter:
        label_parts.append(f"dev={tier_filter}")
    if cap_filter:
        label_parts.append(f"cap={cap_filter}")
    label = f"TOTAL ({', '.join(label_parts)})" if label_parts else "TOTAL"
    print(f"  {label:<20} {'':>3} {'':>6} {total_files:>6} {total_loc:>8} "
          f"{total_nie:>4} {total_p0:>4} {total_p1:>4}")
    print()
    return 0


def stub_summary(data: dict) -> int:
    print("\n  packages with unfinished work:")
    print(f"  {'package':<20} {'dev':>3} {'cap':>6} {'NIE':>4} {'P0':>4} {'P1':>4}")
    print(f"  {'-'*20} {'-'*3} {'-'*6} {'-'*4} {'-'*4} {'-'*4}")
    rows = []
    for pkg in data:
        info = data[pkg]
        nie = len(info["nie_sites"])
        p0 = len(info["p0_sites"])
        p1 = len(info["p1_sites"])
        if nie or p0 or p1:
            rows.append((pkg, TIER_MAP.get(pkg, "?"), CAP_TIER_MAP.get(pkg, "?"),
                         nie, p0, p1))
    # sort by (P0 desc, NIE desc, name)
    rows.sort(key=lambda r: (-r[4], -r[3], r[0]))
    for pkg, tier, cap, nie, p0, p1 in rows:
        print(f"  {pkg:<20} {tier:>3} {cap:>6} {nie:>4} {p0:>4} {p1:>4}")
    print(f"  {'-'*20} {'-'*3} {'-'*6} {'-'*4} {'-'*4} {'-'*4}")
    print(f"  totals across all packages:")
    print(f"    NIE: {sum(r[3] for r in rows)}")
    print(f"    P0:  {sum(r[4] for r in rows)}")
    print(f"    P1:  {sum(r[5] for r in rows)}")
    print()
    return 0


def list_p1(data: dict) -> int:
    print("\n  All P1 TODOs:")
    for pkg in sorted(data):
        sites = data[pkg].get("p1_sites", [])
        if not sites:
            continue
        print(f"\n  {pkg} ({len(sites)}):")
        for s in sites:
            print(f"    {s['file']}:{s['line']}")
            print(f"      {s['text']}")
    print()
    return 0


def check_dependencies(data: dict) -> int:
    """Flag Tier A packages that import from Tier C or D — dependency-tier violations."""
    violations = []
    for pkg in data:
        tier = TIER_MAP.get(pkg, "?")
        if tier != "A":
            continue
        for dep in data[pkg]["imports"]:
            dep_tier = TIER_MAP.get(dep, "?")
            if dep_tier in {"C", "D"}:
                violations.append((pkg, dep, dep_tier))
    if not violations:
        print("\n  no Tier A → C/D dependency violations found")
        print()
        return 0
    print(f"\n  found {len(violations)} dependency-tier violations:")
    print(f"  (Tier A code should not depend on Tier C or D code directly)")
    print()
    for pkg, dep, dep_tier in violations:
        print(f"    {pkg:<20} (A) → {dep:<20} ({dep_tier})")
    print()
    return 1


def check_categorization(data: dict) -> int:
    """CI gate: fail if any package in src/tex/ has no dev or cap tier assignment.

    This is the maintenance lock that keeps the tier maps from rotting silently
    as new packages are added. Wire into a pre-commit hook or CI step.
    """
    missing_dev = []
    missing_cap = []
    for pkg in data:
        if pkg not in TIER_MAP:
            missing_dev.append(pkg)
        if pkg not in CAP_TIER_MAP:
            missing_cap.append(pkg)
    extra_dev = [p for p in TIER_MAP if p not in data]
    extra_cap = [p for p in CAP_TIER_MAP if p not in data]

    ok = True
    if missing_dev:
        ok = False
        print(f"\n  [FAIL] {len(missing_dev)} package(s) missing dev-tier in TIER_MAP:")
        for p in missing_dev:
            print(f"    - {p}    (add to TIER_MAP in scripts/audit.py and TIER_OWNERSHIP.md)")
    if missing_cap:
        ok = False
        print(f"\n  [FAIL] {len(missing_cap)} package(s) missing capability tier in CAP_TIER_MAP:")
        for p in missing_cap:
            print(f"    - {p}    (add to CAP_TIER_MAP in scripts/audit.py and CAPABILITY_TIERS.md)")
    if extra_dev:
        print(f"\n  [warn] {len(extra_dev)} stale TIER_MAP entries (package no longer exists):")
        for p in extra_dev:
            print(f"    - {p}")
    if extra_cap:
        print(f"\n  [warn] {len(extra_cap)} stale CAP_TIER_MAP entries (package no longer exists):")
        for p in extra_cap:
            print(f"    - {p}")

    if ok:
        print(f"\n  [ok] all {len(data)} packages have both dev tier and capability tier assignments")
        print()
        return 0
    print(f"\n  fix the above before merging.")
    print()
    return 1


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tex audit navigator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("package", nargs="?", help="Package to inspect")
    parser.add_argument("--list", action="store_true", help="List all packages")
    parser.add_argument("--tier", choices=["A", "B", "C", "D"],
                        help="Filter --list by dev tier")
    parser.add_argument("--capability", "--cap",
                        choices=["D/I", "I/A", "M/O", "E/G", "E/R", "kernel"],
                        help="Filter --list by capability tier")
    parser.add_argument("--stub-summary", action="store_true",
                        help="Show stub counts per package")
    parser.add_argument("--list-p1", action="store_true",
                        help="Enumerate all P1 TODOs")
    parser.add_argument("--check-deps", action="store_true",
                        help="Find Tier A → C/D dependency violations")
    parser.add_argument("--check-categorization", action="store_true",
                        help="CI gate: fail if any package lacks a tier assignment")
    parser.add_argument("--rebuild-data", action="store_true",
                        help="Regenerate audit data from source")
    args = parser.parse_args()

    if args.rebuild_data:
        rebuild_data()
        return 0

    data = load_data()

    if args.list or args.tier or args.capability:
        return list_packages(data, args.tier, args.capability)
    if args.stub_summary:
        return stub_summary(data)
    if args.list_p1:
        return list_p1(data)
    if args.check_deps:
        return check_dependencies(data)
    if args.check_categorization:
        return check_categorization(data)
    if args.package:
        return show_package(args.package, data)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
