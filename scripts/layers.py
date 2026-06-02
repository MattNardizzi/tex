#!/usr/bin/env python3
"""
Layer query utility — show which packages belong to which architectural layer.

Usage:
    python scripts/layers.py                  # print full layer map
    python scripts/layers.py --layer 4        # list packages in Layer 4
    python scripts/layers.py --kind evidence  # list packages by kind
    python scripts/layers.py --tree           # show as a tree

Reads __layer__ and __layer_kind__ from each package __init__.py.
No hardcoded list — the truth is in the packages themselves.
"""
import argparse
import importlib
import importlib.util
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

LAYER_NAMES = {
    1: "Discovery",
    2: "Identity",
    3: "Monitoring",
    4: "Execution Governance",
    5: "Evidence",
    6: "Learning",
}


def discover_packages() -> list[dict]:
    """Walk src/tex/* and read each package's __layer__ marker."""
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    results = []
    for pkg_dir in sorted((SRC / "tex").iterdir()):
        if not pkg_dir.is_dir():
            continue
        init = pkg_dir / "__init__.py"
        if not init.exists():
            continue

        # Parse the file directly rather than importing — avoids triggering
        # heavy module loading just to read the constants.
        ns: dict = {}
        try:
            src = init.read_text(encoding="utf-8")
            # Only execute the constant-assignment lines, not the whole module.
            # Easiest reliable way: regex out the __layer__ and __layer_kind__ lines.
            for line in src.splitlines():
                stripped = line.strip()
                if stripped.startswith("__layer__") or stripped.startswith("__layer_kind__"):
                    exec(stripped, ns)
        except Exception as e:
            print(f"  (warn) failed to read {pkg_dir.name}: {e}", file=sys.stderr)
            continue

        results.append({
            "package": pkg_dir.name,
            "layer": ns.get("__layer__"),
            "kind": ns.get("__layer_kind__", "unknown"),
            "lines": sum(
                sum(1 for _ in p.read_text(encoding="utf-8", errors="replace").splitlines())
                for p in pkg_dir.rglob("*.py")
            ),
            "files": sum(1 for _ in pkg_dir.rglob("*.py")),
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", type=int, help="Show only packages in this layer (1-6)")
    ap.add_argument("--kind", help="Show only packages of this kind")
    ap.add_argument("--tree", action="store_true", help="Show as grouped tree")
    args = ap.parse_args()

    pkgs = discover_packages()

    if args.layer:
        pkgs = [p for p in pkgs if p["layer"] == args.layer]
    if args.kind:
        pkgs = [p for p in pkgs if p["kind"] == args.kind]

    if args.tree or (not args.layer and not args.kind):
        # Grouped view
        by_layer: dict = defaultdict(list)
        for p in pkgs:
            key = p["layer"] if p["layer"] is not None else f"~{p['kind']}"
            by_layer[key].append(p)

        # Print numeric layers first, then cross-cutting/tooling
        for key in sorted(by_layer.keys(), key=lambda k: (isinstance(k, str), k)):
            ps = by_layer[key]
            if isinstance(key, int):
                header = f"Layer {key} — {LAYER_NAMES[key]}"
            else:
                header = key.lstrip("~").replace("_", " ").title()
            total_lines = sum(p["lines"] for p in ps)
            total_files = sum(p["files"] for p in ps)
            print(f"\n{header}  ({len(ps)} packages, {total_files} files, {total_lines:,} lines)")
            print("-" * len(header))
            for p in sorted(ps, key=lambda p: -p["lines"]):
                print(f"  {p['package']:20s}  {p['files']:4d} files  {p['lines']:7,d} lines")
    else:
        # Flat view
        for p in sorted(pkgs, key=lambda p: -p["lines"]):
            layer_str = f"L{p['layer']}" if p["layer"] else p["kind"]
            print(f"  {p['package']:20s}  [{layer_str:25s}]  {p['files']:4d} files  {p['lines']:7,d} lines")


if __name__ == "__main__":
    main()
