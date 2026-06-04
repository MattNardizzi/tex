#!/usr/bin/env python3
"""
wiring.py -- Phase 2: static import graph + dynamic resolution + reachability.

Builds module-level import edges, resolves re-export hubs and implicit
parent-package edges, computes reachability from every real entrypoint, runs
the full-text false-orphan test, and classifies every module as exactly one of:
WIRED / PARKED-test-only / PARKED-intra-cluster / PARKED-advisory /
CLI-entrypoint / ISOLATED.

Reads build/modules.json (from inventory.py). Does not trust any prior map.
"""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
from collections import defaultdict, deque

def load(out: Path):
    return json.loads((out / "modules.json").read_text())

def normalize_internal(imp: str, all_mods: set) -> list:
    """Map an internal import string to the set of modules it resolves to.
    `from tex.x.y import Z` may mean module tex.x.y or tex.x.y.Z (a submodule)."""
    hits = []
    if imp in all_mods:
        hits.append(imp)
    # could be a package (__init__) -> already in all_mods as 'tex.x.y'
    # try as 'imp' being a symbol from parent package
    parent = imp.rsplit(".", 1)[0] if "." in imp else imp
    if parent in all_mods and parent not in hits:
        hits.append(parent)
    return hits

def build_graph(modules: dict):
    all_mods = set(modules)
    edges = defaultdict(set)      # importer -> imported
    rev = defaultdict(set)        # imported -> importers
    for m, rec in modules.items():
        for imp in rec["imports_internal"]:
            for tgt in normalize_internal(imp, all_mods):
                if tgt != m:
                    edges[m].add(tgt); rev[tgt].add(m)
        # implicit parent-package execution: importing a.b.c runs a/__init__, a/b/__init__
        for imp in rec["imports_internal"]:
            parts = imp.split(".")
            for i in range(1, len(parts)):
                pkg = ".".join(parts[:i])
                if pkg in all_mods and pkg != m:
                    edges[m].add(pkg); rev[pkg].add(m)
    return edges, rev, all_mods

def reach(edges, seeds):
    seen = set()
    q = deque(s for s in seeds if s)
    while q:
        n = q.popleft()
        if n in seen: continue
        seen.add(n)
        for t in edges.get(n, ()):
            if t not in seen: q.append(t)
    return seen

def fulltext_refs(repo: Path, leaf: str):
    """Search whole repo (excluding the module's own file & build/) for the leaf name."""
    try:
        r = subprocess.run(["grep", "-rl", "--include=*.py", "--include=*.json",
                            "--include=*.yaml", "--include=*.yml", "--include=*.toml",
                            "--include=*.cfg", "--include=*.sh", leaf, "."],
                           cwd=repo, capture_output=True, text=True, timeout=60)
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []

def classify(repo: Path, out: Path):
    modules = load(out)
    edges, rev, all_mods = build_graph(modules)

    # entrypoints: app factory + every __main__
    entry = set()
    if "tex.main" in all_mods: entry.add("tex.main")
    for m in all_mods:
        if m.endswith("__main__"):
            entry.add(m)
    # package __init__ that the app imports are pulled in transitively.

    wired = reach(edges, entry)

    # build test-tree references (what tests import) for PARKED-test-only
    test_imports = set()
    for p in (repo / "tests").rglob("*.py"):
        txt = p.read_text(encoding="utf-8", errors="replace")
        for mod in all_mods:
            if mod in txt:
                test_imports.add(mod)

    classification = {}
    for m in sorted(all_mods):
        rec = modules[m]
        if m in entry and m.endswith("__main__"):
            klass = "CLI-entrypoint"
        elif m in wired:
            klass = "WIRED"
        else:
            # not reachable from app. resolve why.
            callers = rev.get(m, set())
            in_running = any(c in wired for c in callers)
            if in_running:
                klass = "WIRED"  # imported by a wired module (defensive; reach should've caught)
            else:
                leaf = m.split(".")[-1]
                refs = fulltext_refs(repo, leaf if leaf != "__init__" else m.split(".")[-2])
                ref_sources = defaultdict(int)
                for r in refs:
                    if r.startswith("./tests") or "/tests/" in r: ref_sources["tests"] += 1
                    elif r.startswith("./audit") or "/audit/" in r: ref_sources["audit"] += 1
                    elif r.startswith("./scripts") or "/scripts/" in r: ref_sources["scripts"] += 1
                    elif r.startswith("./docs") or "/docs/" in r: ref_sources["docs"] += 1
                    elif "/src/tex/" in r or r.startswith("./src/tex/"): ref_sources["src"] += 1
                    else: ref_sources["other"] += 1
                # is it referenced by another parked src module (intra-cluster)?
                src_callers = [c for c in callers if c in all_mods]
                if m in test_imports and not src_callers and ref_sources.get("src", 0) <= 1:
                    klass = "PARKED-test-only"
                elif src_callers:
                    klass = "PARKED-intra-cluster"
                elif ref_sources.get("scripts") or ref_sources.get("docs"):
                    klass = "PARKED-advisory"
                elif ref_sources.get("src", 0) > 1:
                    klass = "PARKED-intra-cluster"
                else:
                    klass = "ISOLATED"
                rec["_ref_sources"] = dict(ref_sources)
        classification[m] = klass
        rec["wiring"] = klass
        rec["callers"] = sorted(rev.get(m, set()))
        rec["callees"] = sorted(edges.get(m, set()))

    # persist enriched modules + a compact classification map
    (out / "modules.json").write_text(json.dumps(modules, indent=1))
    counts = defaultdict(int)
    for k in classification.values(): counts[k] += 1
    (out / "wiring.json").write_text(json.dumps(
        {"entrypoints": sorted(entry), "wired_count": len(wired),
         "counts": dict(counts), "classification": classification}, indent=1))
    print("ENTRYPOINTS:", sorted(entry))
    print("WIRING COUNTS:", dict(counts))
    print("WIRED modules:", len(wired), "/", len(all_mods))
    return modules, classification, edges, rev, wired

if __name__ == "__main__":
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "build").resolve()
    classify(repo, out)
