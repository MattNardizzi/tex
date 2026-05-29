"""
Build a transitive-reachability orphan registry.

A file is WIRED if it is reachable (via the import graph) from main.py.

Algorithm:
  1. Build a directed import graph: file -> set of files it imports.
  2. Also add an edge from any file to every parent __init__.py of files it imports,
     because importing tex.X.Y triggers tex.X.__init__.py loading.
  3. BFS from main.py to find WIRED set.
  4. Separately BFS from test files and script files to find TEST_REACHABLE / SCRIPT_REACHABLE.
  5. Classify each file accordingly.

This is the truth-by-code analysis. No docstrings or MD files consulted.
"""
import ast
import json
from pathlib import Path
from collections import defaultdict, deque

ROOT = Path("/home/claude/tex_audit/tex")
SRC = ROOT / "src"
TESTS = ROOT / "tests"
SCRIPTS = ROOT / "scripts"
SDKS = ROOT / "sdks"


def file_to_module(filepath: Path) -> str:
    rel = filepath.relative_to(SRC)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].replace(".py", "")
    return ".".join(parts)


def parse_imports(filepath: Path) -> set[str]:
    """Return set of absolute module/symbol strings this file imports."""
    imports = set()
    is_init = filepath.name == "__init__.py"
    mod = file_to_module(filepath)
    pkg_parts = mod.split(".") if is_init else mod.split(".")[:-1]
    try:
        src = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except SyntaxError:
        return imports
    except OSError:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                keep = len(pkg_parts) - (node.level - 1)
                if keep < 0:
                    continue
                base = ".".join(pkg_parts[:keep])
                if node.module:
                    base_mod = f"{base}.{node.module}" if base else node.module
                else:
                    base_mod = base
            else:
                base_mod = node.module or ""
            if not base_mod:
                continue
            imports.add(base_mod)
            for a in node.names:
                if a.name != "*":
                    imports.add(f"{base_mod}.{a.name}")
    return imports


# Pass 1: index src files
src_files: list[Path] = sorted(SRC.rglob("*.py"))
mod_to_path: dict[str, Path] = {}

for f in src_files:
    mod = file_to_module(f)
    mod_to_path[mod] = f


def resolve_to_path(imp: str) -> Path | None:
    if imp in mod_to_path:
        return mod_to_path[imp]
    parts = imp.split(".")
    for i in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in mod_to_path:
            return mod_to_path[candidate]
    return None


# Pass 2: build directed import graph
graph: dict[Path, set[Path]] = defaultdict(set)

for f in src_files:
    raw_imports = parse_imports(f)
    for imp in raw_imports:
        if not imp.startswith("tex"):
            continue
        target = resolve_to_path(imp)
        if target is None or target == f:
            continue
        graph[f].add(target)
        # Add all parent __init__.py files as transitive dependencies
        # (because Python loads them when importing a submodule)
        mod_target = file_to_module(target)
        parts = mod_target.split(".")
        for i in range(1, len(parts)):
            parent_mod = ".".join(parts[:i])
            if parent_mod in mod_to_path:
                p = mod_to_path[parent_mod]
                if p.name == "__init__.py" and p != f:
                    graph[f].add(p)


# Pass 3: find seeds
main_py = SRC / "tex" / "main.py"
seed_runtime = {main_py}


def find_tex_imports_in_external_file(filepath: Path) -> set[Path]:
    found = set()
    try:
        src = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except (SyntaxError, OSError):
        return found
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("tex"):
                    t = resolve_to_path(alias.name)
                    if t:
                        found.add(t)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("tex"):
                t = resolve_to_path(node.module)
                if t:
                    found.add(t)
                for a in node.names:
                    if a.name != "*":
                        full = f"{node.module}.{a.name}"
                        sub = resolve_to_path(full)
                        if sub:
                            found.add(sub)
    return found


seed_tests = set()
for tf in TESTS.rglob("*.py"):
    seed_tests.update(find_tex_imports_in_external_file(tf))

seed_scripts = set()
for sf in list(SCRIPTS.rglob("*.py")) + list(SDKS.rglob("*.py")):
    seed_scripts.update(find_tex_imports_in_external_file(sf))


# Pass 4: BFS
def reachable_from(seeds: set[Path]) -> set[Path]:
    visited = set(seeds)
    q = deque(seeds)
    while q:
        cur = q.popleft()
        for nxt in graph.get(cur, set()):
            if nxt not in visited:
                visited.add(nxt)
                q.append(nxt)
    return visited

reach_runtime = reachable_from(seed_runtime)
reach_tests = reachable_from(seed_tests)
reach_scripts = reachable_from(seed_scripts)


# Pass 5: classify
def classify(f: Path) -> dict:
    rel = str(f.relative_to(ROOT))
    in_runtime = f in reach_runtime
    in_tests = f in reach_tests
    in_scripts = f in reach_scripts

    if in_runtime:
        verdict = "WIRED"
    elif in_tests and in_scripts:
        verdict = "TEST_AND_SCRIPT_ONLY"
    elif in_tests:
        verdict = "TEST_ONLY"
    elif in_scripts:
        verdict = "SCRIPT_ONLY"
    else:
        verdict = "FULL_ORPHAN"

    ds_line = ""
    try:
        tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        ds = ast.get_docstring(tree)
        if ds:
            ds_line = ds.strip().split("\n")[0][:120]
    except Exception:
        pass

    return {
        "path": rel,
        "module": file_to_module(f),
        "lines": sum(1 for _ in f.read_text(encoding="utf-8", errors="replace").splitlines()),
        "is_init": f.name == "__init__.py",
        "verdict": verdict,
        "reachable_runtime": in_runtime,
        "reachable_tests": in_tests,
        "reachable_scripts": in_scripts,
        "docstring_first_line": ds_line,
    }

results = [classify(f) for f in src_files]
by_verdict = defaultdict(list)
for r in results:
    by_verdict[r["verdict"]].append(r)

with open("/home/claude/audit_output/orphans/code_evidence_registry.json", "w") as fh:
    json.dump({
        "summary": {v: len(rs) for v, rs in by_verdict.items()},
        "files": results,
    }, fh, indent=2)

print("=" * 70)
print(f"TRANSITIVE-REACHABILITY ORPHAN REGISTRY ({len(src_files)} src/tex files)")
print("=" * 70)
for v in ["WIRED", "TEST_AND_SCRIPT_ONLY", "TEST_ONLY", "SCRIPT_ONLY", "FULL_ORPHAN"]:
    print(f"  {v:25s}  {len(by_verdict.get(v, []))} files")

for verdict_name, explainer in [
    ("FULL_ORPHAN", "NO Python file anywhere imports these (true dead code)"),
    ("TEST_ONLY", "Imported ONLY by tests, never by main.py or scripts/sdks"),
    ("SCRIPT_ONLY", "Imported ONLY by scripts/sdks, never by main.py or tests"),
    ("TEST_AND_SCRIPT_ONLY", "Imported by tests AND scripts but not from main.py"),
]:
    rs = by_verdict.get(verdict_name, [])
    if not rs:
        continue
    print()
    print("=" * 70)
    print(f"{verdict_name}  -  {explainer}")
    print("=" * 70)
    for r in sorted(rs, key=lambda r: -r["lines"]):
        marker = " [__init__]" if r["is_init"] else ""
        print(f"  {r['lines']:5d}  {r['path']}{marker}")
        if r["docstring_first_line"]:
            print(f"         {r['docstring_first_line'][:100]}")
