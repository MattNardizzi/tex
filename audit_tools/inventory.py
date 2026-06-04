#!/usr/bin/env python3
"""
inventory.py  --  Phase 0 (inventory) + Phase 1 (full read + behavioral fingerprint).

THE ONE LAW: code is the only witness. This script derives facts only from the
AST and from reading every byte of every first-party module. It does NOT run any
pre-existing audit tooling and does NOT seed from any stored number.

Outputs:
  build/modules.json   -- per-module fingerprint (functions, classes, calls,
                          returns/raises, env reads, external imports, tier, bytes)
  build/read_proof.json-- read-coverage ledger (bytes_read == file_size for all)
  build/inventory.txt  -- human totals + parse errors

Run from repo root: python audit_tools/inventory.py <repo_root> <out_dir>
"""
from __future__ import annotations
import ast, json, os, sys
from pathlib import Path

# ---- scope ----------------------------------------------------------------
# First-party application source only.
FIRST_PARTY_ROOT = "src/tex"

STDLIB = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()

def is_stub_body(node: ast.AST) -> bool:
    """A function whose body is only pass/.../docstring/NotImplementedError/const return."""
    body = [n for n in node.body]
    # strip a leading docstring
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return True
    real = []
    for n in body:
        if isinstance(n, ast.Pass):
            continue
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and n.value.value is Ellipsis:
            continue
        if isinstance(n, ast.Raise):
            # raise NotImplementedError -> stub-ish
            exc = n.exc
            name = None
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                name = exc.func.id
            elif isinstance(exc, ast.Name):
                name = exc.id
            if name == "NotImplementedError":
                continue
            real.append(n)
            continue
        if isinstance(n, ast.Return):
            v = n.value
            if v is None or (isinstance(v, ast.Constant)):
                continue  # returns only a constant / None
            real.append(n)
            continue
        real.append(n)
    return len(real) == 0

def count_real_statements(node: ast.AST) -> int:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    cnt = 0
    for n in body:
        if isinstance(n, ast.Pass):
            continue
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and n.value.value is Ellipsis:
            continue
        cnt += 1
    return cnt

class FnVisitor(ast.NodeVisitor):
    """Collect calls, returns, raises within one function body (not nested defs)."""
    def __init__(self):
        self.calls, self.raises = [], []
        self.returns_something = False
        self._depth = 0
    def visit_FunctionDef(self, n):
        if self._depth == 0:
            self._depth += 1
            self.generic_visit(n)
            self._depth -= 1
        # else: nested def, skip its internals for this fingerprint
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_Call(self, n):
        self.calls.append(_call_name(n.func))
        self.generic_visit(n)
    def visit_Raise(self, n):
        exc = n.exc
        if isinstance(exc, ast.Call):
            self.raises.append(_call_name(exc.func))
        elif isinstance(exc, ast.Name):
            self.raises.append(exc.id)
        elif isinstance(exc, ast.Attribute):
            self.raises.append(_call_name(exc))
        self.generic_visit(n)
    def visit_Return(self, n):
        if n.value is not None and not (isinstance(n.value, ast.Constant)):
            self.returns_something = True
        self.generic_visit(n)

def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""

class EnvVisitor(ast.NodeVisitor):
    """Find os.environ / os.getenv reads -> env var names."""
    def __init__(self):
        self.env = set()
    def visit_Call(self, n):
        nm = _call_name(n.func)
        if nm in ("os.getenv", "os.environ.get", "environ.get", "getenv"):
            if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                self.env.add(n.args[0].value)
        self.generic_visit(n)
    def visit_Subscript(self, n):
        # os.environ["X"]
        base = _call_name(n.value)
        if base.endswith("environ"):
            sl = n.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                self.env.add(sl.value)
        self.generic_visit(n)

def module_name_for(path: Path, repo: Path) -> str:
    rel = path.relative_to(repo / "src").with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)

def analyze(repo: Path, out: Path):
    src_root = repo / FIRST_PARTY_ROOT
    files = sorted(src_root.rglob("*.py"))
    modules = {}
    read_proof = []
    parse_errors = []
    total_loc = total_cls = total_fn = 0

    for f in files:
        raw = f.read_bytes()
        size = len(raw)
        text = raw.decode("utf-8", errors="replace")
        loc = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        read_proof.append({"path": str(f.relative_to(repo)), "file_size": size,
                           "bytes_read": len(raw), "ok": len(raw) == size})
        modname = module_name_for(f, repo)
        rec = {"path": str(f.relative_to(repo)), "module": modname, "loc": loc,
               "size": size, "classes": [], "functions": [],
               "imports_internal": [], "imports_external": [], "env_read": [],
               "dynamic_import_calls": [], "decorators_seen": [],
               "parse_ok": True}
        try:
            tree = ast.parse(text, filename=str(f))
        except SyntaxError as e:
            rec["parse_ok"] = False
            parse_errors.append({"path": rec["path"], "error": str(e)})
            modules[modname] = rec
            continue

        ev = EnvVisitor(); ev.visit(tree); rec["env_read"] = sorted(ev.env)

        # imports
        internal, external, dyn = set(), set(), []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    if a.name.startswith("tex") or top == "tex":
                        internal.add(a.name)
                    else:
                        external.add(top)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and node.level > 0:
                    # relative import -> internal
                    base = modname.rsplit(".", node.level)[0] if "." in modname else "tex"
                    internal.add((base + ("." + mod if mod else "")) if base else mod)
                elif mod.startswith("tex"):
                    internal.add(mod)
                elif mod:
                    external.add(mod.split(".")[0])
            elif isinstance(node, ast.Call):
                cn = _call_name(node.func)
                if cn in ("importlib.import_module", "__import__", "import_module"):
                    arg = None
                    if node.args:
                        a0 = node.args[0]
                        arg = a0.value if isinstance(a0, ast.Constant) else "<var>"
                    dyn.append({"call": cn, "arg": arg,
                                "line": getattr(node, "lineno", 0)})
                if cn in ("pkgutil.walk_packages", "pkgutil.iter_modules",
                          "walk_packages", "iter_modules"):
                    dyn.append({"call": cn, "arg": "<pkg-scan>",
                                "line": getattr(node, "lineno", 0)})
        rec["imports_internal"] = sorted(internal)
        rec["imports_external"] = sorted(x for x in external if x and x not in ("__future__",))
        rec["dynamic_import_calls"] = dyn

        # classes + functions
        def handle_fn(node, cls=None):
            v = FnVisitor(); v.visit(node)
            real_stmts = count_real_statements(node)
            stub = is_stub_body(node)
            if stub:
                tier = "STUB"
            elif real_stmts <= 2:
                tier = "THIN"
            else:
                tier = "REAL"
            args = [a.arg for a in node.args.args]
            if node.args.vararg: args.append("*" + node.args.vararg.arg)
            if node.args.kwarg: args.append("**" + node.args.kwarg.arg)
            decos = [_call_name(d if not isinstance(d, ast.Call) else d.func) for d in node.decorator_list]
            return {"name": (f"{cls}." if cls else "") + node.name,
                    "kind": tier, "is_async": isinstance(node, ast.AsyncFunctionDef),
                    "args": args, "real_statements": real_stmts,
                    "calls": sorted(set(c for c in v.calls if c))[:60],
                    "raises": sorted(set(v.raises)),
                    "returns_value": v.returns_something,
                    "decorators": decos, "line": node.lineno}

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rec["functions"].append(handle_fn(node))
            elif isinstance(node, ast.ClassDef):
                bases = [_call_name(b) for b in node.bases]
                methods = []
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.append(handle_fn(sub, cls=node.name))
                rec["classes"].append({"name": node.name, "bases": bases,
                                       "methods": [m["name"] for m in methods],
                                       "line": node.lineno})
                rec["functions"].extend(methods)
                # capture decorators at class scope too
                for d in node.decorator_list:
                    rec["decorators_seen"].append(_call_name(d if not isinstance(d, ast.Call) else d.func))

        # tier rollup for the module
        kinds = [fn["kind"] for fn in rec["functions"]]
        rec["tier_counts"] = {"REAL": kinds.count("REAL"), "THIN": kinds.count("THIN"),
                              "STUB": kinds.count("STUB"), "total": len(kinds)}
        total_loc += loc; total_cls += len(rec["classes"]); total_fn += len(rec["functions"])
        modules[modname] = rec

    out.mkdir(parents=True, exist_ok=True)
    (out / "modules.json").write_text(json.dumps(modules, indent=1))
    shortfalls = [r for r in read_proof if not r["ok"]]
    (out / "read_proof.json").write_text(json.dumps(
        {"files": len(read_proof), "shortfalls": shortfalls, "ledger": read_proof}, indent=1))
    summary = [
        f"FIRST-PARTY ROOT: {FIRST_PARTY_ROOT}",
        f"modules (py files): {len(files)}",
        f"total LOC: {total_loc}",
        f"total classes: {total_cls}",
        f"total functions/methods: {total_fn}",
        f"parse errors: {len(parse_errors)}",
        f"read shortfalls (bytes_read != size): {len(shortfalls)}",
    ]
    for pe in parse_errors:
        summary.append(f"  PARSE-ERROR {pe['path']}: {pe['error']}")
    (out / "inventory.txt").write_text("\n".join(summary) + "\n")
    print("\n".join(summary))
    return modules

if __name__ == "__main__":
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "build").resolve()
    analyze(repo, out)
