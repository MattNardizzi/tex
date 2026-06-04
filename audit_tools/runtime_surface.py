#!/usr/bin/env python3
"""
runtime_surface.py -- Phase 3 (runtime topology) + Phase 4 (routes + env table).

Derives, from the AST only:
  - every APIRouter(prefix=...) and the @router.<verb>/@app.<verb>/add_api_route
    registrations, resolved to a best-effort full path
  - every thread / asyncio task / scheduler / lifespan hook spawn site
  - every env var read with its in-code default

Reads build/modules.json. Writes build/routes.json, build/runtime.json,
build/env.json.
"""
from __future__ import annotations
import ast, json, re, sys
from pathlib import Path

VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}

def call_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        b = call_name(node.value); return f"{b}.{node.attr}" if b else node.attr
    if isinstance(node, ast.Call): return call_name(node.func)
    return ""

def const(node):
    if isinstance(node, ast.Constant): return node.value
    return None

def kw(call, name):
    for k in call.keywords:
        if k.arg == name: return k.value
    return None

def extract_routes(repo: Path):
    routes = []
    api_dir = repo / "src/tex/api"
    for f in sorted((repo/"src/tex").rglob("*.py")):
        text = f.read_text(encoding="utf-8", errors="replace")
        if "APIRouter" not in text and "add_api_route" not in text and "@app." not in text:
            continue
        try: tree = ast.parse(text)
        except SyntaxError: continue
        rel = str(f.relative_to(repo))
        # map router var -> prefix
        prefixes = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if call_name(node.value.func) == "APIRouter":
                    pfx = kw(node.value, "prefix")
                    pv = const(pfx) if pfx is not None else ""
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            prefixes[t.id] = pv or ""
        # also APIRouter created inside functions and returned
        for node in ast.walk(tree):
            # decorator-based routes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in node.decorator_list:
                    if isinstance(d, ast.Call):
                        fn = call_name(d.func)
                        m = re.match(r"(\w+)\.(\w+)$", fn)
                        if m and m.group(2) in VERBS:
                            var, verb = m.group(1), m.group(2)
                            path = const(d.args[0]) if d.args else None
                            pfx = prefixes.get(var, "")
                            routes.append({"method": verb.upper(),
                                           "path": (pfx or "") + (path or ""),
                                           "prefix": pfx, "raw_path": path,
                                           "router_var": var, "handler": node.name,
                                           "file": rel, "line": node.lineno})
            # add_api_route calls
            if isinstance(node, ast.Call) and call_name(node.func).endswith("add_api_route"):
                var = call_name(node.func).rsplit(".",1)[0]
                path = const(node.args[0]) if node.args else None
                methods = kw(node, "methods")
                mlist = []
                if isinstance(methods, (ast.List, ast.Tuple)):
                    mlist = [const(e) for e in methods.elts]
                routes.append({"method": ",".join(str(x) for x in mlist) or "GET",
                               "path": (prefixes.get(var,"") or "") + (path or ""),
                               "prefix": prefixes.get(var,""), "raw_path": path,
                               "router_var": var, "handler": "add_api_route",
                               "file": rel, "line": node.lineno})
    return routes

def extract_runtime(repo: Path):
    tasks = []
    SPAWN = {"threading.Thread", "Thread", "asyncio.create_task", "create_task",
             "loop.run_in_executor", "run_in_executor", "ThreadPoolExecutor",
             "ProcessPoolExecutor", "asyncio.ensure_future", "asyncio.gather",
             "BackgroundScheduler", "AsyncIOScheduler"}
    for f in sorted((repo/"src/tex").rglob("*.py")):
        text = f.read_text(encoding="utf-8", errors="replace")
        try: tree = ast.parse(text)
        except SyntaxError: continue
        rel = str(f.relative_to(repo))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                cn = call_name(node.func)
                if cn in SPAWN:
                    tasks.append({"kind": cn, "file": rel, "line": node.lineno})
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in node.decorator_list:
                    dn = call_name(d if not isinstance(d, ast.Call) else d.func)
                    if "lifespan" in dn or dn in ("asynccontextmanager",) and node.name=="lifespan":
                        tasks.append({"kind": "lifespan_hook", "name": node.name,
                                      "file": rel, "line": node.lineno})
                if node.name in ("start", "stop", "run", "_run", "_loop", "_tick",
                                 "tick", "_worker", "run_forever") and ("Thread" in text or "daemon" in text or "while True" in text):
                    pass
    return tasks

def extract_env(repo: Path):
    env = {}
    for f in sorted((repo/"src/tex").rglob("*.py")):
        text = f.read_text(encoding="utf-8", errors="replace")
        try: tree = ast.parse(text)
        except SyntaxError: continue
        rel = str(f.relative_to(repo))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                cn = call_name(node.func)
                if cn in ("os.getenv", "os.environ.get"):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        name = node.args[0].value
                        default = const(node.args[1]) if len(node.args) > 1 else None
                        env.setdefault(name, []).append(
                            {"file": rel, "line": node.lineno, "default": default})
            if isinstance(node, ast.Subscript):
                base = call_name(node.value)
                if base.endswith("environ") and isinstance(node.slice, ast.Constant):
                    name = node.slice.value
                    if isinstance(name, str):
                        env.setdefault(name, []).append(
                            {"file": rel, "line": node.lineno, "default": "<required>"})
    return env

def main(repo: Path, out: Path):
    routes = extract_routes(repo)
    runtime = extract_runtime(repo)
    env = extract_env(repo)
    (out/"routes.json").write_text(json.dumps(routes, indent=1))
    (out/"runtime.json").write_text(json.dumps(runtime, indent=1))
    (out/"env.json").write_text(json.dumps(env, indent=1))
    print(f"routes: {len(routes)}  runtime-spawn-sites: {len(runtime)}  env-vars: {len(env)}")
    return routes, runtime, env

if __name__ == "__main__":
    repo = Path(sys.argv[1] if len(sys.argv)>1 else ".").resolve()
    out = Path(sys.argv[2] if len(sys.argv)>2 else "build").resolve()
    main(repo, out)
