#!/usr/bin/env python3
"""
diagrams.py -- Phase 7: render the visual blueprint from code-derived data.

Generates four diagrams as SVG + PNG (Graphviz dot), all node labels and edges
sourced from build/index.json (Phases 2-5):
  1. layer_architecture     -- layers + wired/parked + /evaluate dataflow
  2. package_dependency      -- package-collapsed import graph (+ full module graph file)
  3. decision_path_sequence  -- end-to-end /evaluate trace
  4. runtime_topology        -- threads/tasks/lifespan + state touched

Reads build/index.json. Writes diagrams/*.svg and diagrams/*.png and *.dot.
"""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
from collections import defaultdict

INK = "#14110d"; PAPER = "#ffffff"; SOFT = "#6b6157"
WIRED_C = "#1f6f43"; PARKED_C = "#b0852a"; EDGE = "#8a8178"

def render(dot_src: str, out_base: Path):
    out_base.parent.mkdir(parents=True, exist_ok=True)
    dot_file = out_base.with_suffix(".dot")
    dot_file.write_text(dot_src)
    for fmt in ("svg", "png"):
        subprocess.run(["dot", f"-T{fmt}", str(dot_file), "-o",
                        str(out_base.with_suffix("." + fmt))], check=True)

def esc(s): return s.replace('"', '\\"')

def diagram_layers(idx, out):
    layers = idx["layers"]
    order = ["API / Surface","Voice / Vigil","Engine / Decision","Discovery / Inventory",
             "Identity / Access / Provenance","Monitoring / Observability",
             "Execution Governance","Evidence / Crypto","Learning",
             "Ecosystem / Systemic","Compliance","Parked: _pending","Plumbing / Stores"]
    lines = ['digraph layers {', 'rankdir=TB; bgcolor="white";',
             'node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=11];',
             'edge [color="%s"];' % EDGE,
             'label="Tex — layer architecture (code-derived). green=mostly wired, amber=mostly parked. n=modules, w/p=wired/parked"; labelloc=b; fontname="Helvetica"; fontsize=10;']
    for name in order:
        if name not in layers: continue
        d = layers[name]
        wired = d["wired"]; parked = d["parked"]; n = d["modules"]
        fill = WIRED_C if wired >= parked else PARKED_C
        font = "white"
        lbl = f"{name}\\n{n} modules · {d['loc']} LOC\\nREAL {d['REAL']} / THIN {d['THIN']} / STUB {d['STUB']}\\nwired {wired} · parked {parked}"
        node = name.replace(" ","_").replace("/","_").replace(":","")
        lines.append(f'"{node}" [label="{lbl}" fillcolor="{fill}" fontcolor="{font}"];')
    # primary dataflow of /evaluate across layers (from code trace)
    flow = [("API / Surface","Engine / Decision"),
            ("Engine / Decision","Execution Governance"),
            ("Engine / Decision","Evidence / Crypto"),
            ("Engine / Decision","Monitoring / Observability"),
            ("Engine / Decision","Learning"),
            ("Discovery / Inventory","Engine / Decision"),
            ("Identity / Access / Provenance","Engine / Decision"),
            ("Engine / Decision","Voice / Vigil"),
            ("Engine / Decision","Ecosystem / Systemic")]
    def nz(s): return s.replace(" ","_").replace("/","_").replace(":","")
    for a,b in flow:
        if a in layers and b in layers:
            lines.append(f'"{nz(a)}" -> "{nz(b)}" [penwidth=2 color="{INK}"];')
    lines.append('}')
    render("\n".join(lines), out/"layer_architecture")

def diagram_packages(idx, out):
    # collapse module edges to package (depth-2 e.g. tex.api, tex.engine) level
    mods = idx["modules"]
    def pkg(m):
        parts = m.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else m
    edges = defaultdict(int); wired_pkg = defaultdict(lambda:[0,0])
    for m, r in mods.items():
        p = pkg(m)
        if r["wiring"] in ("WIRED","CLI-entrypoint"): wired_pkg[p][0]+=1
        else: wired_pkg[p][1]+=1
        for c in r["callees"]:
            pc = pkg(c)
            if pc != p:
                edges[(p,pc)] += 1
    lines = ['digraph pkgs {', 'rankdir=LR; bgcolor="white"; concentrate=true;',
             'node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10];',
             'label="Tex — package dependency graph (collapsed, code-derived import edges)"; labelloc=b; fontsize=10;']
    for p,(w,pk) in sorted(wired_pkg.items()):
        fill = WIRED_C if w>=pk else PARKED_C
        lines.append(f'"{p}" [label="{p}\\n{w}w/{pk}p" fillcolor="{fill}" fontcolor="white"];')
    for (a,b),wt in sorted(edges.items(), key=lambda x:-x[1]):
        pen = 1 + min(4, wt//5)
        lines.append(f'"{a}" -> "{b}" [penwidth={pen} color="{EDGE}"];')
    lines.append('}')
    render("\n".join(lines), out/"package_dependency")
    # full module-level dot file (not rendered to png; large)
    flines = ['digraph mods {', 'rankdir=LR; node [shape=box fontsize=7];']
    for m,r in mods.items():
        c = WIRED_C if r["wiring"] in ("WIRED","CLI-entrypoint") else PARKED_C
        flines.append(f'"{m}" [color="{c}"];')
    for m,r in mods.items():
        for c in r["callees"]:
            flines.append(f'"{m}" -> "{c}";')
    flines.append('}')
    (out/"package_dependency_full_module.dot").write_text("\n".join(flines))

def diagram_sequence(idx, out):
    # End-to-end /evaluate trace (code-derived order from the PDP read).
    steps = [
        ("client","POST /evaluate","api/routes.py:116"),
        ("api/routes.py","EvaluateActionCommand.execute","commands/evaluate_action.py"),
        ("EvaluateActionCommand","PolicyDecisionPoint.evaluate","engine/pdp.py:205"),
        ("PDP","deterministic gate + structural FORBID floor","engine/pdp.py:284"),
        ("PDP","contract enforcement (LTLf) → PERMIT?ABSTAIN","engine/pdp.py:349"),
        ("PDP","conformal calibration → PERMIT?ABSTAIN","engine/pdp.py:361"),
        ("PDP","build typed ABSTAIN hold (engine/hold.py)","engine/pdp.py:381"),
        ("PDP","EvidenceRecorder.record (hash-chained, signed)","evidence/recorder.py"),
        ("EvidenceRecorder","signature provider (composite-ML-DSA→ECDSA fallback)","evidence/seal.py"),
        ("api/routes.py","EvaluateResponseDTO.from_command_result","api/routes.py:147"),
        ("client","Verdict: PERMIT | ABSTAIN | FORBID","domain/verdict.py"),
    ]
    lines = ['digraph seq {', 'rankdir=TB; bgcolor="white";',
             'node [shape=box style="rounded,filled" fillcolor="#f3efe9" fontname="Helvetica" fontsize=10];',
             'edge [fontname="Helvetica" fontsize=8 color="%s"];' % INK,
             'label="Tex — live decision path: POST /evaluate (code-derived order)"; labelloc=b; fontsize=10;']
    prev = None
    for i,(actor,act,anchor) in enumerate(steps):
        nid = f"s{i}"
        lines.append(f'"{nid}" [label="{esc(act)}\\n[{anchor}]"];')
        if prev is not None:
            lines.append(f'"{prev}" -> "{nid}";')
        prev = nid
    lines.append('}')
    render("\n".join(lines), out/"decision_path_sequence")

def diagram_runtime(idx, out):
    tasks = idx["runtime_tasks"]
    lines = ['digraph rt {', 'rankdir=LR; bgcolor="white";',
             'node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10];',
             'label="Tex — runtime/concurrency topology (code-derived spawn sites)"; labelloc=b; fontsize=10;']
    lines.append('"uvicorn" [label="uvicorn tex.main:app\\n(ASGI worker)" fillcolor="%s" fontcolor="white"];' % INK)
    lines.append('"lifespan" [label="FastAPI lifespan hook\\nmain.py:1257\\nstart/stop scheduler" fillcolor="#f3efe9"];')
    lines.append('"uvicorn" -> "lifespan";')
    seen=set()
    for t in tasks:
        if t["kind"]=="lifespan_hook": continue
        key=(t["kind"],t["file"],t["line"])
        if key in seen: continue
        seen.add(key)
        nid = t["file"].split("/")[-1].replace(".","_")+str(t["line"])
        state = {"scheduler.py":"BackgroundScanScheduler thread\\nscans tenants on interval\\ntouches discovery ledger",
                 "alerts.py":"alert dispatch thread\\ndrift/threshold alerts",
                 "feed.py":"ContinuousProvenanceFeed thread\\nheld-decision sink",
                 "llm_bridge.py":"specialist LLM bridge thread",
                 "__main__.py":"operator CLI worker thread (separate entrypoint)"}.get(t["file"].split("/")[-1], t["kind"])
        fill = PARKED_C if "__main__" in t["file"] else "#f3efe9"
        fc = "white" if "__main__" in t["file"] else "black"
        lines.append(f'"{nid}" [label="{esc(t["kind"])}\\n{t["file"].split("/")[-1]}:{t["line"]}\\n{state}" fillcolor="{fill}" fontcolor="{fc}"];')
        src = "lifespan" if t["file"].split("/")[-1] in ("scheduler.py",) else "uvicorn"
        lines.append(f'"{src}" -> "{nid}";')
    lines.append('}')
    render("\n".join(lines), out/"runtime_topology")

def main(build: Path, out: Path):
    idx = json.loads((build/"index.json").read_text())
    diagram_layers(idx, out)
    diagram_packages(idx, out)
    diagram_sequence(idx, out)
    diagram_runtime(idx, out)
    print("diagrams written to", out)
    for p in sorted(out.glob("*.svg")): print("  ", p.name)

if __name__ == "__main__":
    build = Path(sys.argv[1] if len(sys.argv)>1 else "build").resolve()
    out = Path(sys.argv[2] if len(sys.argv)>2 else "diagrams").resolve()
    main(build, out)
