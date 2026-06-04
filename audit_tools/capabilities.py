#!/usr/bin/env python3
"""
capabilities.py -- Phase 5 (capability & technology ledger) + index.json assembly.

Maps every module to a layer derived from the package/route structure, computes
per-layer REAL/THIN/STUB and wired/parked rollups, detects frontier-technology
SIGNALS from code (imported libraries + algorithmic markers, never from names),
and emits the machine map index.json combining all prior phases.

Reads build/{modules,wiring,routes,runtime,env}.json. Writes build/index.json,
build/layers.json, build/capabilities.json.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
from collections import defaultdict

# Layers derived from the src/tex package tree + the registered route prefixes.
# Each entry: (layer_name, list_of_package_prefixes). First match wins, longest
# prefix checked first.
LAYER_MAP = [
    ("API / Surface",                ["tex.api"]),
    ("Voice / Vigil",                ["tex.vigil", "tex.semantic"]),
    ("Engine / Decision",            ["tex.engine", "tex.commands", "tex.domain",
                                      "tex.policies", "tex.deterministic", "tex.pcas",
                                      "tex.agent", "tex.retrieval"]),
    ("Discovery / Inventory",        ["tex.discovery"]),
    ("Identity / Access / Provenance",["tex.provenance", "tex.vet"]),
    ("Monitoring / Observability",   ["tex.observability", "tex.drift"]),
    ("Execution Governance",         ["tex.governance", "tex.enforcement", "tex.pep",
                                      "tex.runtime", "tex.safeflow", "tex.contracts",
                                      "tex.intervention", "tex.operator", "tex.specialists",
                                      "tex.adversarial", "tex.camel", "tex.bench"]),
    ("Evidence / Crypto",            ["tex.evidence", "tex.receipts", "tex.proofs",
                                      "tex.pqcrypto", "tex.c2pa", "tex.zkprov",
                                      "tex.nanozk", "tex.tee", "tex.provenance"]),
    ("Learning",                     ["tex.learning"]),
    ("Ecosystem / Systemic",         ["tex.ecosystem", "tex.systemic", "tex.institutional",
                                      "tex.causal"]),
    ("Compliance",                   ["tex.compliance"]),
    ("Parked: _pending",             ["tex._pending"]),
    ("Plumbing / Stores",            ["tex.stores", "tex.db", "tex.memory", "tex.graph",
                                      "tex.ontology", "tex.events", "tex.config",
                                      "tex.ecosystem_config", "tex.frontier_config"]),
]

# Frontier-technology signals: each is (signal_name, predicate over a module rec).
# Signals are derived from imported libraries and algorithmic markers in calls,
# NEVER from the module name. They flag *candidate* techniques to verify by read.
def tech_signals(rec):
    sigs = []
    ext = set(rec["imports_external"])
    calls = set()
    for fn in rec["functions"]:
        calls.update(fn.get("calls", []))
    txt_markers = set()
    # algorithmic markers visible in call names
    joined = " ".join(calls)
    def has(*subs): return any(s in joined.lower() for s in subs)
    if {"cryptography"} & ext and has("ec.", "ecdsa", "secp", "ed25519"):
        sigs.append("classical-signature (ECDSA/Ed25519, pyca)")
    if "poseidon" in ext: sigs.append("Poseidon hash (ext lib)")
    if "oqs" in ext: sigs.append("liboqs PQ backend (ext)")
    if {"torch", "transformers"} & ext: sigs.append("neural model (torch/transformers, ext)")
    if "numpy" in ext: sigs.append("numeric (numpy)")
    if "networkx" in ext: sigs.append("graph (networkx)")
    if "psycopg" in ext: sigs.append("Postgres-backed (psycopg)")
    if "pyasn1" in ext: sigs.append("ASN.1/DER encoding (pyasn1)")
    if "hashlib" in ext and has("sha256", "sha3", "blake", "shake", "new("):
        sigs.append("hashing (hashlib)")
    if "hmac" in ext: sigs.append("HMAC")
    if "math" in ext and has("log", "exp", "sqrt", "erf"):
        sigs.append("statistical math")
    if "struct" in ext: sigs.append("binary packing (struct)")
    return sigs

def impl_status(rec):
    tc = rec["tier_counts"]
    total = tc["total"] or 1
    real = tc["REAL"]; stub = tc["STUB"]
    # detect NotImplementedError raisers
    nie = any("NotImplementedError" in fn.get("raises", []) for fn in rec["functions"])
    if total == 0:
        return "package/dto"
    if stub == total:
        return "stub"
    if real == 0:
        return "thin"
    ratio = real / total
    if stub > 0 and ratio < 0.4:
        return "partial"
    if nie and ratio < 0.6:
        return "partial"
    if ratio >= 0.5:
        return "real"
    return "partial"

def layer_of(mod):
    best = None; best_len = -1
    for name, prefixes in LAYER_MAP:
        for p in prefixes:
            if mod == p or mod.startswith(p + "."):
                if len(p) > best_len:
                    best = name; best_len = len(p)
    return best or "Plumbing / Stores"

def is_capability_bearing(rec):
    # plumbing if mostly DTOs/config/transport with no REAL functions and no tech signal
    if rec["tier_counts"]["REAL"] == 0 and not tech_signals(rec):
        return False
    return True

def main(out: Path):
    modules = json.loads((out/"modules.json").read_text())
    wiring = json.loads((out/"wiring.json").read_text())
    routes = json.loads((out/"routes.json").read_text())
    runtime = json.loads((out/"runtime.json").read_text())
    env = json.loads((out/"env.json").read_text())

    layers = defaultdict(lambda: {"modules": [], "REAL":0,"THIN":0,"STUB":0,
                                  "loc":0,"wired":0,"parked":0})
    capabilities = []
    index = {"meta": {}, "modules": {}, "routes": routes,
             "runtime_tasks": runtime, "env": env, "layers": {}}

    for mod, rec in modules.items():
        layer = layer_of(mod)
        rec["layer"] = layer
        sigs = tech_signals(rec)
        status = impl_status(rec)
        rec["tech_signals"] = sigs
        rec["impl_status"] = status
        L = layers[layer]
        L["modules"].append(mod)
        L["REAL"] += rec["tier_counts"]["REAL"]
        L["THIN"] += rec["tier_counts"]["THIN"]
        L["STUB"] += rec["tier_counts"]["STUB"]
        L["loc"] += rec["loc"]
        if rec.get("wiring") in ("WIRED","CLI-entrypoint"): L["wired"] += 1
        else: L["parked"] += 1

        # pick an anchor: first REAL function line, else module line 1
        anchor_line = 1
        for fn in rec["functions"]:
            if fn["kind"] == "REAL":
                anchor_line = fn["line"]; break
        if is_capability_bearing(rec) and rec["tier_counts"]["total"] > 0:
            capabilities.append({
                "module": mod, "layer": layer, "path": rec["path"],
                "anchor": f"{rec['path']}:{anchor_line}",
                "impl_status": status, "wiring": rec.get("wiring"),
                "tech_signals": sigs,
                "real": rec["tier_counts"]["REAL"],
                "thin": rec["tier_counts"]["THIN"],
                "stub": rec["tier_counts"]["STUB"],
                "loc": rec["loc"],
            })

        # compact index record
        index["modules"][mod] = {
            "path": rec["path"], "loc": rec["loc"], "tier": rec["tier_counts"],
            "impl_status": status, "layer": layer, "wiring": rec.get("wiring"),
            "classes": [c["name"] for c in rec["classes"]],
            "functions": [{"name": fn["name"], "kind": fn["kind"],
                           "calls": fn["calls"][:20], "raises": fn["raises"]}
                          for fn in rec["functions"]],
            "env_read": rec["env_read"],
            "imports_internal": rec["imports_internal"],
            "external_tech": rec["imports_external"],
            "callers": rec.get("callers", []),
            "callees": rec.get("callees", []),
            "dynamic_refs": rec.get("dynamic_import_calls", []),
            "tech_signals": sigs,
        }

    for name, L in layers.items():
        index["layers"][name] = {k: (len(v) if k=="modules" else v) for k,v in L.items()}
        index["layers"][name]["module_list"] = sorted(L["modules"])

    # dedupe live routes (exclude routes whose file is a parked module)
    parked_files = set()
    for mod, rec in modules.items():
        if rec.get("wiring") not in ("WIRED","CLI-entrypoint"):
            parked_files.add(rec["path"])
    live, dead = [], []
    seen = set()
    for r in routes:
        key = (r["method"], r["path"])
        if r["file"] in parked_files:
            dead.append(r); continue
        if key in seen: continue
        seen.add(key); live.append(r)
    index["meta"] = {
        "modules_total": len(modules),
        "loc_total": sum(r["loc"] for r in modules.values()),
        "classes_total": sum(len(r["classes"]) for r in modules.values()),
        "functions_total": sum(len(r["functions"]) for r in modules.values()),
        "wired": wiring["counts"].get("WIRED",0)+wiring["counts"].get("CLI-entrypoint",0),
        "parked": sum(v for k,v in wiring["counts"].items()
                      if k not in ("WIRED","CLI-entrypoint")),
        "routes_defined": len(routes), "routes_live": len(live), "routes_dead": len(dead),
        "entrypoints": wiring["entrypoints"],
        "wiring_counts": wiring["counts"],
    }
    index["routes_live"] = live
    index["routes_dead"] = dead

    (out/"index.json").write_text(json.dumps(index, indent=1))
    (out/"layers.json").write_text(json.dumps(index["layers"], indent=1))
    (out/"capabilities.json").write_text(json.dumps(capabilities, indent=1))
    # also persist enriched modules with layer+status
    (out/"modules.json").write_text(json.dumps(modules, indent=1))
    print("LAYERS:")
    for name in [l[0] for l in LAYER_MAP]:
        if name in index["layers"]:
            d = index["layers"][name]
            print(f"  {name:34} mods={d['modules']:3} loc={d['loc']:6} "
                  f"REAL={d['REAL']:3} THIN={d['THIN']:3} STUB={d['STUB']:3} "
                  f"wired={d['wired']:3} parked={d['parked']:3}")
    print(f"\nroutes live={len(live)} dead={len(dead)} | capabilities={len(capabilities)}")
    return index

if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv)>1 else "build").resolve()
    main(out)
