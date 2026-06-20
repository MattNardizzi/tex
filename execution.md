# Tex Execution Layer — Architecture & Current State

> **Snapshot:** the execution-layer state on `main` after the wave-4 merges
> (PRs #31–#35), 2026-06-19 (built atop `be38614`). This is the honest,
> grep-survivable map of what the execution layer *is*, what is *wired and firing*,
> what is *flag-gated*, what is *deploy/infra-gated*, and what is *deliberately not
> built*. `main` keeps advancing with other work — if in doubt, re-verify against
> current `main` using §8. Words here must match the code; if you change the layer,
> update this file.

---

## 1. What it is (and the ceiling it cannot pass)

The execution layer's job: **stop as many forbidden agent actions as physically
possible, with offline-verifiable proof of every allow / deny / hold.**

The hard ceiling (physics, not engineering debt — do not claim past it):
- Prevention requires **complete mediation** — every path the action could take is
  forced through a Tex chokepoint at a layer *below* what the agent can reach.
- **Inventory ≠ enforcement.** Knowing an agent exists buys zero prevention.
- It can **never** close the *irreducible limits*: a credential the agent already
  holds, a directly-wired physical actuator, covert/side channels, delegation to
  another principal, and the undecidable "is this harmful" — which may only ever
  resolve to **ABSTAIN** (a held decision), never a guess.

So "most powerful possible" tops out at **complete mediation + proof**. Tex
enforces on the path it mediates; it is not, and cannot be, omniscient.

---

## 2. The two halves: the Brain and the Body

The execution layer is **two separate planes**. Conflating them is the #1 source
of overclaim.

| | **Brain — the PDP (decision + proof)** | **Body — the PEP (enforcement)** |
|---|---|---|
| What | Decides PERMIT / ABSTAIN / FORBID; produces proof | Physically mediates the action; calls the Brain |
| Entrypoint | `tex.main:app` (uvicorn) — the Render web service | `python -m tex.pep` (proxy), `python -m tex.operator` (admission), + the eBPF kernel agent (Go) |
| Where it runs | The Render `tex-web` service (managed PaaS) | In front of the agent fleet — Linux nodes / a k8s cluster you control |
| Code | `src/tex/governance/`, `src/tex/engine/`, `src/tex/specialists/`, `src/tex/api/` | `src/tex/pep/`, `pep/kernel/` (Go+C), `src/tex/operator/`, `deploy/helm/tex/` |

**Verified architectural boundary:** importing `tex.main` pulls in **zero**
`tex.pep` and **zero** `tex.operator` modules. The Body is a separate process that
*wraps* agents and *consults* the Brain over HTTP. You **cannot** "wire the eBPF
kernel floor into the model" — by design it lives below/around the model at the
syscall boundary and calls it.

**The seam between them:** the PEP calls the PDP via
- `POST /v1/govern/decide` — rule on one action (proxy, per request)
- `GET /v1/govern/forbid-set` — warm the in-kernel fast-block cache (kernel agent, ~30s)

Both endpoints are real and mounted on the live PDP
(`api/governance_standing_routes.py`; router mounted at `main.py` `create_app`).

---

## 3. The Brain — the decision plane (LIVE on Render, active by default)

**Live call path** (no env flag required):

```
tex.main:app  (== create_app(), the Render service)
  └─ POST /v1/govern/decide                      api/governance_standing_routes.py
       └─ StandingGovernance.decide(...)         governance/standing.py
            ├─ Tier-1 structural FORBID floor (inline, fail-closed):
            │     unsealed identity / non-governable lifecycle
            │     (SLEEPING|REVOKED|QUARANTINED) / out-of-capability-surface → FORBID
            ├─ G9 un-inspectable → ABSTAIN:
            │     action_type ∈ {"https_opaque","http_opaque_body"} → held, released=False
            │     (monotone: only downgrades an otherwise-PERMIT-eligible action;
            │      the FORBID floor still wins first)
            └─ Tier-2 deep adjudication:
                  EvaluateActionCommand → PolicyDecisionPoint.evaluate   engine/pdp.py
                    ├─ build_default_specialist_suite()  (incl. IfcSpecialist)  specialists/judges.py
                    ├─ detect_structural_floor(...)      specialists/structural_floor.py
                    │     deterministic denies short-circuit to FORBID BEFORE the
                    │     probabilistic router (PCAS / CaMeL / IFC / ARGUS / cadence /
                    │     rule-of-two / action-class / RV4-permanent)
                    └─ else → probabilistic router → PERMIT / ABSTAIN
```

**What fires by default, verified by live invocation:**
- **DIFC `SECRET ↛ EGRESS` deterministic hard-deny.** `IfcEngine.evaluate` runs
  `check_noninterference` (a decidable reachability + lattice sub-property over the
  ARM provenance graph) and emits `IfcViolation.SECRET_EGRESS_NONINTERFERENCE`; the
  code is listed in `structural_floor._IFC_HARD_VIOLATION_CODES`, so it
  short-circuits the PDP to **FORBID** — *even when other specialists vote PERMIT*
  (proven live: PCAS PERMIT, IFC floor still FORBID). It carries a re-checkable
  witness (`ifc/noninterference.py::verify_flow_proof`). There is also an
  **integrity dual** (`UNTRUSTED ↛ PRIVILEGED`) that currently rides as a
  high-weight voting signal (not yet promoted to the hard floor — a 1-line wire).
- **Opaque / undecodable content → ABSTAIN.** TLS Tex couldn't terminate
  (`https_opaque`) and request bodies in an encoding Tex can't decode
  (`http_opaque_body`, e.g. br/zstd/stacked/malformed) are held, never
  content-blind PERMITted.
- **Structural FORBID floor** for every deterministic-deny specialist signature.
- **Always-on proof:** every deep decision writes a **hash-chained, signed**
  (ML-DSA / Ed25519, ECDSA fallback) JSONL evidence record + a decision row — no
  flag.

Maturity notes (honest): the DIFC checker is `research_solid` — a *decidable
sub-property* checker, **not** general non-interference. The decision logic is
real and tested; it governs the path it sees.

---

## 4. The proof + learn plane

| Capability | State | Notes |
|---|---|---|
| Hash-chained signed evidence chain + decision store | **always-on** | every deep decision; no flag |
| Proof-carrying **SealedFact** receipts (ATTEMPT/DECISION/ENFORCEMENT) | **flag-gated** | `TEX_SEAL_DECISIONS=1`. Verdict-neutral. **Ledger is in-memory** — grows per request, resets on restart; durable (Postgres) backing is the prod follow-up |
| External RFC-3161 **time-anchor** of the ledger | **PEP-deployment only** | `AnchorScheduler` starts in `tex.pep.__main__`, not in the PDP; needs `TEX_PEP_SEAL=1` + `TEX_PEP_ANCHOR_TSA_URL` |
| **ZK** verdict-proof / arbiter (`zkprov`, `zkpdp`) | **proof-on-demand** | NOT in the live `decide()` import graph; consumed by the offline `tex.capstone.*` compose/verify/tamper plane. The `schnorr-verdict-zk-v1` verdict-over-hidden-score backend exists + is wired into the arbiter, but the arbiter is not called per live decision. `nanozk` is hard-deactivated. `zkprov` also serves a separate `POST /v1/zkprov/prove` training-data-provenance endpoint |
| **Learning** (calibration e-process, abstain-flywheel, drift) | **outcome-driven** | a live `decide()` does NOT update the calibrator at decision time; learning advances on a later `POST /decisions/{id}/seal` (human resolution) or `POST /outcomes`. Decisions DO feed the slower behavioral memory (action ledger, precedent, tenant baseline) that future decisions read |

---

## 5. The Body — the enforcement plane (built + proven; deploy in front of agents)

Runs as separate processes, **not** on Render. Each piece is `separate-pep-plane`
and additionally flag-/deploy-gated as noted.

### 5a. The network PEP — `src/tex/pep/` (`python -m tex.pep`, port 8088)
A transparent egress proxy. `proxy.handle()` rules on each request via the
decision client (`decision_client.py`: HTTP POST to `/v1/govern/decide`, or
in-process), then on a released decision applies, in order:
- **Emission gate** (`_apply_emission_gate`) — re-asserts the agent's permitted
  tool subset on a recognized LLM-provider request before it egresses
  (Approach-B / provider-trusted; only ever TIGHTENS). Decodes gzip/deflate to
  inspect; an undecodable body is labeled `http_opaque_body` → ABSTAIN. Works in
  the default `http` sidecar mode via a piggybacked surface (the decision carries
  `allowed_tools`) or an opt-in fetch resolver.
- **Content-bound single-use permit** (G10) — `TEX_PEP_PERMITS=1` (+ a signing
  secret). Mint → persist → verify-against-fresh-digest → consume. Honest scope: a
  Tex-to-Tex self-check; third-party APIs ignore `X-Tex-Permit`.
- **Sealed terminal-outcome receipt** (G4) — `TEX_PEP_SEAL=1`.
- **Attested identity** (G6) — `TEX_PEP_REQUIRE_IDENTITY=1`; trusted issuer keys
  loaded fail-closed from `TEX_PEP_TRUSTED_ISSUERS[_FILE]`; a presented-but-bad
  card always FORBIDs.
- **Cross-tenant binding** — `TEX_PEP_REQUIRE_TENANT_BINDING=1`; a card must carry
  `aud=tex://<tenant>` (reuses the signed audience claim). Degrade-open when off.
- **Credential broker** (G12) — `TEX_PEP_BROKER=1` (+ permits + signing secret).
  Mints a single-use, action-scoped, PoP-bound downstream credential and strips
  the agent's standing-credential headers (Authorization + an enumerated set:
  cookie/x-api-key/x-amz-security-token/x-goog-api-key + `TEX_PEP_BROKER_STRIP_HEADERS`).
  Honest: sole-custody over the *enumerated* vectors; does not make a 3rd-party
  resource *demand* a Tex credential (resource-side federation). JWKS IdP source
  (Entra/SPIFFE) — crypto real, network fetch is a labeled shim.
- **orig_dst (G7)** — rule on the kernel-captured destination, not the spoofable
  Host header; `TEX_PEP_REQUIRE_DST=1` fails closed when no kernel dst is present.

### 5b. The eBPF kernel floor — `pep/kernel/` (Go loader + C BPF; Linux only)
5 programs attached under governed cgroups: `connect4`, `connect6`, `sendmsg4`,
`sendmsg6`, `sock_ops`. At `connect()`/`sendmsg()`: inline fast-block of known-FORBID
destinations from the `verdict_cache` (warmed from `GET /v1/govern/forbid-set`),
else redirect to the local proxy and re-key the real destination under the source
4-tuple so the proxy recovers it over a UDS. **Verified in-kernel** on a Linux VM:
all 5 verify+attach; FORBID→`EPERM`, non-FORBID→redirect+orig-dst recovery,
UDP-no-proxy→drop (fail-closed). Builds/loads only on Linux (BTF kernel ≥5.10);
not on macOS. A `bpf_lsm/socket_connect` second-enforcement leg is built+tested but
**not shipped** — kernel requires LSM programs be GPL, the object is Apache-2.0
(separate GPL object + relicensing call needed).

### 5c. Born-in-a-box admission — `src/tex/operator/` + `deploy/helm/tex/` (`python -m tex.operator`, port 8443; needs a cluster)
Mutating injector (adds the PEP sidecar/init to new pods), validating deny webhook
(`failurePolicy: Fail`), in-apiserver ValidatingAdmissionPolicy (CEL mirror of the
webhook rules — single source of truth is `webhook.py::approved_runtime_classes`),
cosign image-gating, and a shipped gVisor `RuntimeClass`. **Proven live on a kind
cluster:** the apiserver VAP denied a non-compliant pod and admitted+injected a
compliant one under runsc. (Note: gVisor's netstack doesn't implement the injected
`iptables -m owner` REDIRECT, so under gVisor that redirect is the eBPF node
floor's job, not the in-pod init.)

---

## 6. Env-flag matrix (the Body / PEP — all default OFF, behavior-neutral)

| Var | Default | Gates |
|---|---|---|
| `TEX_PDP_MODE` | `http` | `http` (sidecar → PDP service) vs `inprocess` (governor in-process; only mode where the emission gate's governor fast-path is present) |
| `TEX_PEP_REQUIRE_DST` | off | FORBID when no kernel-verified dst (else trust Host/X-Tex-Upstream) |
| `TEX_PEP_PERMITS` (+ `TEX_PERMIT_SIGNING_SECRET`) | off | content-bound single-use egress permits (G10) |
| `TEX_PEP_SEAL` | off | seal a terminal-outcome receipt per request (G4) |
| `TEX_PEP_ANCHOR_TSA_URL` | unset | external RFC-3161 anchoring (needs `TEX_PEP_SEAL`) |
| `TEX_PEP_REQUIRE_IDENTITY` + `TEX_PEP_TRUSTED_ISSUERS[_FILE]` | off / `{}` | attested-credential requirement (G6) |
| `TEX_PEP_REQUIRE_TENANT_BINDING` | off | require `aud=tex://<tenant>` |
| `TEX_PEP_BROKER` (+ permits + signing secret) | off | credential broker (G12) |
| `TEX_PEP_FETCH_SURFACE` | off | http-mode emission-gate surface fetch (piggyback is primary) |

**PDP / Brain (the Render service):**

| Var | Default | Gates |
|---|---|---|
| `TEX_SEAL_DECISIONS` | off | proof-carrying SealedFact receipts on every decision (verdict-neutral; in-memory ledger) |

> ⚠️ The `TEX_PEP_*` flags belong to the **PEP proxy process**, NOT the Render
> `tex-web` (PDP) service. Setting them on `tex-web` is meaningless-to-harmful
> (e.g. `TEX_PEP_REQUIRE_DST=1` with no kernel loader would FORBID everything).

---

## 7. Current state — the honest one-screen summary

- **Live by default in the deployed PDP (Render `tex-web`):** the decision brain —
  DIFC `SECRET↛EGRESS` hard-deny, opaque/undecodable→ABSTAIN, the structural FORBID
  floor, the identity/governable/surface Tier-1 floor — plus the always-on
  hash-chained signed evidence chain.
- **One flag to light the proof-receipt moat:** `TEX_SEAL_DECISIONS=1` on `tex-web`.
- **Built + flag-gated (Body, default off):** permits, sealing, identity,
  tenant-binding, credential broker, orig_dst hardening.
- **Built + proven on a VM/cluster, needs a real deployment to enforce:** the eBPF
  kernel floor (Linux nodes) and born-in-a-box admission (a cluster). This is the
  **pilot** — route an agent fleet through the PEP; not a Render flag.
- **Research increment / proof-on-demand:** the ZK verdict-over-hidden-score proof
  (wired into the arbiter, not per-decision); the DIFC integrity-dual (voting-tier,
  not yet hard-floor).
- **Deliberately NOT built (the ceiling tier — post-customer, partly hardware):**
  zkML over real model execution (would wire DeepProve/EZKL, not the deactivated
  nanozk), seL4 / CHERI (emulation demo only without Morello silicon), DPU/SmartNIC
  off-host enforcement (needs the card; integrate NVIDIA DOCA).
- **Permanent (physics):** the irreducible limits in §1.

**Bottom line:** the decision-and-proof *brain* is wired into the live model and
verified firing; the enforcement *body* is built and proven and is one
**deployment** (the pilot) away from enforcing — not another commit or flag.

---

## 8. Verify it yourself

```bash
# Run from a checkout of main. Python 3.12 venv at ~/dev/tex/.venv
PYTHONPATH=src ~/dev/tex/.venv/bin/python -m pytest \
  tests/pep tests/authority tests/governance tests/identity \
  tests/zkprov tests/zkpdp tests/operator tests/test_structural_floor.py \
  --ignore=tests/zkprov/test_schnorr_group.py -q
# Known pre-existing reds (NOT this layer): tests/zkprov/test_schnorr_group.py
# (missing sympy import) + 3 governance-history route tests.

# eBPF floor (Linux only — a BTF kernel; e.g. an Ubuntu Lima/Colima VM):
cd pep/kernel && make vm-test     # builds, loads, verifier-checks all 5 progs + in-kernel behavior tests

# Born-in-a-box admission (needs Docker + kind):
make kind-up && make kind-test    # live apiserver deny/admit on a real cluster
```

---

## 9. Pointers (where each piece lives)

- Decision: `src/tex/governance/standing.py`, `src/tex/engine/pdp.py`,
  `src/tex/specialists/{judges,structural_floor,ifc_specialist}.py`,
  `src/tex/governance/private_data_exec/ifc/{noninterference,engine}.py`
- API seam: `src/tex/api/governance_standing_routes.py`, `src/tex/main.py`
- Proof: `src/tex/provenance/`, `src/tex/zkprov/`, `src/tex/zkpdp/` (offline:
  `src/tex/capstone/`)
- PEP proxy: `src/tex/pep/{proxy,decision_client,__main__}.py`,
  `src/tex/emission/`, `src/tex/authority/`, `src/tex/identity/`
- Kernel floor: `pep/kernel/` (C BPF + Go loader)
- Admission: `src/tex/operator/`, `deploy/helm/tex/`, `scripts/kind/`
- Deploy: `render.yaml` (the Render `tex-web` PDP runs `uvicorn tex.main:app`)
