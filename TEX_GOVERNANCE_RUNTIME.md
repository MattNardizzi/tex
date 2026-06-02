# TEX — Standing Governance Runtime

**The live PDP that switches on the instant ignition seals the inventory.**
Canonical spec. This is the document the governance build works from.

---

## 0. The one sentence

When the operator presses *Yes* and ignition completes discovery, Tex does
not merely hold an inventory it can watch — it begins **ruling on every action
every agent attempts, at all times, fail-closed**, and it is honest, out loud,
about exactly how much of the estate it can stop versus only see.

---

## 1. The split that dissolves the clunkiness: PEP ≠ PDP

To block an action in milliseconds, Tex must be on the path when it happens.
That is the only law of physics here. The mistake is thinking *Tex* must
become the thing in the path through per-agent integration. It must not.

- **PEP — Policy Enforcement Point.** The thing physically in the path that
  blocks. Commodity, deployment-bound, *not authored in this repo*. It does
  exactly one thing: ask Tex synchronously "may this cross?" and obey.
- **PDP — Policy Decision Point.** The brain that answers. **This is Tex.**
  It is the part nobody else has built right: everyone ships an empirical
  proxy; Tex ships a witness with a correctness floor.

You never route an agent *through* Tex. You put Tex *behind a boundary every
agent already crosses.*

### The three PEPs (deepest first), all calling the same PDP

| PEP | Mechanism | Catches | Per-agent work |
|---|---|---|---|
| **Kernel floor** | eBPF/Tetragon transparent `connect()` redirect + TLS uprobe | every process incl. rogue/headless/brand-new | **zero** |
| **Semantic chokepoint** | MCP / mesh gateway (reverse proxy, protocol-aware) | structured agent→tool traffic, tool-level meaning | deploy-time only |
| **In-process gate** | `enforcement/TexGate`, `@tex_gated`, ASGI proxy | first-party agents, with full intent | one wrap |

These are **depth, not alternatives.** The kernel floor is the *nothing
escapes unseen* guarantee and the literal answer to "even the second new ones
are added": a kernel hook governs any process the instant it makes a syscall —
there is no integration step for a new agent, because the wire is the kernel.
The gateway adds tool-level semantics. The in-process gate adds intent.

> **Lead decision: kernel-floor-first.** It is the only boundary that catches
> every agent with zero integration. Gateway-first reintroduces the
> observed-not-governed gap (it only governs agents that speak the protocol).

---

## 2. Why the decision is microseconds, not a model call

Discovery already did the slow work. Each agent's **capability surface** — its
sealed blast radius (allowed action types, channels, environments, recipient
domains, tools, MCP servers, data scopes) — is pre-computed on the registry
during the ignition scan and held in memory. So the inline decision is a
cache-hot structural check, not a round trip and not an LLM call.

Grounding (2026 state of the art): deterministic policy engines decide in
**<1 ms** (Cedar) to **~10 µs** (OPA→WASM); the bottleneck everyone names is
*fetching policy + data at decision time*. Tex removes that bottleneck by
pre-fetching the data at discovery time.

### Two tiers

**Tier 1 — Structural floor (inline, microseconds, fail-closed).**
- Unknown / unsealed / not-running agent → **FORBID**. The absence of a proof
  *is* a forbid. This is how new agents are governed by default: no seal, no
  PERMIT on file, first action denied — until the standing scan seals it.
- Action outside the agent's sealed capability surface → **FORBID**.
  (Capability confinement — the CaMeL line, enforced structurally.)

**Tier 2 — Deep adjudication (for actions that clear the floor).**
Delegates to the full six-layer `EvaluateActionCommand`, which fuses identity,
behaviour, capability, and content, seals the decision into the hash-chained
evidence ledger, and returns a verdict:
- `PERMIT` → released.
- `FORBID` → blocked, sealed.
- `ABSTAIN` → a `HeldDecision` is pushed to the held-decision sink (**the one
  unprompted voice**) and the action is blocked. An unresolved hold never
  releases on its own.

**Fail-closed is absolute.** No agent, no surface, deep PDP raised, deep PDP
unavailable → FORBID, never PERMIT. The lower bound holds even when Tex is
degraded.

---

## 3. The disruption: provable, not empirical — a witness, not a logger

Every shipping MCP/agent gateway does *empirical* enforcement: regex
prompt-injection, RBAC tool filters, rate limits, PII regex, LLM-as-judge. The
2026 literature is explicit that this cannot give a verifiable safety lower
bound and that the field must move to **formal runtime verification with
correctness guarantees** (FORGE; "Provably Secure Agent Guardrail"; "Agent
Security is a Systems Problem"). Nobody has shipped it.

Tex already contains the frontier primitives — confirmed in-tree, not stubs:

| Guarantee | Tex module | Frontier reference |
|---|---|---|
| Capability confinement | `camel/` (1,015 LoC) | CaMeL — secure-by-design control/data split |
| Information-flow / taint confinement | `safeflow/`, IFC specialist | FIDES — label-based IFC |
| Causal mediation (denials count) | `causal/` incl. `arm.py`, `_denial_record.py` (5,228 LoC) | Agentic Reference Monitor; "causality laundering" defense |
| Statically-verified policy | `pcas/` Datalog compiler | Datalog: tractable contradiction/redundancy/reachability checks |
| Statistically-sound drift | `drift/` (anytime-valid, BOCPD, CUSUM; 2,744 LoC) | sequential change-point, false-alarm control |
| Cryptographic workload identity | IdP-root discovery + behavioural birth | WIMSE / SPIFFE+SPIRE (IETF draft-klrc-aiagent-auth-00) |
| Sealed evidence | hash-chained ledger + seal-on-decision | admissible, provable after the fact |
| Fail-closed | `enforcement/gate.py` guarantee + Tier-1/2 default | lower bound survives degradation |

The witness difference: Tex can prove not only what it **blocked** but what it
**permitted**, cryptographically. No gateway does this.

---

## 4. Activation flow — what fires the second discovery completes

```
operator presses Yes
        │
        ▼
POST /v1/surface/discovery/ignite            (discovery_surface_routes.py)
        │  is_real_tenant = true
        ├─► discovery_service.scan(...)       seal a behavioural birth per agent
        ├─► scan_scheduler.enroll_tenant(t)   standing watch begins (re-scan/drift/dormancy)
        ├─► standing_governance.activate(t)   ◄── THE KEYSTONE: live PDP switches on
        └─► ignition.fire(t)                  the one spoken line, once
        │
        ▼
from here, every enforcement point calls:
POST /v1/govern/decide  ──►  StandingGovernance.decide(...)
        Tier 1 floor (µs, fail-closed) → Tier 2 deep PDP (sealed) → PERMIT/FORBID/ABSTAIN→voice
GET  /v1/govern/posture ──►  governed-vs-observed boundary, spoken
```

**Correctness does not depend on a refresh tick.** `decide()` always reads the
*live* registry. A brand-new agent the standing scan has not yet sealed simply
isn't in the registry → fail-closed floor forbids it until it is. The scan's
job is to *seal* new agents; the moment it does, `decide()` sees them.

---

## 5. What this build wired (in `tex_4`)

### PDP (decision)
New:
- `src/tex/governance/standing.py` — `StandingGovernance` (the PDP), `DecisionOutcome`, `GovernedPosture`.
- `src/tex/api/governance_standing_routes.py` — `/v1/govern/decide`, `/v1/govern/posture`, `/v1/govern/forbid-set`.

Wired:
- `src/tex/main.py` — `app.state.standing_governance` built from the existing
  registry + `EvaluateActionCommand` + held sink + provenance engine; router registered.
- `src/tex/api/discovery_surface_routes.py` — `ignite()` calls
  `standing_governance.activate(tenant)` for a real tenant, after the inventory
  is sealed and the watch enrolled.

### PEP (enforcement) — all three points, composed
- **In-process** — `src/tex/enforcement/standing_transport.py`:
  `StandingGovernanceTransport` + `build_standing_gate(...)`. Routes the
  already-built `TexGate` (and its LangChain/CrewAI/async adapters) through the
  full two-tier PDP, so the highest-fidelity PEP makes the same ruling as the
  network ones.
- **Transparent proxy / sidecar** — `src/tex/pep/` (`proxy.py`,
  `decision_client.py`, `__main__.py`): the userspace data plane the kernel
  redirects into and the standalone MCP/HTTP gateway. Identity-aware,
  MCP-aware, fail-closed, with filtered tool discovery. Run as a sidecar with
  `python -m tex.pep`.
- **Kernel floor** — `pep/kernel/` (repo root, deploy artifact): the eBPF
  CO-RE `connect()` redirector + inline verdict fast-block (`bpf/`), the Go
  loader/agent (`agent/`), and the build + Kubernetes manifests (`Makefile`,
  `Dockerfile`, `deploy/`). Compiled against the target kernel at deploy;
  authored against the fixed PDP contract.

All Python changes are additive and defensive. **Verified in-container:**
- app composes; `/v1/govern/{decide,posture,forbid-set}` live
- PDP: unknown/unsealed agent → FORBID (floor); out-of-surface → FORBID
  (floor); in-surface → full six-layer engine (IFC + PCAS Datalog + contracts),
  ABSTAIN → the voice; posture speaks governed-vs-observed
- in-process gate: out-of-surface wrapped callable is blocked and never runs
- proxy: unknown agent → 403, out-of-surface MCP call → 403, cold-tenant
  ABSTAIN → 403 (fail-closed), filtered discovery strips unauthorized tools on
  a permitted forward
- regression: discovery/ignition (38) and enforcement/transport (160) tests
  pass unchanged

---

## 6. Deploy posture (the PEP seam is now code, not a TODO)

The PDP is in-process and live. The PEPs:

- **In-process gate** and **transparent proxy** are shipped Python, tested, and
  run today (the proxy as a sidecar via `python -m tex.pep`).
- **Kernel floor** is shipped source under `pep/kernel/`, compiled and attached
  at deploy (`make build` → `docker build` → `kubectl apply -f deploy/`). It is
  the only layer that cannot run in a pure-Python container, by nature — it is
  an eBPF program plus a Go loader bound to the target kernel. It is real,
  idiomatic, and complete against the contract; it is not exercised by the
  in-container test suite because there is no kernel to attach to there.

The contract every PEP codes against is fixed and shipped:
`POST /v1/govern/decide` (obey `released`) and
`GET /v1/govern/forbid-set` (warm the inline cache).

---

## 8. Auto-deploy & auto-enroll (the ambient way)

The PEP installs once per environment and then enrolls workloads
automatically. "Deploy the PEP" is three different questions, each with a
built-in mechanism:

- **Every node** — the kernel-floor `DaemonSet` auto-schedules onto every node
  and any new node that joins. Zero action.
- **Every pod / agent** — turn governance on for a namespace with one label,
  `tex.systems/govern=enabled`, and every new pod is governed with no per-pod
  YAML and no restart. Two routes, same label, same enrollment scope:
  - *Sidecar injection* (`src/tex/operator/webhook.py`): a
    `MutatingAdmissionWebhook` scoped to governed namespaces injects the
    proxy + an egress-redirect init container at pod creation. Portable, no
    node privilege. Pods opt out with `tex.systems/govern-exclude=true`.
  - *Kernel floor* (sidecarless): the eBPF `DaemonSet` governs every workload
    on the node, brand-new ones included, with no injection.
- **First install / new clusters** — GitOps. `deploy/gitops/argocd-application.yaml`
  makes Argo CD install Tex and keep it reconciled (self-healing, fleet-wide,
  onto newly provisioned clusters). "Deploy" becomes "merge."

The operator (`src/tex/operator/`, run as `python -m tex.operator`) is the
enrollment controller (watches namespace labels → `EnrollmentScope`) plus the
webhook plus a `/scope` endpoint the node agents poll. The whole stack — PDP,
operator, webhook, RBAC, cert, optional kernel `DaemonSet` — installs from one
Helm chart (`deploy/helm/tex`).

The one irreducible step is a single, declarative, privileged grant (the Helm
install / the GitOps commit) — the same one-time grant Cilium, Tetragon, and
Istio require, and a feature of the trust model: a system that could load
kernel-level interception with no privileged consent would be malware. The
honest ceiling is *one declarative grant, folded into provisioning, then
automatic forever* — every node, pod, agent, and new cluster.

**Verified in-container:** enrollment reconciles from namespace labels (label
on → governed with tenant; label off → dropped); the webhook injects
`tex-init` + `tex-proxy` only in governed namespaces, skips excluded and
already-injected pods (idempotent). Helm renders at deploy (helm unavailable in
the test sandbox); GitOps manifest validates.

---

## 7. Doctrine invariants (do not erode)

1. PEP is commodity; PDP is the moat. Never build a pipe.
2. Fail-closed everywhere. The absence of a proof is a forbid.
3. The decision is microseconds because discovery pre-fetched the data.
4. ABSTAIN is the only routine unprompted voice. Discovery counts are pull-only.
5. Provable, not empirical. Seal every verdict — permits included.
6. Be honest about the edge of control (governed vs. observed), the same way
   provenance is honest about the edge of sight. Never claim to govern an
   estate you have only mapped.
