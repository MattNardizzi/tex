# SANDBOX_LIVE.md — the practice course

A full-scale replica you rehearse inside. The synthetic Meridian estate runs
through the **real** pipeline; the only thing that isn't real is that the bank
is a set. You press "Yes" once on the interface, Tex maps the estate and goes
live, and a driver keeps ~200 agents acting for days while Tex rules on every
action and surfaces the holds — so you can watch how Tex actually runs and
finish building the interface against real, sealed data.

## The shape

```
  interface (Vercel)            web service (Render)                 worker (Render)
  ─────────────────             ─────────────────────                ───────────────
  press "Yes"  ───ignite──▶  /v1/surface/discovery/ignite
                             (meridian-7 = real tenant)
                               · maps 200 agents
                               · enrols standing watch
                               · activates live PDP
                                        ▲
                             tex-sim-driver waits for ◀── --wait-for-ignition
                             ignition, then drives:
                               POST /v1/govern/decide  ──┐
                                                         │ PERMIT / FORBID → sealed
                                                         │ ABSTAIN → sealed + HELD
                                                         ▼
  held card on glass  ◀──── /v1/vigil  ◀──── held sink
```

## Why `/v1/govern`, not `/evaluate`

The held sink is fed by **StandingGovernance** (the `/v1/govern/decide`
enforcement path), not by `EvaluateActionCommand` (the `/evaluate` audit path).
Drive `/evaluate` and you get sealed decisions and a verdict mix in the
terminal but **nothing on the glass** — the estate looks alive in the logs and
dead on the interface. The driver defaults to `--drive govern`. (Run
`--drive evaluate` if you ever want to *see* that difference.)

Both paths seal hash-chained evidence (govern's Tier-2 deep adjudication runs
the same PDP), so "can I see this decision" / "can I see this agent" have a real
corpus to ground on either way. Govern just also surfaces the holds.

## Run it (Render, unattended, for days)

1. On the **web service**, set:
   ```
   TEX_SANDBOX=1
   TEX_SANDBOX_TENANT=meridian-7
   TEX_SANDBOX_SEED=7
   ```
   `TEX_SANDBOX_TENANT` is what makes "Yes" govern the estate instead of just
   mapping it. Redeploy.

2. On **Vercel**, confirm `VITE_TEX_TENANT=meridian-7` (Production + Preview).

3. Add the **worker** (`render.yaml`, or New → Background Worker). It boots,
   sees `meridian-7` un-ignited, and waits — silent — for your press.

4. Open tex.systems. You get the day-one door: **"Tex." → "Let's begin
   mapping." → Yes / No.** Press **Yes**. Tex maps 200 agents, speaks the
   count, goes live. The worker wakes within ~2s, onboards the governed cohort,
   and starts the stream. Within a heartbeat or two you'll see the first
   ABSTAIN surface as a held card.

## Run it (laptop, zero cost)

Identical, but it dies when your machine sleeps:

```
PYTHONPATH=src python -m tex.sim live reference \
  --wait-for-ignition --drive govern --rate 1 \
  --onboard standard --duration 2d \
  --base-url https://tex-uh4j.onrender.com
```

Use `tmux`/`nohup` so it survives the terminal closing.

## Re-staging the day-one moment

Ignition fires once per tenant. To rehearse the opener again without a
redeploy (sandbox only — refused with 404 when `TEX_SANDBOX` ≠ `1`):

```
curl -X POST "https://tex-uh4j.onrender.com/v1/surface/discovery/reset?tenant_id=meridian-7"
```

The discovered inventory is left intact, so the next "Yes" re-scans it and the
spoken count stays genuine. The worker re-onboards on its next heartbeat.

## Knobs

| flag | default | what it does |
|------|---------|--------------|
| `--rate` | `1` | mean actions/sec across the estate |
| `--abstain-rate` | `0.18` | share of attempts reaching for ABSTAIN content (more holds) |
| `--forbid-rate` | `0.06` | share reaching for FORBID content |
| `--onboard` | `standard` | trust tier for the governed cohort; `none` stresses the cold path |
| `--duration` | — | `2d` / `36h` / `90m`; omit for until-Ctrl-C |
| `--drive` | `govern` | `govern` (holds surface) or `evaluate` (audit only) |

Raise `--abstain-rate` while you're working on the held card and the proof
depth — it gives you more cards to reach into.

## Reading the corpus directly (for building the voice layer)

The voice endpoints (`/v1/ask`, `/v1/speak`, `/v1/voice/token`) are **not built
yet** — the frontend calls them but there is no server side. When you build
`/v1/ask`, it grounds on data the rig already produces:

- **a decision** → `GET /decisions/{id}/replay`, `GET /decisions/{id}/evidence-bundle`
- **a held line's story** → `POST /v1/vigil/explain`
- **an agent's owner / coverage** → `GET /v1/surface/discovery/owner/{id}`,
  `GET /v1/surface/discovery/coverage/{id}`
- **the inventory** → `GET /v1/agents`, `GET /v1/agents/{id}`, `/ledger`

So "can I see this decision" / "can I see this agent" is recall over a
populated ledger and registry, not new plumbing.
