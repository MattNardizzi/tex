# Emission gate — proxy integration snippet (for the EGRESS / `pep/proxy.py` merge step)

> **This file is documentation only.** Per the POW-INFERENCE track rules, this
> thread does **not** edit `src/tex/pep/proxy.py` (the EGRESS thread owns it).
> Below is the 1–2 line integration to apply at merge time, plus the exact seams
> it reuses so the change stays additive.

## What it does

Adds Approach B (provider-trusted re-assertion) as a **third, earlier enforcement
point** in the egress path: when the upstream is a known LLM provider and the body
is a chat/completions request, rewrite the request to the permitted tool subset
*before* it leaves Tex. The agent cannot re-add a tool Tex stripped, provided it
can reach the provider only through the proxy.

## Where it goes

In `proxy.handle` (`src/tex/pep/proxy.py:305`), on the **outbound forward path**,
right before the body egresses (the `self._forward.send(...)` at
`src/tex/pep/proxy.py:441`). It reuses the surface the proxy already resolves via
`_resolve_surface(tenant, agent_id, agent_external_id)`
(`src/tex/pep/proxy.py:823`) — the *same* `CapabilitySurface` the discovery
filter `_filter_tools_list` uses, so no new policy model is introduced.

## The snippet (additive)

```python
# top of proxy.py (imports)
from tex.emission.constraint import compile_constraint
from tex.emission.provider_rewrite import detect_provider, rewrite_provider_request
from tex.emission.seal import seal_constraint, APPROACH_PROVIDER_TRUSTED

# inside proxy.handle, on the outbound path, just before self._forward.send(...):
surface = self._resolve_surface(tenant, agent_id, agent_external_id)
if surface is not None and detect_provider(parsed_json := _try_json(body)) is not None:
    constraint = compile_constraint(surface)
    new_body = json.dumps(
        rewrite_provider_request(parsed_json, constraint)
    ).encode("utf-8")
    fwd_headers["content-length"] = str(len(new_body))
    body = new_body
    # optional: proof-carrying — seal which allowlist H this turn decoded under
    seal_constraint(
        self._seal_ledger,                       # the SealedFactLedger already wired
        constraint,
        subject_id=str(request_id),
        approach=APPROACH_PROVIDER_TRUSTED,
        agent_id=str(agent_id) if agent_id else None,
    )
```

Notes for the merge:

- `_try_json` and `json` are already imported in `proxy.py`; `fwd_headers` and
  `body` are the variables `handle` already forwards (`src/tex/pep/proxy.py:441`).
- `rewrite_provider_request` is **pure** and returns a new dict — it never mutates
  the parsed body, and returns an unchanged copy for an unrecognized dialect, so
  wrapping it is safe even when detection is wrong.
- `seal_constraint` is **fail-closed / observation-only**: `ledger is None` → no-op;
  an append failure is logged and the request proceeds. It never changes what
  egresses. If the proxy has no `SealedFactLedger` wired yet, pass `None`.
- Content-Length must be reset because the rewritten body changes size — mirrors
  exactly what `_filter_tools_list` already does at `src/tex/pep/proxy.py:820`.

## Maturity / honest floor (carry into any release note)

- Tool-name strip + `tool_choice` narrowing: **production** (reliable, provider-
  independent for the menu). It is `provider-trusted`, not Tex-enforced
  unrepresentability — that tier is Approach A (`tex.emission.vllm_mapping`).
- Value-level `pattern` shaping: **research-early**, provider-dependent
  (`strict_structured_output=True` is opt-in and may break OpenAI's strict subset).
- Covers only the tool-emission actuator, only where Tex constrains the decoder,
  only at name/shape granularity. A permitted tool can still semantically launder;
  intent stays the PDP's job. Sound only inside the admission ("born-in-a-box")
  regime that funnels all actuation through the gated decoder.
