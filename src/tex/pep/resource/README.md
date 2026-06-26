# `tex.pep.resource` — the resource-side (demand) PEP (B3)

A **downstream resource** (the actuator — a vault, a mailer, a payments API)
imports this package to **DEMAND a Tex-issued capability token (a TG-PCC)**
before it acts, and to **verify it offline**. No network. No Tex runtime.

```python
from tex.pep.resource import verify_tgpcc, PresentedRequest

chk = verify_tgpcc(
    artifact,                          # the presented TG-PCC ("body.sig" or {token})
    PresentedRequest(method, resource, params),  # the call actually being made
    dpop_proof,                        # the holder's DPoP/PoP proof
    pinned_jwks,                       # fetched ONCE from /.well-known/tex-jwks.json
    pinned_epoch,
    expected_issuer="tex-authority",
)
if not chk.ok:
    deny(chk.reason)                   # default-DENY
```

It returns `ResourceCheck(ok, reason, ...)` and **default-denies**: no token, an
unverifiable leg, or any missing input is a denial — **never a bypass**.

## The 7-step check

`verify_tgpcc` is a **thin assembler** over the audited verify primitives. It
writes **zero new crypto** — it ports already-proven byte discipline from the
authority plane (see *Import purity* below):

0. **Demand-Or-Deny** — no artifact / no token ⇒ DENY (`"no artifact"`). A
   missing credential is a denial, not a bypass.
1. **Intent** — recompute the expected intent commitment from the **presented**
   `(method, resource, params)` (not from the token).
2. **Signature + epoch + expiry + issuer + intent-bind** — one
   `verify_capability_token` call over the pinned JWKS. Altered params after mint
   ⇒ `"intent mismatch"` DENY (confused-deputy defense).
3. **Holder (cnf.jkt / DPoP)** — a sender-constrained token requires a valid
   DPoP proof whose key thumbprint equals the signed `cnf.jkt`. A token *with*
   `cnf` but no/invalid proof DENIES — never a bearer downgrade.
4. **Provenance floor** — re-check `label ⊒ floor` from the signed claims. Under
   the default-deny posture a missing/insufficient floor DENIES.
5–6. Issuer/epoch/expiry fold into step 2; optional EAT evidence appraisal is
   out of scope for this leg.
7. **Default-DENY** — any missing/unverifiable leg returns DENY with the first
   failing reason preserved for the audit/refusal payload.

## What ships

- `verify.py` — `verify_tgpcc` + `verify_capability_token` +
  `verify_prov_commit_floor` + `canonical_intent_commit` (the pure verifier).
- `middleware.py` — `TexDemandMiddleware` (a pure-ASGI middleware that demands a
  TG-PCC header on protected routes) and `asgi_auth_request_app` (a tiny
  204/401/403 endpoint).
- `nginx_auth_request.conf` — an nginx `auth_request` reference that fronts a
  resource and gates it on the verifier subrequest.

## Import purity (load-bearing)

A resource must be able to import the verifier **without** dragging in the Tex
app / PDP / proxy / governance stack. Importing `tex.authority.broker` (or even
`tex.authority.pop` / `tex.authority.taint_label`) pulls **~1300 modules**
including numpy, scipy, starlette and `tex.engine.pdp` — a package-`__init__`
side-effect, not a property of the verify logic. So this package imports **only
the standard library and `cryptography`'s Ed25519 primitive**, and re-expresses
the audited algorithm faithfully. The byte-for-byte parity with
`broker.verify_with_jwks` / `verify_prov_commit_floor` / `pop.verify_pop_proof`
is pinned by `tests/pep/test_resource_verify.py`, which mints **real** broker
tokens and verifies them here, plus a clean-subprocess regression test asserting
the heavy modules stay **out** of `sys.modules`.

## Default-OFF

The TG-PCC plane is dark unless the **issuer** ran with `TEX_TGPCC=1` and a
pinned signing key. With it off the published JWKS is `{"keys": []}` and this
verifier DENIES every token (`"no matching key"`) — the correct fail-closed
posture. Nothing in Tex's default boot imports this package, so it is inert
until a resource explicitly wires it in.

## HONEST boundary — read this

- **Demand-verification, NOT un-bypassable enforcement.** Mounting the
  middleware (or fronting with the nginx recipe) makes the resource demand a
  TG-PCC **only for traffic that traverses the verifier**. A path that does not —
  a raw API key, an alternate port, a direct socket to the upstream — is **not**
  covered. The non-bypassable property is **POSITIONAL-ONLY** (the same limit
  Entra / Faramesh / SatGate concede). To make the position real: pin the
  upstream to loopback and route **all** ingress through the verifier.

- **The verifier SHAPE is PARITY.** An offline public-key + intent-bind +
  holder-bind check is the deployed shape AttestMCP / AIP / Biscuit / Vouchsafe
  already ship. **B3 owns no novel mechanism.**

- **The novelty is INHERITED from B1+.** The one leg whose value is
  beyond-frontier is step 4: re-checking the `prov_commit` **integrity floor** —
  a check no shipped demand-verifier performs, because no shipped minter puts a
  **gated provenance label inside the signed token**. The taint-gated MINT (B1+)
  is what makes that label exist as a precondition of the signature; B3 merely
  re-checks it offline. Say it that way — do not relabel B3 as beyond-frontier.

- **Residual replay (labeled, not hidden).** The holder check is stateless and
  keeps no jti cache, so a captured DPoP proof can be replayed within `max_age`
  (default 120s) against the same token. `ResourceCheck.jti` is surfaced so a
  resource can wire its own seen-jti dedupe store for true single-use.

- **Ed25519 is classical/pre-quantum.** Fine for today's model; not PQ. Do not
  overclaim. RFC 7638/8037 thumbprint interop with a third-party resource server
  is internally byte-consistent but **unverified** against an external DPoP
  vector.
