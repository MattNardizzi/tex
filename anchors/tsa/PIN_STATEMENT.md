# TSA pin statement — freetsa.org (RFC 3161)

This file pins the **external Time-Stamp Authority** whose signature proves the
age of a Tex evidence/decision checkpoint tree-head **without trusting Tex's
signing key**. Pinning is the load-bearing, out-of-band act: the offline
verifier (`tex.interchange.external_anchor.verify_anchor_receipt`) only trusts a
timestamp token that is cryptographically signed by the certificate pinned here.

> "Independent of Tex's key" is a fact about **which certificate you pin**, not
> something Tex's code can self-assert — the same discipline as
> `gix_witness.py`'s structural `federated=False`. A relying party who does not
> trust Tex should fetch this CA cert from freetsa.org **themselves** and confirm
> the fingerprint below before relying on any anchor.

## Pinned certificate

- **Authority:** freetsa.org (a free, public, no-account RFC 3161 TSA)
- **File:** [`freetsa_cacert.pem`](freetsa_cacert.pem) (the Free TSA Root CA)
- **Subject:** `C=DE, ST=Bayern, L=Wuerzburg, CN=www.freetsa.org, OU=Root CA, O=Free TSA`
- **Validity:** `2016-03-13T01:52:13Z` → `2041-03-07T01:52:13Z`
- **DER SHA-256:** `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc`
- **PEM file SHA-256:** `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`

The TSA leaf cert that actually signs each token is **issued by** this Root CA
and carries the `id-kp-timeStamping` extended key usage; the verifier checks
both (chain to this pin **and** the timestamping EKU).

## Verify the pin independently

```bash
curl -s https://freetsa.org/files/cacert.pem -o /tmp/freetsa_cacert.pem
# DER fingerprint must equal the value above:
openssl x509 -in /tmp/freetsa_cacert.pem -outform DER \
  | openssl dgst -sha256
# and it must byte-match the committed pin:
diff <(openssl x509 -in /tmp/freetsa_cacert.pem -outform DER | sha256sum) \
     <(openssl x509 -in anchors/tsa/freetsa_cacert.pem -outform DER | sha256sum)
```

## Provenance of this pin (honesty)

- The DER/PEM SHA-256 values above were **computed this session (2026-06-17)**
  from the bytes fetched from `https://freetsa.org/files/cacert.pem`, and the
  offline verifier was confirmed to accept a **real** freetsa.org token
  (`genTime 2026-06-17T15:32:26Z`) pinned to this cert.
- This is `research-early`: one TSA is a single trust root. The strongest
  long-term anchor is Bitcoin-anchored OpenTimestamps (no CA, proof-of-work
  trust), which the anchor interface is structured to add as an alternate
  backend. Until then, the honest claim is: "this tree-head existed no later than
  `<genTime>`, per freetsa.org, verified against freetsa's key — not Tex's."

## Rotation

To pin a different / additional authority, drop its CA (or leaf) cert here and
point `TEX_EVIDENCE_ANCHOR_TSA_CERT` at it. The verifier accepts an **exact leaf
pin** (fingerprint match) or a **CA pin** (token's signer cert is directly issued
by the pinned CA), so rotation under one CA needs no code change.
