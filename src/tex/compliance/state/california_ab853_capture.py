"""
California AB 853 — Capture Device Manufacturer obligations.

AB 853 (signed 13 October 2025) extends the California AI Transparency
Act (SB 942 / CAITA) to **capture device manufacturers**, with effective
date **1 January 2028**.

§ 22757.3 obligations (as added by AB 853)
------------------------------------------
For any "capture device" produced for sale in California from
1 January 2028, a capture device manufacturer must:

  (1) Provide users with the option to include a latent disclosure
      identifying the capture device and the time and date of the
      content's creation or alteration in content captured by the
      device.
  (2) Embed latent disclosures in content captured by the device
      **by default**.

A "capture device" is a device capable of recording photographs, audio,
or video content — including built-in cameras, microphones, and voice
recorders — for sale in California.

Status (May 2026)
-----------------
**NOT YET EFFECTIVE.** Module exists as a P2 stub so the
``FrontierFlags.compliance`` flag and the ``tests/frontier/
test_scaffolding_imports.py`` registry can find a real module path
ahead of the 1 January 2028 effective date.

References
----------
- AB 853 (Cal. Stats. 2025) amending Cal. Bus. & Prof. Code § 22757
  et seq.
- C2PA Specification 2.x (the de-facto provenance-data standard for
  capture-device assertions)
- IPTC ``digitalSourceType`` controlled vocabulary, term
  ``digitalCapture`` (the capture-device-content marker)

Priority: P2.
"""


def emit_capture_device_evidence() -> dict:
    """
    TODO(P2): emit AB 853 § 22757.3 capture-device evidence record:
          - assert latent-disclosure-by-default is enabled on the
            capture device
          - bind to the C2PA capture-device assertion
            (``c2pa.actions.v2`` with ``digitalSourceType =
            digitalCapture``)
          - carry the device identifier and capture timestamp
        Effective 1 January 2028.
    """
    raise NotImplementedError("AB 853 capture device evidence")
