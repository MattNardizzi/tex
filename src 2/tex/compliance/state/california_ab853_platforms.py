"""
California AB 853 — Large Online Platform obligations.

AB 853 (signed 13 October 2025) extends the California AI Transparency
Act (SB 942 / CAITA) to **large online platforms** that distribute
content, with effective date **1 January 2027**.

§ 22757.2 obligations (as added by AB 853)
------------------------------------------
A "large online platform" must, beginning 1 January 2027:

  (1) Detect whether system-provenance data is present in any content
      it distributes.
  (2) Provide a user interface that discloses the availability of
      system provenance data — including whether content was generated
      or substantially altered by a GenAI system, or captured by a
      capture device — and provides certain information on the
      content's authenticity and modification history.
  (3) Allow users to inspect system provenance data in an easily
      accessible manner.

A "GenAI hosting platform" — an internet website or application that
makes available for download the source code or model weights of a
GenAI system to a California resident — must, beginning 1 January 2027,
not knowingly make available a GenAI system unless the system supports
manifest and latent disclosure capabilities equivalent to those required
of covered providers under § 22757.1.

Status (May 2026)
-----------------
**NOT YET EFFECTIVE.** Module exists as a P1 stub so the
``FrontierFlags.compliance`` flag and the ``tests/frontier/
test_scaffolding_imports.py`` registry can find a real module path
ahead of the 1 January 2027 effective date.

References
----------
- AB 853 (Cal. Stats. 2025) amending Cal. Bus. & Prof. Code § 22757
  et seq.
- C2PA Specification 2.x (the de-facto provenance-data standard)

Priority: P1.
"""


def emit_large_online_platform_evidence() -> dict:
    """
    TODO(P1): emit AB 853 § 22757.2 evidence record for a large online
        platform's content-distribution event:
          - assert provenance-data detection occurred
          - assert UI-display obligation was met
          - assert user-inspect path is exposed
        Effective 1 January 2027.
    """
    raise NotImplementedError("AB 853 large online platform evidence")


def emit_genai_hosting_platform_evidence() -> dict:
    """
    TODO(P1): emit AB 853 GenAI-hosting-platform evidence record for a
        model-weights or source-code download event:
          - assert the hosted GenAI system supports the § 22757.1
            manifest + latent disclosure obligations
          - bind to the C2PA manifest (or equivalent industry-standard
            artifact) attesting to the hosted system's compliance
        Effective 1 January 2027.
    """
    raise NotImplementedError("AB 853 GenAI hosting platform evidence")
