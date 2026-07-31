;;
;; cpsa_models/tex_cosign_v2.scm
;;
;; CPSA (Cryptographic Protocol Shapes Analyzer, MITRE, v4.4.5) model
;; of the Tex evidence cosign + outer C2PA signature composition.
;;
;; Reference: Thread 6 FRONTIER_DELTA. arxiv 2604.24890 §"Recommendations"
;; calls for formal-methods analysis of provenance protocols. This
;; file is that analysis for the Tex composition. Run with:
;;
;;     cabal install cpsa            ;; install CPSA v4.x
;;     cpsa tex_cosign_v2.scm        ;; produces .txt shapes
;;     cpsashapes tex_cosign_v2.txt  ;; reduces to canonical shapes
;;
;; The vendored output is in cpsa_models/tex_cosign_v2_shapes.json
;; (parsed for CI; see src/tex/c2pa/cpsa_shapes.py).
;;
;; Protocol roles
;; --------------
;;
;; * Tex signer (TS) — produces the manifest, holds the OUTER C2PA
;;   private key (ECDSA P-256 or Ed25519, C2PA 2.4 §13.2 allow-list)
;;   AND the COSIGN private key (ML-DSA-65 in production, Ed25519 in
;;   CI). Composes the Merkle root over seven typed leaves and signs.
;;
;; * Verifier (V) — receives the manifest. Re-derives the Merkle root
;;   from the claim's assertions, verifies the outer signature
;;   against the claim CBOR, and verifies the cosign signature
;;   against the Merkle root.
;;
;; * Adversary (Dolev-Yao) — implicit. Can read, intercept, modify,
;;   and re-inject messages but cannot forge signatures without the
;;   corresponding private key.
;;
;; Security goals
;; --------------
;;
;; G1 (authentication of outer signature):
;;   If V accepts an outer signature S_outer as valid for claim
;;   bytes C, then TS produced S_outer on C with the outer private
;;   key. (Standard ECDSA / EdDSA authentication.)
;;
;; G2 (authentication of cosign):
;;   If V accepts a cosign signature S_cosign as valid for Merkle
;;   root R, then TS produced S_cosign on R with the cosign private
;;   key.
;;
;; G3 (binding: outer covers cosign):
;;   If V accepts S_outer on C, then C contains the cosign assertion
;;   (label "tex.evidence_cosign") with the same R that the cosign
;;   signed. This rules out the cross-validator contradiction attack
;;   #3 from arxiv 2604.24890.
;;
;; G4 (binding: cosign covers every attack-defense leaf):
;;   If V accepts S_cosign on R, then R was computed from a Merkle
;;   tree containing the seven typed leaves at their stable labels.
;;   This is enforced structurally by the Merkle root computation;
;;   we state it here for CPSA to confirm no alternate shape exists.
;;
;; G5 (no signature reflection):
;;   No execution shape exists where an adversary can re-use S_cosign
;;   on a different Merkle root R' even if every public element of R'
;;   matches R, because the cosign signing input is the raw 32-byte
;;   root and the signature is over those exact bytes.
;;

(herald "Tex evidence cosign v2 — outer + Merkle cosign composition"
        (algebra diffie-hellman)
        (bound 8))

(defprotocol tex-cosign-v2 basic

  ;; Outer-signing role: produces the C2PA outer COSE_Sign1 over the
  ;; canonical claim CBOR, which includes the tex.evidence_cosign
  ;; assertion carrying the Merkle root R.
  (defrole outer-signer
    (vars (ts name) (claim text) (root data) (s-outer skey))
    (trace
      ;; TS computes R, builds claim C containing R, signs C with the
      ;; outer key (s-outer).
      (send (cat ts claim root (enc claim s-outer)))
    )
    (uniq-orig root)
    (non-orig s-outer))

  ;; Cosign-signing role: signs the raw Merkle root R with the cosign
  ;; private key (s-cosign). The same TS principal holds both keys.
  (defrole cosign-signer
    (vars (ts name) (root data) (s-cosign skey))
    (trace
      (send (cat ts root (enc root s-cosign)))
    )
    (uniq-orig root)
    (non-orig s-cosign))

  ;; Verifier role: receives both signatures, checks them against
  ;; the corresponding public keys, and binds them via the root.
  (defrole verifier
    (vars (ts name) (claim text) (root data) (s-outer skey) (s-cosign skey))
    (trace
      (recv (cat ts claim root
                 (enc claim s-outer)
                 (enc root s-cosign)))
    )
    (non-orig s-outer s-cosign))
)

;; Goal G1 + G2 + G3 + G4: the verifier-point-of-view skeleton.
(defskeleton tex-cosign-v2
  (vars (ts name) (claim text) (root data) (s-outer skey) (s-cosign skey))
  (defstrand verifier 1 (ts ts) (claim claim) (root root)
             (s-outer s-outer) (s-cosign s-cosign))
  (non-orig s-outer s-cosign)
  (comment "If the verifier accepts both signatures, CPSA should "
           "find exactly the one shape where TS executed both "
           "outer-signer and cosign-signer with the same root, "
           "and no shape where any signature was produced by anyone "
           "other than TS."))

;; Goal G5: no signature reflection across roles. We model an attempt
;; to reuse an outer signature as a cosign signature.
(defskeleton tex-cosign-v2
  (vars (ts name) (claim text) (root data) (s-outer skey))
  (defstrand outer-signer 1 (ts ts) (claim claim) (root root) (s-outer s-outer))
  (non-orig s-outer)
  (comment "CPSA must find no shape where (enc claim s-outer) is "
           "consumed as if it were (enc root s-cosign). Type-disjointness "
           "of `claim` (text) vs `root` (data) is the structural barrier."))
