"""
Tex Aegis — Formal proofs.

This package houses Lean 4 / Mathlib4 proof artifacts that
mechanically verify load-bearing properties of the Tex governance
layer.

Files
-----
- ``non_interference.lean`` — Proves that the FIDES product-lattice
  capability algebra is monotone: every operation preserves or raises
  the security label of every data value. This is the precondition
  for non-interference (Volpano-Smith 1996). The proof is in abstract
  form; refinement to the Python interpreter is intentionally not
  attempted (would require a verified compiler).

Building
--------
The Lean files are not part of the Python build. To check them::

    pip install elan       # one-time
    elan default leanprover/lean4:v4.10.0
    lake build             # from a Mathlib4 lake project pointing here

CI does not build Lean for this delivery; the file is intended for
publication review and manual proof checking.
"""
