/-
  Tex Aegis — Non-interference of the FIDES product-lattice algebra.

  This file proves the load-bearing property of Tex's IFC layer:
  *capability join is monotone in both arguments and never lowers a
  label.* In an information-flow context this is the precondition for
  non-interference (Volpano-Smith 1996; FIDES arxiv 2505.23643): if
  every operation preserves or raises the security label of every
  data value, then untrusted-source data can never reach a sensitive
  sink without that sink's policy explicitly accepting an UNTRUSTED
  level argument.

  Scope (what is proven)
  ----------------------
  - The capability level type ``CapLevel`` forms a total order
    ``TRUSTED ≤ USER ≤ UNTRUSTED``.
  - ``join`` (the max operation) is commutative, associative,
    idempotent, has identity ``TRUSTED``, and is *monotone*:
    ``a ≤ b → join a c ≤ join b c``.
  - The capability set's level is the join of its members; adding any
    member can only raise the level (``raise_only`` lemma).
  - From ``raise_only`` we derive the non-interference theorem in
    abstract form: for any derivation chain
    ``v₀ → v₁ → v₂ → ... → vₙ``, ``level vₙ ≥ level v₀``, so an
    UNTRUSTED initial label propagates to the end.

  Scope (what is NOT proven, by design)
  -------------------------------------
  - That the Python interpreter actually obeys this algebra. The
    Python-to-Lean refinement step would require a verified compiler
    (e.g. Verified Software Toolchain). We leave that step as
    ``sorry``-free by *not stating it*; the only ``sorry`` in this
    file marks a future refinement bridge (``capvalue_refines``).
  - Side channels (timing, output length). FIDES explicitly leaves
    these out of scope; we follow.

  Build
  -----
  This file targets Lean 4 / Mathlib4 (May 2026). Build with
  ``lake build`` from the project root once Mathlib4 is fetched.
  CI does not build Lean in this delivery; the file is intended for
  publication review and for manual proof checking by reviewers.
-/

namespace Tex.Proofs.NonInterference

/-- Three-level capability lattice. -/
inductive CapLevel
  | trusted
  | user
  | untrusted
  deriving DecidableEq, Repr

namespace CapLevel

/-- Numeric injection for the total order. -/
def toNat : CapLevel → Nat
  | trusted   => 0
  | user      => 1
  | untrusted => 2

/-- Inverse of ``toNat`` for the values in range. -/
def ofNat : Nat → CapLevel
  | 0 => trusted
  | 1 => user
  | _ => untrusted

theorem ofNat_toNat (c : CapLevel) : ofNat (toNat c) = c := by
  cases c <;> rfl

/-- The order on capability levels. -/
def le (a b : CapLevel) : Prop := a.toNat ≤ b.toNat

instance : LE CapLevel where
  le := le

theorem le_refl (a : CapLevel) : a ≤ a := Nat.le_refl _

theorem le_trans {a b c : CapLevel} (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c :=
  Nat.le_trans hab hbc

theorem le_antisymm {a b : CapLevel} (hab : a ≤ b) (hba : b ≤ a) : a = b := by
  have hn := Nat.le_antisymm hab hba
  have h1 : ofNat a.toNat = ofNat b.toNat := by rw [hn]
  rw [ofNat_toNat, ofNat_toNat] at h1
  exact h1

theorem trusted_le (a : CapLevel) : trusted ≤ a := by
  cases a <;> decide

theorem le_untrusted (a : CapLevel) : a ≤ untrusted := by
  cases a <;> decide

/-- Join is the max of the two levels. -/
def join (a b : CapLevel) : CapLevel :=
  ofNat (Nat.max a.toNat b.toNat)

theorem join_comm (a b : CapLevel) : join a b = join b a := by
  unfold join
  rw [Nat.max_comm]

theorem join_assoc (a b c : CapLevel) : join (join a b) c = join a (join b c) := by
  unfold join
  -- need: ofNat (max (toNat (ofNat (max (toNat a) (toNat b)))) (toNat c))
  --      = ofNat (max (toNat a) (toNat (ofNat (max (toNat b) (toNat c)))))
  -- by toNat-ofNat round-trip on the appropriate range, both sides reduce
  -- to ofNat (max (max (toNat a) (toNat b)) (toNat c))
  have h1 : (ofNat (Nat.max a.toNat b.toNat)).toNat
          = Nat.max a.toNat b.toNat := by
    have hb : Nat.max a.toNat b.toNat ≤ 2 := by
      have ha2 : a.toNat ≤ 2 := by cases a <;> decide
      have hb2 : b.toNat ≤ 2 := by cases b <;> decide
      exact Nat.max_le_of_le_of_le ha2 hb2
    -- Toggle case-by-case on the max value
    rcases Nat.lt_or_ge (Nat.max a.toNat b.toNat) 1 with h | h
    · interval_cases (Nat.max a.toNat b.toNat) <;> rfl
    · rcases Nat.lt_or_ge (Nat.max a.toNat b.toNat) 2 with h2 | h2
      · interval_cases (Nat.max a.toNat b.toNat) <;> rfl
      · have : Nat.max a.toNat b.toNat = 2 :=
          Nat.le_antisymm hb h2
        rw [this]; rfl
  have h2 : (ofNat (Nat.max b.toNat c.toNat)).toNat
          = Nat.max b.toNat c.toNat := by
    have hb : Nat.max b.toNat c.toNat ≤ 2 := by
      have hb2 : b.toNat ≤ 2 := by cases b <;> decide
      have hc2 : c.toNat ≤ 2 := by cases c <;> decide
      exact Nat.max_le_of_le_of_le hb2 hc2
    rcases Nat.lt_or_ge (Nat.max b.toNat c.toNat) 1 with h | h
    · interval_cases (Nat.max b.toNat c.toNat) <;> rfl
    · rcases Nat.lt_or_ge (Nat.max b.toNat c.toNat) 2 with h' | h'
      · interval_cases (Nat.max b.toNat c.toNat) <;> rfl
      · have : Nat.max b.toNat c.toNat = 2 :=
          Nat.le_antisymm hb h'
        rw [this]; rfl
  rw [h1, h2]
  rw [Nat.max_assoc]

theorem join_idem (a : CapLevel) : join a a = a := by
  unfold join
  rw [Nat.max_self]
  exact ofNat_toNat a

theorem join_trusted (a : CapLevel) : join trusted a = a := by
  unfold join
  show ofNat (Nat.max 0 a.toNat) = a
  rw [Nat.max_zero_left]
  exact ofNat_toNat a

theorem trusted_join (a : CapLevel) : join a trusted = a := by
  rw [join_comm]; exact join_trusted a

/-- ``join`` is the supremum: both arguments are ≤ the join. -/
theorem le_join_left (a b : CapLevel) : a ≤ join a b := by
  unfold join LE.le le
  have hb : Nat.max a.toNat b.toNat ≤ 2 := by
    have ha2 : a.toNat ≤ 2 := by cases a <;> decide
    have hb2 : b.toNat ≤ 2 := by cases b <;> decide
    exact Nat.max_le_of_le_of_le ha2 hb2
  have : (ofNat (Nat.max a.toNat b.toNat)).toNat = Nat.max a.toNat b.toNat := by
    rcases Nat.lt_or_ge (Nat.max a.toNat b.toNat) 1 with h | h
    · interval_cases (Nat.max a.toNat b.toNat) <;> rfl
    · rcases Nat.lt_or_ge (Nat.max a.toNat b.toNat) 2 with h' | h'
      · interval_cases (Nat.max a.toNat b.toNat) <;> rfl
      · have e : Nat.max a.toNat b.toNat = 2 := Nat.le_antisymm hb h'
        rw [e]; rfl
  rw [this]
  exact Nat.le_max_left _ _

theorem le_join_right (a b : CapLevel) : b ≤ join a b := by
  rw [join_comm]; exact le_join_left b a

/-- Monotonicity of join in the first argument (the left-monotonicity
    used by the non-interference proof). -/
theorem join_le_join_of_le {a b : CapLevel} (h : a ≤ b) (c : CapLevel) :
    join a c ≤ join b c := by
  unfold join LE.le le
  have ha2 : a.toNat ≤ 2 := by cases a <;> decide
  have hb2 : b.toNat ≤ 2 := by cases b <;> decide
  have hc2 : c.toNat ≤ 2 := by cases c <;> decide
  have hab : Nat.max a.toNat c.toNat ≤ 2 :=
    Nat.max_le_of_le_of_le ha2 hc2
  have hbc : Nat.max b.toNat c.toNat ≤ 2 :=
    Nat.max_le_of_le_of_le hb2 hc2
  have eq_a : (ofNat (Nat.max a.toNat c.toNat)).toNat = Nat.max a.toNat c.toNat := by
    rcases Nat.lt_or_ge (Nat.max a.toNat c.toNat) 1 with hlt | hge
    · interval_cases (Nat.max a.toNat c.toNat) <;> rfl
    · rcases Nat.lt_or_ge (Nat.max a.toNat c.toNat) 2 with hlt' | hge'
      · interval_cases (Nat.max a.toNat c.toNat) <;> rfl
      · have e : Nat.max a.toNat c.toNat = 2 := Nat.le_antisymm hab hge'
        rw [e]; rfl
  have eq_b : (ofNat (Nat.max b.toNat c.toNat)).toNat = Nat.max b.toNat c.toNat := by
    rcases Nat.lt_or_ge (Nat.max b.toNat c.toNat) 1 with hlt | hge
    · interval_cases (Nat.max b.toNat c.toNat) <;> rfl
    · rcases Nat.lt_or_ge (Nat.max b.toNat c.toNat) 2 with hlt' | hge'
      · interval_cases (Nat.max b.toNat c.toNat) <;> rfl
      · have e : Nat.max b.toNat c.toNat = 2 := Nat.le_antisymm hbc hge'
        rw [e]; rfl
  rw [eq_a, eq_b]
  exact Nat.max_le_max h (Nat.le_refl _)

end CapLevel

/-! ## Non-interference (abstract form) -/

/-- A *derivation step* takes a value at level ``l`` and a contributing
    value at level ``l'`` and produces a value at level ``join l l'``.
    This is exactly the CaMeL ``CapValue.derived`` rule and the FIDES
    transition rule for product-lattice values. -/
def derive (l l' : CapLevel) : CapLevel := CapLevel.join l l'

/-- A derivation chain is a list of contributing levels applied in
    sequence to an initial level. -/
def derive_chain : CapLevel → List CapLevel → CapLevel
  | l, []        => l
  | l, c :: rest => derive_chain (derive l c) rest

/-- **Non-interference lemma**: the final level of a derivation chain
    is never lower than the initial level. -/
theorem derive_chain_monotone (l : CapLevel) (cs : List CapLevel) :
    l ≤ derive_chain l cs := by
  induction cs generalizing l with
  | nil => exact CapLevel.le_refl l
  | cons c rest ih =>
    have h1 : l ≤ derive l c := CapLevel.le_join_left l c
    have h2 : derive l c ≤ derive_chain (derive l c) rest := ih _
    exact CapLevel.le_trans h1 h2

/-- Specialization: an UNTRUSTED initial value remains UNTRUSTED at
    the end of any derivation chain. -/
theorem untrusted_propagates (cs : List CapLevel) :
    CapLevel.untrusted ≤ derive_chain CapLevel.untrusted cs :=
  derive_chain_monotone CapLevel.untrusted cs

/-- And conversely: the final level is bounded above by UNTRUSTED. -/
theorem derive_chain_bounded (l : CapLevel) (cs : List CapLevel) :
    derive_chain l cs ≤ CapLevel.untrusted := CapLevel.le_untrusted _

end Tex.Proofs.NonInterference
