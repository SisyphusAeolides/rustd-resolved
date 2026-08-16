-- SPDX-License-Identifier: LGPL-2.1-or-later
module Resolved.DNS.Name where

open import Agda.Builtin.Nat using (Nat; zero; suc)
open import Agda.Builtin.Equality using (_≡_; refl)
open import Agda.Builtin.List using (List; []; _∷_)
open import Agda.Builtin.String using (String)

infix 4 _≤_
data _≤_ : Nat → Nat → Set where
  z≤n : ∀ {n} → zero ≤ n
  s≤s : ∀ {m n} → m ≤ n → suc m ≤ suc n

≤-refl : ∀ {n} → n ≤ n
≤-refl {zero} = z≤n
≤-refl {suc n} = s≤s ≤-refl

≤-trans : ∀ {a b c} → a ≤ b → b ≤ c → a ≤ c
≤-trans z≤n _ = z≤n
≤-trans (s≤s left) (s≤s right) = s≤s (≤-trans left right)

data ⊥ : Set where

¬_ : Set → Set
¬ A = A → ⊥

suc-not≤self : ∀ {n} → ¬ (suc n ≤ n)
suc-not≤self {zero} ()
suc-not≤self {suc n} (s≤s proof) = suc-not≤self proof

record DNSName : Set where
  constructor name
  field
    labels : List String
    labelCount : Nat
    bounded : labelCount ≤ 127

nameBound : (value : DNSName) → DNSName.labelCount value ≤ 127
nameBound (name _ _ proof) = proof

record CompressionStep (from to : Nat) : Set where
  constructor pointer
  field
    decreases : suc to ≤ from

noSelfPointer : ∀ {offset} → ¬ (CompressionStep offset offset)
noSelfPointer (pointer proof) = suc-not≤self proof

record TTLResult : Set where
  constructor ttl
  field
    original : Nat
    elapsed : Nat
    remaining : Nat
    neverIncreases : remaining ≤ original

zeroTTL : (original elapsed : Nat) → TTLResult
zeroTTL original elapsed = ttl original elapsed zero z≤n
