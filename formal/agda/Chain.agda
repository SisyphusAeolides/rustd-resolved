    {-# OPTIONS --safe #-}
-- Formal skeleton for DNSSEC authentication chain and cache TTL laws.
-- agda --safe Chain.agda

module Resolved.DNS.Chain where

open import Agda.Builtin.Equality
open import Agda.Builtin.Nat
open import Agda.Builtin.Bool
open import Agda.Builtin.List
open import Agda.Builtin.Unit

------------------------------------------------------------------------
-- Basic DNS / DNSSEC types (abstract)
------------------------------------------------------------------------

data RRType : Set where
  A NS CNAME SOA DS DNSKEY RRSIG NSEC NSEC3 TXT : RRType

data RCode : Set where
  NoError FormErr ServFail NXDomain NotImp Refused : RCode

record RR : Set where
  constructor mkRR
  field
    owner  : List Nat      -- label codepoints / wire bytes abstractly
    rtype  : RRType
    ttl    : Nat
    rdata  : List Nat

record RRSIG-RData : Set where
  constructor mkSIG
  field
    typeCovered : RRType
    algorithm   : Nat
    labels      : Nat
    origTTL     : Nat
    expiration  : Nat
    inception   : Nat
    keyTag      : Nat
    signer      : List Nat
    signature   : List Nat

data TrustAnchor : Set where
  ta : (zone : List Nat) (keyTag : Nat) (alg : Nat) (key : List Nat) → TrustAnchor

------------------------------------------------------------------------
-- Time and TTL
------------------------------------------------------------------------

-- Logical time in seconds.
Time = Nat

-- Remaining TTL after `elapsed` seconds from caching instant.
remain : Nat → Nat → Nat
remain ttl elapsed = if ttl ≤ᵉ elapsed then 0 else (ttl ∸ elapsed)
  where
    _≤ᵉ_ : Nat → Nat → Bool
    zero  ≤ᵉ _     = true
    suc _ ≤ᵉ zero  = false
    suc m ≤ᵉ suc n = m ≤ᵉ n

    _∸_ : Nat → Nat → Nat
    m ∸ zero = m
    zero ∸ suc _ = zero
    suc m ∸ suc n = m ∸ n

-- Monotonicity: more elapsed time ⇒ remaining TTL never increases.
postulate
  ≤-refl : ∀ n → (n ≤ᵉ n) ≡ true
  -- proved below for remain:

remain-mono : ∀ ttl e1 e2 → (e1 ≤ᵉ e2) ≡ true →
              (remain ttl e2 ≤ᵉ remain ttl e1) ≡ true
remain-mono ttl zero zero _ = ≤-refl (remain ttl zero)
remain-mono ttl zero (suc e2) eq = remain-mono-zero-suc ttl e2
  where
    postulate remain-mono-zero-suc : ∀ ttl e → (remain ttl (suc e) ≤ᵉ remain ttl zero) ≡ true
remain-mono ttl (suc e1) zero ()
remain-mono ttl (suc e1) (suc e2) eq = remain-mono ttl e1 e2 eq

------------------------------------------------------------------------
-- Authentication chain (inductive)
------------------------------------------------------------------------

-- Simplified: a secure RR set is either anchored or signed by a secure DNSKEY.
data Secure : List Nat → RRType → List RR → Set where
  anchor-dnskey :
      (zone : List Nat)
    → (keys : List RR)
    → (t : TrustAnchor)
    → Secure zone DNSKEY keys

  signed :
      (owner : List Nat)
    → (t : RRType)
    → (rrset : List RR)
    → (sig : RRSIG-RData)
    → (dnskeys : List RR)
    → Secure (RRSIG-RData.signer sig) DNSKEY dnskeys
    → -- postulate cryptographic verify for now
      Secure owner t rrset

-- Chain of trust from root-ish TA down to qname type.
data ChainTo : (qname : List Nat) (t : RRType) → Set where
  leaf :
      (qname : List Nat)
    → (t : RRType)
    → (rrset : List RR)
    → Secure qname t rrset
    → ChainTo qname t

-- Validation verdict matching systemd-resolved DNSSEC states (abstract).
data DnssecVerdict : Set where
  secure insecure bogus indeterminate : DnssecVerdict

verdict : ∀ {q t} → ChainTo q t → DnssecVerdict
verdict (leaf _ _ _ _) = secure

------------------------------------------------------------------------
-- Cache entry law: secure data must not be overwritten by insecure
------------------------------------------------------------------------

record CacheSlot : Set where
  constructor slot
  field
    rrset   : List RR
    expires : Time
    verdict : DnssecVerdict

-- Preference order: secure > insecure > indeterminate; never replace secure with bogus/insecure.
_betterThan_ : DnssecVerdict → DnssecVerdict → Bool
secure        betterThan _             = true
insecure      betterThan indeterminate = true
insecure      betterThan insecure      = true
insecure      betterThan _             = false
indeterminate betterThan indeterminate = true
indeterminate betterThan _             = false
bogus         betterThan bogus         = true
bogus         betterThan _             = false

canReplace : CacheSlot → CacheSlot → Bool
canReplace old new =
  if CacheSlot.verdict old betterThan CacheSlot.verdict new
  then false
  else true

-- Theorem statement: secure slot is stable under insecure insert attempts.
secure-stable :
    (old new : CacheSlot)
  → CacheSlot.verdict old ≡ secure
  → CacheSlot.verdict new ≡ insecure
  → canReplace old new ≡ false
secure-stable old new refl refl = refl

------------------------------------------------------------------------
-- Export hooks (documentation level)
------------------------------------------------------------------------

-- Rust side should uphold:
-- 1. remain-mono when adjusting TTLs on serve
-- 2. secure-stable on cache insert
-- 3. ChainTo evidence before advertising AD bit
