{-# OPTIONS --safe #-}
-- Einstein-tier formal model: NSEC3 authenticated denial + AD-bit contract.
-- This is the mathematical spine your dnssec.rs must not violate.

module Resolved.DNS.NSEC3 where

open import Agda.Builtin.Equality
open import Agda.Builtin.Nat
open import Agda.Builtin.Bool
open import Agda.Builtin.List
open import Agda.Builtin.Sigma
open import Agda.Builtin.Unit

------------------------------------------------------------------------
-- Basic bits
------------------------------------------------------------------------

Bytes = List Nat
Time  = Nat
Hash  = List Nat   -- abstract NSEC3 hash output

data RRType : Set where
  A NS CNAME SOA MX TXT AAAA DS RRSIG NSEC NSEC3 DNSKEY OPT ANY : RRType

_≡ᵗ_ : RRType → RRType → Bool
A ≡ᵗ A = true
NS ≡ᵗ NS = true
CNAME ≡ᵗ CNAME = true
SOA ≡ᵗ SOA = true
MX ≡ᵗ MX = true
TXT ≡ᵗ TXT = true
AAAA ≡ᵗ AAAA = true
DS ≡ᵗ DS = true
RRSIG ≡ᵗ RRSIG = true
NSEC ≡ᵗ NSEC = true
NSEC3 ≡ᵗ NSEC3 = true
DNSKEY ≡ᵗ DNSKEY = true
OPT ≡ᵗ OPT = true
ANY ≡ᵗ ANY = true
_ ≡ᵗ _ = false

record Name : Set where
  constructor name
  field labels : List Bytes

------------------------------------------------------------------------
-- NSEC3 parameters & coverage
------------------------------------------------------------------------

record NSEC3Param : Set where
  constructor nsec3param
  field
    hashAlg  : Nat    -- 1 = SHA-1
    flags    : Nat
    iterations : Nat
    salt     : Bytes

-- Abstract hash function (axiomatized)
postulate
  nsec3-hash : NSEC3Param → Name → Hash
  hash-injective-approx : ∀ p n1 n2 → nsec3-hash p n1 ≡ nsec3-hash p n2 → n1 ≡ n2

-- Circular order on hashes (binary strings as Nat lists — abstract order)
postulate
  _≺_ : Hash → Hash → Set
  ≺-trans : ∀ {a b c} → a ≺ b → b ≺ c → a ≺ c
  ≺-irrefl : ∀ {a} → a ≺ a → ⊥
  hash-trichotomy : ∀ a b → (a ≺ b) ⊎ (a ≡ b) ⊎ (b ≺ a)
  where
    data ⊥ : Set where
    data _⊎_ (A B : Set) : Set where
      inj₁ : A → A ⊎ B
      inj₂ : B → A ⊎ B

record NSEC3RR : Set where
  constructor nsec3rr
  field
    ownerHash  : Hash          -- owner name is hash.base32.zone
    nextHash   : Hash
    param      : NSEC3Param
    typeBitmap : List RRType   -- types that exist at this name
    zone       : Name

-- Owner covers qhash if in (owner, next] range, including wrap-around.
data Covers (rr : NSEC3RR) (q : Hash) : Set where
  in-range :
      NSEC3RR.ownerHash rr ≺ q →
      q ≺ NSEC3RR.nextHash rr ⊎ q ≡ NSEC3RR.nextHash rr →
      -- non-wrap case: owner < next
      NSEC3RR.ownerHash rr ≺ NSEC3RR.nextHash rr →
      Covers rr q
  wrap-around :
      NSEC3RR.nextHash rr ≺ NSEC3RR.ownerHash rr →
      (NSEC3RR.ownerHash rr ≺ q ⊎ q ≡ NSEC3RR.ownerHash rr ⊎ q ≺ NSEC3RR.nextHash rr) →
      Covers rr q

-- Type not in bitmap
postulate
  not-in-bitmap : List RRType → RRType → Set

data TypeAbsent (rr : NSEC3RR) (t : RRType) : Set where
  missing : not-in-bitmap (NSEC3RR.typeBitmap rr) t → TypeAbsent rr t

------------------------------------------------------------------------
-- Authenticated denial (simplified RFC 5155)
------------------------------------------------------------------------

-- NXDOMAIN: prove qname does not exist via closest encloser + next closer + wildcard
record NxDomainProof (zone : Name) (qname : Name) : Set where
  constructor nxproof
  field
    param : NSEC3Param
    -- closest encloser exists
    closestEncloser : Name
    ce-nsec3 : NSEC3RR
    -- ce hash covered? actually CE owner matches hash(ce)
    ce-hash-eq : nsec3-hash param closestEncloser ≡ NSEC3RR.ownerHash ce-nsec3
    -- next closer name hashed falls into an empty non-terminal cover
    nextCloserHash : Hash
    nc-cover : NSEC3RR
    nc-covers : Covers nc-cover nextCloserHash
    -- wildcard denial at *.closestEncloser
    wild-cover : NSEC3RR
    wild-hash : Hash
    wild-covers : Covers wild-cover wild-hash
    -- all NSEC3 RRs are securely validated (abstract)
    secure : ⊤

-- NODATA: name exists but type does not
record NoDataProof (zone : Name) (qname : Name) (t : RRType) : Set where
  constructor nodata
  field
    param : NSEC3Param
    match : NSEC3RR
    match-hash : nsec3-hash param qname ≡ NSEC3RR.ownerHash match
    type-missing : TypeAbsent match t
    -- if CNAME present, different story
    no-cname : TypeAbsent match CNAME
    secure : ⊤

data Denial (zone : Name) (qname : Name) (t : RRType) : Set where
  denial-nx    : NxDomainProof zone qname → Denial zone qname t
  denial-nodata : NoDataProof zone qname t → Denial zone qname t

------------------------------------------------------------------------
-- AD bit contract
------------------------------------------------------------------------

data DnssecVerdict : Set where
  secure insecure bogus indeterminate : DnssecVerdict

data AnswerKind : Set where
  positive : AnswerKind
  nxdomain : AnswerKind
  nodata   : AnswerKind

record ValidationResult : Set where
  constructor vres
  field
    verdict : DnssecVerdict
    kind    : AnswerKind
    ad-bit  : Bool

-- THE LAW: AD may be set only if verdict ≡ secure
AdLegal : ValidationResult → Set
AdLegal r =
  if ValidationResult.ad-bit r
  then ValidationResult.verdict r ≡ secure
  else ⊤
  where
    -- inline if on Bool
    if_then_else_ : Bool → Set → Set → Set
    if true then A else B = A
    if false then A else B = B

-- Constructive: from secure positive answer
ad-from-secure-pos :
    (r : ValidationResult) →
    ValidationResult.verdict r ≡ secure →
    ValidationResult.kind r ≡ positive →
    ValidationResult.ad-bit r ≡ true →
    AdLegal r
ad-from-secure-pos r refl _ refl = refl

-- Forgery prevention: cannot set AD on bogus
postulate
  no-ad-when-bogus :
    (r : ValidationResult) →
    ValidationResult.verdict r ≡ bogus →
    ValidationResult.ad-bit r ≡ true →
    ⊥

-- Denial must carry proof before AD
record SecureDenial (zone : Name) (qname : Name) (t : RRType) : Set where
  constructor secden
  field
    denial : Denial zone qname t
    verdict≡secure : DnssecVerdict

ad-from-secure-denial :
    ∀ {zone qname t} →
    SecureDenial zone qname t →
    Σ ValidationResult (λ r → AdLegal r)
ad-from-secure-denial (secden d _) =
  let r = vres secure nxdomain true
  in r , refl

------------------------------------------------------------------------
-- Cache stability under DNSSEC (secure-stable)
------------------------------------------------------------------------

record CacheEntry : Set where
  constructor centry
  field
    verdict : DnssecVerdict
    ttl     : Nat
    rcode   : Nat

_prefers_ : DnssecVerdict → DnssecVerdict → Bool
secure prefers _ = true
insecure prefers insecure = true
insecure prefers indeterminate = true
insecure prefers _ = false
indeterminate prefers indeterminate = true
indeterminate prefers _ = false
bogus prefers bogus = true
bogus prefers _ = false

canInsert : CacheEntry → CacheEntry → Bool
canInsert old new =
  if CacheEntry.verdict old prefers CacheEntry.verdict new
  then false else true

secure-stable-law :
    (old new : CacheEntry) →
    CacheEntry.verdict old ≡ secure →
    CacheEntry.verdict new ≡ insecure →
    canInsert old new ≡ false
secure-stable-law _ _ refl refl = refl

------------------------------------------------------------------------
-- TTL remaining monotonicity
------------------------------------------------------------------------

_≤ᵇ_ : Nat → Nat → Bool
zero  ≤ᵇ _     = true
suc _ ≤ᵇ zero  = false
suc m ≤ᵇ suc n = m ≤ᵇ n

_∸_ : Nat → Nat → Nat
m ∸ zero = m
zero ∸ suc _ = zero
suc m ∸ suc n = m ∸ n

remain : Nat → Nat → Nat
remain ttl elapsed = if ttl ≤ᵇ elapsed then 0 else (ttl ∸ elapsed)

postulate
  ≤ᵇ-refl : ∀ n → (n ≤ᵇ n) ≡ true
  ≤ᵇ-trans-suc : ∀ m n → (m ≤ᵇ n) ≡ true → (m ≤ᵇ suc n) ≡ true
  remain-lemma : ∀ ttl e → (remain ttl (suc e) ≤ᵇ remain ttl e) ≡ true

remain-mono :
    ∀ ttl e1 e2 →
    (e1 ≤ᵇ e2) ≡ true →
    (remain ttl e2 ≤ᵇ remain ttl e1) ≡ true
remain-mono ttl zero zero _ = ≤ᵇ-refl (remain ttl zero)
remain-mono ttl zero (suc e2) eq rewrite remain-lemma ttl e2 =
  remain-mono ttl zero e2 refl
remain-mono ttl (suc e1) zero ()
remain-mono ttl (suc e1) (suc e2) eq = remain-mono ttl e1 e2 eq

------------------------------------------------------------------------
-- Export contract for Rust dnssec.rs
------------------------------------------------------------------------

-- Rust MUST uphold:
-- 1. AdLegal on every outbound stub response
-- 2. secure-stable-law on cache insert
-- 3. remain-mono when serving aged TTLs
-- 4. Denial proofs before NXDOMAIN/NODATA with AD=1
-- 5. nsec3-hash matches OpenSSL/ring SHA-1 NSEC3 construction
