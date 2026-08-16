-- SPDX-License-Identifier: LGPL-2.1-or-later
module Resolved.DNS.Transaction where

open import Agda.Builtin.Nat using (Nat; zero; suc)
open import Resolved.DNS.Name using (_≤_; z≤n)

record AttemptBudget : Set where
  constructor budget
  field
    used : Nat
    maximum : Nat
    bounded : used ≤ maximum

defaultAttempts : Nat
defaultAttempts = 24

queryDeadlineSeconds : Nat
queryDeadlineSeconds = 120

data Transport : Set where
  datagram : Transport
  stream : Transport

transportTimeoutSeconds : Transport → Nat
transportTimeoutSeconds datagram = 5
transportTimeoutSeconds stream = 10

fresh : (maximum : Nat) → AttemptBudget
fresh maximum = budget zero maximum z≤n

defaultBudget : AttemptBudget
defaultBudget = fresh defaultAttempts

data AddressWork : Set where
  ipv4Only : AddressWork
  ipv6Only : AddressWork
  bothFamilies : AddressWork

parallelWidth : AddressWork → Nat
parallelWidth ipv4Only = 1
parallelWidth ipv6Only = 1
parallelWidth bothFamilies = 2
