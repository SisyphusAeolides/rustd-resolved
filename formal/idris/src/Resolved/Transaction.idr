-- SPDX-License-Identifier: LGPL-2.1-or-later
module Resolved.Transaction

%default total

public export
record AttemptBudget where
  constructor MkAttemptBudget
  maximum : Nat
  used : Nat

public export
defaultAttempts : Nat
defaultAttempts = 24

public export
queryDeadlineSeconds : Nat
queryDeadlineSeconds = 120

public export
data Transport = Datagram | Stream

public export
transportTimeoutSeconds : Transport -> Nat
transportTimeoutSeconds Datagram = 5
transportTimeoutSeconds Stream = 10

public export
freshBudget : AttemptBudget
freshBudget = MkAttemptBudget defaultAttempts 0

public export
remaining : AttemptBudget -> Nat
remaining budget = minus (maximum budget) (used budget)

public export
canEmit : AttemptBudget -> Bool
canEmit budget = used budget < maximum budget

public export
consume : AttemptBudget -> Maybe AttemptBudget
consume budget =
  if canEmit budget
     then Just (MkAttemptBudget (maximum budget) (S (used budget)))
     else Nothing

public export
data AddressWork = IPv4Only | IPv6Only | BothFamilies

public export
parallelWidth : AddressWork -> Nat
parallelWidth IPv4Only = 1
parallelWidth IPv6Only = 1
parallelWidth BothFamilies = 2
