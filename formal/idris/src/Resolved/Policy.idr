-- SPDX-License-Identifier: LGPL-2.1-or-later
module Resolved.Policy

import Data.List
import Data.Vect

%default total

public export
data Protocol = UnicastDNS | LLMNR | MulticastDNS

public export
data AddressFamily = Unspecified | IPv4 | IPv6

public export
data Validation = Insecure | Authenticated | Bogus

public export
data ResolutionPath
  = Synthetic
  | HostsFile
  | Network Protocol
  | Refused

public export
record DNSName (labels : Nat) where
  constructor MkDNSName
  components : Vect labels String

public export
record Policy where
  constructor MkPolicy
  llmnrEnabled : Bool
  mdnsEnabled : Bool
  unicastSingleLabel : Bool

public export
isSingleLabel : DNSName labels -> Bool
isSingleLabel (MkDNSName []) = False
isSingleLabel (MkDNSName [_]) = True
isSingleLabel (MkDNSName (_ :: _ :: _)) = False

public export
routeName : Policy -> DNSName labels -> ResolutionPath
routeName policy name =
  if isSingleLabel name then
    if llmnrEnabled policy then Network LLMNR
    else if unicastSingleLabel policy then Network UnicastDNS
    else Refused
  else Network UnicastDNS

public export
routeLocalName : Policy -> DNSName labels -> ResolutionPath
routeLocalName policy _ =
  if mdnsEnabled policy then Network MulticastDNS else Refused

public export
data SupportedClass = Internet | AnyClass

public export
data SupportedType
  = A
  | AAAA
  | PTR
  | CNAME
  | SOA
  | MX
  | TXT
  | SRV
  | TLSA
  | SSHFP
  | AnyType

public export
data QueryDecision = Accept | RejectClass | RejectType

public export
validateQuery : Maybe SupportedClass -> Maybe SupportedType -> QueryDecision
validateQuery Nothing _ = RejectClass
validateQuery _ Nothing = RejectType
validateQuery (Just _) (Just _) = Accept

public export
record CacheWitness where
  constructor MkCacheWitness
  originalTTL : Nat
  elapsed : Nat
  remaining : Nat
  remainingIsDifference : remaining = minus originalTTL elapsed

public export
ageTTL : (ttl : Nat) -> (elapsed : Nat) -> CacheWitness
ageTTL ttl elapsed = MkCacheWitness ttl elapsed (minus ttl elapsed) Refl
