||| Dependent DNS wire names and compression-pointer safety.
||| Compile: idris2 --check WireName.idr
||| Goal: executable spec + proofs that feed property tests / FFI contracts.

module WireName

import Data.Buffer
import Data.List
import Data.Nat
import Data.Vect
import Data.Bits

%default total

||| A single DNS label: length 1..63 (root handled separately).
public export
data Label : Nat -> Type where
  MkLabel : (n : Nat) -> (0 _ : LTE 1 n) => (0 _ : LTE n 63) =>
            Vect n Bits8 -> Label n

||| Uncompressed absolute name: sequence of labels + root, total wire <= 255.
public export
data AbsName : Nat -> Type where
  Root : AbsName 1
  Cons : {n, rest : Nat} ->
         Label n ->
         AbsName rest ->
         {auto 0 prf : LTE (S n + rest) 255} ->
         AbsName (S n + rest)

public export
wireSize : AbsName w -> Nat
wireSize {w} _ = w

||| Maximum pointer hops before we declare a cycle (DNS messages <= 64k; 256 is plenty).
public export
MaxHops : Nat
MaxHops = 256

public export
data DecodeErr
  = OOB
  | BadLabelLen
  | PointerCycle
  | PointerHopLimit
  | NameTooLong
  | CompressionToMiddle
  | Truncated

||| Cursor into an immutable message view.
public export
record MsgView where
  constructor MkMsg
  bytes : List Bits8
  len   : Nat
  {auto 0 lenOk : length bytes = len}

public export
indexByte : MsgView -> (i : Nat) -> Maybe Bits8
indexByte (MkMsg bs len) i =
  if i >= len then Nothing else index' bs i
  where
    index' : List Bits8 -> Nat -> Maybe Bits8
    index' [] _ = Nothing
    index' (x :: _) Z = Just x
    index' (_ :: xs) (S k) = index' xs k

||| Seen offsets for cycle detection (simple ordered list; binary set in production).
public export
seenHas : List Nat -> Nat -> Bool
seenHas [] _ = False
seenHas (x :: xs) o = x == o || seenHas xs o

||| Decode uncompressed / compressed name starting at `off`.
||| Returns (labels as list of byte vectors, next offset after name).
||| Compression jumps do not advance "next" past the first pointer.
public export
partial -- recursion on hops/remaining; mark total with well-founded later
decodeName : MsgView -> (off : Nat) -> (hops : Nat) -> (seen : List Nat) ->
             (budget : Nat) -> Either DecodeErr (List (List Bits8), Nat)
decodeName msg off hops seen budget =
  if hops >= MaxHops then Left PointerHopLimit
  else if seenHas seen off then Left PointerCycle
  else if budget == 0 then Left NameTooLong
  else case indexByte msg off of
    Nothing => Left OOB
    Just b =>
      let v = cast {to=Nat} b in
      if v == 0 then
        Right ([], S off)
      else if v >= 192 then
        -- pointer: top 2 bits 11, low 14 bits offset
        case indexByte msg (S off) of
          Nothing => Left OOB
          Just b2 =>
            let hi = v `minus` 192
                target = hi * 256 + cast {to=Nat} b2
            in if target >= msg.len then Left OOB
               else if target >= off && hops == 0 then
                 -- first label pointer ok; still must not loop
                 case decodeName msg target (S hops) (off :: seen) budget of
                   Left e => Left e
                   Right (labs, _) => Right (labs, off + 2)
               else
                 case decodeName msg target (S hops) (off :: seen) budget of
                   Left e => Left e
                   Right (labs, _) =>
                     if hops == 0 then Right (labs, off + 2)
                     else Right (labs, off + 2) -- nested pointer: consumer uses outer next
      else if v > 63 then
        Left BadLabelLen
      else
        case takeBytes msg (S off) v of
          Nothing => Left OOB
          Just lab =>
            case decodeName msg (S off + v) hops (off :: seen) (budget `minus` (S v)) of
              Left e => Left e
              Right (rest, next) => Right (lab :: rest, next)

  where
    takeBytes : MsgView -> Nat -> Nat -> Maybe (List Bits8)
    takeBytes m start n = go start n []
      where
        go : Nat -> Nat -> List Bits8 -> Maybe (List Bits8)
        go _ Z acc = Just (reverse acc)
        go i (S k) acc = case indexByte m i of
          Nothing => Nothing
          Just x => go (S i) k (x :: acc)

||| Proof-shaped predicate: name decode consumed within message.
public export
data ValidNameAt : MsgView -> Nat -> Type where
  VN : (labs : List (List Bits8)) -> (next : Nat) ->
       {auto 0 inBounds : LTE next (len msg)} ->
       decodeName msg off 0 [] 255 = Right (labs, next) ->
       ValidNameAt msg off

||| Lowercase ASCII for cache keys (spec-level).
public export
foldAscii : Bits8 -> Bits8
foldAscii b =
  if b >= 65 && b <= 90 then b + 32 else b

public export
foldLabel : List Bits8 -> List Bits8
foldLabel = map foldAscii

||| Exportable check used by Rust property tests via C FFI later.
public export
nameIsSafe : MsgView -> Nat -> Bool
nameIsSafe msg off =
  case decodeName msg off 0 [] 255 of
    Right _ => True
    Left _  => False
