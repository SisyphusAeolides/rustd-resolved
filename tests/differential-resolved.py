#!/usr/bin/env python3
"""Compare two DNS stub endpoints without mutating the host resolver configuration."""

from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import asdict, dataclass
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import struct
import sys
import time
from typing import Iterable, Sequence

DNS_HEADER_LENGTH = 12
CLASS_IN = 1
TYPE_BY_NAME = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "DNAME": 39,
    "DS": 43,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "NSEC3": 50,
    "TLSA": 52,
    "CAA": 257,
    "SVCB": 64,
    "HTTPS": 65,
}
NAME_BY_TYPE = {value: key for key, value in TYPE_BY_NAME.items()}
NAME_RDATA_TYPES = {2, 5, 12, 39}


class DnsError(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "Endpoint":
        if value.startswith("["):
            closing = value.find("]")
            if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
                raise argparse.ArgumentTypeError(f"invalid endpoint: {value}")
            return cls(value[1:closing], int(value[closing + 2 :]))
        host, separator, port = value.rpartition(":")
        if not separator or not host:
            raise argparse.ArgumentTypeError(f"invalid endpoint: {value}")
        return cls(host, int(port))

    def address(self) -> tuple[str, int]:
        return self.host, self.port


@dataclass(frozen=True)
class QueryCase:
    name: str
    rr_type: int
    rr_class: int = CLASS_IN

    @classmethod
    def parse(cls, value: str) -> "QueryCase":
        name, separator, type_name = value.rpartition(":")
        if not separator or not name:
            raise argparse.ArgumentTypeError("query cases use NAME:TYPE")
        try:
            rr_type = int(type_name, 0)
        except ValueError:
            try:
                rr_type = TYPE_BY_NAME[type_name.upper()]
            except KeyError as error:
                raise argparse.ArgumentTypeError(f"unknown RR type: {type_name}") from error
        if not 0 < rr_type <= 0xFFFF:
            raise argparse.ArgumentTypeError(f"invalid RR type: {rr_type}")
        return cls(name=name, rr_type=rr_type)

    def label(self) -> str:
        return f"{self.name}:{NAME_BY_TYPE.get(self.rr_type, self.rr_type)}"


@dataclass(frozen=True)
class NormalizedQuestion:
    name: str
    rr_type: int
    rr_class: int


@dataclass(frozen=True)
class NormalizedRecord:
    section: str
    owner: str
    rr_type: int
    rr_class: int
    rdata: str


@dataclass(frozen=True)
class NormalizedMessage:
    rcode: int
    authoritative: bool
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    authenticated: bool
    checking_disabled: bool
    questions: tuple[NormalizedQuestion, ...]
    records: tuple[NormalizedRecord, ...]


@dataclass
class ProtocolResult:
    protocol: str
    endpoint: str
    elapsed_ms: float
    message: NormalizedMessage | None = None
    error: str | None = None


@dataclass
class Comparison:
    case: str
    protocol: str
    equal: bool
    reference: ProtocolResult
    candidate: ProtocolResult
    differences: list[str]


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\0"
    output = bytearray()
    for label in name.split("."):
        encoded = label.encode("idna")
        if not encoded or len(encoded) > 63:
            raise DnsError(f"invalid DNS label in {name!r}")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    if len(output) > 255:
        raise DnsError(f"DNS name is too long: {name!r}")
    return bytes(output)


def make_query(case: QueryCase, identifier: int, dnssec: bool) -> bytes:
    flags = 0x0100
    additional = 1 if dnssec else 0
    packet = bytearray(struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, additional))
    packet.extend(encode_name(case.name))
    packet.extend(struct.pack("!HH", case.rr_type, case.rr_class))
    if dnssec:
        packet.extend(b"\0")
        packet.extend(struct.pack("!HHIH", 41, 1232, 0x8000, 0))
    return bytes(packet)


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise DnsError("unexpected EOF in DNS-over-TCP response")
        output.extend(chunk)
    return bytes(output)


def exchange(endpoint: Endpoint, packet: bytes, protocol: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in endpoint.host else socket.AF_INET
    socktype = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, socktype) as stream:
        stream.settimeout(timeout)
        if protocol == "udp":
            stream.connect(endpoint.address())
            sent = stream.send(packet)
            if sent != len(packet):
                raise DnsError("short UDP send")
            return stream.recv(65535)
        stream.connect(endpoint.address())
        stream.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", read_exact(stream, 2))[0]
        if length < DNS_HEADER_LENGTH:
            raise DnsError("short DNS-over-TCP frame")
        return read_exact(stream, length)


class Parser:
    def __init__(self, packet: bytes) -> None:
        self.packet = packet

    def u16(self, offset: int) -> int:
        if offset < 0 or offset + 2 > len(self.packet):
            raise DnsError("truncated u16")
        return struct.unpack_from("!H", self.packet, offset)[0]

    def u32(self, offset: int) -> int:
        if offset < 0 or offset + 4 > len(self.packet):
            raise DnsError("truncated u32")
        return struct.unpack_from("!I", self.packet, offset)[0]

    def name(self, offset: int) -> tuple[str, int]:
        labels: list[bytes] = []
        cursor = offset
        next_offset: int | None = None
        visited: set[int] = set()
        expanded = 1
        for _ in range(128):
            if cursor >= len(self.packet):
                raise DnsError("truncated DNS name")
            length = self.packet[cursor]
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(self.packet):
                    raise DnsError("truncated compression pointer")
                target = ((length & 0x3F) << 8) | self.packet[cursor + 1]
                if target >= len(self.packet):
                    raise DnsError("out-of-range compression pointer")
                if next_offset is None:
                    next_offset = cursor + 2
                if target in visited:
                    raise DnsError("compression pointer loop")
                visited.add(target)
                cursor = target
                continue
            if length & 0xC0:
                raise DnsError("invalid DNS label type")
            cursor += 1
            if length == 0:
                try:
                    text = ".".join(label.decode("ascii").lower() for label in labels) + "."
                except UnicodeDecodeError:
                    text = ".".join(label.hex() for label in labels) + "."
                return text, next_offset if next_offset is not None else cursor
            if length > 63 or cursor + length > len(self.packet):
                raise DnsError("invalid DNS label")
            labels.append(self.packet[cursor : cursor + length])
            cursor += length
            expanded += length + 1
            if expanded > 255:
                raise DnsError("expanded DNS name is too long")
        raise DnsError("too many DNS compression pointers")

    def question(self, offset: int) -> tuple[NormalizedQuestion, int]:
        name, offset = self.name(offset)
        if offset + 4 > len(self.packet):
            raise DnsError("truncated DNS question")
        rr_type, rr_class = struct.unpack_from("!HH", self.packet, offset)
        return NormalizedQuestion(name, rr_type, rr_class), offset + 4

    def record(self, section: str, offset: int) -> tuple[NormalizedRecord, int]:
        owner, offset = self.name(offset)
        if offset + 10 > len(self.packet):
            raise DnsError("truncated DNS record header")
        rr_type, rr_class, _ttl, length = struct.unpack_from("!HHIH", self.packet, offset)
        rdata_offset = offset + 10
        end = rdata_offset + length
        if end > len(self.packet):
            raise DnsError("truncated DNS record data")
        rdata = self.normalize_rdata(rr_type, rdata_offset, end)
        return NormalizedRecord(section, owner, rr_type, rr_class, rdata), end

    def normalize_rdata(self, rr_type: int, start: int, end: int) -> str:
        raw = self.packet[start:end]
        if rr_type == 1 and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if rr_type == 28 and len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
        if rr_type in NAME_RDATA_TYPES:
            name, consumed = self.name(start)
            if consumed != end:
                raise DnsError("trailing data after compressed name")
            return name
        if rr_type == 15:
            if len(raw) < 3:
                raise DnsError("short MX data")
            preference = self.u16(start)
            name, consumed = self.name(start + 2)
            if consumed != end:
                raise DnsError("trailing MX data")
            return f"{preference} {name}"
        if rr_type == 33:
            if len(raw) < 7:
                raise DnsError("short SRV data")
            priority, weight, port = struct.unpack_from("!HHH", self.packet, start)
            target, consumed = self.name(start + 6)
            if consumed != end:
                raise DnsError("trailing SRV data")
            return f"{priority} {weight} {port} {target}"
        if rr_type == 6:
            mname, cursor = self.name(start)
            rname, cursor = self.name(cursor)
            if cursor + 20 != end:
                raise DnsError("invalid SOA data")
            values = struct.unpack_from("!IIIII", self.packet, cursor)
            return " ".join((mname, rname, *(str(value) for value in values)))
        if rr_type == 16:
            items: list[str] = []
            cursor = start
            while cursor < end:
                length = self.packet[cursor]
                cursor += 1
                if cursor + length > end:
                    raise DnsError("truncated TXT item")
                items.append(self.packet[cursor : cursor + length].hex())
                cursor += length
            return ",".join(items)
        if rr_type == 46:
            if len(raw) < 19:
                raise DnsError("short RRSIG data")
            type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag = (
                struct.unpack_from("!HBBIIIH", self.packet, start)
            )
            signer, cursor = self.name(start + 18)
            if cursor > end:
                raise DnsError("truncated RRSIG signer")
            signature = self.packet[cursor:end].hex()
            return (
                f"{type_covered} {algorithm} {labels} {original_ttl} {expiration} "
                f"{inception} {key_tag} {signer} {signature}"
            )
        if rr_type == 47:
            next_name, cursor = self.name(start)
            if cursor > end:
                raise DnsError("truncated NSEC next name")
            return f"{next_name} {self.packet[cursor:end].hex()}"
        if rr_type in {64, 65}:
            if len(raw) < 3:
                raise DnsError("short SVCB data")
            priority = self.u16(start)
            target, cursor = self.name(start + 2)
            if cursor > end:
                raise DnsError("truncated SVCB target")
            return f"{priority} {target} {self.packet[cursor:end].hex()}"
        if rr_type == 257:
            if len(raw) < 2:
                raise DnsError("short CAA data")
            flags = raw[0]
            tag_length = raw[1]
            if 2 + tag_length > len(raw):
                raise DnsError("truncated CAA tag")
            tag = raw[2 : 2 + tag_length].decode("ascii", "backslashreplace").lower()
            value = raw[2 + tag_length :].hex()
            return f"{flags} {tag} {value}"
        return raw.hex()

    def message(self) -> NormalizedMessage:
        if len(self.packet) < DNS_HEADER_LENGTH:
            raise DnsError("short DNS packet")
        _identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", self.packet, 0)
        offset = DNS_HEADER_LENGTH
        questions: list[NormalizedQuestion] = []
        for _ in range(qd):
            question, offset = self.question(offset)
            questions.append(question)
        records: list[NormalizedRecord] = []
        for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
            for _ in range(count):
                record, offset = self.record(section, offset)
                if record.rr_type != 41:
                    records.append(record)
        if offset != len(self.packet):
            raise DnsError("trailing bytes after DNS message")
        return NormalizedMessage(
            rcode=flags & 0xF,
            authoritative=bool(flags & 0x0400),
            truncated=bool(flags & 0x0200),
            recursion_desired=bool(flags & 0x0100),
            recursion_available=bool(flags & 0x0080),
            authenticated=bool(flags & 0x0020),
            checking_disabled=bool(flags & 0x0010),
            questions=tuple(sorted(questions, key=lambda item: (item.name, item.rr_type, item.rr_class))),
            records=tuple(
                sorted(
                    records,
                    key=lambda item: (
                        item.section,
                        item.owner,
                        item.rr_type,
                        item.rr_class,
                        item.rdata,
                    ),
                )
            ),
        )


def run_query(
    endpoint: Endpoint,
    case: QueryCase,
    protocol: str,
    timeout: float,
    dnssec: bool,
) -> ProtocolResult:
    identifier = random.SystemRandom().randrange(1, 65536)
    packet = make_query(case, identifier, dnssec)
    started = time.monotonic()
    try:
        response = exchange(endpoint, packet, protocol, timeout)
        elapsed = (time.monotonic() - started) * 1000
        if len(response) < 2 or struct.unpack_from("!H", response, 0)[0] != identifier:
            raise DnsError("response identifier does not match query")
        return ProtocolResult(
            protocol=protocol,
            endpoint=f"{endpoint.host}:{endpoint.port}",
            elapsed_ms=elapsed,
            message=Parser(response).message(),
        )
    except (DnsError, OSError, ValueError) as error:
        return ProtocolResult(
            protocol=protocol,
            endpoint=f"{endpoint.host}:{endpoint.port}",
            elapsed_ms=(time.monotonic() - started) * 1000,
            error=f"{type(error).__name__}: {error}",
        )


def compare_messages(
    reference: ProtocolResult,
    candidate: ProtocolResult,
    compare_ad: bool,
) -> list[str]:
    differences: list[str] = []
    if reference.error != candidate.error:
        differences.append(f"error: {reference.error!r} != {candidate.error!r}")
    if reference.message is None or candidate.message is None:
        return differences
    left = reference.message
    right = candidate.message
    fields = (
        "rcode",
        "authoritative",
        "truncated",
        "recursion_desired",
        "recursion_available",
        "checking_disabled",
        "questions",
        "records",
    )
    for field in fields:
        if getattr(left, field) != getattr(right, field):
            differences.append(f"{field}: {getattr(left, field)!r} != {getattr(right, field)!r}")
    if compare_ad and left.authenticated != right.authenticated:
        differences.append(f"authenticated: {left.authenticated!r} != {right.authenticated!r}")
    return differences


def compare_one(
    reference_endpoint: Endpoint,
    candidate_endpoint: Endpoint,
    case: QueryCase,
    protocol: str,
    timeout: float,
    dnssec: bool,
    compare_ad: bool,
) -> Comparison:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        reference_future = executor.submit(
            run_query, reference_endpoint, case, protocol, timeout, dnssec
        )
        candidate_future = executor.submit(
            run_query, candidate_endpoint, case, protocol, timeout, dnssec
        )
        reference = reference_future.result()
        candidate = candidate_future.result()
    differences = compare_messages(reference, candidate, compare_ad)
    return Comparison(
        case=case.label(),
        protocol=protocol,
        equal=not differences,
        reference=reference,
        candidate=candidate,
        differences=differences,
    )


def serializable(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return {key: serializable(item) for key, item in asdict(value).items()}
    if isinstance(value, tuple):
        return [serializable(item) for item in value]
    if isinstance(value, list):
        return [serializable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): serializable(item) for key, item in value.items()}
    return value


def default_cases() -> list[QueryCase]:
    hostname = socket.gethostname().rstrip(".")
    values = [
        QueryCase("localhost", TYPE_BY_NAME["A"]),
        QueryCase("localhost", TYPE_BY_NAME["AAAA"]),
        QueryCase("_localdnsstub", TYPE_BY_NAME["A"]),
        QueryCase("_localdnsproxy", TYPE_BY_NAME["A"]),
        QueryCase("invalid", TYPE_BY_NAME["A"]),
    ]
    if hostname and hostname.lower() != "localhost":
        values.extend(
            [
                QueryCase(hostname, TYPE_BY_NAME["A"]),
                QueryCase(hostname, TYPE_BY_NAME["AAAA"]),
            ]
        )
    return values


def parse_case_file(path: Path) -> list[QueryCase]:
    cases: list[QueryCase] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            cases.append(QueryCase.parse(line))
        except argparse.ArgumentTypeError as error:
            raise DnsError(f"{path}:{number}: {error}") from error
    return cases


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Endpoint.parse, required=True)
    parser.add_argument("--candidate", type=Endpoint.parse, required=True)
    parser.add_argument("--case", action="append", type=QueryCase.parse, default=[])
    parser.add_argument("--case-file", action="append", type=Path, default=[])
    parser.add_argument("--protocol", choices=("udp", "tcp", "both"), default="both")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=min(16, (os.cpu_count() or 2) * 2))
    parser.add_argument("--dnssec", action="store_true")
    parser.add_argument("--compare-ad", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--allow-differences", action="store_true")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    if options.timeout <= 0 or options.repeat <= 0 or options.jobs <= 0:
        raise DnsError("timeout, repeat, and jobs must be positive")
    cases = list(options.case)
    for path in options.case_file:
        cases.extend(parse_case_file(path))
    if not cases:
        cases = default_cases()
    protocols: Sequence[str] = ("udp", "tcp") if options.protocol == "both" else (options.protocol,)
    work = [
        (case, protocol)
        for _ in range(options.repeat)
        for case in cases
        for protocol in protocols
    ]
    comparisons: list[Comparison] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.jobs) as executor:
        futures = [
            executor.submit(
                compare_one,
                options.reference,
                options.candidate,
                case,
                protocol,
                options.timeout,
                options.dnssec,
                options.compare_ad,
            )
            for case, protocol in work
        ]
        for future in concurrent.futures.as_completed(futures):
            comparisons.append(future.result())
    comparisons.sort(key=lambda item: (item.case, item.protocol, item.reference.elapsed_ms))

    failures = [comparison for comparison in comparisons if not comparison.equal]
    for comparison in comparisons:
        status = "PASS" if comparison.equal else "DIFF"
        print(
            f"{status:4} {comparison.protocol:3} {comparison.case} "
            f"reference={comparison.reference.elapsed_ms:.1f}ms "
            f"candidate={comparison.candidate.elapsed_ms:.1f}ms"
        )
        for difference in comparison.differences:
            print(f"     {difference}")

    report = {
        "reference": asdict(options.reference),
        "candidate": asdict(options.candidate),
        "dnssec": options.dnssec,
        "compare_ad": options.compare_ad,
        "comparisons": [serializable(comparison) for comparison in comparisons],
        "passed": len(comparisons) - len(failures),
        "failed": len(failures),
    }
    if options.json:
        options.json.parent.mkdir(parents=True, exist_ok=True)
        options.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{report['passed']} comparison(s) passed; {report['failed']} differed")
    return 0 if not failures or options.allow_differences else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DnsError, OSError) as error:
        print(f"differential-resolved: {error}", file=sys.stderr)
        raise SystemExit(2) from error
