#!/usr/bin/env python3
"""Destructive split-DNS/VPN route-change certification for RustD-Resolved."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

PUBLIC_UPSTREAM = "10.204.0.1"
CLIENT_PUBLIC = "10.204.0.2"
VPN_A_UPSTREAM = "10.205.0.1"
CLIENT_VPN_A = "10.205.0.2"
VPN_B_UPSTREAM = "10.206.0.1"
CLIENT_VPN_B = "10.206.0.2"
PREFIX = "30"
UPSTREAM_PORT = 15353
STUB_PORT = 1053
PROXY_PORT = 1054
PUBLIC_ANSWER = "192.0.2.90"
VPN_A_ANSWER = "192.0.2.91"
VPN_B_ANSWER = "192.0.2.92"


def command(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, text=True, capture_output=capture)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command is missing: {name}")


def terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def ifindex(namespace: str, interface: str) -> int:
    output = command(
        "ip", "netns", "exec", namespace, "ip", "-o", "link", "show", "dev", interface,
        capture=True,
    ).stdout
    try:
        value = int(output.split(":", 1)[0])
    except (ValueError, IndexError) as error:
        raise RuntimeError(f"unable to resolve ifindex for {interface}: {output!r}") from error
    if value <= 0:
        raise RuntimeError(f"invalid ifindex for {interface}: {value}")
    return value


def write_link(path: Path, dns: str, route_domain: bool, default_route: bool) -> None:
    text = (
        "ADMIN_STATE=configured\n"
        "OPER_STATE=routable\n"
        f"DNS={dns}:{UPSTREAM_PORT}\n"
        + ("ROUTE_DOMAINS=corp.test\n" if route_domain else "")
        + f"DNS_DEFAULT_ROUTE={'yes' if default_route else 'no'}\n"
        "LLMNR=no\n"
        "MDNS=no\n"
        "DNS_OVER_TLS=no\n"
        "DNSSEC=no\n"
    )
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o644)
    os.replace(temporary, path)


def count_name(path: Path, name: str) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if len(line.split()) >= 2 and line.split()[1] == name
    )


def probe(namespace: str, probe_path: Path, name: str, answer: str, identifier: int) -> None:
    result = command(
        "ip", "netns", "exec", namespace, sys.executable, str(probe_path),
        "127.0.0.1", str(STUB_PORT), "--protocol", "both",
        "--identifier", hex(identifier), "--name", name, "--answer", answer,
        check=False, capture=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
        raise RuntimeError(f"DNS probe failed for {name}: {detail}")


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    record = {
        "gate": "dns.vpn_change",
        "status": "pass",
        "detail": (
            "first-party four-namespace campaign completed alternating route-only corp.test ownership "
            "between two live VPN links; every unique UDP/TCP stub query resolved through the selected "
            "VPN DNS server, the inactive VPN server never saw that cycle's private name, and the public "
            "default-route DNS server observed zero corp.test queries"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "scripts/vpn-split-dns-driver.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run(options: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("VPN split-DNS certification must run as root")
    if options.iterations < 20:
        raise RuntimeError("dns.vpn_change certification requires at least 20 iterations")
    for binary in ("ip", "python3", "git"):
        require_command(binary)

    repository = options.repository.resolve()
    resolver = options.binary.resolve()
    server = repository / "tests/scenarios/lab_dns_server.py"
    probe_path = repository / "tests/scenarios/lab_dns_probe.py"
    for path in (resolver, server, probe_path):
        if not path.exists():
            raise RuntimeError(f"required lab path is missing: {path}")
    if not os.access(resolver, os.X_OK):
        raise RuntimeError(f"resolver is not executable: {resolver}")

    revision = command("git", "-C", str(repository), "rev-parse", "HEAD", capture=True).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve the exact resolver commit SHA")

    suffix = f"{os.getpid() % 100000:05d}"
    client_ns = f"rdc{suffix}"
    public_ns = f"rdp{suffix}"
    vpn_a_ns = f"rda{suffix}"
    vpn_b_ns = f"rdb{suffix}"
    namespaces = (client_ns, public_ns, vpn_a_ns, vpn_b_ns)
    cp = f"cp{suffix}"[:15]
    pp = f"pp{suffix}"[:15]
    ca = f"ca{suffix}"[:15]
    pa = f"pa{suffix}"[:15]
    cb = f"cb{suffix}"[:15]
    pb = f"pb{suffix}"[:15]
    processes: list[subprocess.Popen[str]] = []

    with tempfile.TemporaryDirectory(prefix="rustd-vpn-split-dns-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        state_dir = root / "links"
        state_dir.mkdir(mode=0o755)
        runtime = root / "runtime"
        config = root / "resolved.conf"
        config.write_text(
            "[Resolve]\nDNS=\nFallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
            encoding="utf-8",
        )
        config.chmod(0o644)
        public_queries = root / "public.queries"
        vpn_a_queries = root / "vpn-a.queries"
        vpn_b_queries = root / "vpn-b.queries"
        resolver_log = root / "resolver.log"

        try:
            for namespace in namespaces:
                command("ip", "netns", "add", namespace)
                command("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")

            for client_if, peer_if, peer_ns in ((cp, pp, public_ns), (ca, pa, vpn_a_ns), (cb, pb, vpn_b_ns)):
                command("ip", "link", "add", client_if, "type", "veth", "peer", "name", peer_if)
                command("ip", "link", "set", client_if, "netns", client_ns)
                command("ip", "link", "set", peer_if, "netns", peer_ns)

            for namespace, interface, address in (
                (client_ns, cp, CLIENT_PUBLIC),
                (public_ns, pp, PUBLIC_UPSTREAM),
                (client_ns, ca, CLIENT_VPN_A),
                (vpn_a_ns, pa, VPN_A_UPSTREAM),
                (client_ns, cb, CLIENT_VPN_B),
                (vpn_b_ns, pb, VPN_B_UPSTREAM),
            ):
                command("ip", "netns", "exec", namespace, "ip", "address", "add", f"{address}/{PREFIX}", "dev", interface)
                command("ip", "netns", "exec", namespace, "ip", "link", "set", interface, "up")

            public_index = ifindex(client_ns, cp)
            vpn_a_index = ifindex(client_ns, ca)
            vpn_b_index = ifindex(client_ns, cb)
            write_link(state_dir / str(public_index), PUBLIC_UPSTREAM, False, True)
            write_link(state_dir / str(vpn_a_index), VPN_A_UPSTREAM, True, False)
            write_link(state_dir / str(vpn_b_index), VPN_B_UPSTREAM, False, False)

            server_specs = (
                (public_ns, PUBLIC_UPSTREAM, PUBLIC_ANSWER, "test", public_queries),
                (vpn_a_ns, VPN_A_UPSTREAM, VPN_A_ANSWER, "corp.test", vpn_a_queries),
                (vpn_b_ns, VPN_B_UPSTREAM, VPN_B_ANSWER, "corp.test", vpn_b_queries),
            )
            for namespace, address, answer, accepted_suffix, query_log in server_specs:
                process = subprocess.Popen(
                    [
                        "ip", "netns", "exec", namespace, sys.executable, str(server),
                        "--listen", address, "--port", str(UPSTREAM_PORT),
                        "--suffix", accepted_suffix, "--answer", answer,
                        "--query-log", str(query_log),
                    ],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                )
                processes.append(process)
            time.sleep(0.3)
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f"controlled DNS upstream failed to start: {process.stderr.read()}")

            with resolver_log.open("w", encoding="utf-8") as resolver_output:
                environment = os.environ.copy()
                environment["RUSTD_NETWORK_LINKS_DIR"] = str(state_dir)
                resolver_process = subprocess.Popen(
                    [
                        "ip", "netns", "exec", client_ns, str(resolver),
                        "--config", str(config),
                        "--listen", f"127.0.0.1:{STUB_PORT}",
                        "--proxy-listen", f"127.0.0.1:{PROXY_PORT}",
                        "--runtime-directory", str(runtime),
                        "--workers", "2", "--no-varlink", "--no-dbus",
                    ],
                    stdout=resolver_output, stderr=subprocess.STDOUT, text=True, env=environment,
                )
                processes.append(resolver_process)
                time.sleep(0.5)
                if resolver_process.poll() is not None:
                    raise RuntimeError(f"resolver failed to start: {resolver_process.returncode}")

                for cycle in range(1, options.iterations + 1):
                    active_a = cycle % 2 == 1
                    write_link(state_dir / str(vpn_a_index), VPN_A_UPSTREAM, active_a, False)
                    write_link(state_dir / str(vpn_b_index), VPN_B_UPSTREAM, not active_a, False)
                    time.sleep(0.5)
                    if resolver_process.poll() is not None:
                        raise RuntimeError(f"resolver exited during VPN change {cycle}: {resolver_process.returncode}")

                    private_name = f"vpn-{cycle:03d}.corp.test"
                    public_name = f"public-{cycle:03d}.test"
                    active_log = vpn_a_queries if active_a else vpn_b_queries
                    inactive_log = vpn_b_queries if active_a else vpn_a_queries
                    expected_answer = VPN_A_ANSWER if active_a else VPN_B_ANSWER
                    before_active = count_name(active_log, private_name)
                    before_inactive = count_name(inactive_log, private_name)
                    before_public_private = count_name(public_queries, private_name)

                    probe(client_ns, probe_path, private_name, expected_answer, 0x7300 + cycle * 4)
                    probe(client_ns, probe_path, public_name, PUBLIC_ANSWER, 0x7302 + cycle * 4)
                    time.sleep(0.05)

                    if count_name(active_log, private_name) <= before_active:
                        raise RuntimeError(f"selected VPN DNS server saw no query at change {cycle}")
                    if count_name(inactive_log, private_name) != before_inactive:
                        raise RuntimeError(f"inactive VPN DNS server received protected query at change {cycle}")
                    if count_name(public_queries, private_name) != before_public_private:
                        raise RuntimeError(f"protected query leaked to public DNS at change {cycle}")

                if resolver_process.poll() is not None:
                    raise RuntimeError(f"resolver exited after VPN campaign: {resolver_process.returncode}")

            evidence = options.evidence_out or (repository / "target/certification/dns-vpn-change.jsonl")
            write_evidence(evidence.resolve(), revision, options.iterations)
            print(f"PASS dns.vpn_change iterations={options.iterations} evidence={evidence}")
            return 0
        except BaseException:
            if resolver_log.exists():
                print("--- resolver log ---", file=sys.stderr)
                print(resolver_log.read_text(encoding="utf-8"), file=sys.stderr)
            for label, log in (("public", public_queries), ("vpn-a", vpn_a_queries), ("vpn-b", vpn_b_queries)):
                if log.exists():
                    print(f"--- {label} query log ---", file=sys.stderr)
                    print(log.read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                terminate(process)
            for namespace in reversed(namespaces):
                command("ip", "netns", "del", namespace, check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument(
        "--binary", type=Path,
        default=Path(os.environ.get("RUSTD_RESOLVED_BIN", "target/release/rustd-resolved")),
    )
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


def main() -> int:
    options = parse_args()
    if options.scenario != "vpn-split-dns" or options.gate != "dns.vpn_change":
        raise RuntimeError(f"unsupported VPN lab scenario/gate: {options.scenario}/{options.gate}")
    if not options.binary.is_absolute():
        options.binary = options.repository / options.binary
    return run(options)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"VPN split-DNS lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
