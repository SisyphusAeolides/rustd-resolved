#!/usr/bin/env python3
from pathlib import Path

main = Path("src/main.rs")
text = main.read_text()
start = text.index("fn spawn_dbus(")
end = text.index("\nfn spawn_varlink(", start)
replacement = r'''fn spawn_dbus(
    resolver: &Arc<Resolver>,
    disabled: bool,
) -> Result<Option<thread::JoinHandle<()>>, Box<dyn Error>> {
    if disabled {
        return Ok(None);
    }
    let resolver = Arc::clone(resolver);
    Ok(Some(
        thread::Builder::new()
            .name("rustd-resolved-dbus".to_owned())
            .spawn(move || {
                while !rustd_resolved::daemon::stop_requested() {
                    let server = DbusServer::new(Arc::clone(&resolver));
                    match server.run() {
                        Ok(()) if rustd_resolved::daemon::stop_requested() => break,
                        Ok(()) => {
                            eprintln!("rustd-resolved: D-Bus bridge stopped unexpectedly; retrying");
                        }
                        Err(error) => {
                            eprintln!("rustd-resolved: D-Bus bridge unavailable: {error}; retrying");
                        }
                    }
                    for _ in 0..10 {
                        if rustd_resolved::daemon::stop_requested() {
                            return;
                        }
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            })?,
    ))
}
'''
text = text[:start] + replacement + text[end:]
main.write_text(text)

core = Path("src/dbus_core.rs")
text = core.read_text()
old = '        "systemd-resolved"\n'
new = '        "rustd-resolved"\n'
if old not in text:
    raise SystemExit("D-Bus SyslogIdentifier migration point not found")
core.write_text(text.replace(old, new, 1))

lifecycle = Path("src/lifecycle.rs")
text = lifecycle.read_text()
text = text.replace(
    "//! systemd integration: sd_notify, watchdog, signal-driven control flags.",
    "//! Resolver lifecycle integration: service notifications, watchdog, and signal-driven control flags.",
    1,
)
text = text.replace('info!("sd_notify READY=1");', 'info!("RustD notify READY=1");', 1)
lifecycle.write_text(text)

live = Path("tests/live-dbus-isolation.py")
live.write_text(r'''#!/usr/bin/env python3
"""Verify that the optional D-Bus bridge cannot take down native resolution."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: live-dbus-isolation.py RUSTD_RESOLVED RUSTD_RESOLVECTL")
    daemon = Path(sys.argv[1]).resolve()
    resolvectl = Path(sys.argv[2]).resolve()
    if not daemon.is_file() or not os.access(daemon, os.X_OK):
        raise FileNotFoundError(daemon)
    if not resolvectl.is_file() or not os.access(resolvectl, os.X_OK):
        raise FileNotFoundError(resolvectl)

    with tempfile.TemporaryDirectory(prefix="rustd-resolved-dbus-isolation-") as temporary:
        root = Path(temporary)
        run_dir = root / "run"
        varlink = run_dir / "io.rustd.Resolve"
        config = root / "resolved.conf"
        log = root / "daemon.log"
        config.write_text(
            "[Resolve]\n"
            "DNS=\n"
            "FallbackDNS=\n"
            "DNSSEC=no\n"
            "DNSOverTLS=no\n"
            "LLMNR=no\n"
            "MulticastDNS=no\n",
            encoding="utf-8",
        )
        port = free_port()
        environment = os.environ.copy()
        environment["DBUS_SYSTEM_BUS_ADDRESS"] = f"unix:path={root / 'missing-system-bus'}"

        with log.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                [
                    str(daemon),
                    "--config",
                    str(config),
                    "--listen",
                    f"127.0.0.1:{port}",
                    "--runtime-directory",
                    str(run_dir),
                    "--varlink",
                    str(varlink),
                    "--workers",
                    "1",
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
            )
            try:
                deadline = time.monotonic() + 15
                last = "native Varlink socket did not appear"
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log_file.flush()
                        details = log.read_text(encoding="utf-8", errors="replace")
                        raise AssertionError(
                            f"resolver exited while D-Bus was unavailable: {process.returncode}\n{details}"
                        )
                    if varlink.exists():
                        query = subprocess.run(
                            [str(resolvectl), "--socket", str(varlink), "query", "localhost"],
                            text=True,
                            capture_output=True,
                            timeout=5,
                        )
                        if query.returncode == 0:
                            break
                        last = query.stderr or query.stdout
                    time.sleep(0.1)
                else:
                    raise AssertionError(last)

                time.sleep(2)
                if process.poll() is not None:
                    log_file.flush()
                    details = log.read_text(encoding="utf-8", errors="replace")
                    raise AssertionError(
                        f"optional D-Bus failure stopped the native resolver\n{details}"
                    )
            finally:
                terminate(process)

        output = log.read_text(encoding="utf-8", errors="replace")
        if "D-Bus bridge unavailable" not in output:
            raise AssertionError(f"expected D-Bus retry diagnostic was not emitted:\n{output}")
        if "D-Bus server failed" in output:
            raise AssertionError("legacy fatal D-Bus diagnostic remains")

    print("D-Bus outage isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''')
live.chmod(0o755)

makefile = Path("Makefile")
text = makefile.read_text()
old = "\t\ttests/live-dns.py tests/deterministic-dns-server.py tests/live-llmnr.py tests/restart-soak.py scripts/probe-stub.py; \\\n"
new = "\t\ttests/live-dns.py tests/live-dbus-isolation.py tests/deterministic-dns-server.py tests/live-llmnr.py tests/restart-soak.py scripts/probe-stub.py; \\\n"
if old not in text:
    raise SystemExit("Makefile Python validation list not found")
makefile.write_text(text.replace(old, new, 1))

workflow = Path(".github/workflows/build-and-test.yml")
text = workflow.read_text()
marker = '''      - name: Check live D-Bus contracts
        if: ${{ matrix.toolchain == 'stable' }}
        shell: bash
        run: bash tests/dbus-introspection.sh target/release/rustd-resolved target/release/rustd-resolvectl
'''
insert = '''      - name: Check D-Bus outage isolation
        if: ${{ matrix.toolchain == 'stable' }}
        shell: bash
        run: |
          set -euo pipefail
          if ! getent passwd rustd-resolve >/dev/null; then
            sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustd-resolve
          fi
          sudo python3 tests/live-dbus-isolation.py target/release/rustd-resolved target/release/rustd-resolvectl

'''
if marker not in text:
    raise SystemExit("build-and-test live D-Bus insertion point not found")
workflow.write_text(text.replace(marker, insert + marker, 1))

print("hardened optional D-Bus bridge and added live isolation regression")
