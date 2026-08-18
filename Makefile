SHELL := /bin/sh
CC ?= cc
undefine FC
FC ?= gfortran
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Werror -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
FFLAGS ?= -O2 -g -std=f2018 -Wall -Wextra -Werror -fimplicit-none
LDLIBS ?= -lssl -lcrypto
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
SYSCONFDIR ?= /etc
DATADIR ?= $(PREFIX)/share
NSSWITCHDIR ?= $(DATADIR)/rustd-resolved
RUSTD_LIBEXECDIR ?= $(PREFIX)/lib/rustd
RUSTD_UNITDIR ?= $(PREFIX)/lib/rustd/system
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
DBUSSERVICEDIR ?= $(PREFIX)/share/dbus-1/system-services
DBUSPOLICYDIR ?= $(PREFIX)/share/dbus-1/system.d
POLKITDIR ?= $(PREFIX)/share/polkit-1/actions
.PHONY: all build test check-native check-rust check-formal check-packaging check-live check-nss check-reproducible clean install
.PHONY: nss release boot-smoke certify certify-smoke bench

all: build

build:
	cargo build --release --locked

check-native:
	mkdir -p build
	$(FC) $(FFLAGS) -Jbuild -c ffi/routing.f90 -o build/routing.o
	$(CC) $(CFLAGS) -Iffi -c ffi/native.c -o build/native.o
	$(CC) $(CFLAGS) -Iffi -c ffi/interface.c -o build/interface.o
	$(CC) $(CFLAGS) -Iffi -c ffi/tls.c -o build/tls.o
	$(CC) $(CFLAGS) -Iffi -c ffi/dnssec.c -o build/dnssec.o
	$(CC) $(CFLAGS) -Iffi -c ffi/netlink.c -o build/netlink.o
	$(CC) $(CFLAGS) -Iffi -c ffi/networkd.c -o build/networkd.o
	$(CC) $(CFLAGS) -Iffi -c ffi/mdns.c -o build/mdns.o
	$(CC) $(CFLAGS) -Iffi -c ffi/test_native.c -o build/test_native.o
	$(CC) $(CFLAGS) -Iffi -c ffi/test_mdns.c -o build/test_mdns.o
	$(FC) build/test_native.o build/native.o build/interface.o build/tls.o build/dnssec.o build/netlink.o build/networkd.o build/mdns.o build/routing.o $(LDLIBS) -o build/test_native
	./build/test_native
	$(CC) build/test_mdns.o build/mdns.o -o build/test_mdns
	./build/test_mdns

check-rust:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings
	cargo test --all-targets --all-features --locked

check-formal:
	idris2 --build formal/idris/resolved-policy.ipkg
	agda -i formal/agda formal/agda/Resolved/DNS/Name.agda
	agda -i formal/agda formal/agda/Resolved/DNS/Transaction.agda

check-packaging:
	bash -n tests/direct-root-privilege-drop.sh tests/release_feature_boundary.sh tests/ops_runtime_contract.sh tests/dbus-introspection.sh scripts/boot-smoke.sh scripts/installed-certification.sh
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	PYTHONPYCACHEPREFIX="$$work/pycache" python3 -m py_compile \
		tests/live-dns.py tests/deterministic-dns-server.py tests/live-llmnr.py tests/restart-soak.py scripts/probe-stub.py; \
	cargo metadata --locked --no-deps --format-version 1 >"$$work/cargo-metadata.json"; \
	python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); package=next(p for p in data["packages"] if p["name"]=="rustd-resolved"); bins=sorted(t["name"] for t in package["targets"] if "bin" in t["kind"]); expected=["rustd-resolvectl", "rustd-resolved"]; assert bins==expected, f"unexpected Cargo binary targets: {bins}"; default=set(package["features"]["default"]); assert default=={"fortran-routing", "idna-name"}, f"unexpected production default features: {sorted(default)}"' "$$work/cargo-metadata.json"; \
	test '$(RUSTD_UNITDIR)' = '$(PREFIX)/lib/rustd/system'; \
	test -f packaging/rustd/rustd-resolved.service; \
	test -f packaging/rustd/rustd-resolved-varlink.socket; \
	test -f packaging/rustd/rustd-resolved-monitor.socket; \
	test -f packaging/tmpfiles/rustd-resolved.conf; \
	test -f packaging/sysusers/rustd-resolve.conf; \
	test -f packaging/nsswitch.conf.fragment; \
	test -f packaging/dbus/org.freedesktop.resolve1.service; \
	test -f packaging/dbus/org.freedesktop.resolve1.conf; \
	test -f packaging/polkit/org.freedesktop.resolve1.policy; \
	grep -Fq 'After=rustd-sysusers.service network-pre.target' packaging/rustd/rustd-resolved.service; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd-resolved --dbus' packaging/rustd/rustd-resolved.service; \
	grep -Fq 'Conflicts=systemd-resolved.service' packaging/rustd/rustd-resolved.service; \
	grep -Fq 'ProtectSystem=full' packaging/rustd/rustd-resolved.service; \
	grep -Fq 'ReadWritePaths=/run/rustd /var/lib/rustd/resolved' packaging/rustd/rustd-resolved.service; \
	grep -Fq 'd /var/lib/rustd/resolved 0750 rustd-resolve rustd-resolve -' packaging/tmpfiles/rustd-resolved.conf; \
	grep -Fq 'drop_privileges("rustd-resolve", &config.runtime_directory)' src/main.rs; \
	grep -Fq '(UINT64_C(1) << CAP_NET_BIND_SERVICE) | (UINT64_C(1) << CAP_NET_RAW)' ffi/native.c; \
	test -f packaging/NetworkManager/conf.d/20-rustd-resolved.conf; \
	grep -Fq 'dns=none' packaging/NetworkManager/conf.d/20-rustd-resolved.conf; \
	grep -Fq 'rc-manager=unmanaged' packaging/NetworkManager/conf.d/20-rustd-resolved.conf; \
	grep -Fq 'systemd-resolved=false' packaging/NetworkManager/conf.d/20-rustd-resolved.conf; \
	grep -Fq 'L+ /etc/resolv.conf - - - - /run/rustd/resolve/stub-resolv.conf' packaging/tmpfiles/rustd-resolved.conf; \
	grep -Fq 'hosts: files myhostname rustd_dns [!UNAVAIL=return] dns' packaging/nsswitch.conf.fragment; \
	grep -Fq 'Exec=/usr/bin/rustctl start rustd-resolved.service' packaging/dbus/org.freedesktop.resolve1.service; \
	grep -Fq '<policy user="rustd-resolve">' packaging/dbus/org.freedesktop.resolve1.conf; \
	grep -Fq 'unix-user:rustd-resolve' packaging/polkit/org.freedesktop.resolve1.policy; \
	! grep -E -q 'SystemdService=|systemd-resolve|Exec=/bin/false' packaging/dbus/org.freedesktop.resolve1.service packaging/dbus/org.freedesktop.resolve1.conf packaging/polkit/org.freedesktop.resolve1.policy; \
	grep -Fq 'getenv("RUSTD_NOTIFY_SOCKET")' ffi/native.c; \
	! grep -Fq 'getenv("NOTIFY_SOCKET")' ffi/native.c; \
	grep -Fq '_nss_rustd_dns_gethostbyname4_r' nss/nss-rustd-dns.sym; \
	grep -Fq 'ListenStream=/run/rustd/resolve/io.rustd.Resolve' packaging/rustd/rustd-resolved-varlink.socket; \
	grep -Fq 'ListenStream=/run/rustd/resolve/io.rustd.Resolve.Monitor' packaging/rustd/rustd-resolved-monitor.socket; \
	grep -Fq 'RUSTCTL="$${RUSTD_RESOLVED_RUSTCTL:-/usr/bin/rustctl}"' scripts/boot-smoke.sh; \
	grep -Fq 'RUNTIME_DIR="$${RUSTD_RESOLVED_RUNTIME_DIR:-/run/rustd/resolve}"' scripts/boot-smoke.sh; \
	grep -Fq 'io.rustd.Resolve' scripts/boot-smoke.sh; \
	! grep -E -q 'systemctl|systemd-resolved|/run/systemd/resolve|resolvectl-rs' scripts/boot-smoke.sh; \
	! grep -R -E -q 'libnss_resolve|hosts:.*\bresolve\b' packaging PKGBUILD; \
	bad=$$(grep -R -nE 'systemd' packaging --exclude-dir=NetworkManager | grep -v 'Conflicts=systemd-resolved.service' || true); \
	test -z "$$bad"; \
	! grep -E -q 'sd-notify|systemd-compat-paths|resolve1-dbus-compat' Cargo.toml
	bash tests/ops_runtime_contract.sh

check-live: build
	python3 tests/live-dns.py target/release/rustd-resolved target/release/rustd-resolvectl

check-nss:
	$(MAKE) -C nss clean check

check-reproducible:
	bash scripts/build-reproducible-release.sh

test: check-native check-rust check-packaging check-nss

install: build nss
	install -Dm0755 target/release/rustd-resolved $(DESTDIR)$(RUSTD_LIBEXECDIR)/rustd-resolved
	install -Dm0755 target/release/rustd-resolvectl $(DESTDIR)$(BINDIR)/rustd-resolvectl
	install -Dm0755 nss/libnss_rustd_dns.so.2 $(DESTDIR)$(LIBDIR)/libnss_rustd_dns.so.2
	install -Dm0644 packaging/resolved.conf $(DESTDIR)$(SYSCONFDIR)/rustd/resolved.conf
	install -Dm0644 packaging/nsswitch.conf.fragment $(DESTDIR)$(NSSWITCHDIR)/nsswitch.conf.fragment
	install -Dm0644 packaging/rustd/rustd-resolved.service $(DESTDIR)$(RUSTD_UNITDIR)/rustd-resolved.service
	install -Dm0644 packaging/rustd/rustd-resolved-varlink.socket $(DESTDIR)$(RUSTD_UNITDIR)/rustd-resolved-varlink.socket
	install -Dm0644 packaging/rustd/rustd-resolved-monitor.socket $(DESTDIR)$(RUSTD_UNITDIR)/rustd-resolved-monitor.socket
	install -Dm0644 packaging/tmpfiles/rustd-resolved.conf $(DESTDIR)$(TMPFILESDIR)/rustd-resolved.conf
	install -Dm0644 packaging/sysusers/rustd-resolve.conf $(DESTDIR)$(SYSUSERSDIR)/rustd-resolve.conf
	install -Dm0644 packaging/dbus/org.freedesktop.resolve1.service $(DESTDIR)$(DBUSSERVICEDIR)/org.freedesktop.resolve1.service
	install -Dm0644 packaging/dbus/org.freedesktop.resolve1.conf $(DESTDIR)$(DBUSPOLICYDIR)/org.freedesktop.resolve1.conf
	install -Dm0644 packaging/polkit/org.freedesktop.resolve1.policy $(DESTDIR)$(POLKITDIR)/org.freedesktop.resolve1.policy
	install -Dm0644 packaging/NetworkManager/conf.d/20-rustd-resolved.conf \
		$(DESTDIR)$(PREFIX)/lib/NetworkManager/conf.d/20-rustd-resolved.conf
clean:
	rm -rf build target
	$(MAKE) -C nss clean

nss:
	$(MAKE) -C nss

release: test check-formal check-live check-reproducible

boot-smoke:
	bash scripts/boot-smoke.sh

certify: release boot-smoke
	RUSTD_CERT_MODE=release bash scripts/installed-certification.sh

certify-smoke: boot-smoke
	RUSTD_CERT_MODE=smoke bash scripts/installed-certification.sh

bench:
	bash tests/supremacy/bench_compare.sh