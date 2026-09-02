# Resolve the platform systemd EVR in the buildroot when this SRPM is rebuilt
# by Koji. A zero fallback keeps source-package inspection possible, while a
# real RLC buildroot always supplies the exact capability being replaced.
%{!?systemd_compat_evr:%global systemd_compat_evr %(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' systemd 2>/dev/null || printf '0:0-0')}

Name:           rustd-resolved
Version:        0.2.3
Release:        5%{?dist}
Summary:        RustD native DNS resolver for Fedora
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd-resolved
Source0:        rustd-resolved-%{version}.tar.gz

BuildRequires:  cargo >= 1.74
BuildRequires:  rust >= 1.74
BuildRequires:  rustfmt
BuildRequires:  clippy
BuildRequires:  gcc
BuildRequires:  gcc-gfortran
BuildRequires:  libasan
BuildRequires:  libubsan
BuildRequires:  make
BuildRequires:  openssl
BuildRequires:  openssl-devel
BuildRequires:  liburing-devel
BuildRequires:  python3

Requires:       rustd >= 0.1.2
Requires:       %{name}-nss%{?_isa} = %{version}-%{release}
Provides:       systemd-resolved = %{systemd_compat_evr}
Provides:       systemd-resolved%{?_isa} = %{systemd_compat_evr}
Obsoletes:      systemd-resolved <= %{systemd_compat_evr}

%description
RustD-Resolved is the native DNS resolver and service integration for RustD.
The daemon package retains the bounded org.freedesktop.resolve1 D-Bus
compatibility surface required by Fedora clients and is installed during the
exclusive resolver swap.

%package nss
Summary:        RustD DNS NSS module for staged Fedora cutover

%description nss
The RustD DNS NSS module and authselect fragment. This subpackage contains no
systemd-resolved-owned paths and can be installed before the exclusive cutover,
so Fedora authentication and name-service configuration can be migrated and
validated while the original resolver stack remains installed.

%prep
%autosetup -n rustd-resolved-%{version}
test -f Cargo.lock
test -f certification/rfc5011-rollover-latest.txt

%build
export CARGO_NET_OFFLINE=true
# RPM's build macros provide RUSTFLAGS explicitly, which takes precedence over
# .cargo/config.toml. Keep the libc backend selection from that config active
# on current nightlies: rustix 0.37's linux_raw backend relies on reserved
# rustc_* attributes that newer compilers reject.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg rustix_use_libc"
%make_build build nss

%check
export CARGO_NET_OFFLINE=true
export RUSTFLAGS="${RUSTFLAGS:-} --cfg rustix_use_libc"
make check-native check-rust check-packaging check-nss
cc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-error=cpp -Iffi \
   -fsanitize=address,undefined -fno-omit-frame-pointer \
   ffi/test_iouring_dns.c ffi/iouring_dns.c -luring -o /tmp/rustd-resolved-iouring-sanitize
SR_SKIP_RING=1 ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 /tmp/rustd-resolved-iouring-sanitize
cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-error=cpp -Iffi \
   ffi/test_iouring_dns.c ffi/iouring_dns.c -luring -o /tmp/rustd-resolved-iouring
/tmp/rustd-resolved-iouring

%install
export RUSTFLAGS="${RUSTFLAGS:-} --cfg rustix_use_libc"
make DESTDIR=%{buildroot} \
     PREFIX=%{_prefix} \
     LIBDIR=%{_libdir} \
     install

%files
%license LICENSE*
%doc README.md
%config(noreplace) %{_sysconfdir}/rustd/resolved.conf
%{_bindir}/rustd-resolvectl
%{_prefix}/lib/rustd/rustd-resolved
%{_prefix}/lib/rustd/system/rustd-resolved.service
%{_prefix}/lib/rustd/system/rustd-resolved-varlink.socket
%{_prefix}/lib/rustd/system/rustd-resolved-monitor.socket
%{_prefix}/lib/tmpfiles.d/rustd-resolved.conf
%{_prefix}/lib/sysusers.d/rustd-resolve.conf
%{_datadir}/dbus-1/system-services/org.freedesktop.resolve1.service
%{_datadir}/dbus-1/system.d/org.freedesktop.resolve1.conf
%{_datadir}/polkit-1/actions/org.freedesktop.resolve1.policy
%{_prefix}/lib/NetworkManager/conf.d/99-rustd-resolved.conf
%{_sysconfdir}/rustd/system/dbus-org.freedesktop.resolve1.service

%files nss
%license LICENSE*
%{_libdir}/libnss_rustd_dns.so.2
%{_datadir}/rustd-resolved/nsswitch.conf.fragment

%changelog
* Wed Sep 02 2026 Kenny Glauner <SisyphusAeolides@pm.me> - 0.2.3-5
- Keep the libc backend selection active during RPM installation rebuilds

* Sun Aug 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.2.3-4
- Avoid CAP_FOWNER by chmodding the resolver runtime directory after ownership transition

* Sun Aug 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.2.3-3
- Permit the resolver's bounded runtime-directory ownership transition

* Sun Aug 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.2.3-2
- Allow the resolver's audited privilege transition to use CAP_SETPCAP
- Require RustD system users before resolver activation

* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.2.3-1
- Complete license metadata for the staged NSS subpackage
- Split the nonconflicting NSS module for fail-closed Fedora cutover staging
- Add Fedora RustD-Resolved package with io_uring release regressions
