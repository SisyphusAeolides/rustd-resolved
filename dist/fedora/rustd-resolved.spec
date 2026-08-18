Name:           rustd-resolved
Version:        0.2.3
Release:        1%{?dist}
Summary:        RustD native DNS resolver for Fedora
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd-resolved
Source0:        rustd-resolved-%{version}.tar.gz

BuildRequires:  cargo >= 1.74
BuildRequires:  rust >= 1.74
BuildRequires:  gcc
BuildRequires:  gcc-gfortran
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  liburing-devel
BuildRequires:  python3

Requires:       rustd >= 0.1.2
Conflicts:      systemd-resolved

%description
RustD-Resolved is the native DNS resolver and NSS integration for RustD. The
package installs only RustD-owned runtime paths while retaining the bounded
org.freedesktop.resolve1 D-Bus compatibility surface required by Fedora clients.

%prep
%autosetup -n rustd-resolved-%{version}
test -f Cargo.lock
test -f certification/rfc5011-rollover-latest.txt

%build
export CARGO_NET_OFFLINE=true
%make_build build nss

%check
export CARGO_NET_OFFLINE=true
make check-native check-rust check-packaging check-nss
cc -std=c11 -O1 -g -Wall -Wextra -Werror -Iffi \
   -fsanitize=address,undefined -fno-omit-frame-pointer \
   ffi/test_iouring_dns.c ffi/iouring_dns.c -luring -o /tmp/rustd-resolved-iouring-sanitize
SR_SKIP_RING=1 ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 /tmp/rustd-resolved-iouring-sanitize
cc -std=c11 -O2 -Wall -Wextra -Werror -Iffi \
   ffi/test_iouring_dns.c ffi/iouring_dns.c -luring -o /tmp/rustd-resolved-iouring
/tmp/rustd-resolved-iouring

%install
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
%{_libdir}/libnss_rustd_dns.so.2
%{_prefix}/lib/tmpfiles.d/rustd-resolved.conf
%{_prefix}/lib/sysusers.d/rustd-resolve.conf
%{_datadir}/rustd-resolved/nsswitch.conf.fragment
%{_datadir}/dbus-1/system-services/org.freedesktop.resolve1.service
%{_datadir}/dbus-1/system.d/org.freedesktop.resolve1.conf
%{_datadir}/polkit-1/actions/org.freedesktop.resolve1.policy
%{_prefix}/lib/NetworkManager/conf.d/20-rustd-resolved.conf

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.2.3-1
- Add Fedora RustD-Resolved package with io_uring release regressions
