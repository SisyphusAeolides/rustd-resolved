pkgname=rustd-resolved
pkgver=0.2.1
pkgrel=1
pkgdesc='Compatibility-oriented Rust reimplementation of systemd-resolved'
arch=('x86_64')
url='https://github.com/SisyphusAeolides/rustd-resolved'
license=('LGPL-2.1-or-later')
depends=('systemd' 'openssl')
makedepends=('rust' 'gcc-fortran' 'git')
provides=('systemd-resolved')
conflicts=('systemd-resolved')
source=("${pkgname}::git+${url}.git")
b2sums=('SKIP')

pkgver() {
  cd "${srcdir}/${pkgname}"
  sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1
}

build() {
  cd "${srcdir}/${pkgname}"
  cargo build --release --locked
}

check() {
  cd "${srcdir}/${pkgname}"
  cargo test --locked
}

package() {
  cd "${srcdir}/${pkgname}"
  make install DESTDIR="${pkgdir}" PREFIX=/usr
}
