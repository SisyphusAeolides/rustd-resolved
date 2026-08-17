#!/usr/bin/env bash
set -euo pipefail

TARGET=aarch64-unknown-linux-gnu

sudo dpkg --add-architecture arm64
cat > /tmp/rustd-multiarch.sources <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-security
Components: main universe restricted multiverse
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports
Suites: noble noble-updates noble-security
Components: main universe restricted multiverse
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

apt_options=(
    -o Dir::Etc::sourcelist=/tmp/rustd-multiarch.sources
    -o Dir::Etc::sourceparts=-
    -o APT::Get::List-Cleanup=0
)
sudo apt-get "${apt_options[@]}" update
sudo apt-get "${apt_options[@]}" install --yes --no-install-recommends \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    gfortran-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    libssl-dev:arm64 \
    liburing-dev:arm64

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export FC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gfortran

cargo build --release --locked --target "$TARGET"
