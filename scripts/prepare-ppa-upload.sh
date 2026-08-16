#!/bin/bash
set -e

echo "Preparing rustd-resolved for Launchpad PPA upload..."

# 1. Vendor the dependencies
echo "Vendoring Cargo dependencies..."
mkdir -p .cargo
cargo vendor crates-vendor > .cargo/config.toml

# 2. Build the upstream tarball
echo "Creating upstream source tarball..."
UPSTREAM_VER=$(dpkg-parsechangelog -S Version | cut -d- -f1)
tar czf "../rustd-resolved_${UPSTREAM_VER}.orig.tar.gz" --exclude=./.git --exclude=./debian .

# 3. Build the Debian source package
echo "Building Debian source package..."
debuild -S -sa

echo "Done! You can now upload the resulting _source.changes file to Launchpad:"
echo "dput ppa:sisyphusaeolides/corinth ../rustd-resolved_*.changes"
