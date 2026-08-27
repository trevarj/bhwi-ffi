#!/usr/bin/env bash
# Build the Rust core and generated Swift bindings as a local iOS XCFramework.
# Requires macOS, Xcode command-line tools, Cargo, and the targets in rust-toolchain.toml.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [[ $(uname -s) != Darwin ]]; then
  echo "build-ios.sh requires macOS and Xcode" >&2
  exit 1
fi
for tool in cargo xcodebuild; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

export IPHONEOS_DEPLOYMENT_TARGET=16.0

device=target/aarch64-apple-ios/release/libbhwi_ffi.a
simulator=target/aarch64-apple-ios-sim/release/libbhwi_ffi.a
staging=target/ios-staging
output=target/ios/BhwiFFI.xcframework
generated=ios/Sources/Bhwi/Generated

echo "==> Rust static libraries"
cargo build --release -p bhwi-ffi --target aarch64-apple-ios
cargo build --release -p bhwi-ffi --target aarch64-apple-ios-sim

echo "==> Swift bindings and C module"
rm -rf "$staging" "$generated"
mkdir -p "$staging" "$generated" "$(dirname "$output")"
cargo run --release -q -p bhwi-ffi-bindgen --bin bhwi-ffi-bindgen-swift -- \
  "$device" "$staging" \
  --swift-sources --headers --modulemap --xcframework \
  --module-name BhwiFFI --modulemap-filename module.modulemap
mv "$staging"/*.swift "$generated"/
test -f "$generated/Bhwi.swift"
test -f "$staging/BhwiFFI.h"
test -f "$staging/module.modulemap"

echo "==> XCFramework"
rm -rf "$output"
xcodebuild -create-xcframework \
  -library "$device" -headers "$staging" \
  -library "$simulator" -headers "$staging" \
  -output "$output"

echo "==> $output"
