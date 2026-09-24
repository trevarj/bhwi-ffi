#!/usr/bin/env bash
# Produce everything the Gradle build consumes: JNI shared objects, a host shared
# object for JVM replay tests, and the generated Kotlin bindings.
# Run inside `nix develop` (needs cargo, cargo-ndk, the Android NDK).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

jni_libs=android/lib/src/main/jniLibs
kotlin_out=android/lib/src/main/kotlin

# Wipe generated trees so a removed ABI or renamed type cannot survive a rebuild.
rm -rf "$jni_libs" "$kotlin_out/uniffi"
mkdir -p "$jni_libs" "$kotlin_out"

echo "==> android cdylibs (arm64-v8a, x86_64)"
cargo ndk -t arm64-v8a -t x86_64 -o "$jni_libs" build --locked --release -p bhwi-ffi

echo "==> host cdylib (JVM unit tests)"
cargo build --locked --release -p bhwi-ffi

echo "==> kotlin bindings"
# Library mode reads the metadata out of the freshly built host cdylib, so the
# bindings can never drift from the scaffolding. `--no-format` because ktlint is
# not in the devshell.
cargo run --locked --release -q -p bhwi-ffi-bindgen --bin bhwi-ffi-bindgen -- generate \
  --library target/release/libbhwi_ffi.so \
  --language kotlin \
  --out-dir "$kotlin_out" \
  --no-format

# The Kotlin package is uniffi's default (`uniffi.<namespace>`); pin it here so a
# silent upstream change breaks the build instead of the consumers.
test -f "$kotlin_out/uniffi/bhwi_ffi/bhwi_ffi.kt"
grep -qx 'package uniffi.bhwi_ffi' "$kotlin_out/uniffi/bhwi_ffi/bhwi_ffi.kt"

echo "==> done"
find "$jni_libs" -name '*.so' -printf '%p\n' | sort
echo "$kotlin_out/uniffi/bhwi_ffi/bhwi_ffi.kt"
