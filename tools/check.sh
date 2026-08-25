#!/usr/bin/env bash
# Full gate: Rust lints and tests, the Android artifact build, the AAR, and the
# mavenLocal publication. Run inside `nix develop`.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace

echo "==> build-android"
./tools/build-android.sh

echo "==> gradle"
(cd android && ./gradlew --no-daemon :lib:assembleRelease publishToMavenLocal)

echo "==> jvm replay tests"
# Replays the checked-in Ledger transcripts through the real FFI boundary against the
# host cdylib built above.
(cd android && ./gradlew --no-daemon :lib:testDebugUnitTest)

echo "==> aar contents"
aar=android/lib/build/outputs/aar/lib-release.aar
test -f "$aar"
unzip -l "$aar"

entries=$(unzip -Z1 "$aar")
for want in jni/arm64-v8a/libbhwi_ffi.so jni/x86_64/libbhwi_ffi.so classes.jar; do
  grep -qx "$want" <<<"$entries" || { echo "missing from AAR: $want" >&2; exit 1; }
done

# Both halves of the library must actually be compiled into the AAR, not just present as
# sources: the generated interpreter object and the file class holding the free functions,
# plus the hand-written Kotlin host layer (transports, framing links, loop, facade).
classes=$(unzip -p "$aar" classes.jar > "$root/target/aar-classes.jar" && unzip -Z1 "$root/target/aar-classes.jar")
for want in \
  uniffi/bhwi_ffi/Interp.class \
  uniffi/bhwi_ffi/Bhwi_ffiKt.class \
  com/wizardsardine/bhwi/HwiSession.class \
  com/wizardsardine/bhwi/Hwi.class \
  com/wizardsardine/bhwi/Link.class \
  com/wizardsardine/bhwi/HidChannel.class \
  com/wizardsardine/bhwi/LedgerHidLink.class \
  com/wizardsardine/bhwi/LedgerBleLink.class \
  com/wizardsardine/bhwi/ColdcardHidLink.class \
  com/wizardsardine/bhwi/BitBoxHidLink.class \
  com/wizardsardine/bhwi/JadeSerialLink.class
do
  grep -qx "$want" <<<"$classes" || { echo "missing from classes.jar: $want" >&2; exit 1; }
done

echo "==> mavenLocal publication"
m2=${HOME}/.m2/repository/com/wizardsardine/bhwi-ffi-android/0.1.0-SNAPSHOT
for want in \
  bhwi-ffi-android-0.1.0-SNAPSHOT.aar \
  bhwi-ffi-android-0.1.0-SNAPSHOT.pom \
  bhwi-ffi-android-0.1.0-SNAPSHOT.module \
  bhwi-ffi-android-0.1.0-SNAPSHOT-sources.jar
do
  test -s "$m2/$want" || { echo "missing publication file: $m2/$want" >&2; exit 1; }
done
ls -l "$m2"

echo "==> sample app (consumes the mavenLocal AAR)"
# Must come after the publication: `:sample` depends on the artifact, not the project.
(cd android && ./gradlew --no-daemon :sample:assembleDebug :sample:assembleDebugAndroidTest)

echo "==> all checks passed"
