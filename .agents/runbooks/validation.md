# Validation

Commands below run from the repository root unless stated otherwise. They are
entry points, not recorded passes. Use the changed surface to choose additional
checks; report environmental blockers rather than substituting weaker evidence.

## Docs-only

Check relative links and anchors, named paths, command spelling/prerequisites
against scripts/configuration, and support claims against source and observed
results. Reconcile the catalog's unsupported Swift claims without rewriting its
history. Do not run builds, tests, generators or formatters for documentation-only
changes. Report the documentation checks performed, followed by:
`Skipped code validation because only docs changed.`

## Prerequisites and non-emulator gate

The current workflow is Linux-hosted. Use Nix with flakes and `nix develop` for
Rust plus Android targets, cargo-ndk, JDK, SDK and NDK. The checksum-pinned Gradle
wrapper downloads Gradle; dependencies need network access or populated caches.
For manual setup, match [README prerequisites](../../README.md#prerequisites) and
set `ANDROID_HOME`/`ANDROID_NDK_HOME`. On NixOS the shell's `GRADLE_OPTS` selects
SDK aapt2; the SDK is read-only, so respect the configured build-tools version.

For code, host, packaging or build changes:

```sh
nix develop -c bash tools/check.sh
```

The gate runs, in order:

1. `cargo fmt --all -- --check`
2. `cargo clippy --locked --workspace --all-targets -- -D warnings`
3. `cargo test --locked --workspace`
4. Android native/host builds and Kotlin generation via `tools/build-android.sh`.
5. Gradle release AAR assembly and Maven Local publication, then real JVM replay.
6. AAR JNI/class checks and Maven Local AAR/POM/module/sources checks.
7. Sample and instrumentation APK assembly.

This writes build products and `~/.m2` artifacts. It neither boots an emulator nor
runs instrumentation, Swift checks or physical-device signing. Pair it with a
focused exercise of the changed consumer behavior; a gate pass alone does not
establish a new transport/runtime/signing claim.

## Android build, replay and APK assembly

Useful individual entry points (not replacements for the full gate):

```sh
# Build both native ABIs, host .so and generated Kotlin first.
nix develop -c bash ./tools/build-android.sh
# Install the artifact consumed by the sample.
nix develop -c bash -c 'cd android && bash ./gradlew :lib:publishToMavenLocal'
# Real generated-binding/native-library replay on the host JVM.
nix develop -c bash -c 'cd android && bash ./gradlew :lib:testDebugUnitTest'
# Assemble APKs; this does not run them.
nix develop -c bash -c 'cd android && bash ./gradlew :sample:assembleDebug :sample:assembleDebugAndroidTest'
```

Gradle does not build Rust: rerun the native builder after native changes. It
clears/recreates generated JNI and `kotlin/uniffi` trees. The release AAR is
`android/lib/build/outputs/aar/lib-release.aar`; only arm64-v8a and x86_64 are built.
JVM tests declare the host library and fixtures as inputs and configure their
loading paths. Sample instrumentation uses the published artifact and the same
fixtures; do not substitute a direct project dependency to hide packaging issues.

Keep all six checked-in fixtures present and `BHWI_REGENERATE_FIXTURES` unset for
normal validation. `bhwi-ffi/tests/fixtures.rs` regenerates on **any presence** of
that variable, and writes missing fixture files even without it. Intentional
regeneration is a reviewed protocol/data change, not a way to make drift pass.

## Emulator startup versus instrumentation

After the full gate has published the AAR and assembled the APKs:

```sh
nix develop -c bash tools/instrumentation.sh
# Only when /dev/kvm is usable; default acceleration is off.
BHWI_ACCEL=auto nix develop -c bash tools/instrumentation.sh
```

Choose one invocation. The script uses the separate `nix develop .#emulator`
shell, creates the API 34 x86_64 AVD if needed, targets `emulator-5554`, waits for
boot completion **and** property/package readiness, then runs
`:sample:connectedDebugAndroidTest`. It stops its emulator on exit. Keep that
emulator target free; this command does not target an attached phone.

Report startup/readiness separately from instrumentation execution and results.
Default `BHWI_BOOT_TIMEOUT=1800` allows slow software emulation; inspect
`target/emulator.log` on failure (`BHWI_EMULATOR_LOG` overrides it). APK assembly
and JVM replay cannot establish an ART pass. ART fixture replay verifies packaged
loading and main-safe/off-Main behavior, not physical wallet signing.

## Swift generation only

```sh
nix develop -c cargo build --locked --release -p bhwi-ffi
nix develop -c cargo run --locked --release -p bhwi-ffi-bindgen -- generate --library target/release/libbhwi_ffi.so --language swift --out-dir target/generated-swift --no-format
```

These produce Swift/header/modulemap files, not an Apple consumer package. The
Linux `.so` supplies metadata, not an iOS library. No Swift host or Apple build/test
pipeline exists here despite claims in the priority catalog. Apple validation
requires a selected target, macOS/Xcode, native slices and packaging; do not invoke
nonexistent catalog scripts or report generator output as iOS/macOS support.

## Physical devices and evidence

Use the [new-language acceptance](new-language.md#acceptance) for a new consumer;
exercise actual hardware when claiming a device/transport works. Record artifact
revision, runtime/generator/browser version, OS/architecture, device/model/firmware
and transport with exact commands and outcomes. Signing requires dedicated test
wallets and independent signature/transaction validation, never real funds.

For each applicable layer, report passed, failed, or skipped with a concrete
reason. Separate setup failure from test failure and name the missing tool,
permission, hardware or capability plus the exact rerun command where one exists.
Do not invent target commands or copy historical passes. Redact logs; leave
unavailable platform/device acceptance explicitly open.
