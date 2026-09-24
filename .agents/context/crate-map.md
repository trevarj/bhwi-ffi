# Crate and Surface Map

Paths below are relative to the repository root. Start with the
[README](../../README.md) for the consumer contract.

## Native workspace

| Surface | Responsibility |
| --- | --- |
| `bhwi-ffi/src/lib.rs` | UniFFI exports, network/address types and structured error boundary. |
| `bhwi-ffi/src/types.rs` | Commands, responses, transmits, validation and device-error mapping. |
| `bhwi-ffi/src/interp.rs` | Synchronous command lifecycle and leased device-state borrowing. |
| `bhwi-ffi/src/state.rs` | BitBox Noise pairing, Coldcard connection encryption and exclusive leases. |
| `bhwi-ffi/src/helpers.rs` | Singlesig descriptors, bounded address derivation and PSBT summaries. |
| `bhwi-ffi/tests/` | Interpreter behavior and reference fixture production/comparison. |
| `bindgen/src/main.rs` | `bhwi-ffi-bindgen`, matched to the library's UniFFI dependency. |

These are the two Cargo workspace members: `bhwi-ffi` (cdylib/rlib) and `bindgen`.
`bhwi-async` is a test dependency for reference framing, not shipped host I/O.
`Cargo.toml` selects the `trevarj/bhwi` fork's `pairing-hook-send` branch;
`Cargo.lock` fixes the revision. The sibling checkout is not automatically that
API. Use the README's local-override instructions only when needed; its matching
fork URL supersedes the stale commented patch URL in `Cargo.toml`. Dependency
updates and local override/lockfile changes are not routine validation.

## Kotlin and Android

Handwritten sources live under `android/lib/src/main/kotlin/com/wizardsardine/bhwi/`:
`Transports.kt` defines channels, `Link`, HTTP and transport errors; `Links.kt`
implements Ledger HID/BLE, Coldcard HID, BitBox U2F/HWW and Jade serial framing;
`Cbor.kt` finds complete Jade messages; `Hwi.kt` drives commands and recipient
routing; `HwiSession.kt` serializes commands and owns state, not transport.
These interfaces are not real Android USB/BLE discovery or permission adapters.

Generated `android/lib/src/main/kotlin/uniffi/bhwi_ffi/bhwi_ffi.kt` and
`android/lib/src/main/jniLibs/` are ignored build outputs, cleared/rebuilt by
`tools/build-android.sh`. Gradle does not run Cargo. JVM tests under
`android/lib/src/test/` use real generated bindings and `target/release/libbhwi_ffi.so`.
`android/sample` consumes the Maven Local AAR, not `project(":lib")`; its
`src/androidTest/` assets come from the shared fixtures.

`android/lib/build.gradle.kts` owns the Android artifact contract;
`consumer-rules.pro` in that module keeps JNA/generated reflection working. The
current AAR supports `arm64-v8a` and `x86_64`, minimum API 28, with JNA and coroutine
runtime dependencies. It installs locally as
`com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT`, not a remote release or desktop
JVM distribution.

## Fixtures and tooling

- `fixtures/ledger_*.json`: HID reports (`writes`/`reads`) from in-memory
  `bhwi-async` Ledger framing, including unused report-tail bytes.
- `fixtures/transmit_*.json`: `Interp` payload/encrypted/reply exchanges. The six
  files cover fingerprint, xpub and refusal at these two levels, not signing or
  arbitrary recipient routing. `bhwi-ffi/tests/fixtures.rs` owns their comparison.
- `tools/build-android.sh`: both Android native ABIs, Linux host library and Kotlin
  generation. `tools/check.sh`: non-emulator gate and local publication.
  `tools/instrumentation.sh`: Android emulator boot/readiness and ART replay.
- `flake.nix`/`flake.lock`, `rust-toolchain.toml`, Cargo manifests/lockfile and the
  Gradle files/wrapper are the toolchain-pin authorities; do not duplicate every
  version here. Current scripts use Linux `.so` paths. See
  [validation](../runbooks/validation.md) for setup and commands.

## Current support boundaries

The experimental native API exposes BitBox02, Coldcard, Jade and Ledger, with
Unlock, version, fingerprint, xpub, singlesig address display, message signing and
PSBT signing. An enum variant is not proof every device supports it. Ledger PSBT
signing lacks wallet-policy context; setup/wipe/restore/backup, wallet registration
and multisig address display are absent. Helpers do not fill those gaps.

Kotlin generation, host code, packaging and replay are present; physical-device
support requires separate evidence. Swift is generation-only in this checkout:
there is no Swift host, `Package.swift`, `ios/` pipeline or Apple validation script.
The [priority catalog](../../plans/FFI_LANGUAGE_PRIORITIES_PLAN.md) claims Swift
implementation/checks that are not present here. Preserve the catalog, reconcile
those claims against actual source and evidence, and do not import them as passes.
Browser integration belongs to the sibling BHWI `bhwi-wasm`/website, not this
native workspace; it has a different dependency/capability baseline.
