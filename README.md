# bhwi-ffi

Experimental Android bindings for [BHWI](https://github.com/wizardsardine/bhwi)
(`wizardsardine/bhwi` issue #1). The crate exposes `bhwi-async`'s hardware-wallet
interface to Kotlin through [UniFFI](https://mozilla.github.io/uniffi-rs/), and the
Gradle project here packages it as an AAR (`com.wizardsardine:bhwi-ffi-android`).

Supported devices are the ones `bhwi-async` supports: Ledger (USB HID and BLE),
Coldcard (USB HID), BitBox02 (USB HID), and Jade (USB serial and BLE).

Status: experimental. The API is not stable and the artifact is published as a
snapshot only.

## Architecture

The crate is deliberately thin: all protocol work stays in `bhwi`/`bhwi-async`.

- **Async in both directions.** Device commands are exported as UniFFI async
  methods, so Kotlin sees `suspend fun`. The transports are foreign trait objects
  (`#[uniffi::export(with_foreign)]`) with `async fn` methods, so the host
  implements them as Kotlin `suspend fun` too. Rust never owns a socket, a USB
  handle, or a GATT connection.
- **One worker thread per session.** `bhwi-async` device objects are `!Send`, so
  `connect_*` spawns a dedicated `bhwi-session` thread that constructs and drives
  the device. Commands travel to it over an `mpsc` channel and the result comes
  back over a oneshot, which is what keeps the exported futures `Send` (a UniFFI
  requirement). A panic inside a command stops the worker rather than leaving the
  device mid-protocol.
- **Host-provided transports.** `HidChannel`, `SerialStream`, `BleChannel`,
  `HttpBridge` (Jade PIN server only) and `PairingCodeListener` (BitBox02 noise
  pairing code) are implemented in Kotlin. Ledger's BLE framing and the HID/CBOR
  framing live in Rust so every host gets identical wire behaviour.
- **One command in flight per session.** The channel serialises them. A second
  concurrent call queues behind the first; it does not interleave on the wire.
- **Cancellation is `disconnect()`.** It is idempotent, drops the sender, and every
  later call fails with `HwiError.Closed`. It does not interrupt a command already
  on the wire; the worker exits once that command finishes. Kotlin also gets the
  usual UniFFI `close()` (the handle destructor, `AutoCloseable`) — call
  `disconnect()` for deterministic teardown, then `close()`/`use { }` to free the
  handle.

  The exported name is `disconnect` rather than `close` because every UniFFI object
  already generates a `close()`, and a second one is a Kotlin overload conflict.

## Threading contract

- **Never call a session method from the main thread's blocking path.** You do not
  have to arrange that yourself: every device command is a `suspend fun`, so it
  suspends the calling coroutine instead of blocking it. Calling from
  `Dispatchers.Main` is safe.
- **Blocking happens on the Rust worker thread.** `block_on` runs there, not on any
  JVM thread.
- **Your transport callbacks run off the main thread** and must not block it
  either. They are `suspend fun`s; do the I/O with the platform's async APIs or on
  `Dispatchers.IO`.
- **Foreign objects must be thread-safe.** The Rust traits are `Send + Sync`.
- **Sessions are not for sharing.** One `HwiSession` per connected device; treat
  concurrent use as serialised, not parallel.

## Prerequisites

`nix develop` provides everything:

| Tool | Version |
|---|---|
| Rust | 1.94.0 + `aarch64-linux-android`, `x86_64-linux-android` |
| cargo-ndk | from nixpkgs |
| Android NDK | 28.2.13676358 (r28) |
| JDK | 21 |
| Android SDK | platform 35, build-tools 35.0.0 |

Without Nix, install the same set by hand and export `ANDROID_HOME` /
`ANDROID_NDK_HOME`.

On NixOS the aapt2 that AGP downloads from Maven is dynamically linked and will not
run; the devshell's `GRADLE_OPTS` points AGP at the SDK's own aapt2. Keep using
`nix develop` rather than a bare shell.

Gradle itself is not in the devshell — the committed wrapper downloads it.

| Component | Version |
|---|---|
| Gradle | 8.14.3 (wrapper, checksum-pinned) |
| Android Gradle Plugin | 8.13.2 |
| Kotlin | 2.2.21 |
| JNA | 5.19.0 (`@aar`) |
| kotlinx-coroutines-core | 1.10.2 |

AGP 8.13 is the newest release at time of writing; it requires Gradle 8.13+ and
JDK 17+, and `buildToolsVersion` is pinned to 35.0.0 because the Nix-provided SDK
is read-only and AGP must not try to fetch a different revision.

## Build

```sh
nix develop -c ./tools/build-android.sh
nix develop -c bash -c 'cd android && ./gradlew :lib:publishToMavenLocal'
```

`tools/build-android.sh` produces everything Gradle consumes:

1. `cargo ndk` builds `libbhwi_ffi.so` for `arm64-v8a` and `x86_64` into
   `android/lib/src/main/jniLibs/`.
2. A host `libbhwi_ffi.so` in `target/release/` for JVM unit tests.
3. `bhwi-ffi-bindgen` generates `android/lib/src/main/kotlin/uniffi/bhwi_ffi/bhwi_ffi.kt`
   from that host library (UniFFI "library mode", so the bindings can never drift
   from the scaffolding).

It is idempotent and wipes both generated trees first. Both are `.gitignore`d:
**Gradle does not invoke Cargo**, so any consumer (or CI job) must run the script
before building the AAR. After that, the Gradle build needs only a JDK and the SDK.

`tools/check.sh` is the full gate: `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test`, `build-android.sh`, `:lib:assembleRelease publishToMavenLocal`, then
assertions on the AAR contents and the published files.

### Artifact layout

`com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT` (AAR):

```
jni/arm64-v8a/libbhwi_ffi.so
jni/x86_64/libbhwi_ffi.so
classes.jar            # uniffi/bhwi_ffi/*.class, package uniffi.bhwi_ffi
proguard.txt           # consumer rules keeping JNA + the bindings
```

`x86_64` is there for the emulator; there is no `armeabi-v7a` or `x86` build.
JNA (`net.java.dev.jna:jna:5.19.0@aar`, which ships `libjnidispatch.so`) and
`kotlinx-coroutines-core` come in transitively from the POM. minSdk 28.

To consume it:

```kotlin
repositories { mavenLocal(); google(); mavenCentral() }
dependencies { implementation("com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT") }
```

## Adding a transport

Two cases:

- **New physical link, existing framing.** Implement the matching foreign trait in
  Kotlin and hand it to the relevant `connect_*`. A USB-serial Jade and a BLE Jade
  are both just a `SerialStream`, which is why `connect_jade_usb` and
  `connect_jade_ble` are the same function. Nothing in Rust changes.
- **New framing.** Add a Rust adapter in `bhwi-ffi/src/foreign.rs` implementing
  `bhwi_async::Transport` (or `Channel`) over one of the foreign traits, then a
  `connect_*` in `bhwi-ffi/src/session.rs`. `LedgerBleTransport` is the worked
  example: it does Ledger's BLE chunking (`mtu - 5` for the first frame, `mtu - 3`
  after) on top of the generic `BleChannel`.

Read semantics matter: for `SerialStream`, an empty read means end of stream (the
device is gone), so "no data yet" must suspend instead of returning empty.

## Fixtures and JVM replay testing

`fixtures/*.json` hold report-level Ledger transcripts (`writes` and `reads` as hex
HID reports, plus the expected outcome). They are produced and consumed by
`bhwi-ffi/tests/fixtures.rs`, which drives the real `bhwi-async` Ledger device over
an in-memory `HidChannel`.

The same files let a JVM unit test replay a session through the real bindings, with
no device and no emulator: implement `HidChannel` in Kotlin over the fixture's
`reads`/`writes`, and point JNA at the host library the build script already
produced.

```kotlin
// build.gradle.kts (test task)
systemProperty("jna.library.path", rootProject.file("../target/release").absolutePath)
```

The generated bindings load the library by the base name `bhwi_ffi`, so
`target/release/libbhwi_ffi.so` is found as-is.

## Developing against a local bhwi checkout

`bhwi` and `bhwi-async` are pinned to a git rev in the workspace `Cargo.toml`.
Uncomment the `[patch."https://github.com/wizardsardine/bhwi"]` block at the bottom
of that file to point them at a sibling checkout (`../bhwi`). Do not commit the
patch.

## Would UniFFI also work for iOS?

Yes, and sharing this binding layer with a future iOS target is the recommended
path. Verified against uniffi 0.32 with this crate:

- The same `bhwi-ffi-bindgen` binary emits Swift with
  `generate --library target/release/libbhwi_ffi.so --language swift`, producing
  `bhwi_ffi.swift`, `bhwi_ffiFFI.h` and `bhwi_ffiFFI.modulemap`. No Rust source
  change and no second binding crate.
- The async model carries over: exported device commands become Swift `async
  throws`, and the foreign transport traits become `async throws` protocol
  requirements, so an iOS app implements `HidChannel`/`BleChannel` in Swift exactly
  as Android implements them in Kotlin.

Caveats, all verifiable from the generated output:

- UniFFI declares the foreign protocols as `AnyObject, Sendable`. Swift enforces
  that; Kotlin has no equivalent, so Swift transport implementations must actually
  be concurrency-safe rather than merely documented as such.
- Packaging is not shared. Swift needs the header and modulemap wired into an
  XCFramework; uniffi ships a dedicated `uniffi-bindgen-swift` CLI
  (`uniffi::uniffi_bindgen_swift()`, same `cli` feature) with `--headers`,
  `--modulemap` and `--xcframework` flags for that. Adding it here is a second
  `[[bin]]` in `bindgen/` when an iOS target actually exists.
- Building the iOS `.a`/`.dylib` requires `aarch64-apple-ios` targets and Xcode, so
  that half of the pipeline has to run on macOS.
