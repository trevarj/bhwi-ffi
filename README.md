# bhwi-ffi

bhwi-ffi provides experimental UniFFI bindings to BHWI's sans-I/O Bitcoin hardware-wallet interpreters.

[BHWI](https://github.com/wizardsardine/bhwi) supplies the protocol state machines;
this crate exposes their typed commands, transmits, responses and errors through
[UniFFI](https://mozilla.github.io/uniffi-rs/). Rust handles protocol state. The host
owns I/O, wire framing, HTTP and the driving loop, with no embedded Rust async
runtime.

This repository builds Kotlin bindings and an Android AAR, and contains a local
Swift package for iOS. The API is experimental and not stable. Android publication
installs a snapshot in **Maven Local**; Swift artifacts are built locally, not
published as a remote package.

## Workspace

The Cargo workspace has two members:

| Crate | Responsibility |
|---|---|
| `bhwi-ffi/` | Native FFI library: interpreters, state handles, typed data and pure helpers. |
| `bindgen/` | `bhwi-ffi-bindgen`, using the same UniFFI version as the library. |

Outside the Cargo workspace, `android/` packages the generated bindings and Kotlin
host layer and supplies a consumer sample; `tools/` contains build and verification
scripts. `bhwi-async` is only a test dependency, used to produce reference transport
fixtures; its I/O and runtime integration do not ship in the native library.

## Runtime support

| Host | Status | Evidence and limits |
|---|---|---|
| Kotlin / Android (arm64-v8a, x86_64) | Experimental baseline | JVM fixture replay and Android build/instrumentation tooling; hardware behavior is not guaranteed. Run the separate instrumentation script to execute emulator tests. |
| Swift / iOS 16+ (arm64 device, arm64 simulator) | **UNTESTED** on physical devices | Apple build, simulator XCTest, runtime and device signing are **unverified**. Local XCFramework and caller-owned adapters are required. |
| Swift / macOS | Unsupported | No macOS slice in the XCFramework; the package does not support macOS. |

## Supported devices and capabilities

The binding exposes **BitBox02, Coldcard, Jade and Ledger**. This is not a hardware
validation matrix or a promise that every device supports every command.

The current command subset is `Unlock`, `GetVersion`, `GetMasterFingerprint`,
`GetXpub`, singlesig `DisplayAddress` by derivation path, `SignMessage` and
`SignPsbt`. Ledger PSBT signing is unsupported because this binding does not supply
its wallet-policy context. Setup, wipe, restore, backup, wallet registration and
multisig address display are not exposed.

Device-free helpers build singlesig descriptors (`build_singlesig_descriptor`),
derive receive/change addresses (`derive_addresses`) and inspect PSBTs
(`psbt_summary`). Generated Kotlin names are `buildSinglesigDescriptor`,
`deriveAddresses` and `psbtSummary`.

## Using the bindings

### Interpreter lifecycle

An `Interp` runs one command against one device. Only construction is device-specific:
`new_ledger`, `new_coldcard`, `new_bitbox` or `new_jade`. The shared lifecycle is
`start -> exchange* -> end`:

1. `start(HwiCommand)` returns a `Transmit` containing `payload`, `encrypted` and
   `recipient`.
2. The host delivers that payload and feeds the reply bytes to `exchange`. Repeat
   until it returns no further transmit.
3. `end()` consumes the command state and returns a typed `HwiResponse`.

The Rust boundary is synchronous and performs no I/O. Native objects are
`Send + Sync` and internally locked, but calls in a command's lifecycle must not
interleave. Use one interpreter per command and close its generated wrapper on
all paths, even after `end()`. In Kotlin, use `use { }` or `close()` rather than
relying on garbage collection.

State that survives a command lives in a separate handle: `NoiseHandle` stores
BitBox02 pairing material, and `ColdcardEncryption` stores link-encryption state
for one connection. An interpreter exclusively leases its handle while its command
state is alive; a second interpreter on the same handle fails with `BadState`.
Ending or dropping the interpreter releases the lease. Rejected local input is
validated before native session mutation; a protocol failure retires the command
state, so later calls on that interpreter fail with `BadState`.

Rust's structured `HwiError` distinguishes `Device`, `UserRefused`, `AuthRefused`,
`InvalidInput`, `BadState` and `Internal`. Device refusals and authentication
rejections remain distinct from invalid caller input and lifecycle misuse. These
become Kotlin `HwiException` variants. Transport and HTTP failures belong to the
host and have no FFI error variant.

Messages in these structured `HwiError` values do not carry raw protocol payloads
or key material. This guarantee does **not** cover unexpected failures: UniFFI
catches unwinding panics and reports them separately as Kotlin `InternalException`,
which can preserve panic text. Aborts and out-of-memory failures are not made
recoverable by that boundary.

The Kotlin threading and ownership contract is:

- Generated UniFFI constructors, methods and helpers are synchronous and
  **worker-only**. Protocol parsing and cryptography are not UI-thread work just
  because they perform no I/O. All synchronous `HwiSession` factories are also
  worker-only: `coldcardUsb` generates native key material, `bitboxUsb` restores
  native state, and the other factories currently defer native initialization.
- `Hwi.runCommand`, the seven `HwiSession` suspend commands and `bitboxPairing()` are
  **main-safe**. They run command work in `Dispatchers.IO`; session construction
  still belongs on a worker. Keep construction, use and cleanup in one ownership
  block rather than returning a newly owned native object across a cancellable
  dispatcher boundary.
- Facade-driven transport, HTTP and pairing callbacks run in the command's IO
  context, without fixed worker-thread identity. Adapters must cooperate with
  cancellation and marshal platform/UI callbacks themselves. Direct `Link` use
  retains caller-context execution. Pairing callbacks are synchronous, before the
  next protocol payload; the loop launches no hidden callback coroutines.
- Cancellation is checked at command/transport boundaries. A synchronous native
  call already executing completes before the next checkpoint; cancellation cannot
  preempt it or unblock arbitrary platform I/O. Normal coroutine cancellation stays
  `CancellationException`; `TransportException.Cancelled` is a separate adapter
  domain error.
- `disconnect()` is synchronous, idempotent and outside the command mutex. It closes
  the facade and releases its handle references; later commands fail with
  `HwiException.BadState`. It neither owns/cancels an operation Job nor unblocks the
  caller's transport, and it does not guarantee that an in-flight command cannot
  finish. For teardown: **cancel the operation, unblock caller-owned platform I/O
  if needed, join the operation, disconnect, then dispose the transport**.

### Kotlin host layer

The AAR provides both `uniffi.bhwi_ffi` (generated objects and helpers) and
`com.wizardsardine.bhwi` (handwritten framing, loop and session facade).

`Hwi.runCommand` drives the lifecycle and takes ownership of its `Interp`, closing
it on every path, including cancellation before IO dispatch. Only plain response
data leaves this ownership block:

```kotlin
val response = withContext(Dispatchers.IO) {
    Hwi.runCommand(
        interp = Interp.newLedger(),
        cmd = HwiCommand.GetMasterFingerprint,
        link = link,
    )
}
```

`HwiSession` represents one connected device. Its mutex serializes commands, each
using a fresh interpreter. Suspend commands themselves can be called from Main;
this example keeps synchronous construction and cleanup on IO too:

```kotlin
val (fingerprint, xpub) = withContext(Dispatchers.IO) {
    val session = HwiSession.ledgerUsb(myHidChannel)
    try {
        session.unlock(Network.TESTNET)
        val fingerprint = session.getMasterFingerprint()
        val xpub = session.getExtendedPubkey("m/84'/1'/0'", display = false)
        fingerprint to xpub
    } finally {
        session.disconnect()
    }
}
```

Factories are `ledgerUsb(hid)`, `ledgerBle(ble)`, `coldcardUsb(hid)`,
`bitboxUsb(hid, network, onPairingCode, noiseConfig)`, `jadeUsb(serial, http, network)`
and `jadeBle(serial, http, network)`. Commands are `unlock`, `getInfo`,
`getMasterFingerprint`, `getExtendedPubkey`, `displayAddress`, `signMessage` and
`signPsbt`. The caller owns the transport; session cleanup does not dispose it.

### Transports and framing

Implement the interface for the platform link. Transport failures use the host-side
`TransportException.Io`, `.Disconnected` or `.Cancelled` hierarchy, not
`HwiException`. Adapter error messages must not expose payload bytes.

| Interface | Methods | Used by |
|---|---|---|
| `HidChannel` | `send(report): UInt`, `receive(maxLen): ByteArray` | Ledger, Coldcard and BitBox02 USB |
| `SerialStream` | `writeAll(data)`, `read(maxLen): ByteArray` | Jade USB serial or BLE |
| `BleChannel` | `write(data)`, `read(): ByteArray`, `mtu(): UShort` | Ledger BLE |
| `HttpBridge` | `request(url, body): ByteArray` | Jade PIN server |

- An empty `SerialStream.read` result means **end of stream**, not "no data yet".
  It aborts an incomplete CBOR message. Suspend until data is available, or throw
  `TransportException.Disconnected` when the link drops.
- `HidChannel.receive` and `SerialStream.read` may return fewer bytes than requested,
  never more.
- `HidChannel.send` receives a reused scratch buffer: consume it before returning
  and do not retain its reference. The next report overwrites it; report-level
  fixtures include the reference transport's unused tail bytes on short reports.

A `Link` moves one logical request/response, independent of framing:

```kotlin
interface Link {
    suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray
}
```

The host layer supplies these framings:

| Link | Framing |
|---|---|
| `LedgerHidLink(HidChannel)` | Channel `0x0101`, tag `0x05`, u16 BE sequence, u16 BE total length on the first frame; 64-byte reports. |
| `LedgerBleLink(BleChannel)` | Tag `0x05`, u16 BE sequence, u16 BE length on frame 0; MTU inferred once with `[0x08,0,0,0,0]`. |
| `ColdcardHidLink(HidChannel)` | Length byte with `0x80` on the last chunk and `0x40` when `encrypted`. |
| `BitBoxHidLink(HidChannel)` | U2F-HID frames carrying the HWW request/response layer, including NOTREADY retry. |
| `JadeSerialLink(SerialStream)` | Write, then read until one complete CBOR value has arrived. |

Only Coldcard framing signals `encrypted` on the wire. BitBox02 ignores the flag
because its Noise encryption is already inside the interpreter's payload, as in
the reference transports.

`Recipient.Device` goes through the `Link`. `Recipient.PinServer { url }` is Jade
HTTP traffic: POST the payload to that URL as `application/json` and return the
response body to `exchange`. `Hwi.runCommand` routes it through `HttpBridge` and
fails with `HwiException.BadState` if no bridge was supplied; it must not go to the
device link.

Adding a transport for an **already exposed device/protocol** requires no Rust
change: implement an existing channel interface and reuse its framing, or implement
`Link` directly and honor `encrypted` where the protocol requires it. This does not
add support for a new device protocol.

### BitBox02 pairing

After a successful unlock, export pairing material and restore it on the next
connection to reuse the confirmed pairing. `HwiSession` polls for a pairing code
after each exchange, before the next payload. When driving the loop directly, pass
`pairing = Hwi.Pairing(noiseHandle, onCode)` to `Hwi.runCommand`; it uses
`NoiseHandle.takePairingCode()` to retrieve the code.

For an Android UI, post the code to the view rather than touching UI state from the
IO callback:

```kotlin
withContext(Dispatchers.IO) {
    val session = HwiSession.bitboxUsb(
        hid = myHidChannel,
        network = Network.TESTNET,
        onPairingCode = { code -> view.post { showOnScreen(code) } },
        noiseConfig = store.load(), // null on the first connection
    )
    try {
        session.unlock(Network.TESTNET)
        store.save(session.bitboxPairing())
    } finally {
        session.disconnect()
    }
}
```

`NoiseConfig` is plain data (`privkey: ByteArray?`, `devicePubkeys: List<ByteArray>`),
but it is **key material**: protect its storage as you would a private key. Raw
hosts can export it with `NoiseHandle.export()` once the interpreter's lease is
released and restore it when constructing the next handle.

## Android

### Prerequisites

The current `.so`-based build and JVM tooling is a **Linux-host workflow**.
Platform-neutral bindings do not imply portable build scripts. `nix develop`
provides the pinned toolchain:

| Tool | Version |
|---|---|
| Rust | 1.94.0 with `aarch64-linux-android` and `x86_64-linux-android` |
| cargo-ndk | From pinned nixpkgs |
| Android NDK | 28.2.13676358 (r28) |
| JDK | 21 |
| Android SDK | Platform 35, build-tools 35.0.0 |

Without Nix, install the same tools and export `ANDROID_HOME` and
`ANDROID_NDK_HOME`. On NixOS, AGP's Maven-downloaded aapt2 is dynamically linked and
will not run; the dev shell's `GRADLE_OPTS` selects the SDK's aapt2 instead. Use
`nix develop` rather than a bare shell.

Gradle is downloaded by the committed, checksum-pinned wrapper, not supplied by
the dev shell:

| Component | Version |
|---|---|
| Gradle | 8.14.3 |
| Android Gradle Plugin | 8.13.2 |
| Kotlin | 2.2.21 |
| UniFFI | 0.32.0 |
| JNA | 5.19.0 (`@aar`) |
| kotlinx-coroutines-core | 1.10.2 |

`buildToolsVersion` is pinned to 35.0.0 because the Nix SDK is read-only; AGP must
not try to fetch a different revision.

### Build and install

From the repository root:

```sh
nix develop -c bash ./tools/build-android.sh
nix develop -c bash -c 'cd android && bash ./gradlew :lib:publishToMavenLocal'
```

The native builder uses locked Cargo resolution and produces:

1. `libbhwi_ffi.so` for `arm64-v8a` and `x86_64` under
   `android/lib/src/main/jniLibs/`.
2. `target/release/libbhwi_ffi.so` for host JVM replay.
3. `android/lib/src/main/kotlin/uniffi/bhwi_ffi/bhwi_ffi.kt`, generated from that
   host library's metadata using the version-matched bindgen (UniFFI library mode).

The script clears and regenerates the JNI and generated Kotlin trees; both are
ignored by Git. **Gradle does not run Cargo**: run the builder before building the
AAR, and rerun it after native changes. Once those inputs exist, Gradle needs only
the JDK and Android SDK.

`publishToMavenLocal` installs `com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT`
under `~/.m2/repository/`, with its AAR, POM, Gradle module metadata and sources JAR.
An Android consumer uses:

```kotlin
repositories { mavenLocal(); google(); mavenCentral() }
dependencies { implementation("com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT") }
```

### AAR contents

The release AAR is `android/lib/build/outputs/aar/lib-release.aar`:

```text
jni/arm64-v8a/libbhwi_ffi.so
jni/x86_64/libbhwi_ffi.so
classes.jar            # uniffi/bhwi_ffi/*.class (generated bindings)
                       # com/wizardsardine/bhwi/*.class (Kotlin host layer)
proguard.txt           # consumer rules keeping JNA and the bindings
```

The minimum Android API is 28. `x86_64` supports the emulator; there is no
`armeabi-v7a` or `x86` build. JNA (`net.java.dev.jna:jna:5.19.0@aar`, including
`libjnidispatch.so`) and `kotlinx-coroutines-core` are transitive dependencies of the
published artifact.

## Swift / iOS

`Package.swift` exposes `Bhwi` for iOS 16+. It contains generated UniFFI types
and a Swift host layer (`Hwi`, actor-isolated `HwiSession`, framing links and
transport protocols). Building the local package requires full Xcode, an iOS SDK,
Cargo and the Rust iOS arm64 device/simulator targets in `rust-toolchain.toml`.
On an Apple Silicon Mac, from the repository root:

```sh
bash tools/build-ios.sh
# Add this directory as a local Swift package dependency in Xcode.
bash tools/check-ios.sh
```

The builder uses locked Cargo resolution, generates
`ios/Sources/Bhwi/Generated/Bhwi.swift` plus the C header/module map, and
assembles `target/ios/BhwiFFI.xcframework` from arm64 iOS device and simulator
static libraries. Generated code and native artifacts are ignored: rebuild
after cloning or changing the native API. The package cannot resolve from a
remote checkout without those artifacts. There is no Intel simulator or macOS
slice. `check-ios.sh` selects an available iPhone simulator and runs XCTest;
override selection with `BHWI_IOS_DESTINATION='platform=iOS Simulator,name=iPhone 16'`.
Apple artifact builds and simulator execution remain unverified.

Swift exposes `unlock`, `getInfo`, `getMasterFingerprint`, `getExtendedPubkey`,
`displayAddress`, `signMessage`, `signPsbt` and BitBox02 pairing export, subject
to the native command/device limitations above (notably no Ledger PSBT signing).
For example, a **caller-owned testnet wallet** can supply an unsigned PSBT and
a caller-owned Jade BLE serial adapter and trusted PIN-server HTTP bridge:

```swift
func signOnJade(
  testnetPsbtBase64: String,
  jadeBleStream: any SerialStream,
  trustedPinBridge: any HttpBridge
) async throws -> String {
  let session = HwiSession.jade(
    serial: jadeBleStream, http: trustedPinBridge, network: .testnet)
  do {
    try await session.unlock(network: .testnet)
    let signed = try await session.signPsbt(testnetPsbtBase64)
    await session.disconnect()
    return signed
  } catch {
    await session.disconnect()
    throw error
  }
}
```

This illustrates the API, **not tested device signing**: the caller must
configure the Jade for testnet, create/validate a wallet PSBT, implement BLE
stream framing and a PIN bridge that restricts device-supplied URLs to trusted
HTTPS hosts and prevents unsafe redirects. The returned PSBT still needs
wallet-side verification and finalization. Device signing, platform adapter
integration and acceptance on a signed iOS app remain outstanding.

The caller supplies `HidChannel` (Ledger/Coldcard/BitBox02 USB), `BleChannel`
(Ledger BLE), `SerialStream` (Jade serial/BLE), and `HttpBridge` (Jade PIN
server). Generic USB HID is not available to ordinary iOS apps; USB factories
need an allowed accessory mechanism. No platform transport ships here.
Transport implementations must honor requested read sizes, fail on EOF, avoid
leaking payloads in errors, cooperate with task cancellation and unblock their
own I/O. `HwiSession` serializes commands and pairing export; `disconnect()`
does not cancel an in-flight command or close transport. Cancel the operation,
unblock I/O if necessary, await completion, disconnect, then dispose the
caller-owned transport. Native constructors/helpers are synchronous and belong
off the main actor. Keep BitBox02 pairing key material in secure storage.

The Linux gate additionally checks Swift binding/header/module-map
**generation** against host metadata; it neither builds the iOS XCFramework
nor compiles Swift. Apple simulator replay, iOS runtime and physical-device
signing still require the Apple gate and a signed app with real adapters.

Host-source verification on Linux x86_64 with Swift 5.10.1 passed all 31 XCTest
cases against the real generated bindings and Rust library, using a temporary
host package and explicit XCTest registration. A separate Swift consumer replayed
the Ledger fingerprint fixture and checked post-disconnect errors. The Jade
near-limit coalesced-response regression failed before its fix and passed after.
This does not validate the iOS binary target or establish a supported Linux package.

## Development and verification

Run the full non-emulator gate from the repository root:

```sh
nix develop -c bash tools/check.sh
```

It checks Rust formatting, Clippy and tests; builds both Android ABIs, the host
library and Kotlin bindings; assembles and publishes the AAR to Maven Local; runs
the real JVM replay suite; checks AAR contents and publication files; and builds
the sample and instrumentation APKs. Clippy, Rust tests, native builds and bindgen
use `--locked` so dependency resolution cannot silently update the lockfile. The gate **builds
instrumentation APKs but does not run them**.

The gate also generates the Swift source/header/module map from host metadata;
it does not compile Swift or validate the Apple binary target.

### Fixtures and JVM replay

`fixtures/` has two levels of checked-in vectors, produced and verified by
[`bhwi-ffi/tests/fixtures.rs`](bhwi-ffi/tests/fixtures.rs):

- `ledger_*.json`: report-level transcripts (`writes`/`reads` as hex HID reports)
  generated by the real `bhwi-async` Ledger transport driven in memory. Kotlin
  framing must match these byte for byte.
- `transmit_*.json`: FFI-boundary exchanges (`payload_hex`, `encrypted`, `reply_hex`)
  for replaying the command loop against a scripted `Link`, without wire framing.

`BHWI_REGENERATE_FIXTURES=1` is an explicitly **mutating regeneration option**, not
validation: it rewrites the vectors after an intentional protocol change. Without
it, fixture drift fails the test.

JVM tests replay these vectors through real generated bindings and the host
`libbhwi_ffi.so`, without a device or emulator. Gradle already sets
`jna.library.path` to `target/release` and `bhwi.fixtures.dir` to `fixtures`; the
library loads by the base name `bhwi_ffi`. After running the native builder above,
the JVM suite can also be run alone:

```sh
nix develop -c bash -c 'cd android && bash ./gradlew :lib:testDebugUnitTest'
```

Coverage includes report/transmit replay, typed success and refusal, framing
(Ledger HID/BLE, Coldcard flags, U2F/HWW and CBOR completeness), command
serialization, leases, disconnect and cancellation, structured-error redaction,
malformed-response boundary survival and pure helpers. These are deterministic
binding/transport checks, not validation against every physical device.

### Android instrumentation

`android/sample` consumes the **Maven Local AAR**, not `project(":lib")`. Its
instrumentation test replays the fingerprint fixture from `androidTest` assets,
calling the suspend session API from Main and checking that HID callbacks run off
Main.

After publishing the AAR and building the sample with the full gate:

```sh
nix develop -c bash tools/instrumentation.sh
```

The script creates the API 34 x86_64 AVD `bhwi-api34-x86_64` if needed, boots it
headlessly through the separate `nix develop .#emulator` shell, and runs
`:sample:connectedDebugAndroidTest`. It targets `emulator-5554`, not an attached
phone, and stops its emulator on exit.

`BHWI_ACCEL=off` is the default, even on a host with KVM. If `/dev/kvm` is usable,
opt in explicitly:

```sh
BHWI_ACCEL=auto nix develop -c bash tools/instrumentation.sh
```

`BHWI_BOOT_TIMEOUT=1800` is the default boot/readiness timeout in seconds. The
script checks boot completion and property/package readiness before running the
test. Inspect `target/emulator.log` on boot failure; a successful APK build or JVM
gate is not evidence that instrumentation ran.

### Local BHWI checkout

`Cargo.toml` selects `https://github.com/trevarj/bhwi`, branch `pairing-hook-send`;
`Cargo.lock` records the resolved commit. For development against a sibling
checkout, add this local override to the workspace `Cargo.toml`:

```toml
[patch."https://github.com/trevarj/bhwi"]
bhwi = { path = "../bhwi/bhwi" }
bhwi-async = { path = "../bhwi/bhwi-async" }
```

Using that override requires intentionally updating the local lockfile before
locked builds, for example:

```sh
nix develop -c cargo update -p bhwi -p bhwi-async
```

Do not commit the local override or the resulting local lockfile changes. The
patch URL must match the fork selected above, not the stale commented upstream
URL in `Cargo.toml`.

## Documentation

- [Native API and error boundary](bhwi-ffi/src/lib.rs).
- [Commands, transmits, responses and error mapping](bhwi-ffi/src/types.rs).
- [Kotlin session facade](android/lib/src/main/kotlin/com/wizardsardine/bhwi/HwiSession.kt)
  and [command loop](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Hwi.kt).
- [Transport contracts](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Transports.kt)
  and [framing implementations](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Links.kt).
- [Swift host commands](ios/Sources/Bhwi/Hwi.swift), [sessions](ios/Sources/Bhwi/HwiSession.swift),
  [transport contracts](ios/Sources/Bhwi/Transports.swift) and [framing](ios/Sources/Bhwi/Links.swift).
- [Upstream BHWI design rationale](https://github.com/wizardsardine/bhwi/blob/main/docs/VISION.md).

## License

See [LICENSE](LICENSE).
