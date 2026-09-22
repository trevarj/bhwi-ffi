# bhwi-ffi

Experimental Android bindings for [BHWI](https://github.com/wizardsardine/bhwi)
(`wizardsardine/bhwi` issue #1). The crate exposes `bhwi`'s sans-io interpreter to
Kotlin through [UniFFI](https://mozilla.github.io/uniffi-rs/), and the Gradle
project here packages it as an AAR (`com.wizardsardine:bhwi-ffi-android`).

Supported devices are the ones `bhwi` supports: Ledger, Coldcard, BitBox02 and
Jade, over whatever link the host implements.

Status: experimental. The API is not stable and the artifact is published as a
snapshot only.

The AAR ships two layers, and you can use either:

- **`uniffi.bhwi_ffi`** — the raw interpreter surface generated from the crate.
  Full control: you own the `Interp`, the state handles and the loop.
- **`com.wizardsardine.bhwi`** — a Kotlin host layer over it: the per-device wire
  framing, the driving loop, and an `HwiSession` facade with one suspend method per
  command. Most apps only need this.

## Architecture

The crate contains no I/O at all. The host owns the transport, the per-device wire
framing, the Jade PIN-server HTTP request and the driving loop; the crate owns the
protocol state machines, which come from `bhwi`.

- **One device-generic API.** `Interp` runs one `bhwi::common::Command` against one
  device. Only the constructor is per-device (`new_ledger`, `new_jade`,
  `new_bitbox`, `new_coldcard`). What crosses the boundary is a `Transmit`
  (`payload`, `encrypted`, `recipient`) out and reply bytes in.
- **Everything is synchronous.** No async, no worker threads, no foreign callbacks.
  A command is a loop in Kotlin:

  ```kotlin
  var transmit = interp.start(command)
  while (true) {
      val reply = send(transmit)             // host I/O: USB, BLE, or an HTTP POST
      transmit = interp.exchange(reply) ?: break
  }
  val response = interp.end()
  ```
- **`Recipient` tells the host where a payload goes.** `Device` for the wire,
  `PinServer { url }` for Jade's PIN server (POST the payload as
  `application/json`, feed the response body back to `exchange`).
- **State that outlives a command lives in a handle.** `NoiseHandle` holds BitBox02
  pairing material (`export()` it after an unlock and restore it next time to skip
  the on-screen confirmation; `takePairingCode()` polls the code mid-unlock).
  `ColdcardEncryption` holds the link-encryption engine for one connection. An
  interpreter leases its handle for its lifetime; a second interpreter on a leased
  handle fails with `HwiException.BadState`.
- **Typed errors.** Device refusals are `UserRefused`, pairing/handshake rejection
  is `AuthRefused`, bad caller input is `InvalidInput`, and misuse of the object
  lifecycle is `BadState`. There is no transport error variant: transport failures
  are the host's own, in its own error type.

## The Kotlin host layer (`com.wizardsardine.bhwi`)

Everything below is hand-written Kotlin in the AAR, not generated. It is the host
half the crate deliberately does not contain.

### Transport interfaces

An app implements one of these per link. They are plain suspend interfaces; failures
are reported as `TransportException.Io` / `.Disconnected` / `.Cancelled`, which is a
plain Kotlin hierarchy (the FFI has no transport error variant — transport failures
are the host's own).

| Interface | Methods | Used by |
|---|---|---|
| `HidChannel` | `send(report): UInt`, `receive(maxLen): ByteArray` | Ledger, Coldcard, BitBox02 over USB |
| `SerialStream` | `writeAll(data)`, `read(maxLen): ByteArray` | Jade, over USB serial or BLE |
| `BleChannel` | `write(data)`, `read(): ByteArray`, `mtu(): UShort` | Ledger over BLE |
| `HttpBridge` | `request(url, body): ByteArray` | Jade's PIN server only |

Two contracts that are easy to get wrong:

- **`SerialStream.read` returning an empty array means end of stream**, i.e. the
  device is gone; it aborts the command with "stream ended before complete CBOR
  message". "No data yet" must **not** return empty — suspend until at least one byte
  is available, or throw `TransportException.Disconnected`.
- **`HidChannel.send` gets a reused scratch buffer.** Consume it before returning and
  do not keep a reference; the framing layer overwrites it for the next report.
  (This mirrors the reference transports, down to the stale tail bytes a final short
  chunk leaves behind — which is exactly what the report-level fixtures record.)

`receive`/`read` may return fewer bytes than asked for, never more.

### Links

A `Link` is one logical request/response exchange with a device, whatever the wire
framing underneath:

```kotlin
interface Link {
    suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray
}
```

The framings are ports of the `bhwi-async` transports (cross-checked against the
maintainer's Zig host example):

| Link | Framing |
|---|---|
| `LedgerHidLink(HidChannel)` | channel `0x0101`, tag `0x05`, u16 BE sequence, u16 BE total length, 64-byte reports |
| `LedgerBleLink(BleChannel)` | tag `0x05`, u16 BE sequence, u16 BE length on frame 0; MTU inferred once with `[0x08,0,0,0,0]` |
| `ColdcardHidLink(HidChannel)` | length byte with `0x80` on the last chunk and `0x40` when `encrypted` |
| `BitBoxHidLink(HidChannel)` | U2F-HID frames carrying the HWW request/response layer, with the NOTREADY retry |
| `JadeSerialLink(SerialStream)` | write, then read until one complete CBOR value has arrived |

`encrypted` is only on the wire for Coldcard. BitBox ignores it (its noise encryption
is inside the payload the interpreter already produced), and so do both reference
transports.

### The loop

```kotlin
val response = Hwi.runCommand(Interp.newLedger(), HwiCommand.GetMasterFingerprint, link)
```

`runCommand` does `start` -> send/receive -> `exchange` -> `end`, routes
`Recipient.PinServer` transmits through the `http` bridge (and fails with `BadState`
if there is none), and destroys the `Interp` on every path so its state lease is
released. Pass `pairing = Hwi.Pairing(noiseHandle, ::showCode)` for BitBox02 and the
pairing code is surfaced after every exchange, before the next payload goes out.

### `HwiSession`

One connected device, one command at a time. A `kotlinx` mutex serialises commands;
each one builds a fresh `Interp` and delegates to `Hwi.runCommand`.

```kotlin
val session = HwiSession.ledgerUsb(myHidChannel)
try {
    session.unlock(Network.TESTNET)
    val fingerprint = session.getMasterFingerprint()
    val xpub = session.getExtendedPubkey("m/84'/1'/0'", display = false)
} finally {
    session.disconnect()
}
```

Factories: `ledgerUsb(hid)`, `ledgerBle(ble)`, `coldcardUsb(hid)`,
`bitboxUsb(hid, network, onPairingCode, noiseConfig)`, `jadeUsb(serial, http, network)`,
`jadeBle(serial, http, network)`.

Commands: `unlock`, `getInfo`, `getMasterFingerprint`, `getExtendedPubkey`,
`displayAddress`, `signMessage`, `signPsbt`. `disconnect()` is idempotent and releases
the device state handles; calls after it fail with `HwiException.BadState`. The
transport itself belongs to the caller and is left alone.

### BitBox02 pairing persistence

Export the pairing material after a successful unlock and restore it next time, and
the device stops asking the user to confirm the code:

```kotlin
val session = HwiSession.bitboxUsb(
    hid = myHidChannel,
    network = Network.TESTNET,
    onPairingCode = { code -> showOnScreen(code) },   // first pairing only
    noiseConfig = store.load(),                       // null on the very first run
)
session.unlock(Network.TESTNET)
store.save(session.bitboxPairing())                   // NoiseConfig: privkey + device pubkeys
```

`NoiseConfig` is plain data (`privkey: ByteArray?`, `devicePubkeys: List<ByteArray>`).
It is key material: persist it the way you would a private key.

## Threading contract

- **All calls are blocking and cheap.** They do protocol work only (parsing,
  encryption, PSBT handling) and never wait on a device, so calling from any
  dispatcher is fine.
- **Objects are `Send + Sync`** and internally locked; an `Interp` still runs one
  command, and the sequence `start` / `exchange`* / `end` must not interleave with
  itself.
- **One `Interp` per command, one state handle per connection.** Both are consumed
  or released explicitly (`end()`, or the UniFFI `close()`/`use { }` destructor).

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
`cargo test`, `build-android.sh`, `:lib:assembleRelease publishToMavenLocal`, the JVM
replay suite, assertions on the AAR contents and the published files, and the sample
app build.

### Artifact layout

`com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT` (AAR):

```
jni/arm64-v8a/libbhwi_ffi.so
jni/x86_64/libbhwi_ffi.so
classes.jar            # uniffi/bhwi_ffi/*.class  (generated bindings)
                       # com/wizardsardine/bhwi/*.class  (Kotlin host layer)
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

Entirely host-side: no Rust change. If the new link is one of the shapes above (an
HID report channel, a byte stream, a GATT pair), implement that interface and reuse
the existing `Link`. If it needs its own framing, implement `Link` directly: move
`payload` over the wire, honour `encrypted` if the framing signals it, and return the
reply. The fixtures below exist to verify exactly that layer.

## Fixtures and JVM replay testing

`fixtures/` holds two levels of checked-in vectors, both produced and verified by
`bhwi-ffi/tests/fixtures.rs`:

- `ledger_*.json`: report-level transcripts (`writes`/`reads` as hex HID reports)
  generated by driving the real `bhwi-async` Ledger transport in-memory.
  `bhwi-async` is a dev-dependency for exactly this reason — the host reimplements
  that framing and needs a byte-for-byte reference.
- `transmit_*.json`: the same commands at the FFI boundary (`payload_hex`,
  `encrypted`, `reply_hex` per exchange), so a Kotlin driving loop can be replayed
  against a scripted device.

Set `BHWI_REGENERATE_FIXTURES=1` to rewrite them after an intentional protocol
change; otherwise any drift fails the test.

A JVM unit test replays those vectors through the real bindings, with no device and
no emulator, with JNA pointed at the host library the build script already
produced.

```kotlin
// lib/build.gradle.kts
tasks.withType<Test>().configureEach {
    systemProperty("jna.library.path", rootDir.resolve("../target/release").canonicalPath)
    systemProperty("bhwi.fixtures.dir", rootDir.resolve("../fixtures").canonicalPath)
}
```

The generated bindings load the library by the base name `bhwi_ffi`, so
`target/release/libbhwi_ffi.so` is found as-is.

## Testing

```sh
nix develop -c ./tools/build-android.sh                                  # once
nix develop -c bash -c 'cd android && ./gradlew :lib:testDebugUnitTest'  # JVM replay suite
nix develop -c bash tools/check.sh                                       # everything
```

The JVM suite is the hard gate: it runs the real FFI boundary against the host
cdylib. It covers

- **report-level replay** — the Kotlin Ledger HID framing plus the real interpreter
  against transcripts recorded from `bhwi-async`'s own transport, so any framing
  drift fails as a byte mismatch;
- **transmit-level replay** — the driving loop against a scripted `Link`, asserting
  each payload and its `encrypted` flag, with no framing in the way;
- **framing units** — Ledger HID chunking across reports, Ledger BLE MTU inference /
  fragmentation / reassembly, the Coldcard chunk flags, U2F round trips and the HWW
  retry, and the CBOR completeness scanner;
- **lifecycle** — idempotent disconnect, post-disconnect `BadState`, mutex
  serialisation of concurrent calls, and the state-handle lease (a second `Interp` on
  a leased `NoiseHandle` is a `BadState`);
- **the pure helpers**, against the same vectors the Rust tests use.

`android/sample` is a minimal app that consumes the **published** AAR from
`mavenLocal` (not `project(":lib")`), so it exercises the real consumption path. Its
`androidTest` replays the fingerprint fixture on-device, reading the same
`fixtures/*.json` (wired in as androidTest assets).

```sh
nix develop -c bash tools/instrumentation.sh
```

creates the API 34 x86_64 AVD if needed, boots it headless from the
`nix develop .#emulator` shell, and runs `:sample:connectedDebugAndroidTest`.

**KVM note:** without `/dev/kvm` the script falls back to `-accel off` (full
software emulation). Boot then takes 10-15 minutes, `system_server` can stall long
enough for a run to fail with `Unknown API Level` or
`Can't find service: package` (re-run; the device recovers), and a single
instrumentation test takes ~80s. That is why the JVM suite — not the emulator — is
what `tools/check.sh` gates on. On a host with KVM, pass `BHWI_ACCEL=auto`.

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
- The model carries over unchanged: the exported objects become Swift classes with
  throwing methods, so an iOS app writes the same driving loop in Swift that
  Android writes in Kotlin, over its own transport.

Caveats, all verifiable from the generated output:

- Packaging is not shared. Swift needs the header and modulemap wired into an
  XCFramework; uniffi ships a dedicated `uniffi-bindgen-swift` CLI
  (`uniffi::uniffi_bindgen_swift()`, same `cli` feature) with `--headers`,
  `--modulemap` and `--xcframework` flags for that. Adding it here is a second
  `[[bin]]` in `bindgen/` when an iOS target actually exists.
- Building the iOS `.a`/`.dylib` requires `aarch64-apple-ios` targets and Xcode, so
  that half of the pipeline has to run on macOS.
