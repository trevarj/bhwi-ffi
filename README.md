# bhwi-ffi

bhwi-ffi provides experimental UniFFI bindings to BHWI's sans-I/O Bitcoin hardware-wallet interpreters.

[BHWI](https://github.com/wizardsardine/bhwi) supplies the protocol state machines;
this crate exposes their typed commands, transmits, responses and errors through
[UniFFI](https://mozilla.github.io/uniffi-rs/). Rust handles protocol state. The host
owns I/O, wire framing, HTTP and the driving loop, with no embedded Rust async
runtime.

This repository currently builds Kotlin bindings and an Android AAR containing a
handwritten Kotlin host layer. The API is experimental and not stable. The
publication workflow installs a snapshot in **Maven Local**, not a remote artifact
repository.

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

The native library explicitly enables all seven core families. `Cargo.toml` and
`Cargo.lock` pin core dependencies and UniFFI; all seven have FFI constructors.

## Supported devices and capabilities

The binding exposes **BitBox02, Coldcard, Jade, Ledger, Trezor, KeepKey and Specter-DIY**.
This is not a hardware validation matrix or a promise that every device supports every command.

The current command subset is `Unlock`, `GetVersion`, `GetMasterFingerprint`,
`GetXpub`, `PromptPin`/`SendPin`, singlesig `DisplayAddress` by derivation path,
`RegisterWallet`, `DisplayDescriptorAddress`, `DisplayMultisigAddress`, `SignMessage` and `SignPsbt`.
PSBT signing returns the complete base64 PSBT, never an extracted transaction or
broadcast. Setup, wipe, restore and backup are not exposed.

`WalletPolicy` carries the actual policy name, complete public descriptor and
optional Ledger-only 32-byte HMAC. Descriptors require resolved origin-bearing
account xpubs with unhardened suffixes; hardened origins remain valid. Secrets,
bare keys and unresolved templates are rejected. Ledger
descriptor display uses V2 policy context, BitBox resends its policy, and Jade and
Coldcard use the registered name. The raw multisig API takes 1–15 origin-qualified
keys and its own `Legacy`/`ShWit`/`Wit` format enum. Jade requires public account
xpubs with a concrete unhardened suffix and no wildcard; Trezor accepts these or
fully derived compressed public keys. KeepKey and Coldcard require fully derived
compressed public keys. No family accepts private, wildcard or multipath keys.

Registration returns `WalletRegistration.Complete(hmac)` or
`PendingUserConfirmation`, never a generic task result. Coldcard's enrollment
acknowledgment is pending, not proof of device confirmation or persistence.
Ledger registration accepts a successful completion only with exactly 64 data bytes
and the expected lowered V2 policy ID before returning its 32-byte HMAC.
Names are validated for the actual family before transmission. Reference Ledger
2.4.1 permits 1–64 printable ASCII bytes and BitBox 9.26.1 permits 1–30, both
without leading/trailing spaces; only Ledger default-policy contexts permit an
empty name. Unsupported descriptor/raw-multisig routes fail through the core
adapter, not a no-op.

Ledger `DisplayAddress` by path is limited to standard five-level
`purpose'/coin'/account'/change/index` paths. The pinned core selects the first
three components as the account and the fourth/fifth as change/index; it ignores
trailing components, so arbitrary-depth paths are not faithfully supported.
This limitation does not apply to `GetXpub` or explicit descriptor-policy display.

`SignPsbt { psbt_base64, wallet_policy }` and Kotlin
`signPsbt(psbtBase64, walletPolicy)` require the second argument explicitly.
Ledger always needs a V2 policy: registered wallets use the exact registered
name/descriptor and returned nonzero 32-byte HMAC. Default singlesig instead uses
an **empty name and no HMAC**, with one origin-bearing account xpub, the matching
`pkh`/`sh(wpkh)`/`wpkh`/key-only `tr` wrapper, exactly hardened
purpose/coin/account, account ≤100, and `/<0;1>/*`. The xpub chain must match the
origin coin type. The active Bitcoin app still verifies its network, internal
fingerprint and complete account xpub; the binding cannot prove device ownership
from a supplied fingerprint. Signing does not impose the default address-display
index ceiling of 50,000. A named policy without its HMAC, a zero-filled token or a
nonstandard no-HMAC policy fails before transport; signing never auto-registers.

BitBox script/multisig signing resends its registered policy; singlesig can pass
`null`. Jade, Coldcard, Trezor and KeepKey validate a supplied public policy but retain
the core's context-free full-PSBT flow. An HMAC on any non-Ledger interpreter is rejected.
The result gate binds the returned unsigned transaction to the original request and
preserves existing final scriptSig/witness fields and ECDSA/Taproot signatures,
rather than silently merging or overwriting them. Standard finalized-input cleanup
is allowed only when the exact original signature bytes remain as a returned final
witness item or scriptSig data push. Newly added ECDSA and Taproot partial/key/script
signatures must match the **original** input's requested sighash (implicit ECDSA
`ALL` versus Taproot `DEFAULT`); returned metadata cannot override that request.
Foreign nondefault requests and unchanged signatures are not blanket-rejected.
This is a fail-closed **result-boundary** check, not pre-device/preapproval protection,
independent signature validation or a consensus/script engine. New final-only
stacks are not decoded to establish their sighash modes. The consuming wallet must
independently verify the complete final spend and device result before using it.

Specter signing supplies `DeviceContext::Specter` when a public policy is provided.
The pinned core accepts this context but does not serialize it in the signing
request; it is not independent host-side policy verification.

Device-free helpers build singlesig descriptors (`build_singlesig_descriptor`),
derive receive/change addresses (`derive_addresses`) and inspect PSBTs
(`psbt_summary`). Generated Kotlin names are `buildSinglesigDescriptor`,
`deriveAddresses` and `psbtSummary`.

The opt-in BitBox chain registers a public policy, checks exact receive/change
addresses and signs a disposable 2-of-2 PSBT in both signing orders. The Kotlin/JNA
check reconnects to the same official simulator using a test-only HID TCP adapter
at `127.0.0.1:15423`; its input is public PSBT data, not an encrypted Noise replay.
Initialize a **disposable** official simulator with the core E2E harness's fixed
test mnemonic first; no seed-administration FFI is exposed.

```sh
BHWI_BITBOX_SIGNING_FIXTURE="$PWD/target/bitbox-signing.json" nix develop -c cargo test --locked -p bhwi-ffi --test policy bitbox_policy_firmware_smoke -- --ignored --nocapture --test-threads=1
# Regenerate/build the shared bindings first with tools/build-android.sh.
BHWI_BITBOX_SIGNING_FIXTURE="$PWD/target/bitbox-signing.json" BHWI_BITBOX_SIGNING_RESULT="$PWD/target/bitbox-jvm-signing.json" nix develop -c bash -c 'cd android && bash ./gradlew :lib:testDebugUnitTest --tests com.wizardsardine.bhwi.BitboxSigningFirmwareTest --rerun-tasks'
BHWI_BITBOX_SIGNING_FIXTURE="$PWD/target/bitbox-jvm-signing.json" nix develop -c cargo test --locked -p bhwi-ffi --test policy bitbox_signing_fixture_verifies -- --ignored --nocapture
```

Both Rust checks independently verify signatures against the original
prevouts/scripts/amounts and unchanged unsigned transaction, including exact
preservation of the foreign signature. The JVM test skips without its input
variable. TCP/GUI simulator adapters and async dependencies are test-only; synthetic
replies, prepared commands and simulator runs are not physical-device acceptance.
Ledger firmware signing additionally requires an available container runtime;
a synthetic refusal is not successful signing evidence.

### Trezor and KeepKey authentication

`Interp.new_trezor(network, handle, on_device_passphrase)` and
`new_keepkey(network, handle)` copy a normalized native `HostPassphraseHandle`.
Trezor rejects a host handle together with on-device entry before cloning the handle.
The handle constructor enforces ≤50 NFKD UTF-8 bytes; `clear()` drops its zeroizing
native owner, and a cleared handle fails with `BadState`. There is no secret export.
`validate()` checks a live native owner without copying its secret. Session
configuration uses this method's generated object-lifetime guard before storing a
candidate; a destroyed managed wrapper is rejected before native handle lowering.
Interpreter clones zeroize independently on drop. Managed input Strings and
protocol copies are **not** covered by a total-zeroization guarantee.

`trezorUsb(channel, network)` and `keepkeyUsb(channel, network)` start without
secrets or a selected passphrase mode. On a worker, call `configurePassphrase(handle, onDevice)`
before SendPin/account commands; an unanswered choice fails with BadState. It rejects
busy/disconnected sessions, cleared/closed owners and KeepKey's unsupported on-device mode.
Null/false is an explicitly selected Standard wallet. Choose on-device entry only
from actual Info capability data.
Replacement validation preserves the previous configuration on failure. The session
clears its native owner on replacement/disconnect; callers must not share, clear or
close that handle while configured.
`unlock()` returns the actual typed response, including Info; benign
AlreadyUnlocked returns TaskDone only at that unlock boundary.

`supportsHostPin(info)` is true for KeepKey and Trezor's legacy One model
(`firmware == null` or `"1"`), false for `"T"`, and rejects unknown Trezor models.
A locked T may still report `needs_pin_sent=true`: do not show it a host keypad.
One/KeepKey use `promptPin()` then `sendPin(positions)` over the **same physical
connection**, without intervening Initialize/unlock. Positions are digits 1–9 on
a blank keypad, not the literal PIN. False means authentication rejection.
PIN commands do not overwrite the chosen future passphrase mode; ordinary unlock
uses no recovery host events, seed-administration API or FFI-owned dialogs.
Registration and descriptor address display are explicitly unsupported for these
two families; use the family-specific concrete multisig shapes above. KeepKey
supports only sorted multisig and no Taproot address display. Trezor Taproot signing
support is established only for key-only/key-path spends: Taproot trees and
script-path spends are unestablished, not advertised as supported or independently
verified by this wrapper.
Cancel, unblock I/O and join before disconnecting/clearing the native handle.

The opt-in Rust and Kotlin/JNA smoke checks require an initialized disposable
official **Trezor One 1.13.1** emulator, explicit `BHWI_TREZOR_ADDR=127.0.0.1:21324`,
and its public `BHWI_TREZOR_FINGERPRINT` / `BHWI_TREZOR_ACCOUNT_XPUB` environment.
For a freshly locked PIN fixture, also set `BHWI_TREZOR_PIN` and explicit
`BHWI_TREZOR_DEBUG_ADDR=127.0.0.1:21325`; test-only debuglink maps its current keypad.
Re-lock the fixture before each PIN smoke. Neither smoke initializes or changes a
seed; passphrase protection must be off. These are firmware, not physical USB proofs.
The Rust runner enforces a 30-second absolute deadline on every packet send/receive
within each command and debuglink exchange, not a fresh timeout per packet.

```sh
nix develop -c cargo test --locked -p bhwi-ffi --test trezor_firmware -- --ignored --test-threads=1
# Regenerate/build bindings first with tools/build-android.sh.
nix develop -c bash -c 'cd android && bash ./gradlew :lib:testDebugUnitTest --tests com.wizardsardine.bhwi.TrezorOneFirmwareTest --rerun-tasks'
```

### Specter-DIY serial

`Interp.new_specter(network)` and `HwiSession.specterUsb(stream, network)` use the
actual core interpreter. Unlock returns the actual fingerprint, not invented Info;
the protocol has no version query. Descriptor display requires a public Specter
policy and `display=true`; Taproot display and raw multisig are unsupported.
Names must be nonempty without control characters or `&`, with no invented length
limit. Registration is `Complete(null)` only for exact firmware `success`;
user cancellation remains typed `UserRefused`.

`SpecterSerialLink` writes already-framed requests unchanged and uses one exported
`SpecterFrameDecoder` per exchange. The core validates ACK, trailing bytes and
4 MiB payload / 4 MiB+7 raw frame limits; incomplete means read more. Decoder
completion/error is terminal. The monotonic 300-second default deadline includes
the write. Timeout, cancellation, EOF, write/parser failure retires the link
permanently; only a complete valid frame allows reuse. The caller still closes I/O.

The opt-in firmware checks use explicit loopback serial/GUI addresses and the
official simulator's disposable public BIP39 vector. GUI approval and TCP adapters
are test-only, not USB proof. Start a fresh profile with the existing core
`nix run .#specter`; do not rerun initialization on a partially initialized profile.
Use the runner's actual `Running TCP-UART` GUI announcement before initialization.
The pinned simulator increments occupied ports; readiness must match the owned
announcement and child PID, not merely find default 8787 open. After initialization
reaches the final Menu, USB serial is created: read its actual `Running TCP-USB_VCP`
announcement and confirm that listener belongs to the same owned simulator child
and source cwd. Do not use USBHost's separate hardcoded `Connect to ...:8789` hint
as port evidence, or contact/close unrelated listeners.
The test-owned initializer follows individual screen lines and requires an explicit
fresh-profile flag. Rust independently derives the account, exact receive/change
addresses and PSBT signature key; it exports a public account-8 fixture for the
Kotlin facade and independently verifies the resulting ALL signature and metadata:

```sh
: "${BHWI_SPECTER_GUI_ADDR:?Set the actual owned runner-reported GUI endpoint before initialization}"
BHWI_SPECTER_FRESH_PROFILE=1 nix develop -c cargo test --locked -p bhwi-ffi --test specter_firmware specter_fixture_initialize -- --ignored --exact
: "${BHWI_SPECTER_ADDR:?Set the actual same-child TCP-USB_VCP endpoint announced after initialization}"
export BHWI_SPECTER_SIGNING_FIXTURE="$PWD/target/specter-signing.json" BHWI_SPECTER_SIGNING_RESULT="$PWD/target/specter-jvm-signing.json"
nix develop -c cargo test --locked -p bhwi-ffi --test specter_firmware specter_serial_policy_firmware_smoke -- --ignored --exact
# Regenerate/build shared bindings first with tools/build-android.sh.
nix develop -c bash -c 'cd android && bash ./gradlew :lib:testDebugUnitTest --tests com.wizardsardine.bhwi.SpecterFirmwareTest --rerun-tasks'
nix develop -c cargo test --locked -p bhwi-ffi --test specter_firmware specter_signing_fixture_verifies -- --ignored --exact
```


## Using the bindings

### Interpreter lifecycle

An `Interp` runs one command against one device. Only construction is device-specific:
`new_ledger`, `new_coldcard`, `new_bitbox`, `new_jade`, `new_trezor`, `new_keepkey`
or `new_specter`. The shared lifecycle is
`start -> exchange* -> end`:

1. `start(HwiCommand)` returns a `Transmit` containing `payload`, `encrypted` and
   `recipient`.
2. Deliver device/PIN-server payloads and feed reply bytes to `exchange`.
   Repeat until no further transmit is returned. Fail closed on unexpected
   `Recipient.Host` requests; this wallet-only API has no host-response method.
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
Ending or dropping the interpreter releases the lease. Pure input validation and
family adapter lowering precede native session mutation; a rejected preflight keeps
the same interpreter and its lease usable. Errors from actual runtime start or
exchange retire the command state, so later calls fail with `BadState`. Runtime
errors are not reusable preflight merely because they report `InvalidInput`.

Rust's structured `HwiError` distinguishes `Device`, `UserRefused`, `AuthRefused`,
`DeviceAlreadyUnlocked`, `InvalidInput`, `BadState` and `Internal`. Core
`UserCancelled` maps directly to `UserRefused`, without parsing device strings or
inferring refusal from missing results. `HwiSession.unlock` alone treats typed
`DeviceAlreadyUnlocked` as benign; other commands propagate it. These become Kotlin
`HwiException` variants. Transport and HTTP failures belong to the host.

`HwiResponse.Info` preserves the device's `version`, `firmware` (which can be a
model identifier), `initialized`, `networks`, `label`,
`on_device_passphrase_entry`, `needs_pin_sent` and `needs_passphrase_sent`, including
unknown (`None`) values.

Messages in these structured `HwiError` values do not carry raw protocol payloads
or key material. This guarantee does **not** cover unexpected failures: UniFFI
catches unwinding panics and reports them separately as Kotlin `InternalException`,
which can preserve panic text. Aborts and out-of-memory failures are not made
recoverable by that boundary.

Native `WalletPolicy` and `WalletRegistration` Debug output redacts HMACs, including
nested responses. Generated Kotlin records may still stringify registration tokens:
**do not log these objects**, real HMACs, PINs, passphrases or complete PSBTs.

The Kotlin threading and ownership contract is:

- Generated UniFFI constructors, methods and helpers are synchronous and
  **worker-only**. Protocol parsing and cryptography are not UI-thread work just
  because they perform no I/O. All synchronous `HwiSession` factories are also
  worker-only: `coldcardUsb` generates native key material, `bitboxUsb` restores
  native state, and the other factories currently defer native initialization.
- `Hwi.runCommand`, `HwiSession` suspend commands and `bitboxPairing()` are
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
`bitboxUsb(hid, network, onPairingCode, noiseConfig)`, `jadeUsb(serial, http, network)`,
`jadeBle(serial, http, network)`, `trezorUsb(channel, network)`, `keepkeyUsb(channel, network)`
and `specterUsb(stream, network)`.
Commands are `unlock`, `getInfo`, `promptPin`, `sendPin`, `getMasterFingerprint`,
`getExtendedPubkey`, `displayAddress`, `registerWallet`, `displayDescriptorAddress`,
`displayMultisigAddress`, `signMessage` and `signPsbt`.
The caller owns the transport; session cleanup does not dispose it.

For example, after retrieving the exact public BIP84 account:

```kotlin
val descriptor = buildSinglesigDescriptor(xpub, fingerprint, "m/84'/1'/0'", AddressFormat.NATIVE_SEGWIT, Network.TESTNET)
val signedPsbt = session.signPsbt(unsignedPsbt, WalletPolicy("", descriptor, null)) // Ledger default, not a registered label.
```

Regenerate all bindings from this shared contract and migrate callers to the
explicit policy argument rather than retaining the old one-argument command.

### Transports and framing

Implement the interface for the platform link. Transport failures use the host-side
`TransportException.Io`, `.Disconnected`, `.Timeout` or `.Cancelled` hierarchy, not
`HwiException`. Adapter error messages must not expose payload bytes.

| Interface | Methods | Used by |
|---|---|---|
| `HidChannel` | `send(report): UInt`, `receive(maxLen): ByteArray` | Ledger, Coldcard, BitBox02 USB; Trezor/KeepKey HID or WebUSB |
| `SerialStream` | `writeAll(data)`, `read(maxLen): ByteArray` | Jade USB serial/BLE; Specter-DIY USB serial |
| `BleChannel` | `write(data)`, `read(): ByteArray`, `mtu(): UShort` | Ledger BLE |
| `HttpBridge` | `request(url, body): ByteArray` | Jade PIN server |

- An empty `SerialStream.read` result means **end of stream**, not "no data yet".
  It aborts an incomplete message/frame. Suspend until data is available, or throw
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
| `TrezorV1Link(HidChannel)` | Shared Trezor/KeepKey V1: 64-byte packets, `0x3f` + 63 bytes, zero padding; exact packet I/O, `##` + u16 BE type + u32 BE body length, body ≤65536 bytes. Returns header/body without padding; failed/cancelled exchanges permanently retire the link. |
| `SpecterSerialLink(SerialStream)` | Core `SpecterFrameDecoder` validates a complete ACK+payload+CRLF reply, ≤4 MiB+7; whole-exchange deadline defaults to 300 seconds, failed/cancelled exchanges permanently retire the link. |

Raw Trezor/KeepKey `Interp.exchange` replies must contain exactly one `##` header
and its declared body (`8 + body length` bytes); truncated or trailing bytes retire
the command with a redacted `Device` error. Physical-report padding is the host
framing layer's responsibility and must not be passed to the interpreter.

Only Coldcard framing signals `encrypted` on the wire. BitBox02 ignores the flag
because its Noise encryption is already inside the interpreter's payload, as in
the reference transports.

`Recipient.Device` goes through the `Link`. `Recipient.PinServer { url }` is Jade
HTTP traffic: POST the payload to that URL as `application/json` and return the
response body to `exchange`. `Hwi.runCommand` routes it through `HttpBridge` and
fails with `HwiException.BadState` if no bridge was supplied; it must not go to the
device link.

`Recipient.Host` preserves a typed PIN-matrix or recovery-character request for
fail-closed routing, never device or HTTP traffic. No currently exposed command
produces management host prompts, and there is no host-response, recovery/setup UI
or generic host callback. `Hwi.runCommand` rejects every unexpected host request.
Ordinary `PromptPin`/`SendPin` remain separate wallet-authentication commands.

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
For a consumer-owned repository, pass an absolute path; Gradle's publication and
the sample's exclusive Maven Local resolution both honor the same override:

```sh
nix develop -c bash -c 'cd android && bash ./gradlew -Dmaven.repo.local=/absolute/path/.bhwi-maven :lib:publishToMavenLocal'
nix develop -c bash tools/check.sh -Dmaven.repo.local=/absolute/path/.bhwi-maven
```

Consumers must resolve this module exclusively from that repository, without
developer-cache or remote fallback (add alongside other dependency repositories):

```kotlin
exclusiveContent {
    forRepository { maven { url = uri("/absolute/path/.bhwi-maven") } }
    filter { includeModule("com.wizardsardine", "bhwi-ffi-android") }
}
// In dependencies:
implementation("com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT")
```

The full gate checks the AAR's native ABIs and generated/host classes, then compares
the published AAR byte-for-byte with the build output before sample consumption.

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

## Swift and iOS

Sharing this UniFFI crate with future Swift bindings is the recommended path. The
same version-matched generator can emit Swift; a Swift host would drive the same
interpreter lifecycle over its own transports.

Build the host library (also done by the Android builder), then generate:

```sh
nix develop -c cargo build --locked --release -p bhwi-ffi
nix develop -c cargo run --locked --release -p bhwi-ffi-bindgen -- generate --library target/release/libbhwi_ffi.so --language swift --out-dir target/generated-swift --no-format
```

This produces `bhwi_ffi.swift`, `bhwi_ffiFFI.h` and `bhwi_ffiFFI.modulemap` in
`target/generated-swift/`, **not a tested iOS package**. This repository has no Swift
host layer or Apple build/XCFramework pipeline. The Linux `.so` supplies generation
metadata, not an iOS runtime library; native Apple builds require the appropriate
Apple targets and Xcode/macOS, followed by platform-specific packaging.

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
(Ledger HID/BLE, Coldcard flags, U2F/HWW, Jade CBOR, Trezor/KeepKey V1 and Specter serial), command
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
# Or use an already running target without starting or stopping an emulator:
ANDROID_SERIAL=emulator-5558 nix develop -c bash tools/instrumentation.sh
```

Without `ANDROID_SERIAL`, the script creates the API 34 x86_64 AVD
`bhwi-api34-x86_64` if needed, boots it headlessly through the separate
`nix develop .#emulator` shell, and runs `:sample:connectedDebugAndroidTest`.
It owns and pins `emulator-5554` and stops that emulator on exit; an already present
device at that port is rejected rather than taken over. With `ANDROID_SERIAL`,
it requires that exact running, authorized device, pins all ADB/Gradle operations
to it, and never launches or kills an emulator. The script also forwards
`-Dmaven.repo.local=/absolute/path/.bhwi-maven` when testing an overridden publication.

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

For a sibling core checkout, add this local override to the workspace `Cargo.toml`;
its patch URL must match the pinned dependency URL:

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

Do not commit the local override or the resulting local lockfile changes.

## Documentation

- [Native API and error boundary](bhwi-ffi/src/lib.rs).
- [Commands, transmits, responses and error mapping](bhwi-ffi/src/types.rs).
- [Kotlin session facade](android/lib/src/main/kotlin/com/wizardsardine/bhwi/HwiSession.kt)
  and [command loop](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Hwi.kt).
- [Transport contracts](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Transports.kt)
  and [framing implementations](android/lib/src/main/kotlin/com/wizardsardine/bhwi/Links.kt).
- [Upstream BHWI design rationale](https://github.com/wizardsardine/bhwi/blob/main/docs/VISION.md).

## License

See [LICENSE](LICENSE).
