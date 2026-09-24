# FFI language priorities

## Context
Produce a general prioritized catalog for onboarding relevant languages to the BHWI ecosystem, considering Bitcoin wallets on desktop, mobile, browsers, and other platforms. Enumerate each language/runtime and its integration direction so the user can request a deeper plan for each later. This is not a wave-based rollout or authorization to implement several bindings. Broad coverage and experimental APIs are acceptable, but usable onboarding must culminate in a complete transaction-signing workflow.

## Evidence gathered
- Sparrow's upstream repository identifies Java and a desktop wallet supporting hardware wallets: https://github.com/sparrowwallet/sparrow . Evidence of a JVM consumer ecosystem, not evidence that Sparrow wants this library.
- Electrum's upstream README identifies Python and Qt, hardware-wallet integration, and desktop/Android distributions: https://github.com/spesmilo/electrum . Evidence of Python wallet use, not a binding adoption commitment.
- BlueWallet's README identifies React Native with Android, iOS, and Mac Catalyst build instructions: https://github.com/BlueWallet/BlueWallet/blob/master/README.md . React Native must be evaluated separately from Node/Electron bindings.
- BDK's binding design describes Swift, Kotlin (Android and server-side JVM), Java, Python, Dart/Flutter, and React Native bindings around Rust/UniFFI: https://bitcoindevkit.github.io/book-of-bdk/design/bindings/ . SDK ecosystem evidence; not market-share data or proof all generators have equal maturity.
- AQUA's repository identifies an iOS/Android wallet with Flutter and Dart FFI components: https://github.com/AquaWallet/aqua-wallet .
- Wasabi's repository identifies C#/.NET and desktop Windows/Linux/macOS: https://github.com/WalletWasabi/WalletWasabi .
- Nunchuk's README describes a C++ library used by desktop and mobile applications, with hardware interaction currently requiring an HWI binary: https://github.com/nunchuk-io/libnunchuk . Its multisig focus intersects capabilities not exposed by bhwi-ffi today.
- BitBoxApp's README describes a React UI, Go backend, and Qt desktop shell; Go is the hardware-integration candidate, not necessarily the UI language: https://github.com/bitboxswiss/bitbox-wallet-app .
- The external TypeScript generator advertises React Native/JSI, browser/WASM, and a new Node/N-API runtime: https://github.com/jhugman/uniffi-bindgen-react-native . Compatibility with this repository's pinned UniFFI 0.32.0 and native dependencies is not yet verified.
- UniFFI describes WASM support as external-generator work with target-specific scaffolding features: https://mozilla.github.io/uniffi-rs/next/wasm/configuration.html . These are next-version docs, not proof of a successful build with the current lockfile.
- WebHID requires a browser permission/device-selection flow and is marked experimental: https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API . Actual browser/model compatibility remains a validation gate.
- Blockstream's native iOS wallet repository identifies Swift: https://github.com/Blockstream/green_ios ; its README describes Bitcoin wallet functionality and reuse of the cross-platform GDK library.
- BDK's Dart repository documents generated UniFFI-Dart bindings, a native library, Flutter sample, and Dart Native Assets packaging: https://github.com/bitcoindevkit/bdk-dart . This is a stronger starting precedent than assuming Dart requires a new hand-written C API; compatibility with bhwi-ffi still needs checking.

## Repository baseline
- `README.md`, `Package.swift`, and `ios/Sources/Bhwi/`: experimental sans-I/O bindings; Kotlin/Android AAR and Swift host layers are implemented. Swift supplies a local iOS XCFramework build path, not a verified Apple package or hardware integration.
- `bhwi-ffi/Cargo.toml:10-29`: cdylib/rlib, no shipped async I/O runtime, OS randomness dependency, BHWI BitBox feature enabled.
- `android/lib/src/main/kotlin/com/wizardsardine/bhwi/HwiSession.kt:19-177`: one command at a time, caller-owned transport, persistent BitBox pairing and per-connection Coldcard state, worker-only synchronous native factories.
- `README.md:364-393`: checked-in report/transmit fixtures and real JVM replay; no physical-device support claim. Existing fixtures should anchor cross-language checks rather than inventing new protocols.
- `README.md:35-39`: Ledger PSBT signing, wallet registration, and multisig address display are absent. New language bindings must not be advertised as fixing these capability gaps.
- Read-only scout inspected the pinned UniFFI 0.32.0 generator: built-in Kotlin, Swift, Python, Ruby. Other candidate languages need separately evaluated generators or bridges.
- Existing browser integration lives in the sibling/main repository: `../bhwi/bhwi-wasm/src/lib.rs` exports a wasm-bindgen `Client` with direct WebHID/WebUSB/WebSerial transports and PSBT signing; `../bhwi/website/README.md:5-16` describes its Chromium-based demo. It uses BHWI-async, unlike this native UniFFI crate's host-driven I/O.
- Source and publication differ: current browser source exposes `sign_psbt`, while published `bhwi-wasm@0.0.1` declarations do not (https://unpkg.com/bhwi-wasm@0.0.1/bhwi_wasm.d.ts). The scout also inspected the scoped package and found the same omission. Existing npm/build/publication infrastructure should be reused, not recreated.
- `Cargo.toml:9-19` pins this FFI to the `trevarj/bhwi` `pairing-hook-send` branch and UniFFI 0.32.0. The scout confirmed current upstream/main browser code is on a different, newer revision. Treat browser and native command/device coverage separately; a dependency migration requires its own plan if the chosen native signing workflow needs it.

## Approach
Use this document as the onboarding catalog. Each numbered entry is an independent subject for a later language-specific plan, not a delivery wave or approval to implement it. The order recommends planning attention based on actual wallet stacks, platform reach, and reuse; it is not a market-share ranking.

Keep existing Kotlin/Android and browser support visible rather than counting them as new languages. For new bindings, preserve the current sans-I/O split: Rust owns protocol state and cryptography; the host owns command driving, framing, permissions, I/O, and user interaction. Do not introduce a universal C API merely to make the catalog appear uniform.

### Existing baseline: Kotlin / Android and Kotlin / desktop JVM
- **Relevance:** Native Android wallet development; BDK also distinguishes Android and desktop JVM consumers.
- **Today:** Android AAR, generated bindings, handwritten command/session/framing code, and Linux-host JVM replay exist. This is not a verified physical-device matrix or a desktop JVM distribution.
- **Onboarding direction:** Complete consumer-facing transport integration and signing proof around the existing host layer. Treat Android AAR and desktop JVM JAR/native artifacts as separate packaging targets. Desktop JVM work should share the Java entry below, not become a duplicate native binding.
- **Deeper-plan focus:** Named device/transport combinations, permission handling, lifecycle/disconnect behavior, pairing persistence, and Android versus desktop native-library loading.

### 1. Swift: native iOS and macOS
- **Why prioritize:** Complements the existing Android integration; native Swift Bitcoin wallets and BDK Swift provide concrete ecosystem precedent.
- **Today:** Version-matched UniFFI generation, Swift framing/command/session code, shared-fixture XCTest replay, and a local Swift Package/XCFramework builder are implemented. The package targets iOS 16+ on arm64 devices and arm64 simulators. **iOS is untested on physical devices; Apple builds and simulator execution remain unverified.** No macOS package slice or platform I/O adapter is supplied.
- [x] Swift generation and host orchestration/framing implementation.
- [x] Local iOS Swift Package and XCFramework build scripts.
- [x] Linux-host Swift source replay: 31 XCTest cases and a separate real-binding fingerprint/disconnect consumer passed with Swift 5.10.1 on x86_64. This is supporting evidence, not Apple runtime acceptance.
- [ ] Apple-native package build, installation in a Swift consumer, and simulator replay.
- [ ] Real Apple transport/permissions integration and protected pairing persistence.
- [ ] Complete test-network signing, independent signature/transaction verification, device refusal and disconnect acceptance.
- [ ] macOS artifact and runtime-specific transport validation.
- **Completion boundary:** The Swift implementation is checked off, not full language onboarding. Follow the shared acceptance contract below before promoting a device/OS/transport tuple to tested support. A Linux replay cannot establish iOS or macOS support.
- **Apple commands:** On macOS with full Xcode and the pinned Rust targets, run `bash tools/build-ios.sh`, then add the checkout as a local package in Xcode. On Apple Silicon with an iOS 16+ iPhone simulator, run `bash tools/check-ios.sh`; optionally select it with `BHWI_IOS_DESTINATION='platform=iOS Simulator,name=iPhone 16'`.
- **Remaining setup:** Select a supported signing device and an actual permitted Apple transport, a dedicated test wallet, and a funded test-network PSBT with complete prevout/derivation metadata. Ledger signing remains unsupported. Do not equate macOS USB access with iOS USB access.

### 2. TypeScript / JavaScript: three distinct runtime entries
- **Why prioritize:** React Native is used by BlueWallet; JavaScript UI stacks also appear in desktop wallet architectures. UI language alone does not prove where a wallet integrates hardware.
- **React Native:** No delivered binding here. Evaluate the existing external UniFFI TypeScript/JSI generator against the current contract, then package native Android/iOS artifacts with a TypeScript-facing module. Do not require a Swift facade solely because iOS is a target; generated JSI can be an independent native route. Preserve native-thread/JS-thread and session ownership semantics.
- **Node / Electron:** No delivered binding here. Evaluate the same project's Node/N-API path before inventing another wrapper. Package a native-backed npm module; Electron must validate its actual runtime/native loading and keep privileged hardware access outside untrusted renderer content. A Node check does not establish Electron support.
- **Browser, already implemented upstream:** Reuse `bhwi-wasm` and its wasm-bindgen `Client`, not the native UniFFI TypeScript generator. Direct WebHID/WebUSB/WebSerial adapters, wallet registration, and `sign_psbt(psbt, policy_name?, wallet_descriptor?, wallet_hmac_hex?)` exist in current source; the demo targets Chromium-based browsers. The onboarding work is source/release API alignment and real browser-to-device signing proof. Published 0.0.1 declarations lack signing, so consuming the published package is not equivalent to using current source. Keep existing npm packaging/publication infrastructure; no companion or duplicate browser transport stack.
- **Deeper-plan focus:** Compatibility with pinned UniFFI, typed errors/byte handling/object ownership, runtime-specific packaging, and complete signing over each runtime's real transport. Shared language does not imply shared native integration.

### 3. Dart / Flutter: cross-platform wallet applications
- **Why prioritize:** AQUA is a concrete Flutter wallet example; BDK supplies a UniFFI-Dart/native-assets precedent. Flutter reaches both mobile and desktop, but those targets need separate transport validation.
- **Today:** No Dart binding or package in bhwi-ffi.
- **Onboarding direction:** Start from the UniFFI-Dart approach used by BDK and check support for this crate's objects, enums, errors, byte buffers, and state handles. Target a Dart package usable from Flutter with explicit native assets. Do not add a second hand-maintained public API preemptively.
- **Deeper-plan focus:** Pinned generator compatibility, isolate/thread boundaries, native object lifetimes, platform plugins for hardware access, and Android/iOS/desktop packaging. A Flutter web target uses browser/WASM constraints, not Dart native FFI.

### 4. Java: desktop JVM consumers
- **Why prioritize:** Sparrow is a direct example of a Java desktop Bitcoin wallet with hardware support. This is a hardware-wallet audience, not just general language popularity.
- **Today:** Generated Kotlin and a coroutine-based Kotlin host exist; no Java-facing package is delivered. Kotlin/JVM availability alone does not establish ergonomic Java access.
- **Onboarding direction:** First evaluate Java calls through existing generated JVM types and an Android-independent host artifact. Add only the Java-facing adaptation actually required for suspend methods, unsigned types, ownership, and errors; evaluate a dedicated Java generator only if interoperability fails the consumer contract.
- **Deeper-plan focus:** A Java-only sample, JAR plus per-OS native libraries, asynchronous command API, and real desktop transport/signing. Sparrow is ecosystem evidence, not an assumed adopter or a promised drop-in replacement.

### 5. Python: desktop wallets, local tools, and hardware-attached services
- **Why prioritize:** Electrum demonstrates established Bitcoin wallet use; the built-in generator reduces binding novelty. Useful beyond UI code for local integration and diagnostics.
- **Today:** The pinned generator supports Python, but bhwi-ffi provides no Python host layer or distribution.
- **Onboarding direction:** Generate from existing metadata; provide a small Python command/session layer and a Python package with clearly identified native dependencies. Reuse protocol fixtures and current lifecycle rather than designing a separate command protocol.
- **Deeper-plan focus:** Native-library/wheel distribution, blocking I/O behavior, deterministic resource release, pairing persistence, and actual desktop device adapters. A remote Python service cannot reach a user's local signer without an additional transport architecture; none is implied.

### 6. C# / .NET: desktop wallet applications
- **Why retain:** Wasabi provides concrete cross-platform .NET wallet evidence.
- **Today:** No C# integration or distribution is supplied.
- **Onboarding direction:** Evaluate maintained UniFFI-compatible C# generation before committing to a custom P/Invoke boundary. Intended consumer artifact is a NuGet package with explicit runtime-native assets.
- **Deeper-plan focus:** Generator compatibility, managed/native lifetime and disposal, asynchronous UI-safe commands, exceptions and byte marshaling, and desktop device access. Any necessary C ABI is scoped to the demonstrated consumer requirement, not a mandatory prerequisite for every language.

### 7. C and C++: native wallet libraries and applications
- **Why retain:** Nunchuk uses a C++ wallet library on desktop/mobile and currently documents an HWI binary for hardware access. This is a plausible integration category, not evidence of an adoption request.
- **Today:** No supported C/C++ SDK is provided. A generated Swift FFI header is implementation plumbing, not an ergonomic or stable C API.
- **Onboarding direction:** Treat C as an ABI integration surface and C++ as a consumer language. For a selected consumer, define the smallest necessary explicit ownership/error/byte-buffer boundary and a thin C++ RAII layer where needed. Do not expose Rust layout or make a speculative general-purpose C framework.
- **Deeper-plan focus:** Whether in-process integration actually replaces a needed existing HWI workflow, native packaging, ownership, and required multisig/device capabilities. Current wallet registration, multisig address display, and Ledger signing gaps may block the target workflow regardless of binding quality.

### 8. Go: wallet backends and local hardware services
- **Why retain:** BitBoxApp's Go backend demonstrates why the hardware-facing language matters even when the UI is React.
- **Today:** No Go integration is provided.
- **Onboarding direction:** Evaluate maintained generator support first; use a minimal cgo boundary only when required by a named consumer and reuse a supported C boundary if one already exists. Intended distribution is a Go module with an explicit native build/distribution story.
- **Deeper-plan focus:** Goroutine versus native-call scheduling, cancellation and disconnection, ownership across cgo, cross-compilation, and device-local access. Do not add a network signer service or remote custody model as part of a language binding.

### 9. Ruby and additional long-tail languages
- **Why lower priority:** Ruby generation is already available, but this research found no comparable wallet-adoption evidence to justify prioritizing it above the entries above.
- **Onboarding direction:** Preserve Ruby as an explicitly enumerated option, triggered by a real consumer; generation alone is not onboarding. Other languages such as PHP, Lua, or Zig enter the same catalog when a wallet consumer or required platform justifies them. Do not create packages merely because a generic ABI makes them possible.
- **Deeper-plan focus:** The actual consumer workflow, maintained tooling, native packaging, host I/O, and the same signing acceptance used for every other language.

### Rust: native access, not an additional FFI target
Use the existing BHWI Rust libraries for Rust consumers. Do not route them through a foreign-language layer. Rust-based desktop apps do not by themselves justify a new frontend binding when their native backend can own hardware integration.

## Shared onboarding contract
Each language-specific plan must cover five concrete pieces: generated/native API access, host orchestration/framing, platform transport and permissions, a consumer-installable artifact, and a complete signing example. A generator-only experiment may be useful evidence but must not be labeled an onboarded language.

Reuse `Interp`'s `start -> exchange* -> end` semantics, typed errors, state-handle leases, command serialization, and deterministic resource release in native hosts. Reuse the existing async `Client` flow for browsers instead of forcing both architectures into a new universal wrapper. Pairing persistence includes secret material and needs platform-appropriate protection.

Capabilities are recorded per language/runtime/OS/device/transport, not inferred from a language name. Existing UniFFI limitations, especially Ledger PSBT signing and wallet-policy/multisig gaps, are shared prerequisites when a desired workflow requires them; do not patch around them separately in each language. For a selected workflow that is unsupported, plan the core capability/dependency change explicitly before the binding work and retain the signing requirement.

## Verification
The original catalog was researched without executing builds or physical signing. The Swift implementation status above is tracked separately; source availability and configured checks are not Apple runtime or device test results. No iOS device is available for this refinement, so physical-device acceptance remains open.

Swift refinement verification: the full `nix develop -c bash tools/check.sh` gate passed, including Rust formatting/Clippy/tests, Android artifacts/publication/JVM replay and Swift generation. All 31 Swift XCTest cases passed against the real generated bindings and host Rust library in a temporary Linux package with explicit XCTest registration. The Jade near-limit coalesced-envelope regression failed before its fix and passed afterward. A separate Swift consumer replayed fingerprint `f5acc2fd` and checked post-disconnect `BadState`. `tools/check-ios.sh` correctly rejected this Linux host; no Apple package build, simulator execution or physical signing ran.

For each subsequent language-specific onboarding plan, apply this acceptance contract:
1. **Real consumer:** Install/build the proposed artifact in a minimal application written in that language and running in the claimed runtime. Loading a Rust library indirectly through a different language's example does not count.
2. **Deterministic behavior:** Replay existing success/refusal transcripts through the real binding and check response values, structured errors, and lifecycle release. Reuse `fixtures/` rather than copying new protocol expectations. Replay is supporting evidence, not signing acceptance.
3. **Full signing:** Use a dedicated test wallet/device and a funded test-network single-signer PSBT with all required input/derivation metadata. Connect through the runtime's actual transport, unlock/pair/register as required, display the intended transaction for device approval, sign it, and retrieve the signed PSBT. Independently verify signatures against its previous outputs and check inputs, outputs, and fee are unchanged; finalize to a valid transaction. Broadcasting is not required and real funds must not be used. Multisig-specific claims additionally require all necessary signers and policy context, not one partial signature.
4. **Failure behavior:** Reject the signing request on the device and disconnect during an operation. Surface an error without reporting signing success, releasing command/session resources according to the platform's ownership model. Do not silently retry a signing request.
5. **Scope of evidence:** Record device model/firmware, OS/architecture, transport, runtime/browser version, and package revision. A successful tuple establishes only that tuple, not all devices or platforms in the catalog.

Existing entry points available when implementing a selected target:
- Native baseline, working directory `/home/trev/Workspace/bhwi-ffi`: `nix develop -c bash tools/check.sh`. This runs the existing non-emulator gate, not physical signing.
- Browser consumer, working directory `/home/trev/Workspace/bhwi`: `nix run .#website`. Open the served demo in Chromium with a connected supported test device and use its PSBT-signing UI. Test current source separately from the published npm artifact because their APIs differ.
- Each later target plan must supply that target's exact build/run commands and fixed test-device/PSBT setup. Do not invent these now for unselected integrations.

## Assumptions & contingencies
- Priorities optimize broad wallet ecosystem reach rather than one committed adopter. A real adopter can move its language earlier without changing the onboarding contract.
- Experimental API/package versions are acceptable. Production stability and remote publication are not prerequisites for the initial signing proof, but the exact artifact must be reproducibly consumable.
- Browser scope is direct access with no installed companion. Where browser/device APIs do not permit a combination, mark it unsupported; do not substitute a daemon or promise universal browser support.
- The catalog does not authorize implementation of other languages, dependency upgrades, or package publication. Swift branch refinement is separately requested; its remaining Apple/device acceptance and macOS scope are not silently waived.

