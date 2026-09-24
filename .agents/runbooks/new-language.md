# New-Language Onboarding

Use the existing [language priority catalog](../../plans/FFI_LANGUAGE_PRIORITIES_PLAN.md)
for selection and ecosystem rationale, especially its
[shared contract](../../plans/FFI_LANGUAGE_PRIORITIES_PLAN.md#shared-onboarding-contract)
and [verification contract](../../plans/FFI_LANGUAGE_PRIORITIES_PLAN.md#verification).
Do not duplicate its ranking. Each language/runtime is an independent selection,
not a rollout wave or authorization for more languages, dependency upgrades or
publication. Experimental/local packages are acceptable; stable APIs and remote
publication are not prerequisites for a reproducible consumer and signing proof.

## Select and reconcile

1. Select one requested language/runtime and intended consumer. Record the OS and
   architecture, device/model/firmware, transport and required signing workflow.
   Android is not desktop JVM; iOS is not macOS; React Native, Node/Electron and
   browser are different runtimes; Dart native does not establish Flutter web.
2. Check actual source, artifacts and execution evidence before adopting catalog
   status. Its Swift host, package, Apple scripts and replay claims are **not
   present in this checkout**: Swift here is generation-only. Preserve the catalog
   as research, explicitly reconcile discrepancies, and use current source and
   evidence for claims. See the [crate map](../context/crate-map.md).
3. Identify shared capability prerequisites. This native API lacks Ledger policy
   context for PSBT signing, wallet registration and multisig address display.
   If the selected workflow needs them, explicitly plan the core/dependency change
   before binding work and obtain authorization for that scope. Do not lower
   completion to fingerprint retrieval or patch around gaps per language.

## Choose the existing architecture

- **Native hosts:** use the pinned UniFFI metadata and sans-I/O contract. Verify
  the selected generator against records, enums, typed errors, bytes, objects and
  ownership; being listed by a generator is not compatibility evidence. Evaluate
  Java access through the existing JVM route before adding another binding.
- **Browser:** reuse the sibling BHWI `bhwi-wasm` async `Client` and direct
  WebHID/WebUSB/WebSerial route, not native UniFFI or a universal wrapper. The
  catalog records a source/published-npm signing API mismatch: verify the exact
  release used, not merely current source. Reuse its packaging infrastructure.
  Unsupported browser/device access remains unsupported; no installed companion,
  duplicate transport stack or network signer service is implied.
- **Rust:** use the Rust libraries directly. A Rust-backed UI does not by itself
  require another frontend binding. Do not preemptively build a universal C ABI;
  any demonstrated C/cgo/P/Invoke boundary belongs to the selected consumer scope.

## Deliver all five pieces

1. **API access:** generated/native bindings with matching metadata, byte/error
   mapping, explicit ownership and deterministic native disposal.
2. **Idiomatic host orchestration/framing:** native hosts drive
   `start -> exchange* -> end`, serialize commands and respect state leases;
   browsers retain the existing async `Client` flow. Reuse protocol/fixture
   expectations. Define worker/UI/isolate boundaries, cancellation and cleanup.
3. **Platform transport and permissions:** implement real discovery/permission/I/O
   for the selected runtime, including UI callbacks, disconnect/unblocking, Jade
   PIN-server routing and protected BitBox pairing persistence where applicable.
   The host owns transport; reuse framing rather than adding Rust I/O. Do not
   assume macOS USB access implies iOS access or Node loading proves Electron.
4. **Consumer-installable artifact:** reproducible native slices and runtime
   loading with dependencies and platform constraints stated. Include exact
   setup/build/install/run commands for the selected target, not invented commands
   for unselected generators. Local installation is sufficient, publication is
   separately authorized.
5. **Complete signing example:** a small application written in the selected
   language on the claimed runtime, with fixed test-device/wallet/PSBT setup and
   the full acceptance below. An example in another language indirectly loading
   Rust, generation alone, compilation or replay is not completed onboarding.

Preserve the applicable [root invariants](../../AGENTS.md#architecture-and-ownership),
typed refusal/authentication/transport/cancellation distinctions and security
rules. Native hosts protect persisted pairing private keys and show pairing codes
before the next payload. Release command/session resources on every path. Native
calls are not preemptible; teardown must cancel, unblock and join I/O before
disconnect/disposal.
Use existing descriptor/address/PSBT helpers, but not a summary as a signature or
transaction validator.

## Acceptance

All requirements apply to the selected tuple; record separate evidence for each.

1. **Real consumer:** install/build the proposed artifact in the language's own
   minimal application on the claimed runtime. Prove platform loading and actual
   API use, not only a generated file or another language's sample.
2. **Deterministic behavior:** replay the existing success/refusal transcripts
   through the real binding; assert response values, structured errors and
   lifecycle/lease release. Reuse `fixtures/`, adding only meaningful target gaps.
   Separate installation/loading, replay and emulator/simulator evidence.
3. **Full signing:** use a dedicated test wallet/device and a funded test-network
   single-signer PSBT containing complete prevout and derivation metadata. Connect
   through the runtime's actual permitted transport; unlock/pair/register where
   required; display the intended transaction for human device approval; sign
   and retrieve the signed PSBT. Independently verify signatures against previous
   outputs and verify that inputs, outputs and fee are unchanged; finalize a valid
   transaction. Broadcasting is not required. **Never use real funds.** Multisig
   claims additionally require all necessary signers and policy context, not one
   partial signature.
4. **Failure and cleanup:** reject signing on the device and disconnect during an
   operation. Require visible errors, no false signing success, no silent signing
   retry, and correct command/session/native/transport cleanup according to
   ownership. Check cancellation and post-disconnect behavior without promising
   that disconnect preempts an already-running native call.
5. **Scoped evidence:** record package/source revision, generator version,
   runtime/browser version, OS/architecture, device model/firmware and transport
   with commands and results. A passing tuple certifies only that tuple, not a
   whole language, device family or platform. If hardware, tools or capabilities
   are unavailable, state the exact prerequisite and keep onboarding/signing
   acceptance open; Linux replay is not Apple or physical-device proof.

## Existing entry points

- Native baseline: `nix develop -c bash tools/check.sh` from this repository;
  [validation](validation.md) explains its limits and generation-only Swift path.
- Browser baseline: `nix run .#website` from the sibling `../bhwi` root; its demo
  requires Chromium and an appropriate test device. Validate current source and
  the proposed npm artifact separately, including the signing API.
- The selected target's implementation must supply its own verified exact
  build/install/run commands and signing setup. Do not reuse absent Swift scripts
  from the catalog or fabricate commands for other integrations.
