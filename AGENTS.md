# BHWI FFI Agent Rules

## Scope and workflow

- This is the repository policy; load only the applicable resources from
  [`.agents/README.md`](.agents/README.md). Direct task instructions take precedence.
- Check the existing branch and worktree before work; preserve unrelated changes.
  A documentation-only task does not require a new branch. Keep edits scoped and
  prefer existing APIs and dependencies over parallel abstractions.
- Technical claims must match current source, artifacts and observed execution.
  Plans are not proof of implementation or support. Keep support claims specific
  to language/runtime/OS/architecture/device/transport.
- Do not stage, commit, push, open or update a PR, or publish remotely unless asked.
  When authorized, use signed, atomic Conventional Commits with brief messages.
  If signing is unavailable, report it; do not fall back
  to unsigned commits. Do not commit generated bindings, build products or local
  dependency overrides.

## Architecture and ownership

- Rust owns protocol state and cryptography. Hosts own command driving, framing,
  discovery, permissions, transport, HTTP and UI. Do not embed transport clients
  or an async runtime in the shipped FFI. OS randomness for Coldcard keys is
  intentional; sans-I/O does not mean no OS dependency.
- One `Interp` runs one command: `start -> exchange* -> end`. Call `end` for a
  result only after `exchange` returns no next transmit; always close/drop the
  generated object, including on error, cancellation and after `end`. Internal
  locking and `Send + Sync` do not permit interleaved command lifecycles.
- `NoiseHandle` and `ColdcardEncryption` are exclusively leased by a live
  interpreter; a second lease or Noise export while leased returns `BadState`.
  Local input validation precedes session mutation; non-`BadState` protocol errors
  retire the command. Early `end` consumes it and fails. Lease release is not
  permission to retry a command or silently retry signing.
- Preserve the unsafe borrowing argument in `interp.rs`/`state.rs`: exclusive
  atomic leases, owning `Arc` liveness, mutex-serialized access, and `Session.inner`
  dropping before `Session.lease`. Coldcard installs its key before lease release
  and never exports it; use one encryption handle per physical connection, with
  no second unlock on an already-unlocked handle.
- Preserve the generated `uniffi.bhwi_ffi` / handwritten
  `com.wizardsardine.bhwi` split. Regenerate bindings with the matched workspace
  bindgen; never hand-edit them. Reuse existing framing and pure helpers.
- `Recipient.Device` uses the device `Link`; Jade `Recipient.PinServer` uses the
  host HTTP bridge (POST JSON to the supplied URL), never the device transport.
  HID send buffers are borrowed/reused: consume before returning, do not retain.
  HID/serial reads must not exceed the requested length; empty serial reads mean EOF.

## Threading, errors and secrets

- Kotlin `Hwi.runCommand`, session suspend commands and pairing export are
  main-safe; generated synchronous calls/helpers and session factories are
  worker-only. Session commands are mutex-serialized. Callbacks run in the IO
  context without fixed thread identity; adapters marshal UI work and cooperate
  with cancellation. Running synchronous native calls cannot be preempted.
- The caller owns the physical transport. `disconnect()` is idempotent and rejects
  later calls, but neither cancels jobs nor unblocks I/O nor prevents an in-flight
  result. Teardown: cancel, unblock platform I/O if needed, join, disconnect, then
  dispose the transport.
- Preserve `HwiError` distinctions: `Device`, `UserRefused`, `AuthRefused`,
  `InvalidInput`, `BadState`, `Internal`. Host transport/HTTP errors stay separate;
  coroutine cancellation must remain cancellation. Structured errors redact raw
  payloads and keys; unexpected UniFFI panic failures may retain panic text and do
  not make aborts or allocation failures recoverable.
- Protect BitBox pairing storage as private-key material. Export after successful
  unlock and lease release; restore on the next session. Surface new pairing codes
  after exchange and before sending the next payload, while the lease is live.
- Never log secrets, PINs, private keys or real HMACs; avoid raw device payloads and
  full PSBTs. Use synthetic/test-network data and redact evidence. Signing checks
  use dedicated test wallets, never real funds. PSBT summaries may lack amounts
  or fees and are not independent signature or transaction validation.

## Validation and delivery

- Docs-only: check links, paths, commands against source and support/evidence
  wording; skip builds, tests and formatters. Code/build/package changes: follow
  the [validation runbook](.agents/runbooks/validation.md), run the non-emulator
  gate and exercise the affected consumer path. Report APK assembly, emulator
  startup, instrumentation and physical-device signing as separate evidence.
- New-language work follows the [onboarding runbook](.agents/runbooks/new-language.md).
  Generation or replay alone is not onboarding. Shared capability gaps require
  an explicit core/dependency prerequisite, not per-language workarounds.
- Update affected callers and documentation when changing an API, lifecycle,
  package or validation command. Do not broaden scope into other languages,
  dependency upgrades or publication without authorization.
- PRs use the [short factual template](.agents/templates/pr-description.md):
  relevant behavior/API/package/security impacts and an actual `Checks:` line,
  not an implementation diary or unchecked checklist.
- Handoff briefly states changes; relevant API/host/package/dependency/security
  impacts; commands passed, failed or skipped with reasons; unsupported/unverified
  tuples and concrete blockers; and unrelated changes deliberately left untouched.
