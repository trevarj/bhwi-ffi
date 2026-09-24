import Foundation

/// Connected device facade. Actor isolation serializes commands and state-handle access.
public actor HwiSession {
  private var makeInterp: (() throws -> Interp)?
  private let link: any Link
  private let http: (any HttpBridge)?
  private var noise: NoiseHandle?
  private let onPairingCode: ((String) -> Void)?
  private var commandRunning = false
  private var commandWaiters: [(UUID, CheckedContinuation<Void, Error>)] = []

  private init(
    makeInterp: @escaping () throws -> Interp,
    link: any Link,
    http: (any HttpBridge)? = nil,
    noise: NoiseHandle? = nil,
    onPairingCode: ((String) -> Void)? = nil
  ) {
    self.makeInterp = makeInterp
    self.link = link
    self.http = http
    self.noise = noise
    self.onPairingCode = onPairingCode
  }

  public func unlock(network: Network) async throws {
    _ = try await run(.unlock(network: network))
  }

  public func getInfo() async throws -> HwiResponse {
    let response = try await run(.getVersion)
    guard case .info = response else { throw unexpectedResponse() }
    return response
  }

  public func getMasterFingerprint() async throws -> String {
    guard case .fingerprint(let hex) = try await run(.getMasterFingerprint) else {
      throw unexpectedResponse()
    }
    return hex
  }

  public func getExtendedPubkey(path: String, display: Bool) async throws -> String {
    guard case .xpub(let xpub) = try await run(.getXpub(path: path, display: display)) else {
      throw unexpectedResponse()
    }
    return xpub
  }

  public func displayAddress(
    path: String,
    display: Bool,
    format: AddressFormat? = nil
  ) async throws -> String {
    let command = HwiCommand.displayAddress(path: path, display: display, format: format)
    guard case .address(let address) = try await run(command) else { throw unexpectedResponse() }
    return address
  }

  public func signMessage(message: Data, path: String) async throws -> String {
    guard
      case .messageSignature(let base64) = try await run(.signMessage(message: message, path: path))
    else {
      throw unexpectedResponse()
    }
    return base64
  }

  public func signPsbt(_ psbtBase64: String) async throws -> String {
    guard case .signedPsbt(let signed) = try await run(.signPsbt(psbtBase64: psbtBase64)) else {
      throw unexpectedResponse()
    }
    return signed
  }

  /// Export after successful BitBox unlock and persist in the caller's secure storage.
  public func bitboxPairing() async throws -> NoiseConfig {
    try await acquireCommand()
    defer { releaseCommand() }
    try Task.checkCancellation()
    guard makeInterp != nil else { throw HwiError.BadState(msg: "session is disconnected") }
    guard let noise else {
      throw HwiError.BadState(msg: "this session has no BitBox02 pairing state")
    }
    return try noise.export()
  }

  /// Idempotent; does not cancel a command or close the caller-owned transport.
  /// Cancel the command task, unblock platform I/O if needed, and await its completion
  /// before disconnecting and disposing the transport.
  public func disconnect() {
    makeInterp = nil
    noise = nil
  }

  private func run(_ command: HwiCommand) async throws -> HwiResponse {
    try await acquireCommand()
    defer { releaseCommand() }
    try Task.checkCancellation()
    guard let makeInterp else { throw HwiError.BadState(msg: "session is disconnected") }
    let pairing = noise.flatMap { noise in
      onPairingCode.map { Hwi.Pairing(noise: noise, onCode: $0) }
    }
    return try await Hwi.runCommand(
      interp: try makeInterp(),
      command: command,
      link: link,
      http: http,
      pairing: pairing
    )
  }

  private func acquireCommand() async throws {
    try Task.checkCancellation()
    if !commandRunning {
      commandRunning = true
      return
    }
    let id = UUID()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        commandWaiters.append((id, continuation))
      }
    } onCancel: {
      Task { await self.cancelWaiter(id) }
    }
  }

  private func cancelWaiter(_ id: UUID) {
    guard let index = commandWaiters.firstIndex(where: { $0.0 == id }) else { return }
    commandWaiters.remove(at: index).1.resume(throwing: CancellationError())
  }

  private func releaseCommand() {
    if commandWaiters.isEmpty {
      commandRunning = false
    } else {
      commandWaiters.removeFirst().1.resume()
    }
  }

  private func unexpectedResponse() -> HwiError {
    .Internal(msg: "the device answered with an unexpected response kind")
  }

  public static func ledgerUSB(hid: any HidChannel) -> HwiSession {
    HwiSession(makeInterp: { Interp.newLedger() }, link: LedgerHidLink(channel: hid))
  }

  public static func ledgerBLE(ble: any BleChannel) -> HwiSession {
    HwiSession(makeInterp: { Interp.newLedger() }, link: LedgerBleLink(channel: ble))
  }

  /// Synchronous native key generation; call off the main actor.
  public static func coldcardUSB(hid: any HidChannel) -> HwiSession {
    let encryption = ColdcardEncryption()
    return HwiSession(
      makeInterp: { try Interp.newColdcard(encryption: encryption) },
      link: ColdcardHidLink(channel: hid)
    )
  }

  /// Restores native pairing state synchronously; call off the main actor.
  public static func bitboxUSB(
    hid: any HidChannel,
    network: Network,
    onPairingCode: @escaping (String) -> Void,
    noiseConfig: NoiseConfig? = nil
  ) throws -> HwiSession {
    let noise = try NoiseHandle(config: noiseConfig)
    return HwiSession(
      makeInterp: { try Interp.newBitbox(noise: noise, network: network) },
      link: BitBoxHidLink(channel: hid),
      noise: noise,
      onPairingCode: onPairingCode
    )
  }

  public static func jade(
    serial: any SerialStream,
    http: any HttpBridge,
    network: Network
  ) -> HwiSession {
    HwiSession(
      makeInterp: { Interp.newJade(network: network) },
      link: JadeSerialLink(stream: serial),
      http: http
    )
  }
}
