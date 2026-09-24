import Foundation

/// Drives the sans-I/O interpreter over caller-owned links.
/// Consumes the interpreter's command state on every exit. Do not reuse it.
public enum Hwi {
  /// The callback runs synchronously off the main actor, before the next payload.
  /// Marshal UI updates to the main actor in the callback.
  public struct Pairing {
    public let noise: any NoiseHandleProtocol
    public let onCode: (String) -> Void

    public init(noise: any NoiseHandleProtocol, onCode: @escaping (String) -> Void) {
      self.noise = noise
      self.onCode = onCode
    }
  }

  public static func runCommand(
    interp: any InterpProtocol,
    command: HwiCommand,
    link: any Link,
    http: (any HttpBridge)? = nil,
    pairing: Pairing? = nil
  ) async throws -> HwiResponse {
    // An early end retires the interpreter and releases any state lease after a
    // transport error or task cancellation.
    var ended = false
    defer { if !ended { _ = try? interp.end() } }

    try Task.checkCancellation()
    var transmit = try interp.start(cmd: command)
    while true {
      try Task.checkCancellation()
      let reply = try await deliver(transmit: transmit, link: link, http: http)
      try Task.checkCancellation()
      let next = try interp.exchange(reply: reply)
      try Task.checkCancellation()
      if let code = pairing?.noise.takePairingCode() { pairing?.onCode(code) }
      guard let next else { break }
      transmit = next
    }
    try Task.checkCancellation()
    ended = true
    return try interp.end()
  }

  static func deliver(
    transmit: Transmit,
    link: any Link,
    http: (any HttpBridge)?
  ) async throws -> Data {
    switch transmit.recipient {
    case .device:
      return try await link.exchange(payload: transmit.payload, encrypted: transmit.encrypted)
    case .pinServer(let url):
      // Jade supplies this URL; never hand a cleartext or credential-bearing URL
      // to an HTTP adapter. The adapter must still restrict its trusted hosts.
      guard let endpoint = URLComponents(string: url),
        endpoint.scheme?.lowercased() == "https",
        endpoint.host?.isEmpty == false,
        endpoint.user == nil, endpoint.password == nil, endpoint.fragment == nil
      else {
        throw TransportError.io("jade: unsafe PIN-server URL")
      }
      guard let http else {
        throw HwiError.BadState(msg: "this command needs an HttpBridge for the Jade PIN server")
      }
      return try await http.request(url: url, body: transmit.payload)
    }
  }
}
