import Foundation

/// Drives the sans-I/O interpreter over caller-owned links.
public enum Hwi {
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

    var transmit = try interp.start(cmd: command)
    while true {
      try Task.checkCancellation()
      let reply = try await deliver(transmit: transmit, link: link, http: http)
      let next = try interp.exchange(reply: reply)
      if let code = pairing?.noise.takePairingCode() { pairing?.onCode(code) }
      guard let next else { break }
      transmit = next
    }
    let response = try interp.end()
    ended = true
    return response
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
      guard let http else {
        throw HwiError.BadState(msg: "this command needs an HttpBridge for the Jade PIN server")
      }
      return try await http.request(url: url, body: transmit.payload)
    }
  }
}
