import Foundation

@testable import Bhwi

extension Data {
  init(hex: String) {
    self.init(
      stride(from: 0, to: hex.count, by: 2).map { offset in
        let start = hex.index(hex.startIndex, offsetBy: offset)
        let end = hex.index(start, offsetBy: 2)
        return UInt8(hex[start..<end], radix: 16)!
      })
  }

  var hex: String { map { String(format: "%02x", $0) }.joined() }
}

struct ReportFixture: Decodable {
  let expected: String
  let reads: [String]
  let writes: [String]
}

struct TransmitFixture: Decodable {
  struct Exchange: Decodable {
    let encrypted: Bool
    let payloadHex: String
    let replyHex: String

    enum CodingKeys: String, CodingKey {
      case encrypted
      case payloadHex = "payload_hex"
      case replyHex = "reply_hex"
    }
  }

  let exchanges: [Exchange]
}

func fixture<T: Decodable>(_ name: String, as type: T.Type = T.self) throws -> T {
  guard let url = Bundle.module.url(forResource: name, withExtension: nil) else {
    throw CocoaError(.fileNoSuchFile)
  }
  return try JSONDecoder().decode(type, from: Data(contentsOf: url))
}

actor ScriptedHid: HidChannel {
  private var reads: [Data]
  private(set) var writes: [Data] = []

  init(reads: [Data]) { self.reads = reads }

  func send(_ report: Data) async throws -> Int {
    writes.append(report)
    return report.count
  }

  func receive(maxLength: Int) async throws -> Data {
    guard !reads.isEmpty else { throw TransportError.disconnected }
    return reads.removeFirst().prefix(maxLength)
  }

  func recordedWrites() -> [Data] { writes }
}

actor ScriptedSerial: SerialStream {
  private var reads: [Data]
  private(set) var writes: [Data] = []

  init(reads: [Data]) { self.reads = reads }

  func writeAll(_ data: Data) async throws { writes.append(data) }

  func read(maxLength: Int) async throws -> Data {
    guard !reads.isEmpty else { return Data() }
    return reads.removeFirst().prefix(maxLength)
  }
}

actor ScriptedBle: BleChannel {
  nonisolated let mtu: Int
  private var reads: [Data]
  private(set) var writes: [Data] = []

  init(mtu: Int, reads: [Data]) {
    self.mtu = mtu
    self.reads = reads
  }

  func write(_ data: Data) async throws { writes.append(data) }

  func read() async throws -> Data {
    guard !reads.isEmpty else { throw TransportError.disconnected }
    return reads.removeFirst()
  }

  func recordedWrites() -> [Data] { writes }
}

final class FakeInterp: InterpProtocol, @unchecked Sendable {
  private let transmits: [Transmit]
  private let response: HwiResponse
  private(set) var replies: [Data] = []
  private(set) var endCalls = 0
  private var index = 0

  init(transmits: [Transmit], response: HwiResponse) {
    self.transmits = transmits
    self.response = response
  }

  func start(cmd _: HwiCommand) throws -> Transmit {
    index = 1
    return transmits[0]
  }

  func exchange(reply: Data) throws -> Transmit? {
    replies.append(reply)
    guard index < transmits.count else { return nil }
    defer { index += 1 }
    return transmits[index]
  }

  func end() throws -> HwiResponse {
    endCalls += 1
    guard endCalls == 1 else { throw HwiError.BadState(msg: "interpreter is finished") }
    return response
  }
}

actor FakeLink: Link {
  private var replies: [Data]
  private(set) var calls: [(Data, Bool)] = []
  var error: Error?

  init(replies: [Data] = [], error: Error? = nil) {
    self.replies = replies
    self.error = error
  }

  func exchange(payload: Data, encrypted: Bool) async throws -> Data {
    calls.append((payload, encrypted))
    if let error { throw error }
    return replies.removeFirst()
  }

  func recordedCalls() -> [(Data, Bool)] { calls }
}

final class FakeNoise: NoiseHandleProtocol, @unchecked Sendable {
  var codes: [String]

  init(codes: [String]) { self.codes = codes }

  func export() throws -> NoiseConfig { NoiseConfig(privkey: nil, devicePubkeys: []) }
  func takePairingCode() -> String? { codes.isEmpty ? nil : codes.removeFirst() }
}
