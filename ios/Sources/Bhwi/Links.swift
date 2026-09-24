import Foundation

/// One logical request/response exchange over caller-owned I/O.
/// Serialize exchanges; links are not safe for concurrent commands. Cancellation is
/// cooperative: adapters must unblock their own platform I/O when a task is cancelled.
public protocol Link: AnyObject {
  func exchange(payload: Data, encrypted: Bool) async throws -> Data
}

private let hidReportLength = 64

private func be16(_ bytes: [UInt8], _ offset: Int) -> Int {
  (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
}

public final class LedgerHidLink: Link {
  private let channel: HidChannel

  public init(channel: HidChannel) {
    self.channel = channel
  }

  public func exchange(payload: Data, encrypted _: Bool) async throws -> Data {
    guard payload.count <= 0xffff else {
      throw TransportError.io("ledger: APDU longer than the HID protocol allows")
    }
    let payload = [UInt8](payload)
    var framed = [UInt8](repeating: 0, count: payload.count + 2)
    framed[0] = UInt8((payload.count >> 8) & 0xff)
    framed[1] = UInt8(payload.count & 0xff)
    framed.replaceSubrange(2..., with: payload)

    var report = [UInt8](repeating: 0, count: hidReportLength)
    report[0] = UInt8((Self.channelID >> 8) & 0xff)
    report[1] = UInt8(Self.channelID & 0xff)
    report[2] = Self.tag
    var sequence = 0
    var offset = 0
    while offset < framed.count {
      try Task.checkCancellation()
      let count = min(hidReportLength - 5, framed.count - offset)
      report[3] = UInt8((sequence >> 8) & 0xff)
      report[4] = UInt8(sequence & 0xff)
      report.replaceSubrange(5..<(5 + count), with: framed[offset..<(offset + count)])
      guard try await channel.send(Data(report)) >= report.count else {
        throw TransportError.io("ledger: could not send the whole HID report")
      }
      offset += count
      sequence += 1
    }

    var answer: [UInt8] = []
    var wantedSequence = 0
    var expected = 0
    while true {
      try Task.checkCancellation()
      let read = [UInt8](try await channel.receive(maxLength: hidReportLength))
      guard read.count <= hidReportLength else {
        throw TransportError.io("ledger: HID report exceeds the requested length")
      }
      guard (wantedSequence == 0 && read.count >= 7) || (wantedSequence != 0 && read.count >= 5)
      else {
        throw TransportError.io("ledger: incomplete HID header")
      }
      guard be16(read, 0) == Self.channelID else {
        throw TransportError.io("ledger: invalid channel")
      }
      guard read[2] == Self.tag else { throw TransportError.io("ledger: invalid tag") }
      guard be16(read, 3) == wantedSequence else {
        throw TransportError.io("ledger: invalid sequence idx")
      }

      var position = 5
      if wantedSequence == 0 {
        expected = be16(read, 5)
        position = 7
      }
      let count = min(hidReportLength - position, expected - answer.count)
      guard read.count >= position + count else {
        throw TransportError.io("ledger: incomplete HID payload")
      }
      if count > 0 { answer.append(contentsOf: read[position..<(position + count)]) }
      if answer.count >= expected { return Data(answer) }
      wantedSequence += 1
    }
  }

  private static let channelID = 0x0101
  private static let tag: UInt8 = 0x05
}

public final class ColdcardHidLink: Link {
  private let channel: HidChannel

  public init(channel: HidChannel) {
    self.channel = channel
  }

  public func exchange(payload: Data, encrypted: Bool) async throws -> Data {
    guard !payload.isEmpty, payload.count <= Self.maximumResponseLength else {
      throw TransportError.io("coldcard: request exceeds the protocol message limit")
    }
    let payload = [UInt8](payload)
    var report = [UInt8](repeating: 0, count: hidReportLength)
    let chunks = (payload.count + Self.chunk - 1) / Self.chunk
    for index in 0..<chunks {
      try Task.checkCancellation()
      let offset = index * Self.chunk
      let count = min(Self.chunk, payload.count - offset)
      let last = index == chunks - 1
      report[0] = UInt8(count | (last ? 0x80 | (encrypted ? 0x40 : 0) : 0))
      report.replaceSubrange(1..<(1 + count), with: payload[offset..<(offset + count)])
      guard try await channel.send(Data(report)) >= report.count else {
        throw TransportError.io("coldcard: could not send the whole HID report")
      }
    }

    var answer: [UInt8] = []
    var first = true
    while true {
      try Task.checkCancellation()
      let report = [UInt8](try await channel.receive(maxLength: hidReportLength))
      guard report.count == hidReportLength else {
        throw TransportError.io("coldcard: could not read the whole HID report")
      }
      let flag = Int(report[0])
      let fram = first && Array(report[1..<5]) == Self.fram
      let count = flag & 0x3f
      guard count <= Self.maximumResponseLength - answer.count else {
        throw TransportError.io("coldcard: response exceeds the protocol message limit")
      }
      answer.append(contentsOf: report[1..<(1 + count)])
      first = false
      if flag & 0x80 != 0 || fram { return Data(answer) }
    }
  }

  private static let chunk = 63
  private static let fram = Array("fram".utf8)
  // ckcc-protocol/ckcc/constants.py MAX_MSG_LEN; BHWI uses 2048-byte file chunks.
  // ncry v1 uses AES-CTR, so encryption does not expand the response.
  private static let maximumResponseLength = 2048 + 12
}

enum U2f {
  static let frameLength = 64
  static let channelID: UInt32 = 0xff00_ff00
  static let firmwareCommand: UInt8 = 0xc1
  private static let initialDataLength = frameLength - 7
  private static let continuationDataLength = frameLength - 5
  private static let maximumMessageLength = initialDataLength + 127 * continuationDataLength

  static func frameCount(_ length: Int) -> Int {
    length <= initialDataLength
      ? 1 : 1 + (length - initialDataLength + continuationDataLength - 1) / continuationDataLength
  }

  static func encode(_ message: Data) throws -> Data {
    let message = [UInt8](message)
    guard message.count <= maximumMessageLength else {
      throw TransportError.io("bitbox: message needs more U2F frames than allowed")
    }
    var output = [UInt8](repeating: 0, count: frameCount(message.count) * frameLength)
    putBE32(&output, at: 0, value: channelID)
    output[4] = firmwareCommand
    output[5] = UInt8((message.count >> 8) & 0xff)
    output[6] = UInt8(message.count & 0xff)
    let first = min(initialDataLength, message.count)
    output.replaceSubrange(7..<(7 + first), with: message[0..<first])

    var offset = first
    var frame = 1
    var sequence: UInt8 = 0
    while offset < message.count {
      let base = frame * frameLength
      putBE32(&output, at: base, value: channelID)
      output[base + 4] = sequence
      let count = min(continuationDataLength, message.count - offset)
      output.replaceSubrange(
        (base + 5)..<(base + 5 + count), with: message[offset..<(offset + count)])
      offset += count
      sequence &+= 1
      frame += 1
    }
    return Data(output)
  }

  static func decode(_ data: Data) throws -> Data? {
    let bytes = [UInt8](data)
    guard bytes.count >= 7 else { return nil }
    guard readBE32(bytes, at: 0) == channelID else {
      throw TransportError.io("bitbox: wrong U2F channel id")
    }
    guard bytes[4] == firmwareCommand else {
      throw TransportError.io("bitbox: wrong U2F command")
    }
    let length = be16(bytes, 5)
    guard length <= maximumMessageLength else {
      throw TransportError.io("bitbox: message needs more U2F frames than allowed")
    }
    guard bytes.count >= frameCount(length) * frameLength else { return nil }

    var output = [UInt8](repeating: 0, count: length)
    var count = min(initialDataLength, length)
    output.replaceSubrange(0..<count, with: bytes[7..<(7 + count)])
    var written = count
    var from = frameLength
    var sequence: UInt8 = 0
    while written < length {
      guard readBE32(bytes, at: from) == channelID else {
        throw TransportError.io("bitbox: wrong U2F continuation channel id")
      }
      guard bytes[from + 4] == sequence else {
        throw TransportError.io("bitbox: wrong U2F continuation sequence")
      }
      count = min(continuationDataLength, length - written)
      output.replaceSubrange(
        written..<(written + count), with: bytes[(from + 5)..<(from + 5 + count)])
      written += count
      from += frameLength
      sequence += 1
    }
    return Data(output)
  }

  private static func putBE32(_ bytes: inout [UInt8], at: Int, value: UInt32) {
    for index in 0..<4 { bytes[at + index] = UInt8((value >> (8 * (3 - index))) & 0xff) }
  }

  private static func readBE32(_ bytes: [UInt8], at: Int) -> UInt32 {
    var value: UInt32 = 0
    for index in 0..<4 { value = (value << 8) | UInt32(bytes[at + index]) }
    return value
  }
}

public final class BitBoxHidLink: Link {
  private let channel: HidChannel

  public init(channel: HidChannel) {
    self.channel = channel
  }

  public func exchange(payload: Data, encrypted _: Bool) async throws -> Data {
    var request = Data([Self.requestNew])
    request.append(payload)
    var response = try await query(request)
    while true {
      try Task.checkCancellation()
      guard let status = response.first else {
        throw TransportError.io("bitbox: unexpected HWW response")
      }
      switch status {
      case Self.responseAck: return Data(response.dropFirst())
      case Self.responseNotReady: response = try await query(Data([Self.requestRetry]))
      case Self.responseBusy: throw TransportError.io("bitbox: device busy")
      case Self.responseNack: throw TransportError.io("bitbox: device NACK")
      default: throw TransportError.io("bitbox: unexpected HWW response")
      }
    }
  }

  private func query(_ message: Data) async throws -> Data {
    let encoded = try U2f.encode(message)
    var offset = 0
    while offset < encoded.count {
      try Task.checkCancellation()
      let frame = encoded.subdata(in: offset..<(offset + U2f.frameLength))
      guard try await channel.send(frame) >= frame.count else {
        throw TransportError.io("bitbox: could not send the whole HID report")
      }
      offset += U2f.frameLength
    }

    var buffer = Data()
    while true {
      try Task.checkCancellation()
      let report = try await channel.receive(maxLength: U2f.frameLength)
      guard report.count == U2f.frameLength else {
        throw TransportError.io("bitbox: could not read the whole HID report")
      }
      buffer.append(report)
      if let decoded = try U2f.decode(buffer) { return decoded }
    }
  }

  private static let requestNew: UInt8 = 0x00
  private static let requestRetry: UInt8 = 0x01
  private static let responseAck: UInt8 = 0x00
  private static let responseNotReady: UInt8 = 0x01
  private static let responseBusy: UInt8 = 0x02
  private static let responseNack: UInt8 = 0x03
}

public final class JadeSerialLink: Link {
  private let stream: SerialStream
  private var pending = Data()

  public init(stream: SerialStream) {
    self.stream = stream
  }

  public func exchange(payload: Data, encrypted _: Bool) async throws -> Data {
    try Task.checkCancellation()
    try await stream.writeAll(payload)
    var buffer = pending
    pending.removeAll()
    while true {
      if let length = try Cbor.valueLength(buffer) {
        pending = Data(buffer.dropFirst(length))
        return Data(buffer.prefix(length))
      }
      try Task.checkCancellation()
      let chunk = try await stream.read(maxLength: Self.chunkLength)
      guard chunk.count <= Self.chunkLength else {
        throw TransportError.io("jade: serial read exceeds the requested length")
      }
      guard !chunk.isEmpty else {
        throw TransportError.io("stream ended before complete CBOR message")
      }
      guard chunk.count <= Cbor.maximumMessageLength + Self.chunkLength - 1 - buffer.count else {
        throw TransportError.io("jade: response exceeds the protocol message limit")
      }
      buffer.append(chunk)
    }
  }

  private static let chunkLength = 1024
}

public final class LedgerBleLink: Link {
  private let channel: BleChannel
  private var negotiatedFrameSize: Int?

  public init(channel: BleChannel) {
    self.channel = channel
  }

  public func exchange(payload: Data, encrypted _: Bool) async throws -> Data {
    let size = try await frameSize()
    guard payload.count <= 0xffff else {
      throw TransportError.io("ledger: APDU longer than the BLE protocol allows")
    }
    let payload = [UInt8](payload)
    var sequence = 0
    var offset = 0
    while offset < payload.count || sequence == 0 {
      try Task.checkCancellation()
      let header = sequence == 0 ? 5 : 3
      let count = min(size - header, payload.count - offset)
      var frame = [UInt8](repeating: 0, count: header + count)
      frame[0] = Self.apduTag
      frame[1] = UInt8((sequence >> 8) & 0xff)
      frame[2] = UInt8(sequence & 0xff)
      if sequence == 0 {
        frame[3] = UInt8((payload.count >> 8) & 0xff)
        frame[4] = UInt8(payload.count & 0xff)
      }
      frame.replaceSubrange(header..<(header + count), with: payload[offset..<(offset + count)])
      try await channel.write(Data(frame))
      offset += count
      sequence += 1
    }

    var answer: [UInt8] = []
    var expected = 0
    var wantedSequence = 0
    while true {
      try Task.checkCancellation()
      let frame = [UInt8](try await channel.read())
      if frame.count < 3 || frame[0] != Self.apduTag { continue }
      let sequence = be16(frame, 1)
      guard sequence == wantedSequence else {
        throw TransportError.io(
          "ledger: BLE frame out of order: expected \(wantedSequence), got \(sequence)")
      }
      var from = 3
      if sequence == 0 {
        guard frame.count >= 5 else {
          throw TransportError.io("ledger: BLE first frame is missing the length header")
        }
        expected = be16(frame, 3)
        from = 5
      }
      let count = min(frame.count - from, expected - answer.count)
      if count > 0 { answer.append(contentsOf: frame[from..<(from + count)]) }
      if answer.count >= expected { return Data(answer) }
      wantedSequence += 1
    }
  }

  private func frameSize() async throws -> Int {
    guard channel.mtu >= Self.minimumMtu else {
      throw TransportError.io("ledger: BLE channel must support at least 20-byte writes")
    }
    if let negotiatedFrameSize { return negotiatedFrameSize }
    let size = max(min(try await inferMtu(), channel.mtu), Self.minimumMtu)
    negotiatedFrameSize = size
    return size
  }

  private func inferMtu() async throws -> Int {
    try await channel.write(Data([Self.mtuTag, 0, 0, 0, 0]))
    for _ in 0..<Self.mtuAttempts {
      try Task.checkCancellation()
      let frame = [UInt8](try await channel.read())
      if frame.first == Self.mtuTag {
        return frame.count > 5 ? Int(frame[5]) : Self.minimumMtu
      }
    }
    throw TransportError.io("ledger: no BLE MTU answer from the device")
  }

  private static let apduTag: UInt8 = 0x05
  private static let mtuTag: UInt8 = 0x08
  private static let minimumMtu = 20
  private static let mtuAttempts = 8
}
