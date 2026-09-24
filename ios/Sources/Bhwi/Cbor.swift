import Foundation

/// Structural CBOR walk used only to find the end of one Jade response.
enum Cbor {
  // Jade MAX_OUTPUT_MSG_SIZE, including the larger camera-debug configuration.
  // https://github.com/Blockstream/Jade/blob/6f46b8a8b2c602fd18d6835eab64e5e5e1e7ee1a/main/process.h
  static let maximumMessageLength = 3 * 1024 * 30

  static func valueLength(_ data: Data) throws -> Int? {
    let bytes = [UInt8](data)
    let length = try endOfValue(bytes, at: 0, end: bytes.count)
    guard (length ?? data.count) <= maximumMessageLength else {
      throw TransportError.io("jade: CBOR response exceeds the protocol message limit")
    }
    return length
  }

  static func endOfValue(_ bytes: [UInt8], at: Int, end: Int, depth: Int = 0) throws -> Int? {
    guard depth <= 64 else {
      throw TransportError.io("jade: CBOR nesting exceeds 64 levels")
    }
    guard at < end else { return nil }
    let initial = Int(bytes[at])
    let major = initial >> 5
    let info = initial & 0x1f
    var position = at + 1
    let value: UInt64

    switch info {
    case 0..<24:
      value = UInt64(info)
    case 24...27:
      let width = 1 << (info - 24)
      guard position + width <= end else { return nil }
      var read: UInt64 = 0
      for index in 0..<width {
        read = (read << 8) | UInt64(bytes[position + index])
      }
      position += width
      value = read
    case 31:
      switch major {
      case 2, 3:
        return try endOfChunks(bytes, from: position, end: end, major: major, depth: depth)
      case 4, 5:
        return try endOfItems(bytes, from: position, end: end, isMap: major == 5, depth: depth)
      default:
        throw TransportError.io("jade: malformed CBOR, indefinite length for major type \(major)")
      }
    default:
      throw TransportError.io("jade: malformed CBOR, reserved additional information \(info)")
    }
    guard position <= maximumMessageLength else {
      throw TransportError.io("jade: CBOR response exceeds the protocol message limit")
    }

    // Strings need one byte per unit, arrays at least one per item, maps two per pair.
    // Reject impossible declarations now instead of waiting for an unbounded body.
    if (2...5).contains(major) {
      let minimumBytesPerItem = major == 5 ? 2 : 1
      guard value <= UInt64((maximumMessageLength - position) / minimumBytesPerItem) else {
        throw TransportError.io("jade: CBOR declared length exceeds the protocol message limit")
      }
    }

    switch major {
    case 0, 1, 7:
      return position
    case 2, 3:
      guard value <= UInt64(end - position) else { return nil }
      return position + Int(value)
    case 4:
      guard value <= UInt64(end - position) else { return nil }
      return try endOfItems(bytes, from: position, end: end, count: Int(value), depth: depth)
    case 5:
      guard value <= UInt64((end - position) / 2) else { return nil }
      return try endOfItems(bytes, from: position, end: end, count: Int(value) * 2, depth: depth)
    default:
      return try endOfValue(bytes, at: position, end: end, depth: depth + 1)
    }
  }

  private static func endOfChunks(
    _ bytes: [UInt8],
    from: Int,
    end: Int,
    major: Int,
    depth: Int
  ) throws -> Int? {
    var position = from
    while true {
      guard position < end else { return nil }
      let initial = Int(bytes[position])
      if initial == 0xff { return position + 1 }
      guard initial >> 5 == major else {
        throw TransportError.io("jade: malformed CBOR, chunk of the wrong major type")
      }
      guard initial & 0x1f != 31 else {
        throw TransportError.io("jade: malformed CBOR, nested indefinite string")
      }
      guard let next = try endOfValue(bytes, at: position, end: end, depth: depth + 1) else {
        return nil
      }
      position = next
    }
  }

  private static func endOfItems(
    _ bytes: [UInt8],
    from: Int,
    end: Int,
    count: Int? = nil,
    isMap: Bool = false,
    depth: Int
  ) throws -> Int? {
    var position = from
    var left = count
    var items = 0
    while left != 0 {
      guard position < end else { return nil }
      if count == nil, bytes[position] == 0xff {
        guard !isMap || items.isMultiple(of: 2) else {
          throw TransportError.io("jade: malformed CBOR, map key without a value")
        }
        return position + 1
      }
      guard let next = try endOfValue(bytes, at: position, end: end, depth: depth + 1) else {
        return nil
      }
      position = next
      items += 1
      if let current = left { left = current - 1 }
    }
    return position
  }
}
