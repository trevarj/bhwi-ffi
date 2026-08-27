import Foundation

/// Structural CBOR walk used only to find the end of one Jade response.
enum Cbor {
  static func isComplete(_ data: Data) throws -> Bool {
    let bytes = [UInt8](data)
    return try endOfValue(bytes, at: 0, end: bytes.count) != nil
  }

  static func endOfValue(_ bytes: [UInt8], at: Int, end: Int) throws -> Int? {
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
      case 2, 3: return try endOfChunks(bytes, from: position, end: end, major: major)
      case 4, 5: return try endOfItems(bytes, from: position, end: end)
      default:
        throw TransportError.io("jade: malformed CBOR, indefinite length for major type \(major)")
      }
    default:
      throw TransportError.io("jade: malformed CBOR, reserved additional information \(info)")
    }

    switch major {
    case 0, 1, 7:
      return position
    case 2, 3:
      guard value <= UInt64(end - position) else { return nil }
      return position + Int(value)
    case 4:
      guard value <= UInt64(end - position) else { return nil }
      return try endOfItems(bytes, from: position, end: end, count: Int(value))
    case 5:
      guard value <= UInt64((end - position) / 2) else { return nil }
      return try endOfItems(bytes, from: position, end: end, count: Int(value) * 2)
    default:
      return try endOfValue(bytes, at: position, end: end)
    }
  }

  private static func endOfChunks(
    _ bytes: [UInt8],
    from: Int,
    end: Int,
    major: Int
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
      guard let next = try endOfValue(bytes, at: position, end: end) else { return nil }
      position = next
    }
  }

  private static func endOfItems(
    _ bytes: [UInt8],
    from: Int,
    end: Int,
    count: Int? = nil
  ) throws -> Int? {
    var position = from
    var left = count
    while left != 0 {
      guard position < end else { return nil }
      if count == nil, bytes[position] == 0xff { return position + 1 }
      guard let next = try endOfValue(bytes, at: position, end: end) else { return nil }
      position = next
      if let current = left { left = current - 1 }
    }
    return position
  }
}
