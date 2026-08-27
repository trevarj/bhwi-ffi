import Foundation

/// Failure reported by a caller-owned transport.
public enum TransportError: Error, LocalizedError, Equatable {
  case io(String)
  case disconnected

  public var errorDescription: String? {
    switch self {
    case .io(let message): message
    case .disconnected: "device disconnected"
    }
  }
}

/// Raw HID report channel for Ledger, Coldcard, or BitBox02.
public protocol HidChannel: AnyObject {
  func send(_ report: Data) async throws -> Int
  func receive(maxLength: Int) async throws -> Data
}

/// Byte stream for Jade over USB serial or BLE.
public protocol SerialStream: AnyObject {
  func writeAll(_ data: Data) async throws
  /// Return at least one byte, or throw `TransportError.disconnected` at EOF.
  func read(maxLength: Int) async throws -> Data
}

/// GATT characteristic pair for Ledger BLE.
public protocol BleChannel: AnyObject {
  func write(_ data: Data) async throws
  func read() async throws -> Data
  var mtu: Int { get }
}

/// Jade PIN-server HTTP bridge. Implementations POST JSON and return the response body.
public protocol HttpBridge: AnyObject {
  func request(url: String, body: Data) async throws -> Data
}
