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
/// Commands invoke adapters off the main actor, without a fixed thread identity.
/// Adapters own cancellation/unblocking and must marshal platform callbacks as needed.
/// Reports exclude a platform HID report-ID prefix. Sends consume the entire report;
/// reads return at most `maxLength` bytes and throw `disconnected` at EOF.
public protocol HidChannel: AnyObject {
  func send(_ report: Data) async throws -> Int
  func receive(maxLength: Int) async throws -> Data
}

/// Byte stream for Jade over USB serial or BLE.
public protocol SerialStream: AnyObject {
  func writeAll(_ data: Data) async throws
  /// Return 1...maxLength bytes, or throw `TransportError.disconnected` at EOF.
  /// Empty data is also treated as EOF, never as "no data yet".
  func read(maxLength: Int) async throws -> Data
}

/// GATT characteristic pair for Ledger BLE.
public protocol BleChannel: AnyObject {
  func write(_ data: Data) async throws
  func read() async throws -> Data
  /// Maximum GATT value length for writes (not the ATT MTU including its header).
  var mtu: Int { get }
}

/// Jade PIN-server HTTP bridge. Implementations POST JSON and return the response body.
/// The device supplies the URL: restrict requests to your trusted PIN-server hosts
/// and do not follow redirects to untrusted destinations. Cancellation must unblock I/O.
public protocol HttpBridge: AnyObject {
  func request(url: String, body: Data) async throws -> Data
}
