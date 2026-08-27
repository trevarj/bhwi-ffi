import Foundation
import XCTest

@testable import Bhwi

private actor ConcurrentLedgerHid: HidChannel {
  private let reply: Data
  private var inFlight = 0
  private(set) var maximumInFlight = 0

  init(reply: Data) { self.reply = reply }

  func send(_ report: Data) async throws -> Int {
    inFlight += 1
    maximumInFlight = max(maximumInFlight, inFlight)
    return report.count
  }

  func receive(maxLength: Int) async throws -> Data {
    try await Task.sleep(nanoseconds: 20_000_000)
    inFlight -= 1
    return reply.prefix(maxLength)
  }
}

private actor NeverReplyHid: HidChannel {
  private(set) var receiveCount = 0

  func send(_ report: Data) async throws -> Int { report.count }

  func receive(maxLength _: Int) async throws -> Data {
    receiveCount += 1
    try await Task.sleep(nanoseconds: 60_000_000_000)
    return Data()
  }
}

final class SessionTests: XCTestCase {
  func testLedgerSessionReplaysRustFixture() async throws {
    let reports: ReportFixture = try fixture("ledger_get_master_fingerprint.json")
    let channel = ScriptedHid(reads: reports.reads.map(Data.init(hex:)))
    let session = HwiSession.ledgerUSB(hid: channel)

    let fingerprint = try await session.getMasterFingerprint()
    XCTAssertEqual(fingerprint, reports.expected)
    await session.disconnect()
  }

  func testCommandsRemainSerializedAcrossActorReentrancy() async throws {
    let reports: ReportFixture = try fixture("ledger_get_master_fingerprint.json")
    let channel = ConcurrentLedgerHid(reply: Data(hex: reports.reads[0]))
    let session = HwiSession.ledgerUSB(hid: channel)

    async let first = session.getMasterFingerprint()
    async let second = session.getMasterFingerprint()
    let values = try await [first, second]

    XCTAssertEqual(values, [reports.expected, reports.expected])
    let maximumInFlight = await channel.maximumInFlight
    XCTAssertEqual(maximumInFlight, 1)
  }

  func testCancellationPropagatesAndDisconnectIsIdempotent() async throws {
    let channel = NeverReplyHid()
    let session = HwiSession.ledgerUSB(hid: channel)
    let command = Task { try await session.getMasterFingerprint() }
    while await channel.receiveCount == 0 { await Task.yield() }

    command.cancel()
    do {
      _ = try await command.value
      XCTFail("expected cancellation")
    } catch is CancellationError {
      // Expected: cancellation is never mapped to HwiError.
    }

    await session.disconnect()
    await session.disconnect()
    do {
      _ = try await session.getMasterFingerprint()
      XCTFail("expected disconnected session")
    } catch HwiError.BadState {
      // Expected.
    }
  }

  func testBitBoxPairingConfigurationRoundTrips() async throws {
    let config = NoiseConfig(
      privkey: Data(repeating: 7, count: 32),
      devicePubkeys: [Data(repeating: 9, count: 32)]
    )
    let session = try HwiSession.bitboxUSB(
      hid: ScriptedHid(reads: []),
      network: .testnet,
      onPairingCode: { _ in },
      noiseConfig: config
    )

    let pairing = try await session.bitboxPairing()
    XCTAssertEqual(pairing, config)
    await session.disconnect()
  }
}
