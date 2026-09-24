import Foundation
import XCTest

@testable import Bhwi

private actor GatedLedgerHid: HidChannel {
  private let reply: Data
  private let entered: XCTestExpectation
  private var continuation: CheckedContinuation<Void, Never>?
  private var pause = true
  private var inFlight = 0
  private(set) var maximumInFlight = 0

  init(reply: Data, entered: XCTestExpectation) {
    self.reply = reply
    self.entered = entered
  }

  func send(_ report: Data) async throws -> Int {
    inFlight += 1
    maximumInFlight = max(maximumInFlight, inFlight)
    return report.count
  }

  func receive(maxLength: Int) async throws -> Data {
    if pause {
      pause = false
      await withCheckedContinuation {
        continuation = $0
        entered.fulfill()
      }
    }
    inFlight -= 1
    return reply.prefix(maxLength)
  }

  func release() {
    continuation?.resume()
    continuation = nil
  }
}

private extension HwiSession {
  func fingerprint(entered: XCTestExpectation) async throws -> String {
    entered.fulfill()
    return try await getMasterFingerprint()
  }

  // Called after `entered` to ensure the actor has suspended in the queued command.
  func synchronize() {}
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
    let entered = expectation(description: "first command is receiving")
    let queued = expectation(description: "second command entered the session")
    let channel = GatedLedgerHid(reply: Data(hex: reports.reads[0]), entered: entered)
    let session = HwiSession.ledgerUSB(hid: channel)
    let first = Task { try await session.getMasterFingerprint() }
    await fulfillment(of: [entered], timeout: 5)
    let second = Task { try await session.fingerprint(entered: queued) }
    await fulfillment(of: [queued], timeout: 5)
    await session.synchronize()
    await channel.release()
    let values = try await [first.value, second.value]

    XCTAssertEqual(values, [reports.expected, reports.expected])
    let maximumInFlight = await channel.maximumInFlight
    XCTAssertEqual(maximumInFlight, 1)
    await session.disconnect()
  }

  func testCancellationPropagatesAndDisconnectIsIdempotent() async throws {
    let reports: ReportFixture = try fixture("ledger_get_master_fingerprint.json")
    let entered = expectation(description: "command is receiving")
    let channel = GatedLedgerHid(reply: Data(hex: reports.reads[0]), entered: entered)
    let session = HwiSession.ledgerUSB(hid: channel)
    let command = Task { try await session.getMasterFingerprint() }
    await fulfillment(of: [entered], timeout: 5)

    command.cancel()
    await channel.release()
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

  func testQueuedCancellationDoesNotWaitForActiveTransportOrReleaseItsLock() async throws {
    let reports: ReportFixture = try fixture("ledger_get_master_fingerprint.json")
    let entered = expectation(description: "first command is receiving")
    let queued = expectation(description: "second command entered the session")
    let cancelled = expectation(description: "queued command completed")
    let channel = GatedLedgerHid(reply: Data(hex: reports.reads[0]), entered: entered)
    let session = HwiSession.ledgerUSB(hid: channel)
    let first = Task { try await session.getMasterFingerprint() }
    await fulfillment(of: [entered], timeout: 5)
    let second = Task {
      defer { cancelled.fulfill() }
      return try await session.fingerprint(entered: queued)
    }
    await fulfillment(of: [queued], timeout: 5)
    await session.synchronize()

    second.cancel()
    await fulfillment(of: [cancelled], timeout: 5)
    await channel.release()
    let fingerprint = try await first.value
    XCTAssertEqual(fingerprint, reports.expected)
    do {
      _ = try await second.value
      XCTFail("expected queued cancellation")
    } catch is CancellationError {
      // Expected, while the first command still held the transport.
    }
    let next = try await session.getMasterFingerprint()
    XCTAssertEqual(next, reports.expected)
    let maximumInFlight = await channel.maximumInFlight
    XCTAssertEqual(maximumInFlight, 1)
    await session.disconnect()
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
