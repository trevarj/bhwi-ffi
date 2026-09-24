import Foundation
import XCTest

@testable import Bhwi

private actor FakeHttp: HttpBridge {
  private(set) var calls: [(String, Data)] = []
  let reply: Data

  init(reply: Data) { self.reply = reply }

  func request(url: String, body: Data) async throws -> Data {
    calls.append((url, body))
    return reply
  }
}

private final class OrderRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func append(_ event: String) {
    lock.lock()
    events.append(event)
    lock.unlock()
  }

  func snapshot() -> [String] {
    lock.lock()
    defer { lock.unlock() }
    return events
  }
}

private actor OrderLink: Link {
  let recorder: OrderRecorder
  private var call = 0

  init(recorder: OrderRecorder) { self.recorder = recorder }

  func exchange(payload _: Data, encrypted _: Bool) async throws -> Data {
    call += 1
    recorder.append("send\(call)")
    return Data()
  }
}

private final class CancellingBitBoxLink: Link {
  private(set) var payloads: [Data] = []

  func exchange(payload: Data, encrypted _: Bool) async throws -> Data {
    payloads.append(payload)
    if payloads.count == 1 { return Data() }
    withUnsafeCurrentTask { $0?.cancel() }
    return Data([0])
  }
}

final class HwiTests: XCTestCase {
  func testDeviceAndPinServerRouting() async throws {
    let transmits = [
      Transmit(payload: Data([1]), encrypted: true, recipient: .device),
      Transmit(
        payload: Data([2]), encrypted: false, recipient: .pinServer(url: "https://example.test")),
    ]
    let interp = FakeInterp(transmits: transmits, response: .taskDone)
    let link = FakeLink(replies: [Data([3])])
    let http = FakeHttp(reply: Data([4]))

    let response = try await Hwi.runCommand(
      interp: interp,
      command: .getVersion,
      link: link,
      http: http
    )

    XCTAssertEqual(response, .taskDone)
    XCTAssertEqual(interp.replies, [Data([3]), Data([4])])
    let linkCalls = await link.recordedCalls()
    XCTAssertEqual(linkCalls.count, 1)
    XCTAssertTrue(linkCalls[0].1)
    let httpCalls = await http.calls
    XCTAssertEqual(httpCalls.first?.0, "https://example.test")
  }

  func testPairingCodeArrivesBeforeNextPayload() async throws {
    let recorder = OrderRecorder()
    let interp = FakeInterp(
      transmits: [
        Transmit(payload: Data([1]), encrypted: false, recipient: .device),
        Transmit(payload: Data([2]), encrypted: false, recipient: .device),
      ],
      response: .taskDone
    )

    _ = try await Hwi.runCommand(
      interp: interp,
      command: .unlock(network: .bitcoin),
      link: OrderLink(recorder: recorder),
      pairing: Hwi.Pairing(noise: FakeNoise(codes: ["code"])) { _ in recorder.append("code") }
    )

    XCTAssertEqual(recorder.snapshot(), ["send1", "code", "send2"])
  }

  func testCancellationRetiresNativeInterpreterWithoutRemapping() async throws {
    let noise = try NoiseHandle(config: nil)
    let interp = try Interp.newBitbox(noise: noise, network: .testnet)
    let link = FakeLink(error: CancellationError())

    do {
      _ = try await Hwi.runCommand(interp: interp, command: .unlock(network: .testnet), link: link)
      XCTFail("expected cancellation")
    } catch is CancellationError {
      XCTAssertNil(try noise.export().privkey)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
  }

  func testAlreadyCancelledCommandReleasesLeaseWithoutSending() async throws {
    let noise = try NoiseHandle(config: nil)
    let interp = try Interp.newBitbox(noise: noise, network: .testnet)
    let link = FakeLink(error: TransportError.disconnected)
    let command = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await Hwi.runCommand(
        interp: interp, command: .unlock(network: .testnet), link: link)
    }

    do {
      _ = try await command.value
      XCTFail("expected cancellation")
    } catch is CancellationError {
      let calls = await link.recordedCalls()
      XCTAssertTrue(calls.isEmpty)
      XCTAssertNil(try noise.export().privkey)
      let next = try Interp.newBitbox(noise: noise, network: .testnet)
      XCTAssertEqual(try next.start(cmd: .unlock(network: .testnet)).payload, Data("u".utf8))
      _ = try? next.end()
    }
  }

  func testCancellationAfterSynchronousReplyDoesNotAdvanceNativeState() async throws {
    let noise = try NoiseHandle(config: nil)
    let interp = try Interp.newBitbox(noise: noise, network: .testnet)
    let link = CancellingBitBoxLink()
    let command = Task {
      try await Hwi.runCommand(interp: interp, command: .unlock(network: .testnet), link: link)
    }

    do {
      _ = try await command.value
      XCTFail("expected cancellation")
    } catch is CancellationError {
      XCTAssertEqual(link.payloads, [Data("u".utf8), Data("h".utf8)])
      // Consuming the handshake reply would generate the host private key.
      XCTAssertNil(try noise.export().privkey)
    }
  }

  func testUntrustedPinServerUrlNeverReachesHttpAdapter() async {
    let http = FakeHttp(reply: Data())
    for url in ["http://pin.example.test", "https://user:secret@pin.example.test",
                "file:///etc/passwd", "https://pin.example.test/path#fragment"] {
      let interp = FakeInterp(
        transmits: [Transmit(payload: Data([1]), encrypted: false, recipient: .pinServer(url: url))],
        response: .taskDone
      )
      do {
        _ = try await Hwi.runCommand(
          interp: interp, command: .getVersion, link: FakeLink(), http: http)
        XCTFail("expected unsafe URL rejection")
      } catch TransportError.io {
        XCTAssertEqual(interp.endCalls, 1)
      } catch {
        XCTFail("unexpected error: \(error)")
      }
    }
    let calls = await http.calls
    XCTAssertTrue(calls.isEmpty)
  }

  func testMissingPinServerBridgeIsBadState() async {
    let interp = FakeInterp(
      transmits: [
        Transmit(
          payload: Data(), encrypted: false, recipient: .pinServer(url: "https://example.test"))
      ],
      response: .taskDone
    )

    do {
      _ = try await Hwi.runCommand(interp: interp, command: .getVersion, link: FakeLink())
      XCTFail("expected BadState")
    } catch HwiError.BadState {
      // The loop reports the missing host transport without remapping it.
    } catch {
      XCTFail("unexpected error: \(error)")
    }
  }
}
