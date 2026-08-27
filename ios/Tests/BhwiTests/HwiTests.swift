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

  func testCancellationRetiresInterpreterWithoutRemapping() async {
    let interp = FakeInterp(
      transmits: [Transmit(payload: Data(), encrypted: false, recipient: .device)],
      response: .taskDone
    )
    let link = FakeLink(error: CancellationError())

    do {
      _ = try await Hwi.runCommand(interp: interp, command: .getVersion, link: link)
      XCTFail("expected cancellation")
    } catch is CancellationError {
      XCTAssertEqual(interp.endCalls, 1)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
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
      XCTAssertEqual(interp.endCalls, 1)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
  }
}
