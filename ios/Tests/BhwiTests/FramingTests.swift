import Foundation
import XCTest

@testable import Bhwi

final class FramingTests: XCTestCase {
  func testLedgerHidMatchesRustFixture() async throws {
    let reports: ReportFixture = try fixture("ledger_get_master_fingerprint.json")
    let transmits: TransmitFixture = try fixture("transmit_ledger_fingerprint.json")
    let channel = ScriptedHid(reads: reports.reads.map(Data.init(hex:)))

    let reply = try await LedgerHidLink(channel: channel).exchange(
      payload: Data(hex: transmits.exchanges[0].payloadHex),
      encrypted: false
    )

    XCTAssertEqual(reply.hex, transmits.exchanges[0].replyHex)
    let writes = await channel.recordedWrites()
    XCTAssertEqual(writes.map(\.hex), reports.writes)
  }

  func testColdcardEncryptedChunksAndFramWorkaround() async throws {
    var response = Data([0x04])
    response.append(Data("fram".utf8))
    response.append(Data(repeating: 0, count: 59))
    let channel = ScriptedHid(reads: [response])
    let payload = Data((0..<70).map(UInt8.init))

    let reply = try await ColdcardHidLink(channel: channel).exchange(
      payload: payload, encrypted: true)

    XCTAssertEqual(reply, Data("fram".utf8))
    let writes = await channel.recordedWrites()
    XCTAssertEqual(writes.count, 2)
    XCTAssertEqual(writes[0][0], 63)
    XCTAssertEqual(writes[1][0], 0xc7)
  }

  func testU2fRoundTripAcrossFrames() throws {
    let message = Data((0..<180).map { UInt8($0 & 0xff) })
    XCTAssertEqual(try U2f.decode(U2f.encode(message)), message)
  }

  func testBitBoxRetriesNotReadyResponse() async throws {
    let notReady = try U2f.encode(Data([0x01]))
    let acknowledged = try U2f.encode(Data([0x00, 0xcc]))
    let reads = [notReady, acknowledged].flatMap { message in
      stride(from: 0, to: message.count, by: U2f.frameLength).map {
        message.subdata(in: $0..<($0 + U2f.frameLength))
      }
    }
    let channel = ScriptedHid(reads: reads)

    let reply = try await BitBoxHidLink(channel: channel).exchange(
      payload: Data([0x10]), encrypted: false)

    XCTAssertEqual(reply, Data([0xcc]))
    let writes = await channel.recordedWrites()
    XCTAssertEqual(writes.count, 2)
  }

  func testJadeReassemblesOneCborValue() async throws {
    let stream = ScriptedSerial(reads: [Data([0xa1, 0x61]), Data([0x69, 0x01])])
    let link = JadeSerialLink(stream: stream)

    let reply = try await link.exchange(payload: Data([0x81]), encrypted: false)

    XCTAssertEqual(reply, Data([0xa1, 0x61, 0x69, 0x01]))
    let writes = await stream.writes
    XCTAssertEqual(writes, [Data([0x81])])
  }

  func testLedgerBleInfersMtuAndReassemblesReply() async throws {
    let channel = ScriptedBle(
      mtu: 40,
      reads: [Data([0x08, 0, 0, 0, 0, 40]), Data([0x05, 0, 0, 0, 2, 0x90, 0x00])]
    )
    let link = LedgerBleLink(channel: channel)

    let reply = try await link.exchange(payload: Data([0xe1, 0x05]), encrypted: false)

    XCTAssertEqual(reply, Data([0x90, 0x00]))
    let writes = await channel.recordedWrites()
    XCTAssertEqual(writes[0], Data([0x08, 0, 0, 0, 0]))
    XCTAssertEqual(writes[1], Data([0x05, 0, 0, 0, 2, 0xe1, 0x05]))
  }
}
