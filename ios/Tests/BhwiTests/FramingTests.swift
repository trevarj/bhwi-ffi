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

  func testLedgerHidRejectsMissingPayloadBytes() async throws {
    let channel = ScriptedHid(reads: [Data([0x01, 0x01, 0x05, 0, 0, 0, 2, 0x90])])
    do {
      _ = try await LedgerHidLink(channel: channel).exchange(payload: Data([0xe1]), encrypted: false)
      XCTFail("a short report must not invent the missing status byte")
    } catch TransportError.io {
      // Expected.
    }
  }

  func testLedgerHidRejectsLengthOverflowBeforeSending() async throws {
    let channel = ScriptedHid(reads: [])
    do {
      _ = try await LedgerHidLink(channel: channel).exchange(
        payload: Data(repeating: 0, count: 0x10000), encrypted: false)
      XCTFail("expected length rejection")
    } catch TransportError.io {
      let writes = await channel.recordedWrites()
      XCTAssertTrue(writes.isEmpty)
    }
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

  func testColdcardRejectsInvalidRequestLengthBeforeSending() async throws {
    let channel = ScriptedHid(reads: [])
    let link = ColdcardHidLink(channel: channel)
    for payload in [Data(), Data(repeating: 0, count: 2061)] {
      do {
        _ = try await link.exchange(payload: payload, encrypted: false)
        XCTFail("expected request length rejection")
      } catch TransportError.io {
        let writes = await channel.recordedWrites()
        XCTAssertTrue(writes.isEmpty)
      }
    }
  }

  func testColdcardResponseLimitAllowsFullMessagesAndRejectsRunawayReports() async throws {
    let payload = Data(repeating: 0x11, count: 2048 + 12)
    let reports = stride(from: 0, to: payload.count, by: 63).map { offset in
      let end = min(offset + 63, payload.count)
      let count = end - offset
      var report = Data([UInt8(count) | (end == payload.count ? 0x80 : 0)])
      report.append(payload.subdata(in: offset..<end))
      report.append(Data(repeating: 0, count: 63 - count))
      return report
    }
    let reply = try await ColdcardHidLink(channel: ScriptedHid(reads: reports)).exchange(
      payload: Data("dwld".utf8), encrypted: true)
    XCTAssertEqual(reply, payload)

    let unending = Data([0x3f]) + Data(repeating: 0x11, count: 63)
    let channel = ScriptedHid(reads: Array(repeating: unending, count: 34))
    do {
      _ = try await ColdcardHidLink(channel: channel).exchange(
        payload: Data("dwld".utf8), encrypted: true)
      XCTFail("expected oversized response rejection")
    } catch TransportError.io {
      // Must reject the response before exhausting the scripted reports (disconnected).
    }
  }

  func testU2fRoundTripAcrossFrames() throws {
    let message = Data((0..<180).map { UInt8($0 & 0xff) })
    XCTAssertEqual(try U2f.decode(U2f.encode(message)), message)
  }

  func testU2fRejectsInvalidContinuationHeadersAndOversizedLength() throws {
    let encoded = try U2f.encode(Data(repeating: 0xaa, count: 180))
    var wrongChannel = encoded
    wrongChannel[64] ^= 1
    XCTAssertThrowsError(try U2f.decode(wrongChannel))
    var wrongSequence = encoded
    wrongSequence[128 + 4] = 0
    XCTAssertThrowsError(try U2f.decode(wrongSequence))
    var oversized = Data(encoded.prefix(64))
    oversized[5] = 0xff
    oversized[6] = 0xff
    XCTAssertThrowsError(try U2f.decode(oversized))
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

  func testJadeKeepsNearLimitCoalescedResponseForNextExchange() async throws {
    // A real Jade RPC envelope has an id and a result. The second response
    // arrives in the same final read as the first, near its 90 KiB limit.
    let bodyLength = Cbor.maximumMessageLength - 19
    var firstResponse = Data([0xa2, 0x62, 0x69, 0x64, 0x61, 0x31, 0x66])
    firstResponse.append(Data("result".utf8))
    firstResponse.append(contentsOf: [0x5a, 0, UInt8(bodyLength >> 16),
                                      UInt8((bodyLength >> 8) & 0xff), UInt8(bodyLength & 0xff)])
    firstResponse.append(Data(repeating: 0, count: bodyLength))
    let secondResponse = Data([0xa2, 0x62, 0x69, 0x64, 0x61, 0x32, 0x66])
      + Data("result".utf8) + Data([0xf5])
    // Put the surplus in the same final read as the end of the first value:
    // the aggregate exceeds 90 KiB although neither CBOR envelope does.
    let firstPartLength = firstResponse.count - 512
    var reads: [Data] = stride(from: 0, to: firstPartLength, by: 1024).map { offset in
      firstResponse.subdata(in: offset..<min(offset + 1024, firstPartLength))
    }
    reads.append(Data(firstResponse.suffix(512)) + secondResponse)
    let stream = ScriptedSerial(reads: reads)
    let link = JadeSerialLink(stream: stream)

    let first = try await link.exchange(payload: Data([0x10]), encrypted: false)
    let second = try await link.exchange(payload: Data([0x11]), encrypted: false)
    XCTAssertEqual(first, firstResponse)
    XCTAssertEqual(second, secondResponse)
    let writes = await stream.writes
    XCTAssertEqual(writes, [Data([0x10]), Data([0x11])])
  }

  func testJadeAcceptsMaximumFirmwareEnvelopeAndRejectsAggregateOverflow() async throws {
    // MAX_OUTPUT_MSG_SIZE also covers Jade's larger camera-debug configuration.
    let payloadLength = 90 * 1024 - 5
    var response = Data([0x5a, 0, UInt8(payloadLength >> 16),
                         UInt8((payloadLength >> 8) & 0xff), UInt8(payloadLength & 0xff)])
    response.append(Data(repeating: 0, count: payloadLength))
    let reads = stride(from: 0, to: response.count, by: 1024).map {
      response.subdata(in: $0..<min($0 + 1024, response.count))
    }
    let reply = try await JadeSerialLink(stream: ScriptedSerial(reads: reads)).exchange(
      payload: Data([0x81]), encrypted: false)
    XCTAssertEqual(reply, response)

    // Every string chunk fits individually, but the indefinite envelope does not.
    let chunk = Data([0x59, 0x03, 0xfd]) + Data(repeating: 0, count: 1021)
    let oversized = [Data([0x5f])] + Array(repeating: chunk, count: 90) + [Data([0xff])]
    do {
      _ = try await JadeSerialLink(stream: ScriptedSerial(reads: oversized)).exchange(
        payload: Data([0x81]), encrypted: false)
      XCTFail("expected aggregate response rejection")
    } catch TransportError.io {
      // Without the aggregate bound the complete oversized value would be returned.
    }
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

  func testLedgerBleRejectsAnUndersizedChannelBeforeWriting() async throws {
    let channel = ScriptedBle(mtu: 19, reads: [])
    do {
      _ = try await LedgerBleLink(channel: channel).exchange(payload: Data([0xe1]), encrypted: false)
      XCTFail("expected unsupported GATT write length")
    } catch TransportError.io {
      let writes = await channel.recordedWrites()
      XCTAssertTrue(writes.isEmpty)
    }
  }
}
