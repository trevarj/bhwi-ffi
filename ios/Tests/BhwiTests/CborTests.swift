import Foundation
import XCTest

@testable import Bhwi

final class CborTests: XCTestCase {
  func testCompleteNestedValueAndTrailingBytes() throws {
    let value = Data([0xa1, 0x61, 0x69, 0x82, 0x01, 0x02])
    for length in 0..<value.count {
      XCTAssertNil(try Cbor.valueLength(value.prefix(length)))
    }
    XCTAssertEqual(try Cbor.valueLength(value), value.count)
    XCTAssertEqual(try Cbor.valueLength(value + Data([0xff])), value.count)
  }

  func testIndefiniteContainers() throws {
    for value in [Data([0x9f, 0x01, 0x02, 0xff]),
                  Data([0x7f, 0x62, 0x68, 0x69, 0xff]),
                  Data([0xbf, 0x01, 0x02, 0xff])] {
      XCTAssertEqual(try Cbor.valueLength(value), value.count)
    }
  }

  func testMalformedValueFailsWithoutReadingMore() {
    XCTAssertThrowsError(try Cbor.valueLength(Data([0x1c])))
    XCTAssertThrowsError(try Cbor.valueLength(Data([0x7f, 0x5f])))
    XCTAssertThrowsError(try Cbor.valueLength(Data([0xbf, 0x01, 0xff])))
  }

  func testNestingIsBoundedBeforeStackExhaustion() throws {
    XCTAssertEqual(try Cbor.valueLength(Data(repeating: 0x81, count: 64) + Data([0x00])), 65)
    XCTAssertThrowsError(try Cbor.valueLength(Data(repeating: 0x81, count: 65) + Data([0x00])))
  }

  func testImpossibleDeclaredLengthsFailBeforeReceivingTheirBodies() throws {
    for header in [UInt8(0x5b), 0x7b, 0x9b, 0xbb] {
      XCTAssertThrowsError(try Cbor.valueLength(Data([header]) + Data(repeating: 0xff, count: 8)))
    }
    // A large integer is a value, not a length declaration.
    XCTAssertEqual(try Cbor.valueLength(Data([0x1b]) + Data(repeating: 0xff, count: 8)), 9)
  }
}
