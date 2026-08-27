import Foundation
import XCTest

@testable import Bhwi

final class CborTests: XCTestCase {
  func testCompleteNestedValueAndTrailingBytes() throws {
    let value = Data([0xa1, 0x61, 0x69, 0x82, 0x01, 0x02])
    for length in 0..<value.count {
      XCTAssertFalse(try Cbor.isComplete(value.prefix(length)))
    }
    XCTAssertTrue(try Cbor.isComplete(value))
    XCTAssertTrue(try Cbor.isComplete(value + Data([0xff])))
  }

  func testIndefiniteContainers() throws {
    XCTAssertTrue(try Cbor.isComplete(Data([0x9f, 0x01, 0x02, 0xff])))
    XCTAssertTrue(try Cbor.isComplete(Data([0x7f, 0x62, 0x68, 0x69, 0xff])))
  }

  func testMalformedValueFailsWithoutReadingMore() {
    XCTAssertThrowsError(try Cbor.isComplete(Data([0x1c])))
    XCTAssertThrowsError(try Cbor.isComplete(Data([0x7f, 0x5f])))
  }
}
