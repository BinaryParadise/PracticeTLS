import XCTest
import class Foundation.Bundle
@testable import PracticeTLS

final class TLSHandshakeMessageTests: XCTestCase {
    
    func testStream() throws {
        var stream = DataStream([9,1,2,3,4,5])
        XCTAssertEqual(stream.readByte(), 9)
        XCTAssertEqual(stream.read(count: 3), [1,2,3])
        XCTAssertEqual(stream.read(count: 2), [4,5])
        XCTAssertEqual(stream.read(count: 10), nil)
        XCTAssertEqual(stream.position, 0)
    }
}
