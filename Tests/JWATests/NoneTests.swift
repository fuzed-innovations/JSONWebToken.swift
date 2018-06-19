import XCTest
import JWA


class NoneAlgorithmTests: XCTestCase {
    let message = "message".data(using: .utf8)!
    let signature = Data()
    
    static var allTests = [
        ("testName", testName),
        ("testSign", testSign),
        ("testVerify", testVerify)
    ]
    
    func testName() {
        let algorithm = NoneAlgorithm()
        XCTAssertEqual(algorithm.name, "none")
    }
    
    func testSign() {
        let algorithm = NoneAlgorithm()
        XCTAssertEqual(try! algorithm.sign(message), signature)
    }
    
    func testVerify() {
        let algorithm = NoneAlgorithm()
        XCTAssertTrue(try! algorithm.verify(message, signature: signature))
    }
}
