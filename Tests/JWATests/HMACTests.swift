import Foundation
import XCTest
import JWA


class HMACAlgorithmTests: XCTestCase {
  let key = "secret".data(using: .utf8)!
  let message = "message".data(using: .utf8)!
  let sha256Signature = Data(base64Encoded: "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=")!
  let sha384Signature = Data(base64Encoded: "rQ706A2kJ7KjPURXyXK/dZ9Qdm+7ZlaQ1Qt8s43VIX21Wck+p8vuSOKuGltKr9NL")!
  let sha512Signature = Data(base64Encoded: "G7pYfHMO7box9Tq7C2ylieCd5OiU7kVeYUCAc5l1mtqvoGnux8AWR7sXPcsX9V0ir0mhgHG3SMXC7df3qCnGMg==")!
    
    static var allTests = [
        ("testSHA256Name", testSHA256Name),
        ("testSHA384Name", testSHA384Name),
        ("testSHA512Name", testSHA512Name),
        ("testSHA256Sign", testSHA256Sign),
        ("testSHA384Sign", testSHA384Sign),
        ("testSHA512Sign", testSHA512Sign),
        ("testSHA256Verify", testSHA256Verify),
        ("testSHA384Verify", testSHA384Verify),
        ("testSHA512Verify", testSHA512Verify)
    ]

  // MARK: Name

  func testSHA256Name() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha256)
    XCTAssertEqual(algorithm.name, "HS256")
  }

  func testSHA384Name() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha384)
    XCTAssertEqual(algorithm.name, "HS384")
  }

  func testSHA512Name() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha512)
    XCTAssertEqual(algorithm.name, "HS512")
  }

  // MARK: Signing

  func testSHA256Sign() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha256)
    XCTAssertEqual(try! algorithm.sign(message), sha256Signature)
  }

  func testSHA384Sign() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha384)
    XCTAssertEqual(try! algorithm.sign(message), sha384Signature)
  }

  func testSHA512Sign() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha512)
    XCTAssertEqual(try! algorithm.sign(message), sha512Signature)
  }

  // MARK: Verify

  func testSHA256Verify() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha256)
    XCTAssertTrue(try! algorithm.verify(message, signature: sha256Signature))
  }

  func testSHA384Verify() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha384)
    XCTAssertTrue(try! algorithm.verify(message, signature: sha384Signature))
  }

  func testSHA512Verify() {
    let algorithm = HMACAlgorithm(key: key, hash: .sha512)
    XCTAssertTrue(try! algorithm.verify(message, signature: sha512Signature))
  }
}
