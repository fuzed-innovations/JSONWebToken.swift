import XCTest

@testable import JWATests
@testable import JWTTests

//@testable import HMACATests
//@testable import NoneAlgorithmTests
//@testable import RSATests
//
//@testable import ClaimSetTests
//@testable import CompactJSONDecoderTests
//@testable import CompactJSONEncoderTests
//@testable import IntegrationTests
//@testable import JWTDecodeTests
//@testable import JWTEncodeTests
//@testable import PayloadTests

XCTMain([
    testCase(HMACAlgorithmTests.allTests),
    testCase(NoneAlgorithmTests.allTests),
    testCase(RSAAlgorithmTests.allTests),
    testCase(ValidationTests.allTests),
    testCase(CompactJSONDecoderTests.allTests),
    testCase(CompactJSONEncoderTests.allTests),
    testCase(IntegrationTests.allTests),
    testCase(DecodeTests.allTests),
    testCase(JWTEncodeTests.allTests),
    testCase(PayloadTests.allTests)
])
