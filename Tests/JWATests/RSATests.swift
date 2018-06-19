import Foundation
import XCTest
import JWA


class RSAAlgorithmTests: XCTestCase {
    let publicKeyString = """
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBxKkiUejCt3bfeS+SsEgwG
cshdhrp69wQKrpYcEAIa1gN9rxwgW6vBo0R7b386cxRVOEBzdp03CpKe8D3kXB2j
47f0/g8wU6pccHlVSxlqTpjsMTpal1z30b0uf00ZirXJYxFPo8AXvaqQNXKfuSIg
En5b5VLTC0CsakhKiha2tj/xFVRUj+/PUPY4iTrUztMXZi4VrLRpOiIrOUEabtvh
LdG7d5nxsL6YPuvr2QlFTB/ahnudAfpc+hNSx47pOkoeAtCaIV4SCN8FIh19pTxk
wbQHuactZ6qcGnKL8eSlA/ktegwENBNU8JRP7Jic8DVDcaujdUnqgYbRQB8Q6UJD
AgMBAAE=
"""
    lazy var publicKey: RSAAlgorithm.Key = {
        let publicKeyData = Data(base64Encoded: publicKeyString.components(separatedBy: "\n").joined())!
        return RSAAlgorithm.Key.`public`(publicKeyData)
    }()
    
    let privateKeyString = """
MIIEogIBAAKCAQBxKkiUejCt3bfeS+SsEgwGcshdhrp69wQKrpYcEAIa1gN9rxwg
W6vBo0R7b386cxRVOEBzdp03CpKe8D3kXB2j47f0/g8wU6pccHlVSxlqTpjsMTpa
l1z30b0uf00ZirXJYxFPo8AXvaqQNXKfuSIgEn5b5VLTC0CsakhKiha2tj/xFVRU
j+/PUPY4iTrUztMXZi4VrLRpOiIrOUEabtvhLdG7d5nxsL6YPuvr2QlFTB/ahnud
Afpc+hNSx47pOkoeAtCaIV4SCN8FIh19pTxkwbQHuactZ6qcGnKL8eSlA/ktegwE
NBNU8JRP7Jic8DVDcaujdUnqgYbRQB8Q6UJDAgMBAAECggEAbNE3B6dTpeydAOJD
mn6kF5NKPjzulo1u0oK9D3EJRRrkMngu+KKNz16a3IMDeYXtWGEGAMFfPe0pvjHP
ogY97jlry+Z9XoAlQkxZL/5OCx5XCE/yB+ii2h5R5yM8VUI/uc5MeCNC9NFJ8O+k
MBiKywJdhSpH8W5Rmzl8GEkevEPOc5YOZQh3YvUZv7r986vO+zcfyhY6mJ9fyuHC
jJc6r8QfG0OwuiH4tQJ3Qd4r9T0c8EmM6WxFm0gduJ7hrMhjhwyJEwhfO3HD6sww
0WMdZ3SvbjxAdEP+76JIcWxxm2dHqe//3zU1ulsXiN4dVNceIA+9L0eZ6MKMyO14
XCC4gQKBgQCqkk/l2tXr8sFWD2DC4lOuhV7vG3TPmFYI6g1YGao5VBtdFotit1PS
oq2znaUXKBMbES73LhvqBr2f4nIQVU0I8DDgkzYF3nPK7MH7kz4Dv/NcL0M8FzxN
X0XcZ034kY3WGHsgFFRwvPSM728J7V/za+IB+byfZCxAmBksQfqkAwKBgQCp16mH
JTEAUUrYMkVS+UtfO8gpvTDZ45sidF6+XjrFzrgXTc/ySsJvMeY75jP8sdcperTi
Nv0shtiqV2bA+hnEhcF15ponra+bkczgenF+3rN61pdWC8fEz4jDk6NenLz1VPYs
Go40BDhi7KC+cSYlmKtymU+HoejzpcnOweE0wQKBgQCT1FCYtouWfYLgMl27KWo7
I+3+Lv6S+MT/3tGH3F5yZxl8GRDekmJ8eG8w71zob9v3JnJc2cJplkP78MbIrxUf
vQOvbwZwGbajVYRdo+QoXdDtwSx1RPIHYJ3sgj/KQWP6/KahS91PBASyrMTAhtEU
6BgtfCLkxW2w4eFXQSuXvwKBgG1kVXGRN81vjphPUK1Pmgc9tv+DNoqweYQolblh
cdNkANgpqwzwr+j0p8jezY8tcFrsCMNHDav3MmgMoUccDyqvx9pLa/CwgtHdh6rx
0lYX1FwDCThHoCSYUws89VWD+IS/c0sW046XRUYaCLKAqERA3/SQ4FOIqkT7/E5q
O8ZBAoGAchNDtJtOkJjfD4Lg9xCi+RJ5PERcilm70MiOOa+s/vyokxtrkfZQCQtF
NeWwl+nOxEjbI+awk9sftCMrUe6GITZzcGHnWOUd3uWRh0kpPtYTuxbPKMY8M9JM
ZZYFD6pdaMvX9Ozin3/OInHPJk3bKxFYblUdY3bsAYrgDNhQtSg=
"""
    lazy var privateKey: RSAAlgorithm.Key = {
        let privateKeyData = Data(base64Encoded: privateKeyString.components(separatedBy: "\n").joined())!
        return RSAAlgorithm.Key.`private`(privateKeyData)
    }()
    
    let message = "message".data(using: .utf8)!
    let sha256Signature = Data(base64Encoded: "Oif5Awv+1/8Fb68odKlScRt5d5c8f+owSlgdo+6i8POgoDjQFHa5dNWkfSSRmdY4e97nx0GJk4Rvo54hhIT14hzkurCmT6Lt6ak9MDepQ8MUhC9gOWRBATNKhiPcvkro7qL5wO3KbwYaWy8gOFr6NZn0TqoWRUebIz9JFwCt2jL2X6rA7Rydgdm0l6snjOAMZXcRmbRC2Imo9goUbvz6ooQZ33rdYPOitDxCVyCEDXpBiA/xZCOsSRiQR8BbAaEuL3tF9GY9t7KtEXquT/dyluU6p3y1+ExUXPv06PfrhbXXp/vWpeXljXb7lCC6kHeHKoVyYmbbvaWmLvsjGiKhZw==")!
    let sha384Signature = Data(base64Encoded: "VW/XRY0+1BWXwIjYyf2A0NzwuN8zYEZdhEU2qpc91lt/cZ8TFPJ9F6DlDZyCZM14sMK1vSkoErsXD8N6Lfh/7wNVA0J128uH/xLOUXG2l3Dh7UgwyXm5Kcm+3QuJPimld4NJTo8FPYRl9pAN2MeJkUWTrmFR58/AmjvhV7fRan5L3iykxMv2Qg4R6r5HSYP/rumpG8pxv7ZZgUzQWd5F4DwGlkjKg5P4Bj9kxAm5OUVlJF1Wx/Wfimzs16+0OtXcjslGfH9NYfKxDrCldfrhjlUTfVXa6ZAc+D/0ZpiF3oA8oAsN9ocaD58PzXq4Rt6Q2orapRTHeUEhPDfacAWJgw==")!
    let sha512Signature = Data(base64Encoded: "R7NFfTLvZKUvu1lclmmwdL1QD2Ea8JWVxdmid6i0pzUM2Ips/XvLFFFEr+lIBQN/jBNI4b0vYw686D9H/vqux+FQJWX15cZlZlAdvfUJay/VSNYUJZH3YJtzfRmMGwifTKtJRztN/jhHiebx04SwuY3Qn1zcDSMkcHowCa7L/4ryh44Do42aO/IJArBdwaQs5wJ6BcJ5d7LexmTp7ceGwzHGQl5xEaFmoHeDTr1CLa9dIci/j47QmBZ9iOJsmYVETZNomLwj/5pioyBBprMBsCT+GCfZA1Ro1u/OmDS1lCFmSyQ6JEzx2emiKxJDLEl7YAAklJi+rZbq9/9JL2BW7g==")!
    
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
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha256)
        XCTAssertEqual(algorithmPublic.name, "RS256")
        
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha256)
        XCTAssertEqual(algorithmPrivate.name, "RS256")
    }
    
    func testSHA384Name() {
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha384)
        XCTAssertEqual(algorithmPublic.name, "RS384")
        
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha384)
        XCTAssertEqual(algorithmPrivate.name, "RS384")
    }
    
    func testSHA512Name() {
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha512)
        XCTAssertEqual(algorithmPublic.name, "RS512")
        
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha512)
        XCTAssertEqual(algorithmPrivate.name, "RS512")
    }
    
    // MARK: Signing
    
    func testSHA256Sign() {
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha256)
        XCTAssertEqual(try! algorithmPrivate.sign(message), sha256Signature)
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha256)
        XCTAssertThrowsError(try algorithmPublic.sign(message)) { error in
            XCTAssertEqual(error as? RSAAlgorithm.SigningError, RSAAlgorithm.SigningError.privateKeyRequiredToSign)
        }
    }
    
    func testSHA384Sign() {
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha384)
        XCTAssertEqual(try! algorithmPrivate.sign(message), sha384Signature)
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha384)
        XCTAssertThrowsError(try algorithmPublic.sign(message)) { error in
            XCTAssertEqual(error as? RSAAlgorithm.SigningError, RSAAlgorithm.SigningError.privateKeyRequiredToSign)
        }
    }
    
    func testSHA512Sign() {
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha512)
        XCTAssertEqual(try! algorithmPrivate.sign(message), sha512Signature)
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha512)
        XCTAssertThrowsError(try algorithmPublic.sign(message)) { error in
            XCTAssertEqual(error as? RSAAlgorithm.SigningError, RSAAlgorithm.SigningError.privateKeyRequiredToSign)
        }
    }
    
    // MARK: Verify
    
    func testSHA256Verify() {
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha256)
        XCTAssertTrue(try! algorithmPrivate.verify(message, signature: sha256Signature))
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha256)
        XCTAssertTrue(try! algorithmPublic.verify(message, signature: sha256Signature))
    }
    
    func testSHA384Verify() {
        
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha384)
        XCTAssertTrue(try! algorithmPrivate.verify(message, signature: sha384Signature))
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha384)
        XCTAssertTrue(try! algorithmPublic.verify(message, signature: sha384Signature))
    }
    
    func testSHA512Verify() {
        let algorithmPrivate = RSAAlgorithm(key: privateKey, hash: .sha512)
        XCTAssertTrue(try! algorithmPrivate.verify(message, signature: sha512Signature))
        
        let algorithmPublic = RSAAlgorithm(key: publicKey, hash: .sha512)
        XCTAssertTrue(try! algorithmPublic.verify(message, signature: sha512Signature))
    }
}
