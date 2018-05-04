import Foundation
import CryptorRSA


extension RSAAlgorithm {
    var cryptorRSAAlgorithm: Data.Algorithm {
        switch self.hash {
        case .sha256:
            return .sha256
        case .sha384:
            return .sha384
        case .sha512:
            return .sha512
        }
    }
}

extension RSAAlgorithm: SignAlgorithm {
    public func sign(_ message: Data) throws -> Data {
        guard case .`private`(let keyData) = key else {
            throw RSAAlgorithm.SigningError.privateKeyRequiredToSign
        }
        
        guard #available(OSX 10.12, iOS 10.0, *) else {
            throw RSAAlgorithm.SigningError.unsupportedPlatform
        }
        
        let privateKey = try CryptorRSA.createPrivateKey(with: keyData)
        let plainText = CryptorRSA.createPlaintext(with: message)
        guard let signedData = try plainText.signed(with: privateKey, algorithm: cryptorRSAAlgorithm) else {
            throw RSAAlgorithm.SigningError.signingFailed
        }
        
        return signedData.data
    }
}

extension RSAAlgorithm: VerifyAlgorithm {
    public func verify(_ message: Data, signature: Data) throws -> Bool {
        switch key {
        case .`private`:
            return try sign(message) == signature
        case .`public`(let keyData):
            guard #available(OSX 10.12, iOS 10.0, *) else {
                throw RSAAlgorithm.SigningError.unsupportedPlatform
            }
            
            let publicKey = try CryptorRSA.createPublicKey(with: keyData)
            let plainText = CryptorRSA.createPlaintext(with: message)
            let signedData = CryptorRSA.createSigned(with: signature)
            return try plainText.verify(with: publicKey, signature: signedData, algorithm: cryptorRSAAlgorithm)
        }
    }
}
