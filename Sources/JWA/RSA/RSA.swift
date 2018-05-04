import Foundation

final public class RSAAlgorithm: Algorithm {
    public let key: Key
    public let hash: Hash
    
    public enum SigningError: Error {
        case privateKeyRequiredToSign
        case unsupportedPlatform
        case signingFailed
    }
    
    public enum Key {
        case `private`(Data)
        case `public`(Data)
    }
    
    public enum Hash {
        case sha256
        case sha384
        case sha512
    }
    
    public init(key: Key, hash: Hash) {
        self.key = key
        self.hash = hash
    }
    
    public var name: String {
        switch hash {
        case .sha256:
            return "RS256"
        case .sha384:
            return "RS384"
        case .sha512:
            return "RS512"
        }
    }
}
