import Foundation


final public class RSAAlgorithm: Algorithm {
    
    public typealias PEMString = String
    
    public let key: Key
    public let hash: Hash
    
    public enum SigningError: Error {
        
        /// Attempting to use a public key to sign
        case privateKeyRequiredToSign
        
        /// Attempting to sign on an unsupported device platform
        case unsupportedPlatform
        
        /// Generic error when signing fails
        case signingFailed
    }
    
    public enum Key {
        case `private`(PEMString)
        case `public`(PEMString)
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
