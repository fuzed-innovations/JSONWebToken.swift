import Foundation
import JWA


/// Represents a JSON Web Algorithm (JWA)
/// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
public enum Algorithm: CustomStringConvertible {
  /// No Algorithm, i-e, insecure
  case none

  /// HMAC using SHA-256 hash algorithm
  case hs256(Data)

  /// HMAC using SHA-384 hash algorithm
  case hs384(Data)

  /// HMAC using SHA-512 hash algorithm
  case hs512(Data)
    
  /// RSASSA-PKCS1 using SHA-256 hash algorithm
  case rs256(RSAAlgorithm.Key)
    
  /// RSASSA-PKCS1 using SHA-384 hash algorithm
  case rs384(RSAAlgorithm.Key)
    
  /// RSASSA-PKCS1 using SHA-512 hash algorithm
  case rs512(RSAAlgorithm.Key)

  var algorithm: SignAlgorithm & VerifyAlgorithm {
    switch self {
    case .none:
      return NoneAlgorithm()
    case .hs256(let key):
      return HMACAlgorithm(key: key, hash: .sha256)
    case .hs384(let key):
      return HMACAlgorithm(key: key, hash: .sha384)
    case .hs512(let key):
      return HMACAlgorithm(key: key, hash: .sha512)
    case .rs256(let key):
        return RSAAlgorithm(key: key, hash: .sha256)
    case .rs384(let key):
        return RSAAlgorithm(key: key, hash: .sha384)
    case .rs512(let key):
        return RSAAlgorithm(key: key, hash: .sha512)
    }
  }

  public var description: String {
    return algorithm.name
  }
}
