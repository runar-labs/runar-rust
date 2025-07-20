import Foundation
import CryptoKit

/// Utility functions for cryptographic operations
public struct CryptoUtils {
    
    /// Generate a compact identifier from public key bytes
    /// This matches the Rust implementation's compact_id function
    /// - Parameter publicKey: Public key bytes
    /// - Returns: Compact identifier string
    public static func compactId(_ publicKey: Data) -> String {
        // Create a hash of the public key
        let hash = SHA256.hash(data: publicKey)
        
        // Take the first 8 bytes and encode as base58
        let prefix = Data(hash.prefix(8))
        return base58Encode(prefix)
    }
    
    /// Convert CryptoKit P256.KeyAgreement.PrivateKey to ECDHKeyPair
    /// - Parameter key: Key agreement private key
    /// - Returns: ECDH key pair
    public static func convertToECDHKeyPair(_ key: P256.KeyAgreement.PrivateKey) -> ECDHKeyPair {
        return ECDHKeyPair(keyAgreementPrivateKey: key)
    }
    
    /// Convert CryptoKit P256.Signing.PrivateKey to ECDHKeyPair
    /// - Parameter key: Signing private key
    /// - Returns: ECDH key pair
    public static func convertToECDHKeyPair(_ key: P256.Signing.PrivateKey) throws -> ECDHKeyPair {
        let keyAgreementPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.rawRepresentation)
        return ECDHKeyPair(keyAgreementPrivateKey: keyAgreementPrivateKey)
    }
    
    /// Generate a random identifier
    /// - Parameter prefix: Prefix for the identifier
    /// - Returns: Random identifier string
    public static func generateRandomId(prefix: String = "id") -> String {
        let randomBytes = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let randomData = Data(randomBytes)
        let randomString = randomData.base64EncodedString()
            .replacingOccurrences(of: "+", with: "")
            .replacingOccurrences(of: "/", with: "")
            .replacingOccurrences(of: "=", with: "")
            .prefix(12)
        
        return "\(prefix)-\(randomString)"
    }
    
    /// Validate that a public key is a valid P-256 key
    /// - Parameter publicKey: Public key bytes
    /// - Returns: True if valid
    public static func isValidP256PublicKey(_ publicKey: Data) -> Bool {
        do {
            // Try compressed format first (64 bytes)
            if publicKey.count == 64 {
                _ = try P256.Signing.PublicKey(rawRepresentation: publicKey)
                return true
            }
            // Try uncompressed format (65 bytes)
            else if publicKey.count == 65 {
                _ = try P256.Signing.PublicKey(x963Representation: publicKey)
                return true
            }
            return false
        } catch {
            return false
        }
    }
    
    /// Validate that a private key is a valid P-256 key
    /// - Parameter privateKey: Private key bytes
    /// - Returns: True if valid
    public static func isValidP256PrivateKey(_ privateKey: Data) -> Bool {
        do {
            _ = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
            return true
        } catch {
            return false
        }
    }
    
    // MARK: - Private Helper Methods
    
    /// Simple base58 encoding (simplified implementation)
    /// - Parameter data: Data to encode
    /// - Returns: Base58 encoded string
    private static func base58Encode(_ data: Data) -> String {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bytes = [UInt8](data)
        var result = ""
        
        while bytes.count > 0 {
            var remainder = 0
            var newBytes: [UInt8] = []
            
            for byte in bytes {
                remainder = remainder * 256 + Int(byte)
                if remainder >= 58 {
                    newBytes.append(UInt8(remainder / 58))
                    remainder %= 58
                } else if !newBytes.isEmpty {
                    newBytes.append(0)
                }
            }
            
            result = String(alphabet[alphabet.index(alphabet.startIndex, offsetBy: remainder)]) + result
            bytes = newBytes
        }
        
        return result
    }
} 