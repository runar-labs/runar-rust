import Foundation
import CryptoKit
import Security

// MARK: - Error Types

/// Cryptographic key and certificate errors
public enum KeyError: Error, LocalizedError {
    case invalidKeyFormat(String)
    case certificateError(String)
    case certificateNotFound(String)
    case encryptionError(String)
    case decryptionError(String)
    case keyDerivationError(String)
    case keyNotFound(String)
    case keyAlreadyInitialized(String)
    case signingError(String)
    case validationError(String)
    case invalidOperation(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeyFormat(let message):
            return "Invalid key format: \(message)"
        case .certificateError(let message):
            return "Certificate error: \(message)"
        case .certificateNotFound(let message):
            return "Certificate not found: \(message)"
        case .encryptionError(let message):
            return "Encryption error: \(message)"
        case .decryptionError(let message):
            return "Decryption error: \(message)"
        case .keyDerivationError(let message):
            return "Key derivation error: \(message)"
        case .keyNotFound(let message):
            return "Key not found: \(message)"
        case .keyAlreadyInitialized(let message):
            return "Key already initialized: \(message)"
        case .signingError(let message):
            return "Signing error: \(message)"
        case .validationError(let message):
            return "Validation error: \(message)"
        case .invalidOperation(let message):
            return "Invalid operation: \(message)"
        }
    }
}

/// ECDH Key Pair using P-256 curve
/// This is the primary key type for all cryptographic operations
/// ECDH keys can perform both key agreement (ECIES) and signing (ECDSA) operations
public struct ECDHKeyPair: Sendable {
    /// The primary ECDH private key for key agreement operations
    private let keyAgreementPrivateKey: P256.KeyAgreement.PrivateKey
    
    /// The corresponding public key
    public let publicKey: P256.KeyAgreement.PublicKey
    
    /// Initialize with a new random key pair
    public init() throws {
        self.keyAgreementPrivateKey = P256.KeyAgreement.PrivateKey()
        self.publicKey = keyAgreementPrivateKey.publicKey
    }
    
    /// Initialize from existing ECDH private key
    public init(keyAgreementPrivateKey: P256.KeyAgreement.PrivateKey) {
        self.keyAgreementPrivateKey = keyAgreementPrivateKey
        self.publicKey = keyAgreementPrivateKey.publicKey
    }
    
    /// Initialize from raw bytes (32-byte scalar)
    public init(rawRepresentation: Data) throws {
        self.keyAgreementPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        self.publicKey = keyAgreementPrivateKey.publicKey
    }
    
    /// Get the raw scalar bytes (32 bytes)
    public func rawScalarBytes() -> Data {
        return keyAgreementPrivateKey.rawRepresentation
    }
    
    /// Get public key as raw bytes (uncompressed point)
    public func publicKeyBytes() -> Data {
        return publicKey.x963Representation
    }
    
    /// Convert to ECDSA signing key for certificate operations
    public func toECDSASigningKey() throws -> P256.Signing.PrivateKey {
        return try P256.Signing.PrivateKey(rawRepresentation: keyAgreementPrivateKey.rawRepresentation)
    }
    
    /// Convert to ECDSA verifying key for certificate operations
    public func toECDSAVerifyingKey() throws -> P256.Signing.PublicKey {
        return try P256.Signing.PublicKey(rawRepresentation: publicKey.rawRepresentation)
    }
    
    /// Sign data using ECDSA (converts to signing key internally)
    public func sign(data: Data) throws -> Data {
        let signingKey = try toECDSASigningKey()
        let signature = try signingKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    /// Verify signature using ECDSA (converts to verifying key internally)
    public func verify(signature: Data, for data: Data) throws -> Bool {
        let verifyingKey = try toECDSAVerifyingKey()
        let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return verifyingKey.isValidSignature(ecdsaSignature, for: data)
    }
    
    /// Perform ECDH key agreement with another public key
    public func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        return try keyAgreementPrivateKey.sharedSecretFromKeyAgreement(with: publicKey)
    }
    
    /// Static ECIES encryption using recipient's public key (no private key needed)
    public static func encryptECIES(data: Data, recipientPublicKey: Data) throws -> Data {
        // Generate ephemeral key pair for ECDH
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        
        // Convert recipient's public key bytes to KeyAgreement.PublicKey
        // The recipientPublicKey should be in uncompressed SEC1 format (65 bytes)
        let recipientKey = try P256.KeyAgreement.PublicKey(x963Representation: recipientPublicKey)
        
        // Perform ECDH key exchange
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientKey)
        let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }
        
        // Derive encryption key using HKDF
        let encryptionKey = try deriveKey(from: sharedSecretBytes, info: "runar-key-encryption")
        
        // Encrypt the data using AES-GCM
        let encryptedData = try encryptWithSymmetricKey(data, encryptionKey)
        
        // Return ephemeral public key + encrypted data
        let ephemeralPublicBytes = ephemeralPublicKey.x963Representation
        var result = ephemeralPublicBytes
        result.append(encryptedData)
        
        return result
    }
    
    /// Encrypt data using ECIES with recipient's public key
    public func encryptECIES(data: Data, recipientPublicKey: Data) throws -> Data {
        return try ECDHKeyPair.encryptECIES(data: data, recipientPublicKey: recipientPublicKey)
    }
    
    /// Decrypt data using ECIES with our private key
    public func decryptECIES(encryptedData: Data) throws -> Data {
        // Extract ephemeral public key (65 bytes uncompressed) and encrypted data
        guard encryptedData.count >= 65 else {
            throw KeyError.decryptionError("Encrypted data too short for ECIES")
        }
        
        let ephemeralPublicBytes = encryptedData.prefix(65)
        let encryptedPayload = encryptedData.dropFirst(65)
        
        // Reconstruct ephemeral public key
        // The ephemeral public key is stored in uncompressed format (65 bytes)
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicBytes)
        
        // Perform ECDH key exchange using our private key
        let sharedSecret = try keyAgreementPrivateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }
        
        // Derive encryption key using HKDF
        let encryptionKey = try ECDHKeyPair.deriveKey(from: sharedSecretBytes, info: "runar-key-encryption")
        
        // Decrypt the data using AES-GCM
        return try ECDHKeyPair.decryptWithSymmetricKey(encryptedPayload, encryptionKey)
    }
    
    /// Derive key using HKDF
    private static func deriveKey(from sharedSecret: Data, info: String) throws -> Data {
        let infoData = info.data(using: .utf8)!
        let salt = Data() // Empty salt for HKDF
        
        let sharedSecretKey = SymmetricKey(data: sharedSecret)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecretKey,
            salt: salt,
            info: infoData,
            outputByteCount: 32
        )
        
        return Data(derivedKey.withUnsafeBytes { $0 })
    }
    
    /// Encrypt data using AES-256-GCM
    private static func encryptWithSymmetricKey(_ data: Data, _ key: Data) throws -> Data {
        guard key.count == 32 else {
            throw KeyError.encryptionError("Key must be 32 bytes for AES-256")
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        return sealedBox.combined!
    }
    
    /// Decrypt data using AES-256-GCM
    private static func decryptWithSymmetricKey(_ encryptedData: Data, _ key: Data) throws -> Data {
        guard key.count == 32 else {
            throw KeyError.decryptionError("Key must be 32 bytes for AES-256")
        }
        
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        let symmetricKey = SymmetricKey(data: key)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
}

// MARK: - Codable Support

extension ECDHKeyPair {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let privateKeyData = try container.decode(Data.self)
        
        let keyAgreementPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        self.init(keyAgreementPrivateKey: keyAgreementPrivateKey)
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(keyAgreementPrivateKey.rawRepresentation)
    }
} 