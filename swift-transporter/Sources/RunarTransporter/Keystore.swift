import Foundation
import Crypto

// MARK: - Encryption Protocols

/// Protocol for envelope encryption operations
/// Matches the Rust EnvelopeCrypto trait
@available(macOS 12.0, iOS 15.0, *)
public protocol EnvelopeCrypto: AnyObject {
    /// Encrypt data with envelope encryption
    func encrypt(data: Data, label: String) throws -> Data
    
    /// Decrypt data with envelope encryption
    func decrypt(data: Data, label: String) throws -> Data
    
    /// Get the node ID associated with this keystore
    var nodeId: String { get }
}

/// Protocol for label resolution
/// Matches the Rust LabelResolver trait
@available(macOS 12.0, iOS 15.0, *)
public protocol LabelResolver: AnyObject {
    /// Resolve a label to encryption parameters
    func resolveLabel(_ label: String, networkId: String, profileId: String) throws -> LabelResolution
    
    /// Get available labels for a network and profile
    func getAvailableLabels(networkId: String, profileId: String) throws -> [String]
}

/// Result of label resolution
@available(macOS 12.0, iOS 15.0, *)
public struct LabelResolution {
    public let label: String
    public let encryptionKey: Data
    public let algorithm: String
    public let metadata: [String: String]
    
    public init(label: String, encryptionKey: Data, algorithm: String, metadata: [String: String] = [:]) {
        self.label = label
        self.encryptionKey = encryptionKey
        self.algorithm = algorithm
        self.metadata = metadata
    }
}

// MARK: - Default Implementations

/// Default keystore implementation using CryptoKit
@available(macOS 12.0, iOS 15.0, *)
public class DefaultKeystore: EnvelopeCrypto {
    private let nodePublicKey: Data
    private let privateKey: P256.KeyAgreement.PrivateKey
    
    public var nodeId: String {
        return NodeUtils.compactId(from: nodePublicKey)
    }
    
    public init(nodePublicKey: Data, privateKey: P256.KeyAgreement.PrivateKey) {
        self.nodePublicKey = nodePublicKey
        self.privateKey = privateKey
    }
    
    public func encrypt(data: Data, label: String) throws -> Data {
        // Simple AES encryption for now
        // TODO: Implement proper envelope encryption
        let key = SymmetricKey(size: .bits256)
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined ?? Data()
    }
    
    public func decrypt(data: Data, label: String) throws -> Data {
        // Simple AES decryption for now
        // TODO: Implement proper envelope decryption
        let key = SymmetricKey(size: .bits256)
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
}

/// Default label resolver implementation
@available(macOS 12.0, iOS 15.0, *)
public class DefaultLabelResolver: LabelResolver {
    private let labelMappings: [String: LabelResolution]
    
    public init(labelMappings: [String: LabelResolution] = [:]) {
        self.labelMappings = labelMappings
    }
    
    public func resolveLabel(_ label: String, networkId: String, profileId: String) throws -> LabelResolution {
        let fullLabel = "\(networkId):\(profileId):\(label)"
        guard let resolution = labelMappings[fullLabel] else {
            throw RunarTransportError.configurationError("Label not found: \(fullLabel)")
        }
        return resolution
    }
    
    public func getAvailableLabels(networkId: String, profileId: String) throws -> [String] {
        let prefix = "\(networkId):\(profileId):"
        return labelMappings.keys.compactMap { key in
            key.hasPrefix(prefix) ? String(key.dropFirst(prefix.count)) : nil
        }
    }
} 