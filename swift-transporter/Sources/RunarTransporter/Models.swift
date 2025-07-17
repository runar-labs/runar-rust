import Foundation
import Crypto

// MARK: - Core Models

/// Represents a node in the Runar network
public struct RunarNodeInfo: Codable, Equatable, Hashable {
    /// Unique identifier for the node (derived from public key)
    public let nodeId: String
    
    /// Public key of the node
    public let nodePublicKey: Data
    
    /// Human-readable name for the node
    public let nodeName: String
    
    /// Network addresses where this node can be reached
    public let addresses: [String]
    
    /// Additional metadata about the node
    public let metadata: [String: String]
    
    /// Timestamp when this node info was created
    public let createdAt: Date
    
    public init(
        nodeId: String,
        nodePublicKey: Data,
        nodeName: String,
        addresses: [String] = [],
        metadata: [String: String] = [:],
        createdAt: Date = Date()
    ) {
        self.nodeId = nodeId
        self.nodePublicKey = nodePublicKey
        self.nodeName = nodeName
        self.addresses = addresses
        self.metadata = metadata
        self.createdAt = createdAt
    }
}

/// Represents information about a peer discovered on the network
public struct RunarPeerInfo: Codable, Equatable, Hashable {
    /// Public key of the peer
    public let publicKey: Data
    
    /// Network addresses where this peer can be reached
    public let addresses: [String]
    
    /// Human-readable name for the peer
    public let name: String
    
    /// Additional metadata about the peer
    public let metadata: [String: String]
    
    public init(
        publicKey: Data,
        addresses: [String],
        name: String = "",
        metadata: [String: String] = [:]
    ) {
        self.publicKey = publicKey
        self.addresses = addresses
        self.name = name
        self.metadata = metadata
    }
}

/// Represents a network message sent between nodes
public struct RunarNetworkMessage: Codable, Equatable {
    /// ID of the source node
    public let sourceNodeId: String
    
    /// ID of the destination node
    public let destinationNodeId: String
    
    /// Type of the message (e.g., "Request",Response", "Handshake")
    public let messageType: String
    
    /// Payload items contained in the message
    public let payloads: [NetworkMessagePayloadItem]
    
    /// Timestamp when the message was created
    public let timestamp: Date
    
    public init(
        sourceNodeId: String,
        destinationNodeId: String,
        messageType: String,
        payloads: [NetworkMessagePayloadItem] = [],
        timestamp: Date = Date()
    ) {
        self.sourceNodeId = sourceNodeId
        self.destinationNodeId = destinationNodeId
        self.messageType = messageType
        self.payloads = payloads
        self.timestamp = timestamp
    }
}

/// Represents a single payload item in a network message
public struct NetworkMessagePayloadItem: Codable, Equatable {
    /// Path identifier for the payload
    public let path: String
    
    /// Binary data of the payload
    public let valueBytes: Data
    
    /// Correlation ID for request-response matching
    public let correlationId: String
    
    public init(
        path: String,
        valueBytes: Data,
        correlationId: String
    ) {
        self.path = path
        self.valueBytes = valueBytes
        self.correlationId = correlationId
    }
}

// MARK: - Error Types

/// Errors that can occur in the transport layer
public enum RunarTransportError: Error, LocalizedError {
    case configurationError(String)
    case connectionError(String)
    case messageError(String)
    case transportError(String)
    case serializationError(String)
    case timeoutError(String)
    case certificateError(String)
    
    public var errorDescription: String? {
        switch self {
        case .configurationError(let message):
            return "Configuration error: \(message)"
        case .connectionError(let message):
            return "Connection error: \(message)"
        case .messageError(let message):
            return "Message error: \(message)"
        case .transportError(let message):
            return "Transport error: \(message)"
        case .serializationError(let message):
            return "Serialization error: \(message)"
        case .timeoutError(let message):
            return "Timeout error: \(message)"
        case .certificateError(let message):
            return "Certificate error: \(message)"
        }
    }
}

// MARK: - Utilities

/// Utility functions for working with node IDs and keys
public struct NodeUtils {
    /// Generate a compact node ID from a public key
    public static func compactId(from publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate a correlation ID for request-response matching
    public static func generateCorrelationId() -> String {
        return UUID().uuidString
    }
} 