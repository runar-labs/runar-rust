import Foundation
import Crypto

// MARK: - Core Models

/// Represents a node in the Runar network
/// Matches the Rust NodeInfo structure
public struct RunarNodeInfo: Codable, Equatable, Hashable {
    /// Public key of the node
    public let nodePublicKey: Data
    
    /// Network IDs this node participates in
    public let networkIds: [String]
    
    /// Network addresses where this node can be reached
    public let addresses: [String]
    
    /// Services/capabilities provided by this node
    public let services: [ServiceMetadata]
    
    /// Version number for tracking updates
    public let version: Int64
    
    /// Timestamp when this node info was created
    public let createdAt: Date
    
    public init(
        nodePublicKey: Data,
        networkIds: [String] = [],
        addresses: [String] = [],
        services: [ServiceMetadata] = [],
        version: Int64 = 0,
        createdAt: Date = Date()
    ) {
        self.nodePublicKey = nodePublicKey
        self.networkIds = networkIds
        self.addresses = addresses
        self.services = services
        self.version = version
        self.createdAt = createdAt
    }
    
    /// Get the node ID (derived from public key)
    public var nodeId: String {
        return NodeUtils.compactId(from: nodePublicKey)
    }
}

/// Represents information about a peer discovered on the network
/// Matches the Rust PeerInfo structure
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
    
    /// Get the peer ID (derived from public key)
    public var peerId: String {
        return NodeUtils.compactId(from: publicKey)
    }
}

/// Represents a network message sent between nodes
/// Matches the Rust NetworkMessage structure
public struct RunarNetworkMessage: Codable, Equatable {
    /// ID of the source node
    public let sourceNodeId: String
    
    /// ID of the destination node
    public let destinationNodeId: String
    
    /// Type of the message (e.g., "Request", "Response", "Handshake")
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
/// Matches the Rust NetworkMessagePayloadItem structure
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

/// Service metadata for node capabilities
/// Matches the Rust ServiceMetadata structure
public struct ServiceMetadata: Codable, Equatable, Hashable {
    /// Service path/identifier
    public let servicePath: String
    
    /// Network ID this service belongs to
    public let networkId: String
    
    /// Service name
    public let serviceName: String
    
    /// Service description
    public let description: String
    
    /// Actions provided by this service
    public let actions: [ActionMetadata]
    
    /// Events published by this service
    public let events: [EventMetadata]
    
    public init(
        servicePath: String,
        networkId: String,
        serviceName: String,
        description: String = "",
        actions: [ActionMetadata] = [],
        events: [EventMetadata] = []
    ) {
        self.servicePath = servicePath
        self.networkId = networkId
        self.serviceName = serviceName
        self.description = description
        self.actions = actions
        self.events = events
    }
}

/// Action metadata for service capabilities
/// Matches the Rust ActionMetadata structure
public struct ActionMetadata: Codable, Equatable, Hashable {
    /// Action path/identifier
    public let actionPath: String
    
    /// Action name
    public let actionName: String
    
    /// Action description
    public let description: String
    
    /// Input schema for the action
    public let inputSchema: String?
    
    /// Output schema for the action
    public let outputSchema: String?
    
    public init(
        actionPath: String,
        actionName: String,
        description: String = "",
        inputSchema: String? = nil,
        outputSchema: String? = nil
    ) {
        self.actionPath = actionPath
        self.actionName = actionName
        self.description = description
        self.inputSchema = inputSchema
        self.outputSchema = outputSchema
    }
}

/// Event metadata for service capabilities
/// Matches the Rust EventMetadata structure
public struct EventMetadata: Codable, Equatable, Hashable {
    /// Event path/identifier
    public let path: String
    
    /// Event description
    public let description: String
    
    /// Data schema for the event
    public let dataSchema: String?
    
    public init(
        path: String,
        description: String = "",
        dataSchema: String? = nil
    ) {
        self.path = path
        self.description = description
        self.dataSchema = dataSchema
    }
}

// MARK: - Error Types

/// Errors that can occur in the transport layer
/// Matches the Rust NetworkError structure
public enum RunarTransportError: Error, LocalizedError {
    case configurationError(String)
    case connectionError(String)
    case messageError(String)
    case transportError(String)
    case serializationError(String)
    case timeoutError(String)
    case certificateError(String)
    case peerNotConnected(String)
    
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
        case .peerNotConnected(let peerId):
            return "Peer not connected: \(peerId)"
        }
    }
}

// MARK: - Utilities

/// Utility functions for working with node IDs and keys
public struct NodeUtils {
    /// Generate a compact node ID from a public key
    /// Matches the Rust compact_id function
    public static func compactId(from publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate a correlation ID for request-response matching
    public static func generateCorrelationId() -> String {
        return UUID().uuidString
    }
    
    /// Generate a correlation ID with prefix
    public static func generateCorrelationId(withPrefix prefix: String) -> String {
        return "\(prefix)-\(UUID().uuidString)"
    }
} 