import Foundation

// MARK: - Message Type Constants

/// Constants for message types used in the Runar network
public struct MessageTypes {
    /// Handshake message type
    public static let NODE_INFO_HANDSHAKE = "NODE_INFO_HANDSHAKE"
    
    /// Handshake response message type
    public static let NODE_INFO_HANDSHAKE_RESPONSE = "NODE_INFO_HANDSHAKE_RESPONSE"
    
    /// Node info update message type
    public static let NODE_INFO_UPDATE = "NODE_INFO_UPDATE"
    
    /// Request message type
    public static let REQUEST = "Request"
    
    /// Response message type
    public static let RESPONSE = "Response"
    
    /// Error message type
    public static let ERROR = "Error"
    
    /// Handshake message type
    public static let HANDSHAKE = "Handshake"
    
    /// Discovery message type
    public static let DISCOVERY = "Discovery"
    
    /// Announcement message type
    public static let ANNOUNCEMENT = "Announcement"
    
    /// Heartbeat message type
    public static let HEARTBEAT = "Heartbeat"
} 