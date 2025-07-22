import Foundation

// MARK: - Message Type Constants

/// Constants for message types used in the Runar network
/// Matches the Rust implementation with numeric constants
public struct MessageTypes {
    /// Discovery message type (1)
    public static let DISCOVERY = "1"
    
    /// Heartbeat message type (2)
    public static let HEARTBEAT = "2"
    
    /// Announcement message type (3)
    public static let ANNOUNCEMENT = "3"
    
    /// Handshake message type (4)
    public static let HANDSHAKE = "4"
    
    /// Request message type (5)
    public static let REQUEST = "5"
    
    /// Response message type (6)
    public static let RESPONSE = "6"
    
    /// Event message type (7)
    public static let EVENT = "7"
    
    /// Error message type (8)
    public static let ERROR = "8"
    
    /// Node info update message type (9)
    public static let NODE_INFO_UPDATE = "9"
    
    /// Node info handshake response message type (10)
    public static let NODE_INFO_HANDSHAKE_RESPONSE = "10"
    
    /// Node info handshake message type (4) - alias for HANDSHAKE
    public static let NODE_INFO_HANDSHAKE = "4"
} 