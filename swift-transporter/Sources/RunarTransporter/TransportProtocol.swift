import Foundation
import os.log

/// Protocol defining the interface for transport implementations
/// Matches the Rust NetworkTransport trait functionality
@available(macOS 12.0, iOS 15.0, *)
public protocol TransportProtocol: AnyObject {
    /// Start the transport and begin listening for connections
    func start() async throws
    
    /// Stop the transport and clean up resources
    func stop() async
    
    /// Connect to a peer using discovery information
    func connect(to peerInfo: RunarPeerInfo) async throws
    
    /// Send a message to a peer
    func send(message: RunarNetworkMessage) async throws
    
    /// Check if connected to a specific peer
    func isConnected(to peerId: String) async -> Bool
    
    /// Get list of connected peers
    func getConnectedPeers() async -> [String]
}

/// Protocol for handling incoming messages and peer events
@available(macOS 12.0, iOS 15.0, *)
public protocol MessageHandlerProtocol: AnyObject {
    /// Handle an incoming network message
    func handleMessage(_ message: RunarNetworkMessage)
    
    /// Handle peer connection event
    func peerConnected(_ peerInfo: RunarNodeInfo)
    
    /// Handle peer disconnection event
    func peerDisconnected(_ peerId: String)
}

/// Default implementation for MessageHandlerProtocol
@available(macOS 12.0, iOS 15.0, *)
public class DefaultMessageHandler: MessageHandlerProtocol {
    private let logger: Logger
    
    public init(logger: Logger) {
        self.logger = logger
    }
    
    public func handleMessage(_ message: RunarNetworkMessage) {
        logger.info("📥 [DefaultMessageHandler] Received message - Type: \(message.messageType), From: \(message.sourceNodeId)")
    }
    
    public func peerConnected(_ peerInfo: RunarNodeInfo) {
        logger.info("🔗 [DefaultMessageHandler] Peer connected: \(peerInfo.nodeId)")
    }
    
    public func peerDisconnected(_ peerId: String) {
        logger.info("🔚 [DefaultMessageHandler] Peer disconnected: \(peerId)")
    }
} 