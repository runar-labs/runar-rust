import Foundation
import Logging
import AsyncAlgorithms

// MARK: - Main RunarTransporter Factory

/// Main factory for creating QUIC transport instances
/// Provides a unified interface for QUIC transport protocol
@available(macOS 10.15, iOS 13.0, *)
public struct RunarTransporter {
    /// Create a QUIC transport instance using Network.framework (Apple) or NIO (Linux)
    ///
    /// - Parameters:
    ///   - nodeInfo: Node information including ID, public key, and capabilities
    ///   - bindAddress: Address to bind to (e.g., "127.0.0.1:8080")
    ///   - messageHandler: Handler for incoming messages
    ///   - options: Transport-specific options
    ///   - logger: Logger instance for transport logging
    /// - Returns: A transport protocol instance
    public static func createQuicTransport(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        options: NetworkQuicTransportOptions,
        logger: Logger
    ) -> TransportProtocol {
        return NetworkQuicTransporter(
            nodeInfo: nodeInfo,
            bindAddress: bindAddress,
            messageHandler: messageHandler,
            options: options,
            logger: logger
        )
    }
} 