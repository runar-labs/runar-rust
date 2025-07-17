import Foundation
import Logging

// MARK: - Main Library Entry Point

public struct RunarTransporter {
    /// Version of the library
    public static let version = "1.0.0"
    
    /// Create a simple transporter instance
    public static func createSimpleTransporter(
        nodeInfo: RunarNodeInfo,
        logger: Logger
    ) -> TransportProtocol {
        return SimpleTransporter(nodeInfo: nodeInfo, logger: logger)
    }
    
    /// Create a basic transporter instance
    public static func createBasicTransporter(
        nodeInfo: RunarNodeInfo,
        logger: Logger
    ) -> TransportProtocol {
        return BasicTransporter(nodeInfo: nodeInfo, logger: logger)
    }
    
    /// Create a QUIC transporter instance
    public static func createQuicTransporter(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        options: QuicTransportOptions,
        logger: Logger
    ) -> TransportProtocol {
        return QuicTransporter(
            nodeInfo: nodeInfo,
            bindAddress: bindAddress,
            messageHandler: messageHandler,
            options: options,
            logger: logger
        )
    }
    
    /// Create a TCP transporter instance
    public static func createTcpTransporter(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        logger: Logger
    ) -> TransportProtocol {
        return TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: bindAddress,
            messageHandler: messageHandler,
            logger: logger
        )
    }
}

// MARK: - Transport Factory

public struct TransportFactory {
    /// Create a transporter based on type
    public static func createTransporter(
        type: String,
        nodeInfo: RunarNodeInfo,
        bindAddress: String? = nil,
        messageHandler: MessageHandlerProtocol? = nil,
        logger: Logger
    ) -> TransportProtocol {
        switch type.lowercased() {
        case "simple":
            return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
        case "basic":
            return RunarTransporter.createBasicTransporter(nodeInfo: nodeInfo, logger: logger)
        case "quic":
            guard let bindAddress = bindAddress, let messageHandler = messageHandler else {
                logger.warning("QUIC transport requires bindAddress and messageHandler, falling back to SimpleTransporter")
                return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
            }
            return RunarTransporter.createQuicTransporter(
                nodeInfo: nodeInfo,
                bindAddress: bindAddress,
                messageHandler: messageHandler,
                options: QuicTransportOptions(), // Placeholder options, adjust as needed
                logger: logger
            )
        case "tcp":
            guard let bindAddress = bindAddress, let messageHandler = messageHandler else {
                logger.warning("TCP transport requires bindAddress and messageHandler, falling back to SimpleTransporter")
                return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
            }
            return RunarTransporter.createTcpTransporter(
                nodeInfo: nodeInfo,
                bindAddress: bindAddress,
                messageHandler: messageHandler,
                logger: logger
            )
        default:
            logger.warning("Unknown transporter type '\(type)', using SimpleTransporter")
            return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
        }
    }
} 