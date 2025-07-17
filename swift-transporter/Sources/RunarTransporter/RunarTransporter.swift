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
    
    /// Create a QUIC transporter instance (placeholder)
    public static func createQuicTransporter(
        nodeInfo: RunarNodeInfo,
        logger: Logger
    ) -> TransportProtocol {
        return QuicTransporter(nodeInfo: nodeInfo, logger: logger)
    }
}

// MARK: - Transport Factory

public struct TransportFactory {
    /// Create a transporter based on type
    public static func createTransporter(
        type: String,
        nodeInfo: RunarNodeInfo,
        logger: Logger
    ) -> TransportProtocol {
        switch type.lowercased() {
        case "simple":
            return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
        case "basic":
            return RunarTransporter.createBasicTransporter(nodeInfo: nodeInfo, logger: logger)
        case "quic":
            return RunarTransporter.createQuicTransporter(nodeInfo: nodeInfo, logger: logger)
        default:
            logger.warning("Unknown transporter type '\(type)', using SimpleTransporter")
            return RunarTransporter.createSimpleTransporter(nodeInfo: nodeInfo, logger: logger)
        }
    }
} 