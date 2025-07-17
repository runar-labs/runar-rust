import Foundation
import Logging

// MARK: - Basic Transport Implementation

/// Basic transport implementation for the Runar network
public final class BasicTransporter: TransportProtocol {
    private let nodeInfo: RunarNodeInfo
    private let logger: Logger
    private var running = false
    private var peerNodeIds: Set<String> = []
    private let peerUpdateStream: AsyncStream<RunarNodeInfo>
    private let peerUpdateContinuation: AsyncStream<RunarNodeInfo>.Continuation

    public init(nodeInfo: RunarNodeInfo, logger: Logger) {
        self.nodeInfo = nodeInfo
        self.logger = logger
        var continuation: AsyncStream<RunarNodeInfo>.Continuation!
        self.peerUpdateStream = AsyncStream<RunarNodeInfo> { c in continuation = c }
        self.peerUpdateContinuation = continuation
        logger.info("BasicTransporter initialized for node: \(nodeInfo.nodeId)")
    }

    public func start() async throws {
        logger.info("BasicTransporter started")
        running = true
    }

    public func stop() async throws {
        logger.info("BasicTransporter stopped")
        running = false
    }

    public func connect(to peerInfo: RunarPeerInfo) async throws {
        let peerNodeId = peerInfo.publicKey.base64EncodedString()
        logger.info("BasicTransporter connecting to peer: \(peerNodeId)")
        peerNodeIds.insert(peerNodeId)
    }

    public func disconnect(from peerNodeId: String) async throws {
        logger.info("BasicTransporter disconnecting from peer: \(peerNodeId)")
        peerNodeIds.remove(peerNodeId)
    }

    public func isConnected(to peerNodeId: String) async -> Bool {
        logger.info("BasicTransporter checking connection to peer: \(peerNodeId)")
        return peerNodeIds.contains(peerNodeId)
    }

    public func send(_ message: RunarNetworkMessage) async throws {
        logger.info("BasicTransporter sending message to \(message.destinationNodeId): \(message.messageType)")
    }

    public func updatePeers(with nodeInfo: RunarNodeInfo) async throws {
        logger.info("BasicTransporter updating peers with node info: \(nodeInfo.nodeId)")
        peerUpdateContinuation.yield(nodeInfo)
    }

    public var localAddress: String {
        "127.0.0.1:8080"
    }

    public func subscribeToPeerUpdates() -> AsyncStream<RunarNodeInfo> {
        peerUpdateStream
    }
} 