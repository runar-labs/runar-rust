import Foundation
import Logging

// MARK: - Simple Transport Implementation

public final class SimpleTransporter: TransportProtocol {
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
        logger.info("SimpleTransporter initialized for node: \(nodeInfo.nodeId)")
    }

    public func start() async throws {
        logger.info("SimpleTransporter started")
        running = true
    }

    public func stop() async throws {
        logger.info("SimpleTransporter stopped")
        running = false
    }

    public func connect(to peerInfo: RunarPeerInfo) async throws {
        let peerNodeId = peerInfo.publicKey.base64EncodedString()
        logger.info("Connecting to peer: \(peerNodeId)")
        peerNodeIds.insert(peerNodeId)
    }

    public func disconnect(from peerNodeId: String) async throws {
        logger.info("Disconnecting from peer: \(peerNodeId)")
        peerNodeIds.remove(peerNodeId)
    }

    public func isConnected(to peerNodeId: String) async -> Bool {
        logger.info("Checking connection to peer: \(peerNodeId)")
        return peerNodeIds.contains(peerNodeId)
    }

    public func send(_ message: RunarNetworkMessage) async throws {
        logger.info("Sending message to \(message.destinationNodeId): \(message.messageType)")
    }

    public func updatePeers(with nodeInfo: RunarNodeInfo) async throws {
        logger.info("Updating peers with node info: \(nodeInfo.nodeId)")
        peerUpdateContinuation.yield(nodeInfo)
    }

    public var localAddress: String {
        "127.0.0.1:0"
    }

    public func subscribeToPeerUpdates() -> AsyncStream<RunarNodeInfo> {
        peerUpdateStream
    }
} 