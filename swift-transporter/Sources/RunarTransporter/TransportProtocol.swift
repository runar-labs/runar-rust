import Foundation
import Logging

// MARK: - Transport Protocol

public protocol TransportProtocol: AnyObject {
    func start() async throws
    func stop() async throws
    func connect(to peerInfo: RunarPeerInfo) async throws
    func disconnect(from peerNodeId: String) async throws
    func isConnected(to peerNodeId: String) async -> Bool
    func send(_ message: RunarNetworkMessage) async throws
    func updatePeers(with nodeInfo: RunarNodeInfo) async throws
    var localAddress: String { get }
    func subscribeToPeerUpdates() -> AsyncStream<RunarNodeInfo>
}

// MARK: - Message Handler Protocol

public protocol MessageHandlerProtocol {
    func handle(_ message: RunarNetworkMessage) async throws
} 