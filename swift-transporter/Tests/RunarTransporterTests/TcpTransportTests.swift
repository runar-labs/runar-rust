import XCTest
import Logging
@testable import RunarTransporter

final class TcpTransportTests: XCTestCase {
    var logger: Logger!
    
    override func setUp() {
        super.setUp()
        logger = Logger(label: "tcp-test")
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testCreateTcpTransporter() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        let transporter = TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8081",
            messageHandler: messageHandler,
            logger: logger
        )
        
        XCTAssertNotNil(transporter)
        XCTAssertEqual(transporter.localAddress, "127.0.0.1:8081")
    }
    
    func testTcpTransporterLifecycle() async throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        let transporter = TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8082",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // Test start
        try await transporter.start()
        
        // Test stop
        try await transporter.stop()
    }
    
    func testTcpTransporterFactory() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        
        // Test TCP transport creation via factory
        let transporter = TransportFactory.createTransporter(
            type: "tcp",
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8083",
            messageHandler: messageHandler,
            logger: logger
        )
        
        XCTAssertTrue(transporter is TcpTransporter)
    }
    
    func testTcpTransporterFactoryFallback() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        // Test TCP transport creation without required parameters (should fallback to SimpleTransporter)
        let transporter = TransportFactory.createTransporter(
            type: "tcp",
            nodeInfo: nodeInfo,
            logger: logger
        )
        
        XCTAssertTrue(transporter is SimpleTransporter)
    }
    
    func testTcpTransporterPeerUpdates() async throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        let transporter = TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8084",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // Subscribe to peer updates
        let peerUpdates = transporter.subscribeToPeerUpdates()
        
        // Update peers
        try await transporter.updatePeers(with: nodeInfo)
        
        // Check if we receive the update
        var receivedUpdates: [RunarNodeInfo] = []
        for await update in peerUpdates {
            receivedUpdates.append(update)
            break // Just get the first one
        }
        
        XCTAssertEqual(receivedUpdates.count, 1)
        XCTAssertEqual(receivedUpdates.first?.nodeId, nodeInfo.nodeId)
    }
    
    func testTcpTransporterConnectionState() async throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        let transporter = TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8085",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // Test initial connection state
        let isConnected = await transporter.isConnected(to: "test-peer")
        XCTAssertFalse(isConnected)
        
        // Test disconnecting from non-existent peer (should not throw)
        try await transporter.disconnect(from: "test-peer")
    }
    
    func testTcpTransporterErrorHandling() async throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let messageHandler = TestMessageHandler()
        let transporter = TcpTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8086",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // Test sending message when not running
        let message = RunarNetworkMessage(
            sourceNodeId: "source",
            destinationNodeId: "destination",
            messageType: "test",
            payloads: [],
            timestamp: Date()
        )
        
        do {
            try await transporter.send(message)
            XCTFail("Should have thrown TransportError.transportNotRunning")
        } catch TransportError.transportNotRunning {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

// MARK: - Test Message Handler

class TestMessageHandler: MessageHandlerProtocol {
    var receivedMessages: [RunarNetworkMessage] = []
    
    func handle(_ message: RunarNetworkMessage) async throws {
        receivedMessages.append(message)
    }
} 