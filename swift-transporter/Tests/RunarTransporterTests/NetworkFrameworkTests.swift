import XCTest
import Foundation
import os.log
@testable import RunarTransporter

// MARK: - Test Message Handler

@available(macOS 12.0, iOS 15.0, *)
private class TestMessageHandler: MessageHandlerProtocol {
    private let logger: Logger
    private let queue = DispatchQueue(label: "test.message.handler")
    
    var receivedMessages: [RunarNetworkMessage] = []
    var connectedPeers: [RunarNodeInfo] = []
    var disconnectedPeers: [String] = []
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func handleMessage(_ message: RunarNetworkMessage) {
        queue.async {
            self.receivedMessages.append(message)
            self.logger.info("📥 [TestMessageHandler] Received message: \(message.messageType)")
        }
    }
    
    func peerConnected(_ peerInfo: RunarNodeInfo) {
        queue.async {
            self.connectedPeers.append(peerInfo)
            self.logger.info("🔗 [TestMessageHandler] Peer connected: \(peerInfo.nodeId)")
        }
    }
    
    func peerDisconnected(_ peerId: String) {
        queue.async {
            self.disconnectedPeers.append(peerId)
            self.logger.info("🔚 [TestMessageHandler] Peer disconnected: \(peerId)")
        }
    }
}

@available(macOS 12.0, iOS 15.0, *)
final class NetworkFrameworkTests: XCTestCase {
    
    private let logger = Logger(subsystem: "com.runar.transporter.tests", category: "network-framework")
    
    func testBasicConnectionAndCommunication() async throws {
        // Create test node info
        let node1Key = Data(repeating: 0x01, count: 32)
        let node2Key = Data(repeating: 0x02, count: 32)
        
        let node1Info = RunarNodeInfo(
            nodePublicKey: node1Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"],
            services: []
        )
        
        let node2Info = RunarNodeInfo(
            nodePublicKey: node2Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8081"],
            services: []
        )
        
        // Create message handlers
        let messageHandler1 = TestMessageHandler(logger: logger)
        let messageHandler2 = TestMessageHandler(logger: logger)
        
        // Create transporters
        let transporter1 = RunarTransporter.createQuicTransport(
            nodeInfo: node1Info,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler1,
            logger: logger
        )
        
        let transporter2 = RunarTransporter.createQuicTransport(
            nodeInfo: node2Info,
            bindAddress: "127.0.0.1:8081",
            messageHandler: messageHandler2,
            logger: logger
        )
        
        // Start both transporters
        try await transporter1.start()
        try await transporter2.start()
        
        // Wait a moment for listeners to be ready
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Create peer info for connection
        let peer1Info = RunarPeerInfo(
            publicKey: node1Key,
            addresses: ["127.0.0.1:8080"],
            name: "node1"
        )
        
        // Connect transporter2 to transporter1
        try await transporter2.connect(to: peer1Info)
        
        // Wait for connection to establish
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Verify connection
        let isConnected = await transporter2.isConnected(to: peer1Info.peerId)
        XCTAssertTrue(isConnected, "Transporter2 should be connected to node1")
        
        // Send a message from transporter2 to transporter1
        let message = RunarNetworkMessage(
            sourceNodeId: node2Info.nodeId,
            destinationNodeId: node1Info.nodeId,
            messageType: MessageTypes.REQUEST,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/test",
                    valueBytes: "Hello from node2".data(using: .utf8)!,
                    correlationId: "test-123"
                )
            ]
        )
        
        try await transporter2.send(message: message)
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Verify message was received
        XCTAssertGreaterThan(messageHandler1.receivedMessages.count, 0, "Message handler should have received messages")
        
        // Stop transporters
        await transporter1.stop()
        await transporter2.stop()
    }
    
    func testConnectionStateTracking() async throws {
        let nodeKey = Data(repeating: 0x03, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: nodeKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8082"],
            services: []
        )
        
        let messageHandler = TestMessageHandler(logger: logger)
        
        let transporter = RunarTransporter.createQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8082",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // Initially not running
        let initiallyConnected = await transporter.isConnected(to: "peer1")
        XCTAssertFalse(initiallyConnected, "Should not be connected initially")
        
        // Start transporter
        try await transporter.start()
        
        // Still not connected to any peer
        let stillNotConnected = await transporter.isConnected(to: "peer1")
        XCTAssertFalse(stillNotConnected, "Should still not be connected to any peer")
        
        // Get connected peers (should be empty)
        let peers = await transporter.getConnectedPeers()
        XCTAssertTrue(peers.isEmpty)
        
        // Stop transporter
        await transporter.stop()
    }
    
    func testMultipleConnections() async throws {
        let hubKey = Data(repeating: 0x04, count: 32)
        let client1Key = Data(repeating: 0x05, count: 32)
        let client2Key = Data(repeating: 0x06, count: 32)
        
        let hubInfo = RunarNodeInfo(
            nodePublicKey: hubKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8083"],
            services: []
        )
        
        let client1Info = RunarNodeInfo(
            nodePublicKey: client1Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8084"],
            services: []
        )
        
        let client2Info = RunarNodeInfo(
            nodePublicKey: client2Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8085"],
            services: []
        )
        
        let hubHandler = TestMessageHandler(logger: logger)
        let client1Handler = TestMessageHandler(logger: logger)
        let client2Handler = TestMessageHandler(logger: logger)
        
        let transporter1 = RunarTransporter.createQuicTransport(
            nodeInfo: hubInfo,
            bindAddress: "127.0.0.1:8083",
            messageHandler: hubHandler,
            logger: logger
        )
        
        let transporter2 = RunarTransporter.createQuicTransport(
            nodeInfo: client1Info,
            bindAddress: "127.0.0.1:8084",
            messageHandler: client1Handler,
            logger: logger
        )
        
        let transporter3 = RunarTransporter.createQuicTransport(
            nodeInfo: client2Info,
            bindAddress: "127.0.0.1:8085",
            messageHandler: client2Handler,
            logger: logger
        )
        
        // Start all transporters
        try await transporter1.start()
        try await transporter2.start()
        try await transporter3.start()
        
        // Wait for listeners
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        // Create peer info for hub
        let hubPeerInfo = RunarPeerInfo(
            publicKey: hubKey,
            addresses: ["127.0.0.1:8083"],
            name: "hub"
        )
        
        // Connect both clients to hub
        try await transporter2.connect(to: hubPeerInfo)
        try await transporter3.connect(to: hubPeerInfo)
        
        // Wait for connections
        try await Task.sleep(nanoseconds: 2_000_000_000)
        
        // Verify connections
        let isConnected2 = await transporter2.isConnected(to: hubInfo.nodeId)
        let isConnected3 = await transporter3.isConnected(to: hubInfo.nodeId)
        XCTAssertTrue(isConnected2, "Client 1 should be connected to hub")
        XCTAssertTrue(isConnected3, "Client 2 should be connected to hub")
        
        // Check hub's connected peers
        let hubPeers = await transporter1.getConnectedPeers()
        XCTAssertEqual(hubPeers.count, 2, "Hub should have 2 connected peers")
        
        // Stop all
        await transporter1.stop()
        await transporter2.stop()
        await transporter3.stop()
    }
    
    func testMessageSending() async throws {
        let senderKey = Data(repeating: 0x07, count: 32)
        let receiverKey = Data(repeating: 0x08, count: 32)
        
        let senderInfo = RunarNodeInfo(
            nodePublicKey: senderKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8086"],
            services: []
        )
        
        let receiverInfo = RunarNodeInfo(
            nodePublicKey: receiverKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8087"],
            services: []
        )
        
        let senderHandler = TestMessageHandler(logger: logger)
        let receiverHandler = TestMessageHandler(logger: logger)
        
        let transporter1 = RunarTransporter.createQuicTransport(
            nodeInfo: senderInfo,
            bindAddress: "127.0.0.1:8086",
            messageHandler: senderHandler,
            logger: logger
        )
        
        let transporter2 = RunarTransporter.createQuicTransport(
            nodeInfo: receiverInfo,
            bindAddress: "127.0.0.1:8087",
            messageHandler: receiverHandler,
            logger: logger
        )
        
        // Start transporters
        try await transporter1.start()
        try await transporter2.start()
        
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        // Create peer info for receiver
        let receiverPeerInfo = RunarPeerInfo(
            publicKey: receiverKey,
            addresses: ["127.0.0.1:8087"],
            name: "receiver"
        )
        
        // Connect
        try await transporter1.connect(to: receiverPeerInfo)
        
        try await Task.sleep(nanoseconds: 2_000_000_000)
        
        // Send multiple messages
        for i in 1...3 {
            let message = RunarNetworkMessage(
                sourceNodeId: senderInfo.nodeId,
                destinationNodeId: receiverInfo.nodeId,
                messageType: "TestMessage\(i)",
                payloads: [
                    NetworkMessagePayloadItem(
                        path: "/test/\(i)",
                        valueBytes: "Message \(i)".data(using: .utf8)!,
                        correlationId: "test-\(i)"
                    )
                ]
            )
            
            try await transporter1.send(message: message)
        }
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        // Verify messages were received
        XCTAssertEqual(receiverHandler.receivedMessages.count, 3, "Should have received 3 messages")
        
        // Stop
        await transporter1.stop()
        await transporter2.stop()
    }
}

 