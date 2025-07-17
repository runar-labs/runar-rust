import XCTest
@testable import RunarTransporter

final class NetworkFrameworkTests: XCTestCase {
    
    func testBasicConnectionAndCommunication() async throws {
        // Create two transporters
        let transporter1 = QuicTransporter(
            nodeId: "node1",
            port: 8080,
            messageHandler: { message in
                print("Transporter1 received: \(message.messageType)")
            }
        )
        
        let transporter2 = QuicTransporter(
            nodeId: "node2", 
            port: 8081,
            messageHandler: { message in
                print("Transporter2 received: \(message.messageType)")
            }
        )
        
        // Start both transporters
        try await transporter1.start()
        try await transporter2.start()
        
        // Wait a moment for listeners to be ready
        try await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
        
        // Connect transporter2 to transporter1
        try await transporter2.connect(to: "127.0.0.1", peerPort: 8080, peerId: "node1")
        
        // Wait for connection to establish
        try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        
        // Verify connection
        let isConnected = await transporter2.isConnected(to: "node1")
        XCTAssertTrue(isConnected, "Transporter2 should be connected to node1")
        
        // Send a message from transporter2 to transporter1
        let message = RunarNetworkMessage(
            sourceNodeId: "node2",
            destinationNodeId: "node1", 
            messageType: "TestMessage",
            payloads: [
                RunarNetworkMessagePayload(
                    path: "/test",
                    valueBytes: "Hello from node2".data(using: .utf8)!,
                    correlationId: "test-123"
                )
            ]
        )
        
        try await transporter2.send(message: message, to: "node1")
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 200_000_000) // 0.2 seconds
        
        // Stop transporters
        await transporter1.stop()
        await transporter2.stop()
    }
    
    func testConnectionStateTracking() async throws {
        let transporter = QuicTransporter(
            nodeId: "test-node",
            port: 8082,
            messageHandler: { _ in }
        )
        
        // Initially not running
        XCTAssertFalse(await transporter.isConnected(to: "peer1"))
        
        // Start transporter
        try await transporter.start()
        
        // Still not connected to any peer
        XCTAssertFalse(await transporter.isConnected(to: "peer1"))
        
        // Get connected peers (should be empty)
        let peers = await transporter.getConnectedPeers()
        XCTAssertTrue(peers.isEmpty)
        
        // Stop transporter
        await transporter.stop()
    }
    
    func testMultipleConnections() async throws {
        let transporter1 = QuicTransporter(
            nodeId: "hub",
            port: 8083,
            messageHandler: { _ in }
        )
        
        let transporter2 = QuicTransporter(
            nodeId: "client1",
            port: 8084,
            messageHandler: { _ in }
        )
        
        let transporter3 = QuicTransporter(
            nodeId: "client2", 
            port: 8085,
            messageHandler: { _ in }
        )
        
        // Start all transporters
        try await transporter1.start()
        try await transporter2.start()
        try await transporter3.start()
        
        // Wait for listeners
        try await Task.sleep(nanoseconds: 100_000_000)
        
        // Connect both clients to hub
        try await transporter2.connect(to: "127.0.0.1", peerPort: 8083, peerId: "hub")
        try await transporter3.connect(to: "127.0.0.1", peerPort: 8083, peerId: "hub")
        
        // Wait for connections
        try await Task.sleep(nanoseconds: 500_000_000)
        
        // Verify connections
        XCTAssertTrue(await transporter2.isConnected(to: "hub"))
        XCTAssertTrue(await transporter3.isConnected(to: "hub"))
        
        // Check hub's connected peers
        let hubPeers = await transporter1.getConnectedPeers()
        XCTAssertEqual(hubPeers.count, 2, "Hub should have 2 connected peers")
        
        // Stop all
        await transporter1.stop()
        await transporter2.stop()
        await transporter3.stop()
    }
    
    func testMessageSending() async throws {
        var receivedMessages: [RunarNetworkMessage] = []
        
        let transporter1 = QuicTransporter(
            nodeId: "sender",
            port: 8086,
            messageHandler: { message in
                receivedMessages.append(message)
            }
        )
        
        let transporter2 = QuicTransporter(
            nodeId: "receiver",
            port: 8087,
            messageHandler: { message in
                receivedMessages.append(message)
            }
        )
        
        // Start transporters
        try await transporter1.start()
        try await transporter2.start()
        
        try await Task.sleep(nanoseconds: 100_000_000)
        
        // Connect
        try await transporter1.connect(to: "127.0.0.1", peerPort: 8087, peerId: "receiver")
        
        try await Task.sleep(nanoseconds: 500_000_000)
        
        // Send multiple messages
        for i in 1...3 {
            let message = RunarNetworkMessage(
                sourceNodeId: "sender",
                destinationNodeId: "receiver",
                messageType: "TestMessage\(i)",
                payloads: [
                    RunarNetworkMessagePayload(
                        path: "/test/\(i)",
                        valueBytes: "Message \(i)".data(using: .utf8)!,
                        correlationId: "test-\(i)"
                    )
                ]
            )
            
            try await transporter1.send(message: message, to: "receiver")
        }
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 500_000_000)
        
        // Verify messages were received
        XCTAssertEqual(receivedMessages.count, 3, "Should have received 3 messages")
        
        // Stop
        await transporter1.stop()
        await transporter2.stop()
    }
} 