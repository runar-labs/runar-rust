import XCTest
import Logging
import RunarTransporter

@available(macOS 10.15, iOS 13.0, *)
final class QuicEndToEndTests: XCTestCase {
    var logger: Logger!
    var serverTransporter: TransportProtocol!
    var clientTransporter: TransportProtocol!
    var serverMessageHandler: TestMessageHandler!
    var clientMessageHandler: TestMessageHandler!
    
    override func setUp() {
        super.setUp()
        logger = Logger(label: "quic-e2e-test")
        
        // Create message handlers
        serverMessageHandler = TestMessageHandler()
        clientMessageHandler = TestMessageHandler()
        
        // Create node info for server
        let serverPublicKey = Data("server-node-public-key-e2e".utf8)
        let serverNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: serverPublicKey),
            nodePublicKey: serverPublicKey,
            nodeName: "QUICServerE2E",
            addresses: ["127.0.0.1:9092"],
            metadata: ["role": "server", "test": "e2e"],
            createdAt: Date()
        )
        
        // Create node info for client
        let clientPublicKey = Data("client-node-public-key-e2e".utf8)
        let clientNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: clientPublicKey),
            nodePublicKey: clientPublicKey,
            nodeName: "QUICClientE2E",
            addresses: ["127.0.0.1:9093"],
            metadata: ["role": "client", "test": "e2e"],
            createdAt: Date()
        )
        
        // Create QUIC transport options
        let quicOptions = QuicTransportOptions(
            verifyCertificates: false, // For testing
            keepAliveInterval: 15,
            connectionIdleTimeout: 60,
            streamIdleTimeout: 30,
            maxIdleStreamsPerPeer: 100
        )
        
        // Create transporters
        serverTransporter = RunarTransporter.createQuicTransporter(
            nodeInfo: serverNodeInfo,
            bindAddress: "127.0.0.1:9092",
            messageHandler: serverMessageHandler,
            options: quicOptions,
            logger: logger
        )
        
        clientTransporter = RunarTransporter.createQuicTransporter(
            nodeInfo: clientNodeInfo,
            bindAddress: "127.0.0.1:9093",
            messageHandler: clientMessageHandler,
            options: quicOptions,
            logger: logger
        )
    }
    
    override func tearDown() async throws {
        // Clean up transporters
        if let server = serverTransporter {
            try? await server.stop()
        }
        if let client = clientTransporter {
            try? await client.stop()
        }
        
        // Note: super.tearDown() is not async in XCTest, so we don't call it
    }
    
    func testBasicCommunication() async throws {
        logger.info("Starting basic communication test")
        
        // Start both transporters
        try await serverTransporter.start()
        try await clientTransporter.start()
        
        // Wait for startup
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Create peer info for connection
        let serverPublicKey = Data("server-node-public-key-e2e".utf8)
        let peerInfo = RunarPeerInfo(
            publicKey: serverPublicKey,
            addresses: ["127.0.0.1:9092"]
        )
        
        // Connect client to server
        try await clientTransporter.connect(to: peerInfo)
        
        // Wait for connection to establish
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Verify connection
        let isConnected = await clientTransporter.isConnected(to: NodeUtils.compactId(from: serverPublicKey))
        XCTAssertTrue(isConnected, "Client should be connected to server")
        
        // Send message from client to server
        let clientMessage = RunarNetworkMessage(
            sourceNodeId: NodeUtils.compactId(from: Data("client-node-public-key-e2e".utf8)),
            destinationNodeId: NodeUtils.compactId(from: serverPublicKey),
            messageType: "TestMessage",
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/test/basic",
                    valueBytes: "Hello from client!".data(using: .utf8)!,
                    correlationId: UUID().uuidString
                )
            ],
            timestamp: Date()
        )
        
        try await clientTransporter.send(clientMessage)
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Verify server received the message
        XCTAssertEqual(serverMessageHandler.receivedMessages.count, 1, "Server should have received 1 message")
        XCTAssertEqual(serverMessageHandler.receivedMessages.first?.messageType, "TestMessage")
        
        logger.info("Basic communication test completed successfully")
    }
    
    func testConnectionEstablishment() async throws {
        logger.info("Starting connection establishment test")
        
        // Start both transporters
        try await serverTransporter.start()
        try await clientTransporter.start()
        
        // Wait for startup
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Create peer info for connection
        let serverPublicKey = Data("server-node-public-key-e2e".utf8)
        let serverNodeId = NodeUtils.compactId(from: serverPublicKey)
        let peerInfo = RunarPeerInfo(
            publicKey: serverPublicKey,
            addresses: ["127.0.0.1:9092"]
        )
        
        // Verify not connected initially
        var isConnected = await clientTransporter.isConnected(to: serverNodeId)
        XCTAssertFalse(isConnected, "Client should not be connected initially")
        
        // Connect client to server
        try await clientTransporter.connect(to: peerInfo)
        
        // Wait for connection to establish
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Verify connected
        isConnected = await clientTransporter.isConnected(to: serverNodeId)
        XCTAssertTrue(isConnected, "Client should be connected to server")
        
        logger.info("Connection establishment test completed successfully")
    }
    
    func testMessageExchange() async throws {
        logger.info("Starting message exchange test")
        
        // Start both transporters
        try await serverTransporter.start()
        try await clientTransporter.start()
        
        // Wait for startup
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Create peer info for connection
        let serverPublicKey = Data("server-node-public-key-e2e".utf8)
        let peerInfo = RunarPeerInfo(
            publicKey: serverPublicKey,
            addresses: ["127.0.0.1:9092"]
        )
        
        // Connect client to server
        try await clientTransporter.connect(to: peerInfo)
        
        // Wait for connection to establish
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Send message from client to server
        let clientMessage = RunarNetworkMessage(
            sourceNodeId: NodeUtils.compactId(from: Data("client-node-public-key-e2e".utf8)),
            destinationNodeId: NodeUtils.compactId(from: serverPublicKey),
            messageType: "Request",
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/api/data",
                    valueBytes: "Request data from client".data(using: .utf8)!,
                    correlationId: UUID().uuidString
                )
            ],
            timestamp: Date()
        )
        
        try await clientTransporter.send(clientMessage)
        
        // Wait for message processing
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Verify server received the message
        XCTAssertEqual(serverMessageHandler.receivedMessages.count, 1, "Server should have received 1 message")
        XCTAssertEqual(serverMessageHandler.receivedMessages.first?.messageType, "Request")
        
        // Send response from server to client
        let serverResponse = RunarNetworkMessage(
            sourceNodeId: NodeUtils.compactId(from: serverPublicKey),
            destinationNodeId: NodeUtils.compactId(from: Data("client-node-public-key-e2e".utf8)),
            messageType: "Response",
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/api/data/response",
                    valueBytes: "Response data from server".data(using: .utf8)!,
                    correlationId: clientMessage.payloads.first?.correlationId ?? ""
                )
            ],
            timestamp: Date()
        )
        
        try await serverTransporter.send(serverResponse)
        
        // Wait for response processing
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Verify client received the response
        XCTAssertEqual(clientMessageHandler.receivedMessages.count, 1, "Client should have received 1 message")
        XCTAssertEqual(clientMessageHandler.receivedMessages.first?.messageType, "Response")
        
        logger.info("Message exchange test completed successfully")
    }
} 