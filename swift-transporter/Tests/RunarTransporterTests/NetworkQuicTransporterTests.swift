import XCTest
import Foundation
import os.log
@testable import RunarTransporter

@available(macOS 11.0, iOS 14.0, *)
final class NetworkQuicTransporterTests: XCTestCase {
    
    private var logger: Logger!
    
    override func setUp() {
        super.setUp()
        logger = Logger(subsystem: "com.runar.transporter.tests", category: "test")
    }
    
    override func tearDown() {
        logger = nil
        super.tearDown()
    }
    
    func testCreateNodeInfo() {
        // Create a test public key
        let publicKey = Data(repeating: 0x42, count: 32)
        
        // Create node info
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"],
            services: [],
            version: 1
        )
        
        // Verify node ID is generated correctly
        let expectedNodeId = NodeUtils.compactId(from: publicKey)
        XCTAssertEqual(nodeInfo.nodeId, expectedNodeId)
        XCTAssertEqual(nodeInfo.networkIds, ["test-network"])
        XCTAssertEqual(nodeInfo.addresses, ["127.0.0.1:8080"])
        XCTAssertEqual(nodeInfo.version, 1)
    }
    
    func testCreatePeerInfo() {
        // Create a test public key
        let publicKey = Data(repeating: 0x42, count: 32)
        
        // Create peer info
        let peerInfo = RunarPeerInfo(
            publicKey: publicKey,
            addresses: ["127.0.0.1:8081"],
            name: "test-peer",
            metadata: ["test": "value"]
        )
        
        // Verify peer ID is generated correctly
        let expectedPeerId = NodeUtils.compactId(from: publicKey)
        XCTAssertEqual(peerInfo.peerId, expectedPeerId)
        XCTAssertEqual(peerInfo.addresses, ["127.0.0.1:8081"])
        XCTAssertEqual(peerInfo.name, "test-peer")
        XCTAssertEqual(peerInfo.metadata["test"], "value")
    }
    
    func testCreateNetworkMessage() {
        // Create a test message
        let message = RunarNetworkMessage(
            sourceNodeId: "source-node",
            destinationNodeId: "dest-node",
            messageType: MessageTypes.REQUEST,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/test/action",
                    valueBytes: "test data".data(using: .utf8)!,
                    correlationId: "test-correlation"
                )
            ]
        )
        
        XCTAssertEqual(message.sourceNodeId, "source-node")
        XCTAssertEqual(message.destinationNodeId, "dest-node")
        XCTAssertEqual(message.messageType, MessageTypes.REQUEST)
        XCTAssertEqual(message.payloads.count, 1)
        XCTAssertEqual(message.payloads[0].path, "/test/action")
        XCTAssertEqual(message.payloads[0].correlationId, "test-correlation")
    }
    
    func testCreateServiceMetadata() {
        // Create service metadata
        let service = ServiceMetadata(
            servicePath: "/test/service",
            networkId: "test-network",
            serviceName: "TestService",
            description: "A test service",
            actions: [
                ActionMetadata(
                    actionPath: "/test/action",
                    actionName: "testAction",
                    description: "A test action"
                )
            ],
            events: [
                EventMetadata(
                    path: "/test/event",
                    description: "A test event"
                )
            ]
        )
        
        XCTAssertEqual(service.servicePath, "/test/service")
        XCTAssertEqual(service.networkId, "test-network")
        XCTAssertEqual(service.serviceName, "TestService")
        XCTAssertEqual(service.actions.count, 1)
        XCTAssertEqual(service.events.count, 1)
    }
    
    func testNodeUtils() {
        // Test compact ID generation
        let publicKey = Data(repeating: 0x42, count: 32)
        let nodeId = NodeUtils.compactId(from: publicKey)
        
        // Should be 64 characters (32 bytes * 2 hex chars per byte)
        XCTAssertEqual(nodeId.count, 64)
        
        // Test correlation ID generation
        let correlationId = NodeUtils.generateCorrelationId()
        XCTAssertFalse(correlationId.isEmpty)
        
        // Test correlation ID with prefix
        let prefixedId = NodeUtils.generateCorrelationId(withPrefix: "test")
        XCTAssertTrue(prefixedId.hasPrefix("test-"))
    }
    
    func testMessageTypes() {
        // Verify all message types are defined
        XCTAssertEqual(MessageTypes.NODE_INFO_HANDSHAKE, "NODE_INFO_HANDSHAKE")
        XCTAssertEqual(MessageTypes.NODE_INFO_HANDSHAKE_RESPONSE, "NODE_INFO_HANDSHAKE_RESPONSE")
        XCTAssertEqual(MessageTypes.NODE_INFO_UPDATE, "NODE_INFO_UPDATE")
        XCTAssertEqual(MessageTypes.REQUEST, "Request")
        XCTAssertEqual(MessageTypes.RESPONSE, "Response")
        XCTAssertEqual(MessageTypes.ERROR, "Error")
    }
    
    func testTransportOptions() {
        // Test default options
        let defaultOptions = NetworkQuicTransportOptions.default()
        XCTAssertTrue(defaultOptions.verifyCertificates)
        XCTAssertEqual(defaultOptions.keepAliveInterval, 15.0)
        XCTAssertEqual(defaultOptions.connectionIdleTimeout, 60.0)
        XCTAssertEqual(defaultOptions.streamIdleTimeout, 30.0)
        XCTAssertEqual(defaultOptions.maxIdleStreamsPerPeer, 100)
        
        // Test mobile optimized options
        let mobileOptions = NetworkQuicTransportOptions.mobileOptimized()
        XCTAssertEqual(mobileOptions.keepAliveInterval, 30.0)
        XCTAssertEqual(mobileOptions.connectionIdleTimeout, 120.0)
        XCTAssertEqual(mobileOptions.streamIdleTimeout, 60.0)
        XCTAssertEqual(mobileOptions.maxIdleStreamsPerPeer, 50)
        
        // Test high performance options
        let perfOptions = NetworkQuicTransportOptions.highPerformance()
        XCTAssertEqual(perfOptions.keepAliveInterval, 5.0)
        XCTAssertEqual(perfOptions.connectionIdleTimeout, 30.0)
        XCTAssertEqual(perfOptions.streamIdleTimeout, 15.0)
        XCTAssertEqual(perfOptions.maxIdleStreamsPerPeer, 200)
    }
    
    func testCreateTransport() {
        // Create test node info
        let publicKey = Data(repeating: 0x42, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"]
        )
        
        // Create message handler
        let messageHandler = DefaultMessageHandler(logger: logger!)
        
        // Create transport with default options
        let transport = RunarTransporter.createQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler,
            logger: logger!
        )
        
        XCTAssertNotNil(transport)
    }
    
    func testCreateMobileTransport() {
        // Create test node info
        let publicKey = Data(repeating: 0x42, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"]
        )
        
        // Create message handler
        let messageHandler = DefaultMessageHandler(logger: logger!)
        
        // Create mobile optimized transport
        let transport = RunarTransporter.createMobileQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler,
            logger: logger!
        )
        
        XCTAssertNotNil(transport)
    }
} 