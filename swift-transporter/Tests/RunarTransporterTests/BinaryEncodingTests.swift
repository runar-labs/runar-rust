import XCTest
import Foundation
import os.log
@testable import RunarTransporter

@available(macOS 12.0, iOS 15.0, *)
final class BinaryEncodingTests: XCTestCase {
    
    private let logger = Logger(subsystem: "com.runar.transporter.tests", category: "binary-encoding")
    
    // MARK: - Test Setup
    
    override func setUp() async throws {
        try await super.setUp()
    }
    
    override func tearDown() async throws {
        try await super.tearDown()
    }
    
    // MARK: - Network Message Tests
    
    func testNetworkMessageEncodingDecoding() throws {
        // Create a test network message
        let sourceNodeId = "test-source-node-123"
        let destinationNodeId = "test-dest-node-456"
        let messageType = MessageTypes.REQUEST
        let timestamp = Date()
        
        let payload = NetworkMessagePayloadItem(
            path: "/test/service/action",
            valueBytes: "Hello, World!".data(using: .utf8)!,
            correlationId: "test-correlation-789"
        )
        
        let originalMessage = RunarNetworkMessage(
            sourceNodeId: sourceNodeId,
            destinationNodeId: destinationNodeId,
            messageType: messageType,
            payloads: [payload],
            timestamp: timestamp
        )
        
        // Encode the message
        let encodedData = try BinaryMessageEncoder.encodeNetworkMessage(originalMessage)
        
        // Verify encoded data is not empty
        XCTAssertFalse(encodedData.isEmpty, "Encoded data should not be empty")
        XCTAssertGreaterThan(encodedData.count, 0, "Encoded data should have content")
        
        // Decode the message
        let decodedMessage = try BinaryMessageEncoder.decodeNetworkMessage(from: encodedData)
        
        // Verify all fields match
        XCTAssertEqual(decodedMessage.sourceNodeId, sourceNodeId, "Source node ID should match")
        XCTAssertEqual(decodedMessage.destinationNodeId, destinationNodeId, "Destination node ID should match")
        XCTAssertEqual(decodedMessage.messageType, messageType, "Message type should match")
        XCTAssertEqual(decodedMessage.payloads.count, 1, "Should have one payload")
        XCTAssertEqual(decodedMessage.timestamp.timeIntervalSince1970, timestamp.timeIntervalSince1970, accuracy: 0.001, "Timestamp should match")
        
        // Verify payload
        let decodedPayload = decodedMessage.payloads.first!
        XCTAssertEqual(decodedPayload.path, payload.path, "Payload path should match")
        XCTAssertEqual(decodedPayload.valueBytes, payload.valueBytes, "Payload value bytes should match")
        XCTAssertEqual(decodedPayload.correlationId, payload.correlationId, "Payload correlation ID should match")
    }
    
    func testNetworkMessageWithMultiplePayloads() throws {
        let originalMessage = RunarNetworkMessage(
            sourceNodeId: "source-1",
            destinationNodeId: "dest-1",
            messageType: MessageTypes.RESPONSE,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/service1/action1",
                    valueBytes: "Payload 1".data(using: .utf8)!,
                    correlationId: "corr-1"
                ),
                NetworkMessagePayloadItem(
                    path: "/service2/action2",
                    valueBytes: "Payload 2".data(using: .utf8)!,
                    correlationId: "corr-2"
                ),
                NetworkMessagePayloadItem(
                    path: "/service3/action3",
                    valueBytes: "Payload 3".data(using: .utf8)!,
                    correlationId: "corr-3"
                )
            ]
        )
        
        // Encode and decode
        let encodedData = try BinaryMessageEncoder.encodeNetworkMessage(originalMessage)
        let decodedMessage = try BinaryMessageEncoder.decodeNetworkMessage(from: encodedData)
        
        // Verify
        XCTAssertEqual(decodedMessage.payloads.count, 3, "Should have 3 payloads")
        XCTAssertEqual(decodedMessage.payloads[0].path, "/service1/action1", "First payload path should match")
        XCTAssertEqual(decodedMessage.payloads[1].path, "/service2/action2", "Second payload path should match")
        XCTAssertEqual(decodedMessage.payloads[2].path, "/service3/action3", "Third payload path should match")
    }
    
    func testNetworkMessageWithEmptyPayloads() throws {
        let originalMessage = RunarNetworkMessage(
            sourceNodeId: "source-empty",
            destinationNodeId: "dest-empty",
            messageType: MessageTypes.HEARTBEAT,
            payloads: []
        )
        
        // Encode and decode
        let encodedData = try BinaryMessageEncoder.encodeNetworkMessage(originalMessage)
        let decodedMessage = try BinaryMessageEncoder.decodeNetworkMessage(from: encodedData)
        
        // Verify
        XCTAssertEqual(decodedMessage.payloads.count, 0, "Should have no payloads")
        XCTAssertEqual(decodedMessage.messageType, MessageTypes.HEARTBEAT, "Message type should match")
    }
    
    func testNetworkMessageWithUnicodeStrings() throws {
        let originalMessage = RunarNetworkMessage(
            sourceNodeId: "source-unicode-🚀",
            destinationNodeId: "dest-unicode-🌍",
            messageType: "UnicodeMessage-🎉",
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/unicode/🚀/🌍",
                    valueBytes: "Unicode content: 🎉🎊🎈".data(using: .utf8)!,
                    correlationId: "corr-unicode-🎯"
                )
            ]
        )
        
        // Encode and decode
        let encodedData = try BinaryMessageEncoder.encodeNetworkMessage(originalMessage)
        let decodedMessage = try BinaryMessageEncoder.decodeNetworkMessage(from: encodedData)
        
        // Verify
        XCTAssertEqual(decodedMessage.sourceNodeId, "source-unicode-🚀", "Unicode source should match")
        XCTAssertEqual(decodedMessage.destinationNodeId, "dest-unicode-🌍", "Unicode destination should match")
        XCTAssertEqual(decodedMessage.messageType, "UnicodeMessage-🎉", "Unicode message type should match")
        XCTAssertEqual(decodedMessage.payloads.first?.path, "/unicode/🚀/🌍", "Unicode path should match")
        XCTAssertEqual(decodedMessage.payloads.first?.correlationId, "corr-unicode-🎯", "Unicode correlation ID should match")
    }
    
    // MARK: - Node Info Tests
    
    func testNodeInfoEncodingDecoding() throws {
        // Create test node info
        let publicKey = Data(repeating: 0x42, count: 32)
        let networkIds = ["network-1", "network-2", "network-3"]
        let addresses = ["127.0.0.1:8080", "192.168.1.100:8081"]
        let services = [
            ServiceMetadata(
                servicePath: "/service1",
                networkId: "network-1",
                serviceName: "TestService1",
                description: "Test service 1",
                actions: [
                    ActionMetadata(
                        actionPath: "/service1/action1",
                        actionName: "TestAction1",
                        description: "Test action 1"
                    )
                ],
                events: [
                    EventMetadata(
                        path: "/service1/event1",
                        description: "Test event 1"
                    )
                ]
            )
        ]
        let version: Int64 = 12345
        let createdAt = Date()
        
        let originalNodeInfo = RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: networkIds,
            addresses: addresses,
            services: services,
            version: version,
            createdAt: createdAt
        )
        
        // Encode the node info
        let encodedData = try BinaryMessageEncoder.encodeNodeInfo(originalNodeInfo)
        
        // Verify encoded data is not empty
        XCTAssertFalse(encodedData.isEmpty, "Encoded data should not be empty")
        XCTAssertGreaterThan(encodedData.count, 0, "Encoded data should have content")
        
        // Decode the node info
        let decodedNodeInfo = try BinaryMessageEncoder.decodeNodeInfo(from: encodedData)
        
        // Verify all fields match
        XCTAssertEqual(decodedNodeInfo.nodePublicKey, publicKey, "Public key should match")
        XCTAssertEqual(decodedNodeInfo.networkIds, networkIds, "Network IDs should match")
        XCTAssertEqual(decodedNodeInfo.addresses, addresses, "Addresses should match")
        XCTAssertEqual(decodedNodeInfo.version, version, "Version should match")
        XCTAssertEqual(decodedNodeInfo.createdAt.timeIntervalSince1970, createdAt.timeIntervalSince1970, accuracy: 0.001, "Created at should match")
        
        // Verify services
        XCTAssertEqual(decodedNodeInfo.services.count, 1, "Should have one service")
        let decodedService = decodedNodeInfo.services.first!
        XCTAssertEqual(decodedService.servicePath, "/service1", "Service path should match")
        XCTAssertEqual(decodedService.serviceName, "TestService1", "Service name should match")
        XCTAssertEqual(decodedService.actions.count, 1, "Should have one action")
        XCTAssertEqual(decodedService.events.count, 1, "Should have one event")
    }
    
    func testNodeInfoWithEmptyArrays() throws {
        let originalNodeInfo = RunarNodeInfo(
            nodePublicKey: Data(repeating: 0x01, count: 32),
            networkIds: [],
            addresses: [],
            services: []
        )
        
        // Encode and decode
        let encodedData = try BinaryMessageEncoder.encodeNodeInfo(originalNodeInfo)
        let decodedNodeInfo = try BinaryMessageEncoder.decodeNodeInfo(from: encodedData)
        
        // Verify
        XCTAssertEqual(decodedNodeInfo.networkIds.count, 0, "Should have no network IDs")
        XCTAssertEqual(decodedNodeInfo.addresses.count, 0, "Should have no addresses")
        XCTAssertEqual(decodedNodeInfo.services.count, 0, "Should have no services")
    }
    
    func testNodeInfoWithComplexServices() throws {
        let services = [
            ServiceMetadata(
                servicePath: "/complex/service",
                networkId: "complex-network",
                serviceName: "ComplexService",
                description: "A complex service with many actions and events",
                actions: [
                    ActionMetadata(
                        actionPath: "/complex/service/action1",
                        actionName: "ComplexAction1",
                        description: "First complex action",
                        inputSchema: "{\"type\": \"object\", \"properties\": {\"param1\": {\"type\": \"string\"}}}",
                        outputSchema: "{\"type\": \"object\", \"properties\": {\"result\": {\"type\": \"string\"}}}"
                    ),
                    ActionMetadata(
                        actionPath: "/complex/service/action2",
                        actionName: "ComplexAction2",
                        description: "Second complex action"
                    )
                ],
                events: [
                    EventMetadata(
                        path: "/complex/service/event1",
                        description: "First complex event",
                        dataSchema: "{\"type\": \"object\", \"properties\": {\"data\": {\"type\": \"string\"}}}"
                    ),
                    EventMetadata(
                        path: "/complex/service/event2",
                        description: "Second complex event"
                    )
                ]
            )
        ]
        
        let originalNodeInfo = RunarNodeInfo(
            nodePublicKey: Data(repeating: 0x02, count: 32),
            networkIds: ["complex-network"],
            addresses: ["127.0.0.1:8080"],
            services: services
        )
        
        // Encode and decode
        let encodedData = try BinaryMessageEncoder.encodeNodeInfo(originalNodeInfo)
        let decodedNodeInfo = try BinaryMessageEncoder.decodeNodeInfo(from: encodedData)
        
        // Verify
        XCTAssertEqual(decodedNodeInfo.services.count, 1, "Should have one service")
        let decodedService = decodedNodeInfo.services.first!
        XCTAssertEqual(decodedService.actions.count, 2, "Should have 2 actions")
        XCTAssertEqual(decodedService.events.count, 2, "Should have 2 events")
        
        // Verify first action has schemas
        let firstAction = decodedService.actions.first!
        XCTAssertNotNil(firstAction.inputSchema, "First action should have input schema")
        XCTAssertNotNil(firstAction.outputSchema, "First action should have output schema")
        
        // Verify first event has schema
        let firstEvent = decodedService.events.first!
        XCTAssertNotNil(firstEvent.dataSchema, "First event should have data schema")
    }
    
    // MARK: - Error Handling Tests
    
    func testInvalidDataDecoding() {
        // Test with empty data
        XCTAssertThrowsError(try BinaryMessageEncoder.decodeNetworkMessage(from: Data())) { error in
            XCTAssertTrue(error is RunarTransportError, "Should throw RunarTransportError")
        }
        
        // Test with insufficient data
        let insufficientData = Data([0x01, 0x02, 0x03]) // Only 3 bytes
        XCTAssertThrowsError(try BinaryMessageEncoder.decodeNetworkMessage(from: insufficientData)) { error in
            XCTAssertTrue(error is RunarTransportError, "Should throw RunarTransportError")
        }
        
        // Test with invalid UTF-8
        var invalidData = Data()
        let length = UInt32(5).bigEndian
        invalidData.append(withUnsafePointer(to: length) { pointer in
            Data(bytes: pointer, count: MemoryLayout<UInt32>.size)
        })
        invalidData.append(Data([0xFF, 0xFE, 0xFD, 0xFC, 0xFB])) // Invalid UTF-8
        
        XCTAssertThrowsError(try BinaryMessageEncoder.decodeNetworkMessage(from: invalidData)) { error in
            XCTAssertTrue(error is RunarTransportError, "Should throw RunarTransportError")
        }
    }
    
    func testInvalidNodeInfoDecoding() {
        // Test with empty data
        XCTAssertThrowsError(try BinaryMessageEncoder.decodeNodeInfo(from: Data())) { error in
            XCTAssertTrue(error is RunarTransportError, "Should throw RunarTransportError")
        }
        
        // Test with insufficient data for public key length
        let insufficientData = Data([0x01, 0x02, 0x03]) // Only 3 bytes
        XCTAssertThrowsError(try BinaryMessageEncoder.decodeNodeInfo(from: insufficientData)) { error in
            XCTAssertTrue(error is RunarTransportError, "Should throw RunarTransportError")
        }
    }
    
    // MARK: - Performance Tests
    
    func testEncodingPerformance() throws {
        let message = RunarNetworkMessage(
            sourceNodeId: "performance-test-source",
            destinationNodeId: "performance-test-dest",
            messageType: MessageTypes.REQUEST,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/performance/test",
                    valueBytes: Data(repeating: 0x42, count: 1000), // 1KB payload
                    correlationId: "perf-test-123"
                )
            ]
        )
        
        measure {
            for _ in 0..<100 {
                _ = try! BinaryMessageEncoder.encodeNetworkMessage(message)
            }
        }
    }
    
    func testDecodingPerformance() throws {
        let message = RunarNetworkMessage(
            sourceNodeId: "performance-test-source",
            destinationNodeId: "performance-test-dest",
            messageType: MessageTypes.REQUEST,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/performance/test",
                    valueBytes: Data(repeating: 0x42, count: 1000), // 1KB payload
                    correlationId: "perf-test-123"
                )
            ]
        )
        
        let encodedData = try BinaryMessageEncoder.encodeNetworkMessage(message)
        
        measure {
            for _ in 0..<100 {
                _ = try! BinaryMessageEncoder.decodeNetworkMessage(from: encodedData)
            }
        }
    }
}

 