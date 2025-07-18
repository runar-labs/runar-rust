import XCTest
import Foundation
import os.log
@testable import RunarTransporter

// MARK: - Timeout Helper

/// Helper function to run tests with timeout
func runWithTimeout<T>(_ timeout: TimeInterval, operation: @escaping () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            throw RunarTransportError.timeoutError("Operation timed out after \(timeout) seconds")
        }
        
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

final class EndToEndTests: XCTestCase {
    
    func testNodeInfoCreation() throws {
        // Test basic node info creation
        let publicKey = Data(repeating: 0x42, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"],
            services: []
        )
        
        XCTAssertEqual(nodeInfo.nodePublicKey, publicKey)
        XCTAssertEqual(nodeInfo.networkIds, ["test-network"])
        XCTAssertEqual(nodeInfo.addresses, ["127.0.0.1:8080"])
        XCTAssertEqual(nodeInfo.services.count, 0)
    }
    
    func testPeerInfoCreation() throws {
        // Test basic peer info creation
        let publicKey = Data(repeating: 0x42, count: 32)
        let peerInfo = RunarPeerInfo(
            publicKey: publicKey,
            addresses: ["127.0.0.1:8080"],
            name: "Test Peer",
            metadata: ["version": "1.0"]
        )
        
        XCTAssertEqual(peerInfo.publicKey, publicKey)
        XCTAssertEqual(peerInfo.addresses, ["127.0.0.1:8080"])
        XCTAssertEqual(peerInfo.name, "Test Peer")
        XCTAssertEqual(peerInfo.metadata["version"], "1.0")
    }
    
    func testNetworkMessageCreation() throws {
        // Test basic network message creation
        let payload = NetworkMessagePayloadItem(
            path: "/test/path",
            valueBytes: "Hello, World!".data(using: .utf8)!,
            correlationId: "test-correlation"
        )
        
        let message = RunarNetworkMessage(
            sourceNodeId: "node1",
            destinationNodeId: "node2",
            messageType: "TestMessage",
            payloads: [payload]
        )
        
        XCTAssertEqual(message.sourceNodeId, "node1")
        XCTAssertEqual(message.destinationNodeId, "node2")
        XCTAssertEqual(message.messageType, "TestMessage")
        XCTAssertEqual(message.payloads.count, 1)
        XCTAssertEqual(message.payloads[0].path, "/test/path")
    }
    
    func testServiceMetadataCreation() throws {
        // Test service metadata creation
        let action = ActionMetadata(
            actionPath: "/test/action",
            actionName: "TestAction",
            description: "A test action"
        )
        
        let event = EventMetadata(
            path: "/test/event",
            description: "A test event"
        )
        
        let service = ServiceMetadata(
            servicePath: "/test/service",
            networkId: "test-network",
            serviceName: "TestService",
            description: "A test service",
            actions: [action],
            events: [event]
        )
        
        XCTAssertEqual(service.servicePath, "/test/service")
        XCTAssertEqual(service.networkId, "test-network")
        XCTAssertEqual(service.serviceName, "TestService")
        XCTAssertEqual(service.actions.count, 1)
        XCTAssertEqual(service.events.count, 1)
    }
    
    func testNodeUtils() throws {
        // Test node utilities
        let publicKey = Data(repeating: 0x42, count: 32)
        let nodeId = NodeUtils.compactId(from: publicKey)
        
        XCTAssertFalse(nodeId.isEmpty)
        XCTAssertEqual(nodeId.count, 64) // SHA256 hash is 32 bytes = 64 hex chars
        
        let correlationId = NodeUtils.generateCorrelationId()
        XCTAssertFalse(correlationId.isEmpty)
        
        let prefixedCorrelationId = NodeUtils.generateCorrelationId(withPrefix: "test")
        XCTAssertTrue(prefixedCorrelationId.hasPrefix("test-"))
    }
    
    func testTransportErrorTypes() throws {
        // Test transport error types
        let errors: [RunarTransportError] = [
            .configurationError("Config error"),
            .connectionError("Connection error"),
            .messageError("Message error"),
            .transportError("Transport error"),
            .serializationError("Serialization error"),
            .timeoutError("Timeout error"),
            .certificateError("Certificate error"),
            .peerNotConnected("peer123")
        ]
        
        for error in errors {
            XCTAssertFalse(error.localizedDescription.isEmpty)
        }
    }
    
    func testMessageHandlerProtocol() throws {
        // Test that we can create a simple message handler
        let handler = SimpleMessageHandler()
        
        let message = RunarNetworkMessage(
            sourceNodeId: "node1",
            destinationNodeId: "node2",
            messageType: "TestMessage"
        )
        
        // This should not throw
        handler.handleMessage(message)
    }
    
    func testTransportOptionsCreation() throws {
        // Test transport options creation
        let options = NetworkQuicTransportOptions(
            keepAliveInterval: 30.0,
            connectionIdleTimeout: 60.0,
            streamIdleTimeout: 30.0,
            maxIdleStreamsPerPeer: 100,
            certificates: nil,
            privateKey: nil
        )
        
        XCTAssertEqual(options.keepAliveInterval, 30.0)
        XCTAssertEqual(options.connectionIdleTimeout, 60.0)
        XCTAssertEqual(options.streamIdleTimeout, 30.0)
        XCTAssertEqual(options.maxIdleStreamsPerPeer, 100)
        XCTAssertNil(options.certificates)
        XCTAssertNil(options.privateKey)
    }
    
    func testBasicAsyncOperationsWithTimeout() async throws {
        // Test basic async operations with timeout
        try await runWithTimeout(2.0) {
            // Simple async operation that should complete quickly
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
            XCTAssertTrue(true) // Just verify we can complete async operations
        }
    }
    
    func testTimeoutMechanism() async throws {
        // Test that timeout mechanism actually works
        do {
            try await runWithTimeout(0.1) {
                // This should timeout
                try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
                return "should not reach here"
            }
            XCTFail("Should have timed out")
        } catch RunarTransportError.timeoutError {
            // Expected timeout
            XCTAssertTrue(true)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

// MARK: - Helper Classes

/// Simple message handler for testing
private class SimpleMessageHandler: MessageHandlerProtocol {
    func handleMessage(_ message: RunarNetworkMessage) {
        // Simple implementation for testing
        print("Handled message: \(message.messageType)")
    }
    
    func peerConnected(_ peerInfo: RunarNodeInfo) {
        print("Peer connected: \(peerInfo.nodeId)")
    }
    
    func peerDisconnected(_ peerId: String) {
        print("Peer disconnected: \(peerId)")
    }
} 