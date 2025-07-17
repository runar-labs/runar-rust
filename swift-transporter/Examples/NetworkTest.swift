import Foundation
import Logging
import RunarTransporter

// MARK: - Network Test Script

/// A simple network test demonstrating two transporters communicating over the network
@main
struct NetworkTest[object Object]  
    static func main() async[object Object]
        print("🌐 Swift Transporter Network Test)
        print(===================")
        
        // Set up logging
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = .info
            return handler
        }
        
        let logger = Logger(label: "network-test")
        
        do {
            // Create two transporters that will communicate with each other
            let (transporter1ransporter2) = try await createTestTransporters(logger: logger)
            
            print("✅ Created two test transporters")
            
            // Start both transporters
            try await transporter1.start()
            try await transporter2.start()
            
            print("✅ Both transporters started")
            print("   Transporter1: \(transporter1ess)")
            print("   Transporter2: \(transporter2s)")
            
            // Create peer info for connection
            let peerInfo = RunarPeerInfo(
                nodeId: transporter2.nodeInfo.nodeId,
                nodePublicKey: transporter2.nodeInfo.nodePublicKey,
                nodeName: transporter2.nodeInfo.nodeName,
                nodeVersion: transporter2.nodeInfo.nodeVersion,
                nodeCapabilities: transporter2nodeCapabilities,
                nodeMetadata: transporter2.nodeInfo.nodeMetadata,
                addresses: [transporter2.localAddress],
                lastSeen: Date()
            )
            
            // Connect transporter1orter2
            try await transporter1nnect(to: peerInfo)
            print("✅ Transporter1 connected to Transporter2")
            
            // Wait for handshake to complete
            try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            
            // Verify connection
            let isConnected = await transporter1.isConnected(to: transporter2.nodeInfo.nodeId)
            print("📡 Connection status: \(isConnected ? Connected" : Disconnected)      
            // Send messages back and forth
            await sendTestMessages(transporter1: transporter1, transporter2: transporter2, logger: logger)
            
            // Test peer updates
            await testPeerUpdates(transporter1: transporter1, transporter2: transporter2, logger: logger)
            
            // Test bidirectional communication
            await testBidirectionalCommunication(transporter1: transporter1, transporter2: transporter2, logger: logger)
            
            // Clean up
            try await transporter1.stop()
            try await transporter2.stop()
            
            print(n🎉 Network test completed successfully!")
            
        } catch {
            print("❌ Network test failed: \(error)")
            exit(1)
        }
    }
    
    /// Create two test transporters
    private static func createTestTransporters(logger: Logger) async throws -> (TransportProtocol, TransportProtocol) {
        // Create node information
        let publicKey1 = Data("test-node-1public-key".utf8)
        let publicKey2 = Data("test-node-2public-key".utf8)
        
        let nodeInfo1 = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey1),
            nodePublicKey: publicKey1,
            nodeName: "TestNode1",
            nodeVersion: "10,
            nodeCapabilities: ["basic-transport"],
            nodeMetadata: [:]
        )
        
        let nodeInfo2 = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey2),
            nodePublicKey: publicKey2,
            nodeName: "TestNode2",
            nodeVersion: "10,
            nodeCapabilities: ["basic-transport"],
            nodeMetadata: [:]
        )
        
        // Create message handlers
        let messageHandler1 = NetworkTestMessageHandler(name: "Handler1")
        let messageHandler2 = NetworkTestMessageHandler(name: "Handler2")
        
        // Create transport configuration
        let configuration = TransportConfiguration(
            verifyCertificates: false,
            keepAliveInterval:10        connectionIdleTimeout:60            streamIdleTimeout: 3000
            maxIdleStreamsPerPeer: 10,
            certificates: nil,
            privateKey: nil,
            rootCertificates: nil,
            logLevel: .info
        )
        
        // Create transporters
        let transporter1 = RunarTransporter.createBasicTransporter(
            nodeInfo: nodeInfo1,
            bindAddress: 127.0.0.1:8081           messageHandler: messageHandler1,
            configuration: configuration,
            logger: Logger(label: "transporter1")
        )
        
        let transporter2 = RunarTransporter.createBasicTransporter(
            nodeInfo: nodeInfo2,
            bindAddress: 127.0.0.1:8082           messageHandler: messageHandler2,
            configuration: configuration,
            logger: Logger(label: "transporter2")
        )
        
        return (transporter1, transporter2)
    }
    
    /// Send test messages between transporters
    private static func sendTestMessages(
        transporter1: TransportProtocol,
        transporter2: TransportProtocol,
        logger: Logger
    ) async [object Object]
        print("\n📨 Testing message exchange...")
        
        // Send message from transporter1ansporter2
        let message1to2 = RunarNetworkMessage(
            sourceNodeId: transporter1.nodeInfo.nodeId,
            destinationNodeId: transporter2.nodeInfo.nodeId,
            messageType: "TestMessage",
            payloads:           NetworkMessagePayloadItem(
                    path: "/test",
                    valueBytes: Data("Hello from Transporter1!".utf8),
                    correlationId: NodeUtils.generateCorrelationId()
                )
            ]
        )
        
        do[object Object]         try await transporter1send(message1to2)
            print("✅ Sent message from Transporter1 to Transporter2)        } catch {
            print("❌ Failed to send message: \(error)")
        }
        
        // Wait for message processing
        try? await Task.sleep(nanoseconds: 1_000_0001d
        
        // Check if message was received
        let messageCount = transporter2.messageHandler.getMessageCount()
        print("📥 Transporter2 received \(messageCount) messages")
    }
    
    /// Test peer updates
    private static func testPeerUpdates(
        transporter1: TransportProtocol,
        transporter2: TransportProtocol,
        logger: Logger
    ) async [object Object]
        print(n🔄 Testing peer updates...")
        
        // Update node info on transporter1
        var updatedNodeInfo = transporter1fo
        updatedNodeInfo.nodeMetadata["test_key] = est_value"
        updatedNodeInfo.nodeVersion =2.0.0       
        do[object Object]         try await transporter1.updatePeers(with: updatedNodeInfo)
            print("✅ Sent node info update from Transporter1)        } catch {
            print("❌ Failed to send node info update: \(error)")
        }
        
        // Wait for update processing
        try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Check if update was received
        let messageCount = transporter2.messageHandler.getMessageCount()
        print("📥 Transporter2 received \(messageCount) total messages (including updates)")
    }
    
    /// Test bidirectional communication
    private static func testBidirectionalCommunication(
        transporter1: TransportProtocol,
        transporter2: TransportProtocol,
        logger: Logger
    ) async [object Object]
        print("\n🔄 Testing bidirectional communication...")
        
        // Send message from transporter2ansporter1
        let message2to1 = RunarNetworkMessage(
            sourceNodeId: transporter2.nodeInfo.nodeId,
            destinationNodeId: transporter1.nodeInfo.nodeId,
            messageType: "ResponseMessage",
            payloads:           NetworkMessagePayloadItem(
                    path: "/response",
                    valueBytes: Data("Hello from Transporter2!".utf8),
                    correlationId: NodeUtils.generateCorrelationId()
                )
            ]
        )
        
        do[object Object]         try await transporter2send(message2to1)
            print("✅ Sent message from Transporter2 to Transporter1)        } catch {
            print("❌ Failed to send bidirectional message: \(error)")
        }
        
        // Wait for message processing
        try? await Task.sleep(nanoseconds: 1_000_0001d
        
        // Check if message was received
        let messageCount = transporter1.messageHandler.getMessageCount()
        print("📥 Transporter1 received \(messageCount) messages")
    }
}

// MARK: - Network Test Message Handler

/// Message handler for network tests
class NetworkTestMessageHandler: MessageHandlerProtocol[object Object]  private let name: String
    private var messageCount: Int =0 private let queue = DispatchQueue(label: network-test-handler", attributes: .concurrent)
    
    init(name: String) {
        self.name = name
    }
    
    func handle(_ message: RunarNetworkMessage) async throws [object Object]       queue.async(flags: .barrier) [object Object]      self.messageCount += 1
        }
        
        print("📨 [\(name)] Received message: \(message.messageType))
        print("   From: \(message.sourceNodeId))
        print("   To: \(message.destinationNodeId)")
        
        if let payload = message.payloads.first {
            if let payloadString = String(data: payload.valueBytes, encoding: .utf8)[object Object]             print("   Payload: \(payloadString)")
            }
        }
        
        // Simulate processing time
        try await Task.sleep(nanoseconds: 1000// 0.1econds
    }
    
    func getMessageCount() -> Int[object Object]        queue.sync {
            return messageCount
        }
    }
} 