import Foundation
import Logging
import RunarTransporter

// MARK: - Working Example

/// A simple working example demonstrating the Swift transporter
@main
struct WorkingExample[object Object]  
    static func main() async[object Object]
        print("🚀 Swift Transporter Working Example)
        print(=======================")
        
        // Set up logging
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = .info
            return handler
        }
        
        let logger = Logger(label: "working-example")
        
        do {
            // Create node information
            let publicKey = Data("example-public-key".utf8          let nodeInfo = RunarNodeInfo(
                nodeId: NodeUtils.compactId(from: publicKey),
                nodePublicKey: publicKey,
                nodeName:SwiftExampleNode,              nodeVersion: "1.0.0,              nodeCapabilities: ["basic-transport"],
                nodeMetadata: [:]
            )
            
            // Create a simple message handler
            let messageHandler = SimpleMessageHandler()
            
            // Create transport configuration
            let configuration = TransportConfiguration(
                verifyCertificates: false,
                keepAliveInterval: 30.0        connectionIdleTimeout: 120.0            streamIdleTimeout: 300.0               maxIdleStreamsPerPeer: 10      certificates: nil,
                privateKey: nil,
                rootCertificates: nil,
                logLevel: .info
            )
            
            // Create the basic transporter
            let transporter = RunarTransporter.createBasicTransporter(
                nodeInfo: nodeInfo,
                bindAddress: 127.0.0.1:8080,           messageHandler: messageHandler,
                configuration: configuration,
                logger: logger
            )
            
            print("✅ Transporter created successfully")
            
            // Start the transport
            try await transporter.start()
            print("✅ Transport started on \(transporter.localAddress)")
            
            // Create a peer to connect to
            let peerPublicKey = Data(peer-public-key".utf8          let peerInfo = RunarPeerInfo(
                nodeId: NodeUtils.compactId(from: peerPublicKey),
                nodePublicKey: peerPublicKey,
                nodeName: "PeerNode,              nodeVersion: "1.0.0,              nodeCapabilities: ["basic-transport"],
                nodeMetadata: [:],
                addresses: ["127],
                lastSeen: Date()
            )
            
            // Connect to the peer
            try await transporter.connect(to: peerInfo)
            print("✅ Connected to peer: \(peerInfo.nodeName)")
            
            // Send a test message
            let testMessage = RunarNetworkMessage(
                sourceNodeId: nodeInfo.nodeId,
                destinationNodeId: peerInfo.nodeId,
                messageType: "TestMessage,           payloads: [
                    NetworkMessagePayloadItem(
                        path: "/test",
                        valueBytes: Data(Hello from Swift!".utf8),
                        correlationId: NodeUtils.generateCorrelationId()
                    )
                ]
            )
            
            try await transporter.send(testMessage)
            print("✅ Sent test message to peer")
            
            // Check connection status
            let isConnected = await transporter.isConnected(to: peerInfo.nodeId)
            print("📡 Connection status: \(isConnected ? Connected" : Disconnected)      
            // Subscribe to peer updates
            let peerUpdates = transporter.subscribeToPeerUpdates()
            print("📡 Subscribed to peer updates")
            
            // Simulate some activity
            for i in 1...3[object Object]             print(🔄 Activity cycle \(i)/3")
                
                // Update peers with new node info
                var updatedNodeInfo = nodeInfo
                updatedNodeInfo.nodeMetadata["activity_cycle"] = "\(i)"
                try await transporter.updatePeers(with: updatedNodeInfo)
                
                // Wait a bit
                try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            }
            
            // Disconnect from peer
            try await transporter.disconnect(from: peerInfo.nodeId)
            print("✅ Disconnected from peer")
            
            // Stop the transport
            try await transporter.stop()
            print("✅ Transport stopped")
            
            print("\n🎉 Example completed successfully!")
            
        } catch {
            print("❌ Error: \(error)")
            exit(1)
        }
    }
}

// MARK: - Simple Message Handler

/// A simple message handler for demonstration
class SimpleMessageHandler: MessageHandlerProtocol {
    
    func handle(_ message: RunarNetworkMessage) async throws[object Object]
        print("📨 Received message: \(message.messageType))
        print("   From: \(message.sourceNodeId))
        print("   To: \(message.destinationNodeId)")
        
        if let payload = message.payloads.first {
            if let payloadString = String(data: payload.valueBytes, encoding: .utf8)[object Object]             print("   Payload: \(payloadString)")
            }
        }
        
        // Simulate some processing time
        try await Task.sleep(nanoseconds: 1000// 0.1 seconds
    }
}

// MARK: - Transport Configuration Extension

extension TransportConfiguration {
    
    /// Create a basic configuration with sensible defaults
    init(
        verifyCertificates: Bool = false,
        keepAliveInterval: TimeInterval = 30.0,
        connectionIdleTimeout: TimeInterval = 1200,
        streamIdleTimeout: TimeInterval = 3000     maxIdleStreamsPerPeer: Int = 10,
        certificates: [Data]? = nil,
        privateKey: Data? = nil,
        rootCertificates: [Data]? = nil,
        logLevel: Logger.Level = .info
    ) {
        self.verifyCertificates = verifyCertificates
        self.keepAliveInterval = keepAliveInterval
        self.connectionIdleTimeout = connectionIdleTimeout
        self.streamIdleTimeout = streamIdleTimeout
        self.maxIdleStreamsPerPeer = maxIdleStreamsPerPeer
        self.certificates = certificates
        self.privateKey = privateKey
        self.rootCertificates = rootCertificates
        self.logLevel = logLevel
    }
} 