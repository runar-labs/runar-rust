import Foundation
import Logging
import RunarTransporter

@available(macOS 10.15, iOS 13.0, *)
@main
struct QuicExample {
    static func main() async {
        // Set up logging
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = .info
            return handler
        }
        
        let logger = Logger(label: "quic-example")
        logger.info("Starting QUIC-like transport example")
        
        // Create test message handler
        let messageHandler = ExampleMessageHandler()
        
        // Create node info for server
        let serverPublicKey = Data("server-node-public-key".utf8)
        let serverNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: serverPublicKey),
            nodePublicKey: serverPublicKey,
            nodeName: "QUICServer",
            addresses: ["127.0.0.1:9090"],
            metadata: ["role": "server"],
            createdAt: Date()
        )
        
        // Create node info for client
        let clientPublicKey = Data("client-node-public-key".utf8)
        let clientNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: clientPublicKey),
            nodePublicKey: clientPublicKey,
            nodeName: "QUICClient",
            addresses: ["127.0.0.1:9091"],
            metadata: ["role": "client"],
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
        
        // Create server transporter
        let serverTransporter = RunarTransporter.createQuicTransporter(
            nodeInfo: serverNodeInfo,
            bindAddress: "127.0.0.1:9090",
            messageHandler: messageHandler,
            options: quicOptions,
            logger: logger
        )
        
        // Create client transporter
        let clientTransporter = RunarTransporter.createQuicTransporter(
            nodeInfo: clientNodeInfo,
            bindAddress: "127.0.0.1:9091",
            messageHandler: messageHandler,
            options: quicOptions,
            logger: logger
        )
        
        do {
            // Start both transporters
            logger.info("Starting server transporter")
            try await serverTransporter.start()
            
            logger.info("Starting client transporter")
            try await clientTransporter.start()
            
            // Wait a moment for startup
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Create peer info for connection
            let peerInfo = RunarPeerInfo(
                publicKey: serverPublicKey,
                addresses: ["127.0.0.1:9090"]
            )
            
            // Connect client to server
            logger.info("Connecting client to server")
            try await clientTransporter.connect(to: peerInfo)
            
            // Wait for connection to establish
            try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            
            // Send a test message from client to server
            let testMessage = RunarNetworkMessage(
                sourceNodeId: clientNodeInfo.nodeId,
                destinationNodeId: serverNodeInfo.nodeId,
                messageType: "TestMessage",
                payloads: [
                    NetworkMessagePayloadItem(
                        path: "/test",
                        valueBytes: "Hello from QUIC client!".data(using: .utf8)!,
                        correlationId: UUID().uuidString
                    )
                ],
                timestamp: Date()
            )
            
            logger.info("Sending test message from client to server")
            try await clientTransporter.send(testMessage)
            
            // Wait for message processing
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Check connection status
            let isConnected = await clientTransporter.isConnected(to: serverNodeInfo.nodeId)
            logger.info("Client connected to server: \(isConnected)")
            
            // Send a response from server to client
            let responseMessage = RunarNetworkMessage(
                sourceNodeId: serverNodeInfo.nodeId,
                destinationNodeId: clientNodeInfo.nodeId,
                messageType: "TestResponse",
                payloads: [
                    NetworkMessagePayloadItem(
                        path: "/test/response",
                        valueBytes: "Hello from QUIC server!".data(using: .utf8)!,
                        correlationId: UUID().uuidString
                    )
                ],
                timestamp: Date()
            )
            
            logger.info("Sending response from server to client")
            try await serverTransporter.send(responseMessage)
            
            // Wait for response processing
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Disconnect
            logger.info("Disconnecting client from server")
            try await clientTransporter.disconnect(from: serverNodeInfo.nodeId)
            
            // Stop transporters
            logger.info("Stopping client transporter")
            try await clientTransporter.stop()
            
            logger.info("Stopping server transporter")
            try await serverTransporter.stop()
            
            logger.info("QUIC-like transport example completed successfully")
            
        } catch {
            logger.error("Error in QUIC example: \(error)")
        }
    }
}

// MARK: - Example Message Handler

@available(macOS 10.15, iOS 13.0, *)
class ExampleMessageHandler: MessageHandlerProtocol {
    private let logger = Logger(label: "example-handler")
    
    func handle(_ message: RunarNetworkMessage) async throws {
        logger.info("Received message: \(message.messageType) from \(message.sourceNodeId)")
        
        if let payload = message.payloads.first {
            let value = String(data: payload.valueBytes, encoding: .utf8) ?? "unknown"
            logger.info("Message payload: \(value)")
        }
        
        // Echo the message back if it's a test message
        if message.messageType == "TestMessage" {
            logger.info("Echoing test message back to sender")
            // In a real implementation, you would send a response here
        }
    }
} 