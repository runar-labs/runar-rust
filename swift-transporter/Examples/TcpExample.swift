import Foundation
import Logging
import RunarTransporter

// MARK: - TCP Transport Example

@main
struct TcpExample {
    static func main() async {
        // Set up logging
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = .info
            return handler
        }
        
        let logger = Logger(label: "tcp-example")
        logger.info("Starting TCP Transport Example")
        
        // Create message handlers
        let serverHandler = ExampleMessageHandler(name: "Server")
        let clientHandler = ExampleMessageHandler(name: "Client")
        
        // Create node info for server and client
        let serverPublicKey = Data("server-public-key".utf8)
        let serverNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: serverPublicKey),
            nodePublicKey: serverPublicKey,
            nodeName: "ServerNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["role": "server"],
            createdAt: Date()
        )
        
        let clientPublicKey = Data("client-public-key".utf8)
        let clientNodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: clientPublicKey),
            nodePublicKey: clientPublicKey,
            nodeName: "ClientNode",
            addresses: ["127.0.0.1:8081"],
            metadata: ["role": "client"],
            createdAt: Date()
        )
        
        // Create TCP transporters
        let serverTransporter = TcpTransporter(
            nodeInfo: serverNodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: serverHandler,
            logger: logger
        )
        
        let clientTransporter = TcpTransporter(
            nodeInfo: clientNodeInfo,
            bindAddress: "127.0.0.1:8081",
            messageHandler: clientHandler,
            logger: logger
        )
        
        do {
            // Start both transporters
            logger.info("Starting server transporter...")
            try await serverTransporter.start()
            
            logger.info("Starting client transporter...")
            try await clientTransporter.start()
            
            // Wait a moment for servers to start
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Create peer info for connection
            let serverPeerInfo = RunarPeerInfo(
                publicKey: serverPublicKey,
                addresses: ["127.0.0.1:8080"],
                metadata: ["role": "server"]
            )
            
            // Connect client to server
            logger.info("Connecting client to server...")
            try await clientTransporter.connect(to: serverPeerInfo)
            
            // Wait for connection to establish
            try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
            
            // Send a message from client to server
            let message = RunarNetworkMessage(
                sourceNodeId: clientNodeInfo.nodeId,
                destinationNodeId: serverNodeInfo.nodeId,
                messageType: "Hello",
                payloads: [
                    RunarMessagePayload(
                        path: "/greeting",
                        value: "Hello from client!",
                        correlationId: UUID().uuidString
                    )
                ],
                timestamp: Date()
            )
            
            logger.info("Sending message from client to server...")
            try await clientTransporter.send(message)
            
            // Wait for message processing
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Send a response from server to client
            let response = RunarNetworkMessage(
                sourceNodeId: serverNodeInfo.nodeId,
                destinationNodeId: clientNodeInfo.nodeId,
                messageType: "Response",
                payloads: [
                    RunarMessagePayload(
                        path: "/response",
                        value: "Hello back from server!",
                        correlationId: UUID().uuidString
                    )
                ],
                timestamp: Date()
            )
            
            logger.info("Sending response from server to client...")
            try await serverTransporter.send(response)
            
            // Wait for response processing
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
            // Stop transporters
            logger.info("Stopping transporters...")
            try await serverTransporter.stop()
            try await clientTransporter.stop()
            
            logger.info("TCP Transport Example completed successfully!")
            
        } catch {
            logger.error("Error in TCP example: \(error)")
        }
    }
}

// MARK: - Example Message Handler

class ExampleMessageHandler: MessageHandlerProtocol {
    private let name: String
    private let logger = Logger(label: "example-handler")
    
    init(name: String) {
        self.name = name
    }
    
    func handle(_ message: RunarNetworkMessage) async throws {
        logger.info("[\(name)] Received message: \(message.messageType)")
        
        if let payload = message.payloads.first {
            logger.info("[\(name)] Message payload: \(payload.path) = \(payload.value)")
        }
        
        // Simulate some processing time
        try await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
    }
} 