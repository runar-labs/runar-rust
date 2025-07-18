import Foundation
import os.log
import RunarTransporter

/// Basic usage example for the Swift QUIC transporter
/// Demonstrates the same data flow as the Rust implementation
@available(macOS 11.0, iOS 14.0, *)
class BasicUsageExample {
    
    private let logger = Logger(subsystem: "com.runar.transporter.example", category: "basic-usage")
    private var transport: TransportProtocol?
    
    func runExample() async {
        logger.info("🚀 [BasicUsageExample] Starting QUIC transport example")
        
        // Step 1: Create node info (matches Rust NodeInfo)
        let nodePublicKey = Data(repeating: 0x42, count: 32) // Example public key
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: nodePublicKey,
            networkIds: ["example-network"],
            addresses: ["127.0.0.1:8080"],
            services: [
                ServiceMetadata(
                    servicePath: "/example/service",
                    networkId: "example-network",
                    serviceName: "ExampleService",
                    description: "An example service",
                    actions: [
                        ActionMetadata(
                            actionPath: "/example/action",
                            actionName: "exampleAction",
                            description: "An example action"
                        )
                    ],
                    events: [
                        EventMetadata(
                            path: "/example/event",
                            description: "An example event"
                        )
                    ]
                )
            ],
            version: 1
        )
        
        logger.info("📋 [BasicUsageExample] Created node info - ID: \(nodeInfo.nodeId)")
        
        // Step 2: Create message handler (matches Rust message handling)
        let messageHandler = ExampleMessageHandler(logger: logger)
        
        // Step 3: Create transport with default options
        transport = RunarTransporter.createQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler,
            logger: logger
        )
        
        logger.info("🔧 [BasicUsageExample] Created QUIC transport")
        
        // Step 4: Start the transport
        do {
            try await transport?.start()
            logger.info("✅ [BasicUsageExample] Transport started successfully")
            
            // Step 5: Connect to a peer (simulating discovery)
            let peerPublicKey = Data(repeating: 0x43, count: 32) // Example peer key
            let peerInfo = RunarPeerInfo(
                publicKey: peerPublicKey,
                addresses: ["127.0.0.1:8081"],
                name: "example-peer"
            )
            
            logger.info("🔗 [BasicUsageExample] Connecting to peer: \(peerInfo.peerId)")
            try await transport?.connect(to: peerInfo)
            
            // Step 6: Send a message (matches Rust message flow)
            let message = RunarNetworkMessage(
                sourceNodeId: nodeInfo.nodeId,
                destinationNodeId: peerInfo.peerId,
                messageType: MessageTypes.REQUEST,
                payloads: [
                    NetworkMessagePayloadItem(
                        path: "/example/action",
                        valueBytes: "Hello from Swift!".data(using: .utf8)!,
                        correlationId: NodeUtils.generateCorrelationId(withPrefix: "example")
                    )
                ]
            )
            
            logger.info("📤 [BasicUsageExample] Sending message to \(peerInfo.peerId)")
            try await transport?.send(message: message)
            
            // Step 7: Wait a bit and check connections
            try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            
            let connectedPeers = await transport?.getConnectedPeers() ?? []
            logger.info("📊 [BasicUsageExample] Connected peers: \(connectedPeers)")
            
            // Step 8: Send a handshake update (matches Rust notify_node_change)
            let updateMessage = RunarNetworkMessage(
                sourceNodeId: nodeInfo.nodeId,
                destinationNodeId: peerInfo.peerId,
                messageType: MessageTypes.NODE_INFO_UPDATE,
                payloads: [
                    NetworkMessagePayloadItem(
                        path: "",
                        valueBytes: try JSONEncoder().encode(nodeInfo),
                        correlationId: NodeUtils.generateCorrelationId(withPrefix: "update")
                    )
                ]
            )
            
            logger.info("🔄 [BasicUsageExample] Sending node info update")
            try await transport?.send(message: updateMessage)
            
            // Step 9: Wait a bit more
            try await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
            
        } catch {
            logger.error("❌ [BasicUsageExample] Error: \(error)")
        }
        
        // Step 10: Stop the transport
        await transport?.stop()
        logger.info("🔚 [BasicUsageExample] Transport stopped")
    }
}

/// Example message handler that demonstrates the same message flow as Rust
@available(macOS 11.0, iOS 14.0, *)
class ExampleMessageHandler: MessageHandlerProtocol {
    
    private let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func handleMessage(_ message: RunarNetworkMessage) {
        logger.info("📥 [ExampleMessageHandler] Received message - Type: \(message.messageType), From: \(message.sourceNodeId)")
        
        // Handle different message types (matches Rust message handling)
        switch message.messageType {
        case MessageTypes.REQUEST:
            handleRequest(message)
        case MessageTypes.RESPONSE:
            handleResponse(message)
        case MessageTypes.NODE_INFO_HANDSHAKE, MessageTypes.NODE_INFO_HANDSHAKE_RESPONSE:
            handleHandshake(message)
        case MessageTypes.NODE_INFO_UPDATE:
            handleNodeInfoUpdate(message)
        default:
            logger.warning("⚠️ [ExampleMessageHandler] Unknown message type: \(message.messageType)")
        }
    }
    
    func peerConnected(_ peerInfo: RunarNodeInfo) {
        logger.info("🔗 [ExampleMessageHandler] Peer connected: \(peerInfo.nodeId)")
        logger.info("📋 [ExampleMessageHandler] Peer services: \(peerInfo.services.count)")
        
        // Process peer services (matches Rust process_remote_capabilities)
        for service in peerInfo.services {
            logger.info("🔧 [ExampleMessageHandler] Remote service: \(service.serviceName) at \(service.servicePath)")
        }
    }
    
    func peerDisconnected(_ peerId: String) {
        logger.info("🔚 [ExampleMessageHandler] Peer disconnected: \(peerId)")
    }
    
    // MARK: - Private Methods
    
    private func handleRequest(_ message: RunarNetworkMessage) {
        logger.info("⚙️ [ExampleMessageHandler] Processing request from \(message.sourceNodeId)")
        
        // Extract request details (matches Rust local_request)
        guard let payload = message.payloads.first else {
            logger.error("❌ [ExampleMessageHandler] Request has no payload")
            return
        }
        
        logger.info("📋 [ExampleMessageHandler] Request path: \(payload.path)")
        logger.info("🆔 [ExampleMessageHandler] Correlation ID: \(payload.correlationId)")
        
        // In a real implementation, you would:
        // 1. Parse the path to find the service/action
        // 2. Execute the action
        // 3. Send a response back
        
        logger.info("✅ [ExampleMessageHandler] Request processed successfully")
    }
    
    private func handleResponse(_ message: RunarNetworkMessage) {
        logger.info("↩️ [ExampleMessageHandler] Processing response from \(message.sourceNodeId)")
        
        guard let payload = message.payloads.first else {
            logger.error("❌ [ExampleMessageHandler] Response has no payload")
            return
        }
        
        logger.info("🆔 [ExampleMessageHandler] Response correlation ID: \(payload.correlationId)")
        logger.info("✅ [ExampleMessageHandler] Response received successfully")
    }
    
    private func handleHandshake(_ message: RunarNetworkMessage) {
        logger.info("🤝 [ExampleMessageHandler] Processing handshake from \(message.sourceNodeId)")
        
        // Handshake messages are processed by the transport layer
        // This is just for logging
        logger.info("✅ [ExampleMessageHandler] Handshake processed")
    }
    
    private func handleNodeInfoUpdate(_ message: RunarNetworkMessage) {
        logger.info("🔄 [ExampleMessageHandler] Processing node info update from \(message.sourceNodeId)")
        
        // Node info updates are processed by the transport layer
        // This is just for logging
        logger.info("✅ [ExampleMessageHandler] Node info update processed")
    }
}

// MARK: - Usage

@available(macOS 11.0, iOS 14.0, *)
@main
struct BasicUsageApp {
    static func main() async {
        let example = BasicUsageExample()
        await example.runExample()
    }
} 