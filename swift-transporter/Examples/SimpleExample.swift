import Foundation
import os.log
import RunarTransporter

/// Simple example demonstrating the Swift QUIC transporter
/// This example shows the basic usage without complex type annotations
@available(macOS 12.0, iOS 15.0, *)
class SimpleExample {
    
    private let logger = Logger(subsystem: "com.runar.transporter.example", category: "simple")
    
    func runExample() async {
        logger.info("🚀 [SimpleExample] Starting simple QUIC transport example")
        
        // Create a simple node info
        let nodeKey = Data(repeating: 0x42, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: nodeKey,
            networkIds: ["simple-network"],
            addresses: ["127.0.0.1:8080"],
            services: [
                ServiceMetadata(
                    servicePath: "/simple/service",
                    networkId: "simple-network",
                    serviceName: "SimpleService",
                    description: "A simple service"
                )
            ]
        )
        
        logger.info("📋 [SimpleExample] Created node info - ID: \(nodeInfo.nodeId)")
        
        // Create a simple message handler
        let messageHandler = SimpleMessageHandler(logger: logger)
        
        // Create transport with default options
        let transport = RunarTransporter.createQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler,
            logger: logger
        )
        
        logger.info("🔧 [SimpleExample] Created QUIC transport")
        
        // Start the transport
        do {
            try await transport.start()
            logger.info("✅ [SimpleExample] Transport started successfully")
            
            // Test basic functionality
            let connectedPeers = await transport.getConnectedPeers()
            logger.info("📊 [SimpleExample] Connected peers: \(connectedPeers)")
            
            // Wait a bit
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            
        } catch {
            logger.error("❌ [SimpleExample] Error: \(error)")
        }
        
        // Stop the transport
        await transport.stop()
        logger.info("🔚 [SimpleExample] Transport stopped")
    }
}

/// Simple message handler
@available(macOS 12.0, iOS 15.0, *)
class SimpleMessageHandler: MessageHandlerProtocol {
    
    private let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func handleMessage(_ message: RunarNetworkMessage) {
        logger.info("📥 [SimpleMessageHandler] Received message: \(message.messageType)")
    }
    
    func peerConnected(_ peerInfo: RunarNodeInfo) {
        logger.info("🔗 [SimpleMessageHandler] Peer connected: \(peerInfo.nodeId)")
    }
    
    func peerDisconnected(_ peerId: String) {
        logger.info("🔚 [SimpleMessageHandler] Peer disconnected: \(peerId)")
    }
}

// MARK: - Usage

@available(macOS 12.0, iOS 15.0, *)
@main
struct SimpleExampleApp {
    static func main() async {
        let example = SimpleExample()
        await example.runExample()
    }
} 