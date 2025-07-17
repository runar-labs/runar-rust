import Foundation
import RunarTransporter
import Logging

// MARK: - Basic Example

/// Example demonstrating basic usage of the RunarTransporter library
@main
struct BasicExample[object Object]  static func main() async throws[object Object]
        print(🚀 Starting RunarTransporter Basic Example")
        
        // Initialize the library
        RunarTransporter.initialize()
        
        // Create a logger
        let logger = Logger(label:basic-example")
        logger.logLevel = .info
        
        // Create node information
        let publicKey = Data(repeating:42, count: 32/ In real app, use actual key
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "Swift Example Node",
            addresses: ["1270.112345       )
        
        // Create a message handler
        let messageHandler = ExampleMessageHandler()
        
        // Create transport configuration
        let configuration = TransportConfiguration(
            verifyCertificates: false, // Disable for example
            keepAliveInterval:15        connectionIdleTimeout:60            streamIdleTimeout:300          logLevel: .info
        )
        
        // Create and start the transporter
        let transporter = try QuicTransporter(
            nodeInfo: nodeInfo,
            bindAddress: "1272345           messageHandler: messageHandler,
            configuration: configuration,
            logger: logger
        )
        
        try await transporter.start()
        print("✅ Transporter started on \(transporter.localAddress)")
        
        // Subscribe to peer updates
        Task[object Object]         for await peerUpdate in transporter.subscribeToPeerUpdates()[object Object]             print("📡 Peer update received: \(peerUpdate.nodeName)")
            }
        }
        
        // Keep the example running
        print("🔄 Example running... Press Ctrl+C to exit")
        try await Task.sleep(nanoseconds: 3000 seconds
        
        // Cleanup
        try await transporter.stop()
        print("✅ Example completed")
    }
}

// MARK: - Example Message Handler

class ExampleMessageHandler: MessageHandlerProtocol[object Object]
    func handle(_ message: RunarNetworkMessage) async throws[object Object]
        print("📨 Received message:)
        print(  From: \(message.sourceNodeId))
        print(  Type: \(message.messageType))
        print("  Payloads: \(message.payloads.count)")
        
        // Handle different message types
        switch message.messageType {
        case "Request":
            print("  📋 Processing request...")
            // In a real app, you would process the request and send a response
            
        case "Response":
            print("  ✅ Processing response...")
            
        case "Handshake":
            print("  🤝 Processing handshake...")
            
        default:
            print("  ❓ Unknown message type")
        }
    }
}

// MARK: - Helper Extensions

extension Data [object Object] /// Create a Data object filled with a repeating value
    init(repeating value: UInt8, count: Int) {
        self.init(repeating: value, count: count)
    }
} 