# Runar Swift QUIC Transporter

A Swift implementation of the Runar QUIC transport protocol using Apple's Network.framework. This implementation is designed to be compatible with the Rust QUIC transport and follows the same data flow, handshake protocol, and peer management patterns.

**Status**: 🚧 In Development - Core components implemented, some compilation issues remain

> **Note**: This is a work-in-progress implementation. See [CONTINUATION_GUIDE.md](CONTINUATION_GUIDE.md) for detailed status and next steps.

## Features

- **Network.framework QUIC**: Uses Apple's native QUIC implementation for optimal performance on macOS and iOS
- **Rust Compatibility**: Matches the Rust QUIC transport architecture and message flow
- **Handshake Protocol**: Implements the same handshake protocol as the Rust version
- **Peer Management**: Connection pooling and peer state tracking
- **Message Correlation**: Request-response correlation for reliable communication
- **Service Discovery**: Node capability exchange and service metadata handling

## Requirements

- macOS 12.0+ or iOS 15.0+ (for QUIC support)
- Swift 5.9+
- Xcode 13.0+

> **Note**: The Network.framework QUIC APIs require macOS 12.0+ and iOS 15.0+. The implementation includes fallback options for older versions.

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "path/to/runar-swift-transporter", from: "1.0.0")
]
```

## Quick Start

```swift
import Foundation
import os.log
import RunarTransporter

@available(macOS 12.0, iOS 15.0, *)
class MyTransportExample {
    
    private let logger = Logger(subsystem: "com.myapp.transport", category: "example")
    private var transport: TransportProtocol?
    
    func startTransport() async throws {
        // 1. Create node info
        let nodePublicKey = Data(repeating: 0x42, count: 32) // Your actual public key
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: nodePublicKey,
            networkIds: ["my-network"],
            addresses: ["127.0.0.1:8080"],
            services: [
                ServiceMetadata(
                    servicePath: "/my/service",
                    networkId: "my-network",
                    serviceName: "MyService",
                    actions: [
                        ActionMetadata(
                            actionPath: "/my/action",
                            actionName: "myAction",
                            description: "My action"
                        )
                    ]
                )
            ]
        )
        
        // 2. Create message handler
        let messageHandler = MyMessageHandler(logger: logger)
        
        // 3. Create transport
        transport = RunarTransporter.createQuicTransport(
            nodeInfo: nodeInfo,
            bindAddress: "127.0.0.1:8080",
            messageHandler: messageHandler,
            logger: logger
        )
        
        // 4. Start transport
        try await transport?.start()
        
        // 5. Connect to peers
        let peerInfo = RunarPeerInfo(
            publicKey: Data(repeating: 0x43, count: 32),
            addresses: ["127.0.0.1:8081"]
        )
        try await transport?.connect(to: peerInfo)
        
        // 6. Send messages
        let message = RunarNetworkMessage(
            sourceNodeId: nodeInfo.nodeId,
            destinationNodeId: peerInfo.peerId,
            messageType: MessageTypes.REQUEST,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "/my/action",
                    valueBytes: "Hello!".data(using: .utf8)!,
                    correlationId: NodeUtils.generateCorrelationId()
                )
            ]
        )
        try await transport?.send(message: message)
    }
}

// Message handler implementation
@available(macOS 12.0, iOS 15.0, *)
class MyMessageHandler: MessageHandlerProtocol {
    private let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func handleMessage(_ message: RunarNetworkMessage) {
        logger.info("Received message: \(message.messageType) from \(message.sourceNodeId)")
        // Handle the message
    }
    
    func peerConnected(_ peerInfo: RunarNodeInfo) {
        logger.info("Peer connected: \(peerInfo.nodeId)")
        // Handle peer connection
    }
    
    func peerDisconnected(_ peerId: String) {
        logger.info("Peer disconnected: \(peerId)")
        // Handle peer disconnection
    }
}
```

## Current Status

### ✅ Completed
- Core data models matching Rust implementation
- Transport protocol interfaces
- Configuration options
- Factory methods for transport creation
- Simple Network.framework implementation
- Handshake protocol
- Message encoding/decoding (JSON-based)
- Basic peer management

### ⚠️ Known Issues
- Type annotation ambiguity in `SimpleNetworkTransporter.swift` (lines 169, 230)
- NetworkQuicTransporter temporarily disabled due to API compatibility issues
- Some Network.framework QUIC APIs require specific macOS/iOS versions

### 🔄 Next Steps
See [CONTINUATION_GUIDE.md](CONTINUATION_GUIDE.md) for detailed next steps and implementation guidance.

## Architecture

The Swift implementation follows the same architecture as the Rust QUIC transport:

### Core Components

1. **NetworkQuicTransporter**: Main transport implementation using Network.framework
2. **TransportProtocol**: Interface defining transport operations
3. **MessageHandlerProtocol**: Interface for handling incoming messages and peer events
4. **RunarNodeInfo**: Node information structure (matches Rust NodeInfo)
5. **RunarPeerInfo**: Peer discovery information (matches Rust PeerInfo)
6. **RunarNetworkMessage**: Network message structure (matches Rust NetworkMessage)

### Message Flow

The message flow matches the Rust implementation:

1. **Handshake**: `NODE_INFO_HANDSHAKE` → `NODE_INFO_HANDSHAKE_RESPONSE`
2. **Requests**: `Request` messages with correlation IDs
3. **Responses**: `Response` messages with matching correlation IDs
4. **Updates**: `NODE_INFO_UPDATE` for capability changes

### Peer Management

- **Connection Pooling**: Manages active connections to peers
- **Peer State Tracking**: Tracks connection state and activity
- **Handshake Tracking**: Manages handshake state for new connections
- **Request Correlation**: Tracks pending requests for response matching

## Configuration Options

```swift
// Default options
let defaultOptions = NetworkQuicTransportOptions.default()

// Mobile optimized options
let mobileOptions = NetworkQuicTransportOptions.mobileOptimized()

// High performance options
let perfOptions = NetworkQuicTransportOptions.highPerformance()

// Custom options with certificates
let secureOptions = NetworkQuicTransportOptions.withCertificates(
    certificates: [certData],
    privateKey: keyData
)
```

## Transport Factory Methods

```swift
// Basic transport
let transport = RunarTransporter.createQuicTransport(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: handler,
    logger: logger
)

// Mobile optimized transport
let mobileTransport = RunarTransporter.createMobileQuicTransport(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: handler,
    logger: logger
)

// Secure transport with certificates
let secureTransport = RunarTransporter.createSecureQuicTransport(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: handler,
    certificates: [certData],
    privateKey: keyData,
    logger: logger
)
```

## Rust Compatibility

The Swift implementation is designed to be compatible with the Rust QUIC transport:

### Matching Features

- **Same Message Types**: Uses identical message type constants
- **Same Handshake Protocol**: Implements the same handshake flow
- **Same Node Info Structure**: Matches the Rust NodeInfo structure
- **Same Peer Management**: Similar connection pooling and state tracking
- **Same Message Flow**: Request-response correlation and message routing

### Differences

- **Platform**: Uses Network.framework instead of Quinn
- **TLS**: Uses Apple's TLS implementation instead of rustls
- **Serialization**: Uses JSON for now (can be upgraded to protobuf)
- **Certificate Validation**: Uses Apple's certificate validation

## Testing

Run the tests to verify the implementation:

```bash
swift test
```

The test suite includes:
- Node info creation and validation
- Peer info handling
- Message creation and serialization
- Transport options configuration
- Transport creation and basic operations

## Examples

See the `Examples/` directory for complete usage examples:

- `BasicUsage.swift`: Basic transport usage example
- Additional examples for specific use cases

## Development

### Building

```bash
swift build
```

### Running Tests

```bash
swift test
```

### Running Examples

```bash
swift run BasicUsage
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the same license as the main Runar project.

## Roadmap

- [ ] Protobuf message serialization
- [ ] Certificate validation for node IDs
- [ ] Stream management improvements
- [ ] Performance optimizations
- [ ] Additional transport options
- [ ] Integration with Rust QUIC transport for testing 