# RunarTransporter

A Swift networking library for the Runar network, providing multiple transport protocols including QUIC-like transport that mimics the Rust `quic_transport.rs` implementation.

## Features

- **Multiple Transport Protocols**: Simple, Basic, TCP, and QUIC-like transports
- **QUIC-like Transport**: UDP-based transport with custom QUIC-like framing that mimics the Rust implementation
- **Async/Await Support**: Modern Swift concurrency with async/await
- **Message Handling**: Flexible message handling with protocol-based architecture
- **Connection Management**: Automatic connection lifecycle management
- **Peer Discovery**: Support for peer discovery and handshake protocols
- **Stream Management**: QUIC-like stream management for request-response patterns
- **Thread Safety**: Thread-safe implementations with proper locking

## Architecture

The library follows a layered architecture similar to the Rust implementation:

```
RunarTransporter (Public API)
├── SimpleTransporter (Basic implementation)
├── BasicTransporter (Enhanced features)
├── TcpTransporter (TCP-based networking)
└── QuicTransporter (QUIC-like UDP transport)
```

### QUIC-like Transport

The `QuicTransporter` implements a QUIC-like protocol over UDP that closely mimics the Rust `quic_transport.rs` implementation:

- **UDP-based**: Uses UDP with custom QUIC-like packet framing
- **Stream Management**: Supports unidirectional and bidirectional streams
- **Message Patterns**: Handles one-way, request-response, and response patterns
- **Handshake Protocol**: Implements node info exchange handshake
- **Connection Pooling**: Manages peer connections efficiently
- **TLS-like Security**: Framework for certificate-based security (configurable)

## Installation

### Swift Package Manager

Add the following dependency to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/your-repo/RunarTransporter.git", from: "1.0.0")
]
```

## Quick Start

### Basic Usage

```swift
import RunarTransporter
import Logging

// Set up logging
LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .info
    return handler
}

let logger = Logger(label: "example")

// Create node info
let publicKey = Data("my-node-public-key".utf8)
let nodeInfo = RunarNodeInfo(
    nodeId: NodeUtils.compactId(from: publicKey),
    nodePublicKey: publicKey,
    nodeName: "MyNode",
    addresses: ["127.0.0.1:8080"],
    metadata: ["version": "1.0"],
    createdAt: Date()
)

// Create message handler
let messageHandler = MyMessageHandler()

// Create QUIC-like transporter
let transporter = RunarTransporter.createQuicTransporter(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: messageHandler,
    options: QuicTransportOptions(),
    logger: logger
)

// Start the transporter
try await transporter.start()
```

### Message Handler

```swift
class MyMessageHandler: MessageHandlerProtocol {
    func handle(_ message: RunarNetworkMessage) async throws {
        print("Received message: \(message.messageType) from \(message.sourceNodeId)")
        
        if let payload = message.payloads.first {
            let value = String(data: payload.valueBytes, encoding: .utf8) ?? "unknown"
            print("Payload: \(value)")
        }
    }
}
```

### Connecting to Peers

```swift
// Create peer info
let peerPublicKey = Data("peer-public-key".utf8)
let peerInfo = RunarPeerInfo(
    publicKey: peerPublicKey,
    addresses: ["127.0.0.1:8081"]
)

// Connect to peer
try await transporter.connect(to: peerInfo)

// Send message
let message = RunarNetworkMessage(
    sourceNodeId: nodeInfo.nodeId,
    destinationNodeId: NodeUtils.compactId(from: peerPublicKey),
    messageType: "Hello",
    payloads: [
        NetworkMessagePayloadItem(
            path: "/greeting",
            valueBytes: "Hello, peer!".data(using: .utf8)!,
            correlationId: UUID().uuidString
        )
    ],
    timestamp: Date()
)

try await transporter.send(message)
```

## Transport Types

### SimpleTransporter

Basic implementation for testing and development:

```swift
let transporter = RunarTransporter.createSimpleTransporter(
    nodeInfo: nodeInfo,
    logger: logger
)
```

### BasicTransporter

Enhanced implementation with additional features:

```swift
let transporter = RunarTransporter.createBasicTransporter(
    nodeInfo: nodeInfo,
    logger: logger
)
```

### TcpTransporter

TCP-based networking with real network communication:

```swift
let transporter = RunarTransporter.createTcpTransporter(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: messageHandler,
    logger: logger
)
```

### QuicTransporter

QUIC-like transport with UDP and custom framing:

```swift
let options = QuicTransportOptions(
    verifyCertificates: true,
    keepAliveInterval: 15,
    connectionIdleTimeout: 60,
    streamIdleTimeout: 30,
    maxIdleStreamsPerPeer: 100
)

let transporter = RunarTransporter.createQuicTransporter(
    nodeInfo: nodeInfo,
    bindAddress: "127.0.0.1:8080",
    messageHandler: messageHandler,
    options: options,
    logger: logger
)
```

## QUIC-like Transport Details

The QUIC-like transport implements the following features from the Rust `quic_transport.rs`:

### Stream Types

- **Unidirectional Streams**: For one-way messages (handshakes, announcements)
- **Bidirectional Streams**: For request-response communication

### Message Patterns

- **OneWay**: Messages that don't expect responses
- **RequestResponse**: Request messages that expect responses
- **Response**: Response messages sent back on existing streams

### Handshake Protocol

1. Client sends `NODE_INFO_HANDSHAKE` message
2. Server responds with `NODE_INFO_HANDSHAKE_RESPONSE`
3. Both sides exchange node information
4. Connection is established for message exchange

### Packet Structure

```swift
struct QuicPacket: Codable {
    let streamType: StreamType      // unidirectional or bidirectional
    let streamId: UInt64           // unique stream identifier
    let message: RunarNetworkMessage // the actual message
}
```

### Connection Management

- Automatic peer connection tracking
- Connection health monitoring
- Graceful connection cleanup
- Stream correlation for request-response pairs

## Examples

### QUIC-like Transport Example

See `Examples/QuicExample.swift` for a complete example of two QUIC-like transporters communicating over the network.

### TCP Transport Example

See `Examples/TcpExample.swift` for a complete example of TCP-based communication.

## Testing

Run the test suite:

```bash
swift test
```

The tests cover:
- Transport creation and lifecycle
- Connection management
- Message sending and receiving
- Error handling
- Factory methods

## Error Handling

The library provides comprehensive error handling:

```swift
enum TransportError: Error {
    case transportNotRunning
    case peerNotConnected(String)
    case connectionFailed(String)
    case serializationError(String)
    case messageError(String)
}
```

## Thread Safety

All transporters are thread-safe and can be used from multiple concurrent contexts. The QUIC-like transport uses async-safe locking mechanisms for proper concurrency handling.

## Performance

The QUIC-like transport is designed for high-performance networking:
- Efficient UDP packet handling
- Stream reuse for request-response patterns
- Minimal memory allocation
- Async/await for non-blocking operations

## Roadmap

- [ ] Full QUIC protocol implementation
- [ ] TLS certificate support
- [ ] Connection multiplexing
- [ ] Flow control
- [ ] Congestion control
- [ ] NAT traversal
- [ ] IPv6 support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 