# Swift Transporter Library

A Swift implementation of the Runar network transporter, designed to communicate with the Rust QUIC transporter implementation.

## Features

- **QUIC Transport**: High-performance networking using Swift NIO
- **Interoperability**: Compatible with Rust implementation
- **Modern Swift**: Async/await, structured concurrency
- **TLS Security**: Encrypted communications
- **Comprehensive Testing**: Unit and end-to-end tests
- **Cross-Platform**: Works on macOS, Linux, and iOS

## Installation

### Prerequisites

- Swift 5.9+ (for async/await support)
- Swift Package Manager

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: 
    .package(url: "https://github.com/your-org/swift-transporter.git, from: 1.0.0)
]
```

## Quick Start

```swift
import RunarTransporter
import Logging

// Set up logging
LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .info
    return handler
}

// Create node information
let publicKey = Data(your-public-key".utf8)
let nodeInfo = RunarNodeInfo(
    nodeId: NodeUtils.compactId(from: publicKey),
    nodePublicKey: publicKey,
    nodeName: MyNode,
    nodeVersion:10  nodeCapabilities: ["basic-transport"],
    nodeMetadata: [:]
)

// Create message handler
let messageHandler = MyMessageHandler()

// Create transporter
let transporter = RunarTransporter.createBasicTransporter(
    nodeInfo: nodeInfo,
    bindAddress: 1278080    messageHandler: messageHandler,
    configuration: TransportConfiguration(),
    logger: Logger(label: "my-app)
)

// Start the transporter
try await transporter.start()

// Connect to a peer
let peerInfo = RunarPeerInfo(/* ... */)
try await transporter.connect(to: peerInfo)

// Send a message
let message = RunarNetworkMessage(/* ... */)
try await transporter.send(message)

// Subscribe to peer updates
let peerUpdates = transporter.subscribeToPeerUpdates()
for await peerInfo in peerUpdates {
    print("Received peer update: \(peerInfo)")
}
```

## End-to-End Testing

The library includes comprehensive end-to-end tests that demonstrate two transporter instances communicating over the network.

### Running End-to-End Tests

```bash
# Run the end-to-end tests
swift test --filter EndToEndTests

# Run a specific test
swift test --filter EndToEndTests/testBasicCommunication
```

### Manual Network Test

You can also run a manual network test to see two transporters communicating:

```bash
# Run the network test script
swift run NetworkTest
```

This will:
1. Create two transporter instances
2. Start both transporters on different ports
3. Establish a connection between them
4. Send messages back and forth
5. Test peer updates and bidirectional communication

### Test Coverage

The end-to-end tests cover:

- **Basic Communication**: Simple message exchange between two transporters
- **Bidirectional Communication**: Messages flowing in both directions
- **Peer Updates**: Node information updates across the network
- **Connection Lifecycle**: Connect, send messages, disconnect
- **Error Handling**: Invalid connections and message sending

### Example Test Output

```
🚀 Starting basic communication test
✅ Both transporters started
✅ Transporter1 connected to Transporter2
✅ Test message sent from Transporter1to Transporter2
📨 [Handler2] Received message: TestMessage
   From: test-node-1
   To: test-node-2
   Payload: Hello from Transporter1!
✅ Basic communication test completed successfully
```

## Architecture

### Core Components

- **TransportProtocol**: Main interface for transport implementations
- **BasicTransporter**: Simple transport implementation for testing
- **QuicTransporter**: Full QUIC implementation (in development)
- **MessageHandlerProtocol**: Interface for message processing
- **RunarNetworkMessage**: Network message format

### Interoperability with Rust

The Swift implementation is designed to be fully compatible with the Rust QUIC transporter:

- **Message Format**: Identical message structures and serialization
- **Node ID Generation**: Same compact ID algorithm
- **Handshake Protocol**: Compatible NODE_INFO_HANDSHAKE messages
- **TLS Security**: Compatible certificate handling

## Configuration

```swift
let configuration = TransportConfiguration(
    verifyCertificates: true,
    keepAliveInterval: 150,
    connectionIdleTimeout: 600 streamIdleTimeout: 300
    maxIdleStreamsPerPeer: 100,
    certificates: certificates,
    privateKey: privateKey,
    rootCertificates: rootCertificates,
    logLevel: .info
)
```

## Error Handling

The library provides comprehensive error handling:

```swift
do {
    try await transporter.send(message)
} catch RunarTransportError.connectionError(let message) {
    print(Connection error: \(message)")
} catch RunarTransportError.messageError(let message) {
    print(Message error: \(message)")
} catch [object Object]print("Other error: \(error)")
}
```

## Testing

### Unit Tests

```bash
swift test
```

### Integration Tests

```bash
swift test --filter IntegrationTests
```

### Performance Tests

```bash
swift test --filter PerformanceTests
```

## Building

### Development Build

```bash
swift build
```

### Release Build

```bash
swift build -c release
```

### Documentation

```bash
swift package generate-documentation
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Status

- ✅ Core data models and protocols
- ✅ Basic transport implementation
- ✅ End-to-end testing framework
- ✅ Interoperability design
- 🔧 QUIC transport implementation (in progress)
- 🔧 TLS certificate handling (in progress)
- 🔧 Performance optimization (planned)

The library provides a solid foundation for Swift-based Runar network communication with a working basic transport implementation and comprehensive testing framework. 