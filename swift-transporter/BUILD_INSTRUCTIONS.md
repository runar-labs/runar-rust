# Build Instructions for RunarTransporter

## Prerequisites

1**Install Swift**: Download and install Swift from [swift.org](https://swift.org/download/)
2 **Install Xcode** (for macOS): Download from the App Store
3. **Verify Installation**: Run `swift --version` to confirm Swift is installed

## Building the Package

### From Command Line

```bash
# Navigate to the swift-transporter directory
cd swift-transporter

# Build the package
swift build

# Run tests
swift test

# Build for release
swift build -c release
```

### From Xcode1Open Xcode
2. File → Open Package3 Select the `swift-transporter` directory
4. Wait for package resolution
5 Build using Cmd+B

## Running Examples

```bash
# Build and run the basic example
swift run BasicExample

# Or build and run from Xcode
# Select the BasicExample target and run
```

## Testing Interoperability with Rust

To test communication between Swift and Rust implementations:

1. **Start Rust Node**:
   ```bash
   cd runar-node
   cargo run --example basic_node
   ```2**Start Swift Node**:
   ```bash
   cd swift-transporter
   swift run BasicExample
   ```

3. **Verify Communication**:
   - Check logs for handshake messages
   - Verify peer discovery
   - Test message exchange

## Troubleshooting

### Common Issues

1. **Swift not found**: Install Swift from swift.org
2. **Package resolution fails**: Check internet connection and try `swift package resolve`3 **Build errors**: Ensure all dependencies are compatible with Swift 5.9+

### Dependencies

The package uses the following dependencies:
- swift-nio: Network I/O framework
- swift-nio-ssl: TLS/SSL support
- swift-log: Structured logging
- swift-crypto: Cryptographic operations
- swift-async-algorithms: Async sequence utilities

## Platform Support

- ✅ macOS 13.0
- ✅ iOS 160+
- ✅ tvOS 16.0- ✅ watchOS 9.0erformance Testing

```bash
# Run performance tests
swift test --filter PerformanceTests

# Benchmark message throughput
swift run PerformanceBenchmark
```

## Security Testing

```bash
# Run security tests
swift test --filter SecurityTests

# Test TLS certificate validation
swift run SecurityTest
``` 