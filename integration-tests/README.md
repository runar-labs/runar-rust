# Cross-Platform QUIC Transport Integration Testing

This directory contains a comprehensive test suite for validating communication between the Rust and Swift QUIC transport implementations.

## Overview

The test suite validates that both transport implementations can:
- Establish QUIC connections with each other
- Exchange messages using the same protocol
- Handle certificates and TLS properly
- Manage connection lifecycle correctly
- Process different message types (Request, Response, Handshake, etc.)

## Architecture

### Test Components

1. **Rust Transport Test** (`rust-transport-test.rs`)
   - Uses Quinn 0.11.x with rustls
   - Implements the same protocol as the main Rust transport
   - Runs in a Docker container for isolation

2. **Swift Transport Test** (`SwiftTransportTest.swift`)
   - Uses Network.framework QUIC
   - Implements the same protocol as the main Swift transport
   - Runs in a Docker container for isolation

3. **Test Coordinator** (`test-coordinator/`)
   - Orchestrates the test execution
   - Monitors service health
   - Collects and analyzes results
   - Generates test reports

4. **Docker Compose Environment** (`docker-compose.yml`)
   - Manages all test services
   - Provides isolated network environment
   - Handles service dependencies

### Test Scenarios

1. **Health Check Test**
   - Verifies both services are running and healthy
   - Checks basic connectivity

2. **Basic Connection Test**
   - Tests QUIC connection establishment
   - Validates handshake protocol

3. **Message Exchange Test**
   - Tests sending/receiving messages
   - Validates request-response patterns
   - Tests different message types

4. **Protocol Compatibility Test**
   - Validates message serialization
   - Tests certificate validation
   - Checks stream management
   - Verifies error handling

5. **Performance Test**
   - Measures latency and throughput
   - Tests connection establishment time

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.7+ (for result analysis)
- Bash shell

### Running Tests

```bash
# Run the complete test suite
cd integration-tests
./run-tests.sh

# Run with specific options
./run-tests.sh --docker    # Use Docker (default)
./run-tests.sh --local     # Run locally (development)
./run-tests.sh --help      # Show help
```

### Manual Testing

```bash
# Start the test environment
cd integration-tests
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs rust-transport
docker-compose logs swift-transport
docker-compose logs test-coordinator

# Run coordinator manually
docker-compose exec test-coordinator cargo run --bin test-coordinator

# Stop environment
docker-compose down
```

## Test Results

### Output Locations

- **Logs**: `integration-tests/test-logs/`
- **Results**: `integration-tests/test-results/`
- **Reports**: `integration-tests/test-results/test-report.md`

### Result Format

```json
{
  "test_id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "success": true,
  "duration_ms": 1500,
  "details": {
    "connection_established": true,
    "messages_sent": 5,
    "messages_received": 5
  },
  "errors": []
}
```

## Troubleshooting

### Common Issues

1. **Certificate Issues**
   ```
   Error: Certificate validation failed
   Solution: Check that both transports use compatible certificate formats
   ```

2. **Connection Timeout**
   ```
   Error: Connection timeout after 30 seconds
   Solution: Check network configuration and firewall settings
   ```

3. **Protocol Mismatch**
   ```
   Error: Message deserialization failed
   Solution: Verify message format compatibility between implementations
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug
export SWIFT_LOG_LEVEL=debug

# Run with verbose output
./run-tests.sh --docker 2>&1 | tee debug.log
```

### Network Debugging

```bash
# Check network connectivity
docker-compose exec network-monitor netstat -tuln

# Monitor QUIC connections
docker-compose exec network-monitor ss -tuln | grep :5000

# Check container networking
docker network inspect integration-tests_runar-test-network
```

## Development

### Adding New Tests

1. **Add test to coordinator** (`test-coordinator/src/main.rs`):
   ```rust
   self.run_test("new_test_name", |this| async move {
       this.test_new_functionality().await
   }).await?;
   ```

2. **Implement test function**:
   ```rust
   async fn test_new_functionality(&self) -> Result<HashMap<String, serde_json::Value>> {
       // Test implementation
       Ok(details)
   }
   ```

3. **Update test scenarios** in both transport implementations

### Modifying Transport Tests

- **Rust**: Edit `rust-transport-test.rs`
- **Swift**: Edit `SwiftTransportTest.swift`

### Custom Test Environment

```bash
# Create custom docker-compose override
cp docker-compose.yml docker-compose.override.yml

# Modify services as needed
# Run with override
docker-compose -f docker-compose.yml -f docker-compose.override.yml up
```

## Protocol Compatibility

### Message Types

Both implementations must support:
- `Request` - RPC-style requests
- `Response` - RPC-style responses  
- `Handshake` - Initial connection setup
- `Announcement` - Service discovery
- `Heartbeat` - Connection keep-alive

### Message Format

```protobuf
message NetworkMessage {
    string source_node_id = 1;
    string destination_node_id = 2;
    string message_type = 3;
    repeated NetworkMessagePayloadItem payloads = 4;
}

message NetworkMessagePayloadItem {
    string path = 1;
    bytes value_bytes = 2;
    string correlation_id = 3;
}
```

### Certificate Requirements

- Both implementations must support X.509 certificates
- Certificate validation should be configurable
- Node ID must be embedded in certificate SAN or CN
- CA certificate chain validation

## Performance Benchmarks

### Expected Metrics

- **Connection Time**: < 500ms
- **Message Latency**: < 50ms
- **Throughput**: > 100 Mbps
- **Concurrent Connections**: > 100

### Running Benchmarks

```bash
# Run performance tests
./run-tests.sh --docker

# Analyze results
python3 analyze_performance.py test-results/results.json
```

## Continuous Integration

### GitHub Actions

```yaml
name: Cross-Platform QUIC Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Integration Tests
        run: |
          cd integration-tests
          ./run-tests.sh --docker
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: integration-tests/test-results/
```

## Contributing

1. **Add tests** for new functionality
2. **Update documentation** for protocol changes
3. **Ensure compatibility** between implementations
4. **Run full test suite** before submitting PR

## Support

For issues with the test suite:
1. Check the troubleshooting section
2. Review logs in `test-logs/`
3. Create an issue with detailed error information
4. Include test results and environment details 