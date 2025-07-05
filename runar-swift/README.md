# Runar Swift POC

Minimal Swift↔Rust FFI proof of concept for the Runar distributed system.

## Features

- ✅ Swift ↔ Rust FFI communication
- ✅ Node creation and management
- ✅ Request/response with echo service
- ✅ Callback system for async operations
- ✅ Comprehensive test suite

## Structure

```
runar-swift/
├── Sources/RunarSwift/
│   ├── RunarSwift.swift      # Main API
│   ├── RunarTypes.swift      # FFI type definitions
│   ├── RunarError.swift      # Error handling
│   ├── FFICallbacks.swift    # Callback implementations
│   └── Resources/            # Rust static library
└── Tests/RunarSwiftTests/
    ├── RunarSwiftTests.swift # Main test suite
    └── RequestFFITest.swift  # FFI-specific tests
```

## Usage

```swift
import RunarSwift

// Create a node
let config = NodeConfig(
    nodeId: "test-node",
    networkId: "test-network",
    requestTimeoutMs: 5000,
    logLevel: "info"
)
let node = try RunarSwift.createNode(config: config)

// Start the node
node.start { result in
    // Handle start result
}

// Send a request
node.request(path: "/mock/echo", data: "Hello, World!") { result in
    switch result {
    case .success(let response):
        print("Response: \(response)")
    case .failure(let error):
        print("Error: \(error)")
    }
}
```

## Building

1. Build the Rust static library:
   ```bash
   cd ../runar-ios-ffi
   cargo build --release
   ```

2. Copy the library to Swift resources:
   ```bash
   cp target/release/librunar_ios_ffi_macos.a ../runar-swift/Sources/RunarSwift/Resources/
   ```

3. Run Swift tests:
   ```bash
   cd ../runar-swift
   swift test
   ```

## FFI Functions

- `runar_node_create` - Create a new node
- `runar_node_start` - Start a node with callback
- `runar_node_request` - Send request to service
- `test_function` - Simple test function 