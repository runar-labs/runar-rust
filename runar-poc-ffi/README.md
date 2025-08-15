# Rust FFI POC Implementation

This directory contains the Rust implementation of the FFI POC for communicating with Swift and Kotlin clients.

## Project Structure

```
runar-poc-ffi/
├── Cargo.toml          # Rust dependencies and build configuration
├── build.rs            # Build script for generating C headers
├── src/
│   ├── lib.rs          # Main library entry point
│   ├── types.rs        # SampleObject and error definitions
│   ├── transporter.rs  # Transporter trait and mock implementation
│   └── ffi.rs          # C-compatible FFI functions
└── README.md           # This file
```

## Building

### Prerequisites
- Rust toolchain (1.70+)
- `cbindgen` for generating C headers

### Build Commands
```bash
# Build the library
cargo build --release

# Run tests
cargo test

# Generate C headers (will be in target/out/)
cargo build
```

## FFI Interface

### Core Functions

#### `transporter_init() -> i32`
Initializes the transporter instance. Must be called before any other functions.

#### `transporter_cleanup() -> i32`
Cleans up the transporter instance and frees resources.

#### `transporter_request(...) -> i32`
Main function for processing requests from Swift/Kotlin clients.

**Parameters:**
- `topic`: C string pointer to the request topic
- `payload_bytes`: Pointer to CBOR serialized data
- `payload_len`: Length of the payload data
- `peer_node_id`: C string pointer to peer identifier
- `profile_public_key`: Pointer to profile public key bytes
- `profile_key_len`: Length of the profile key
- `response_callback`: Function pointer for successful responses
- `error_callback`: Function pointer for error responses

**Return:** Error code (0 = success, non-zero = error)

### Helper Functions

#### `create_test_object(...) -> i32`
Creates a test SampleObject and serializes it to CBOR for testing purposes.

#### `free_test_object_bytes(...) -> i32`
Frees memory allocated by `create_test_object`.

## Data Flow

1. **Swift/Kotlin** creates a `SampleObject` and serializes it to CBOR
2. **Swift/Kotlin** calls `transporter_request()` with the CBOR data
3. **Rust** deserializes the CBOR data to `SampleObject`
4. **Rust** modifies the object (doubles values, adds metadata)
5. **Rust** serializes the modified object back to CBOR
6. **Rust** calls the response callback with the modified CBOR data
7. **Swift/Kotlin** receives the callback and deserializes the data

## Error Handling

The implementation includes comprehensive error handling:

- **InvalidPointer**: Null pointer parameters
- **SerializationError**: CBOR serialization failures
- **DeserializationError**: CBOR deserialization failures
- **InvalidData**: Invalid string data
- **CallbackError**: Callback function errors
- **UnknownError**: Unexpected errors

## Testing

Run the test suite to verify the implementation:

```bash
cargo test
```

Tests cover:
- Object creation and modification
- CBOR serialization/deserialization
- Error detection and handling
- Memory management

## Memory Management

- All FFI functions validate pointer parameters
- Memory allocated by Rust functions must be freed using corresponding free functions
- The transporter instance is managed globally and cleaned up on `transporter_cleanup()`

## Threading

- The implementation uses Tokio runtime for async operations
- Callbacks are called from the same thread context
- Thread safety is maintained through proper synchronization

## Next Steps

1. **Swift Implementation**: Create Swift wrapper and callback implementations
2. **Kotlin Implementation**: Create Kotlin wrapper and callback implementations
3. **Integration Testing**: Test end-to-end communication
4. **Performance Optimization**: Profile and optimize serialization/deserialization
5. **Error Handling**: Add more specific error scenarios and recovery mechanisms
