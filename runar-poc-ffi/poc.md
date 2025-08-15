# Rust-Swift FFI POC: Transporter Interface

## Overview
This POC demonstrates Foreign Function Interface (FFI) communication between Rust and Swift and kotlin using a simplified transporter interface. The goal is to validate bidirectional data serialization/deserialization using CBOR format.

## Architecture
- **Swift/Kotlin Side**: Client that creates objects, serializes them, and calls the Rust transporter
- **Rust Side**: Transporter implementation with mock logic that processes requests and calls back to Swift/Kotlin
- **Communication**: FFI bridge using C-compatible types and callback functions

## Interface Definition

### Callback Types
```rust
// Response callback: called when request succeeds
pub type ResponseCallback = extern "C" fn(payload_bytes: *const u8, payload_len: usize);

// Error callback: called when request fails
pub type ErrorCallback = extern "C" fn(error_code: u32, error_message: *const c_char);
```

### Transporter Trait
```rust
#[async_trait]
pub trait Transporter {
    async fn request(
        &self,
        topic: &str,
        payload_bytes: &[u8],
        peer_node_id: &str,
        profile_public_key: &[u8],
        response_callback: ResponseCallback,
        error_callback: ErrorCallback,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
```

### FFI Interface (C-compatible)
```rust
#[no_mangle]
pub extern "C" fn transporter_request(
    topic: *const c_char,
    payload_bytes: *const u8,
    payload_len: usize,
    peer_node_id: *const c_char,
    profile_public_key: *const u8,
    profile_key_len: usize,
    response_callback: ResponseCallback,
    error_callback: ErrorCallback,
) -> i32;
```

## Sample Data Objects

### Rust Side
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleObject {
    pub id: u64,
    pub name: String,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
    pub values: Vec<f64>,
}
```

### Swift Side
```swift
struct SampleObject: Codable {
    let id: UInt64
    let name: String
    let timestamp: UInt64
    let metadata: [String: String]
    let values: [Double]
}
```

### Kotlin Side
```kotlin
data class SampleObject(
    val id: ULong,
    val name: String,
    val timestamp: ULong,
    val metadata: Map<String, String>,
    val values: List<Double>
)
```

## Workflow

### 1. Swift/Kotlin Side (Client)
1. Create a `SampleObject` instance
2. Serialize to CBOR bytes using Swift/Kotlin CBOR library
3. Call Rust transporter via FFI
4. Provide response and error callback functions

### 2. Rust Side (Transporter)
1. Receive CBOR bytes from Swift
2. Deserialize to `SampleObject` to validate format
3. Modify object fields (e.g., add processing timestamp, modify values)
4. Serialize modified object back to CBOR
5. Call Swift response callback with modified data

### 3. Swift/Kotlin Side (Validation)
1. Receive modified CBOR bytes via callback
2. Deserialize back to `SampleObject`
3. Verify that modifications were applied correctly

### Error Handling Scenario
For error testing, the Swift/Kotlin side sends a `SampleObject` with `name = "ERROR"` so the Rust side knows to return an error via the error callback.

## Technical Requirements

### Dependencies
- **Rust**: `serde`, `serde_cbor`, `async-trait`, `libc`
- **Swift**: CBOR serialization library (e.g., `CBORCoding`)
- **Kotlin**: CBOR serialization library (e.g., `kotlinx-serialization-cbor`)
- **Build**: `cbindgen` for generating C headers

### Error Handling
- Define standard error codes for common failure scenarios
- Provide meaningful error messages for debugging
- Handle memory allocation/deallocation safely

### Memory Management
- Use `Box::into_raw` and `Box::from_raw` for safe pointer handling
- Ensure proper cleanup of allocated memory
- Validate pointer parameters before use

### Threading
- Handle async operations safely across FFI boundary
- Ensure callbacks are called on appropriate threads
- Consider using dispatch queues for Swift callbacks
- For Kotlin, ensure callbacks are called on the main thread or appropriate coroutine context

## Success Criteria
1. ✅ Swift/Kotlin can create objects and serialize to CBOR
2. ✅ Rust can deserialize Swift/Kotlin's CBOR data
3. ✅ Rust can modify objects and serialize back to CBOR
4. ✅ Swift/Kotlin can deserialize Rust's modified CBOR data
5. ✅ End-to-end data integrity is maintained
6. ✅ Error scenarios are handled gracefully
7. ✅ Memory leaks are prevented

 


