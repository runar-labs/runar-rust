# Runar iOS FFI POC

Minimal Rust FFI bindings for the Runar distributed system.

## Features

- ✅ C-compatible FFI functions
- ✅ Node creation and management
- ✅ Request/response echo service
- ✅ Callback system support
- ✅ Static library generation

## Structure

```
runar-ios-ffi/
├── src/
│   └── lib.rs              # All FFI functions
├── Cargo.toml              # Minimal dependencies
├── build.rs                # C header generation
└── cbindgen.toml           # C binding configuration
```

## FFI Functions

### Node Management
- `runar_node_create(config)` - Create a new node
- `runar_node_start(node, callback)` - Start a node

### Request/Response
- `runar_node_request(node, path, data, len, callback)` - Send request

### Testing
- `test_function()` - Simple test function

## Building

```bash
# Build static library
cargo build --release

# Generate C headers
cargo build
```

## Usage

The static library `librunar_ios_ffi_macos.a` can be linked with Swift applications.

## Dependencies

- `libc` - C types and functions
- `cbindgen` - C header generation 