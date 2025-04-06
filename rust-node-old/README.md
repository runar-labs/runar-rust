# Rust Node (Original Implementation)

This directory contains the original implementation of the Rust Node system, kept for reference purposes.

**IMPORTANT**: This code is not actively maintained and is NOT compiled with the rest of the project. The Cargo.toml has been renamed to Cargo.toml.reference to prevent compilation.

The active implementation is in the `rust-node` directory.

## Purpose

This reference implementation is kept to:
1. Preserve the history of the codebase
2. Provide examples of the original approach
3. Serve as a reference for understanding design decisions in the new implementation

## Notes

- No changes should be made to this code
- For all development work, use the `rust-node` directory
- The `Cargo.toml.reference` file contains the original dependencies and configuration

# Runar Node

Runar Node is the core component of the Runar system, providing a modular service-based architecture for building distributed applications. It offers a robust foundation for service definition, discovery, communication, and management.

## Features

- **Service-oriented Architecture**: Define and manage services with clean, consistent interfaces
- **P2P Communication**: Built-in peer-to-peer networking capabilities
- **Event-driven System**: Subscribe to and publish events across services 
- **Modular Design**: Easily extend and compose services
- **Persistent Storage**: Built-in SQLite database integration
- **Cross-platform**: Works on Linux, macOS, and Windows

## Getting Started

### Installation

Add runar_node to your Cargo.toml:

```toml
[dependencies]
runar_node = { git = "https://github.com/runar-labs/rust-mono", package = "runar_node" }
runar_macros = { git = "https://github.com/runar-labs/rust-mono", package = "runar_macros" }
```

### Basic Usage

```rust
use runar_node::{Node, NodeConfig};
use runar_macros::service;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a node configuration
    let config = NodeConfig::new("my_network", "/tmp/runar", "/tmp/runar/data.db");
    
    // Create and initialize a node
    let mut node = Node::new(config).await?;
    node.init().await?;
    
    // Register services
    // node.add_service(MyService::new()).await?;
    
    // Request from a service
    // let response = node.request("my_service/operation", json!({})).await?;
    
    Ok(())
}
```

## Creating Services

Services can be created using the `service` macro from `runar_macros`:

```rust
use runar_macros::{service, action};
use runar_node::services::{ServiceResponse, RequestContext, ValueType, AbstractService};
use anyhow::Result;

#[service(
    name = "hello_service",
    description = "A simple hello world service"
)]
struct HelloService {
    counter: std::sync::atomic::AtomicU64,
}

impl HelloService {
    fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    #[action]
    async fn greet(&self, name: String) -> Result<ServiceResponse> {
        let count = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ServiceResponse::success(
            format!("Hello, {}! You are visitor #{}", name, count + 1),
            None
        ))
    }
}
```

## Documentation

For more detailed documentation, refer to the API documentation and examples in the [rust-docs](../rust-docs) directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
