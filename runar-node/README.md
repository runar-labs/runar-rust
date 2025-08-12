# Runar Node

A high-performance, distributed service mesh framework for building privacy-preserving applications.

## Overview

The Runar Node provides a complete runtime environment for services to communicate, discover each other, and handle requests in a distributed, encrypted manner. It's designed to be lightweight, performant, and easy to integrate into existing applications.

## Key Features

- **Service Registry**: Automatic service discovery and registration
- **Request/Response**: Type-safe service-to-service communication
- **Event Publishing**: Publish/subscribe pattern for loose coupling
- **Network Transport**: QUIC-based networking with automatic peer discovery
- **Load Balancing**: Built-in load balancing for distributed services
- **Encryption**: End-to-end encryption with selective field access
- **Lifecycle Management**: Automatic service lifecycle management

## Quick Start

```rust
use runar_node::{Node, NodeConfig};
use runar_node::AbstractService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a node configuration
    let config = NodeConfig::new("my-node", "my-network");
    
    // Create and start the node
    let mut node = Node::new(config).await?;
    node.start().await?;
    
    // Your services can now communicate!
    Ok(())
}
```

## Architecture

The Runar Node is built around several core concepts:

- **Node**: The main runtime that manages services and networking
- **Services**: Business logic components that handle requests and publish events
- **Topics**: Hierarchical addressing system for routing messages
- **Network**: Peer-to-peer communication layer with automatic discovery
- **Registry**: Service discovery and metadata management

## Modules

- [`config`](src/config/) - Configuration management for nodes and services
- [`network`](src/network/) - Network transport, discovery, and peer management
- [`node`](src/node/) - Core node implementation and lifecycle management
- [`routing`](src/routing/) - Topic-based routing and path resolution
- [`services`](src/services/) - Service abstraction and registry management

## Service Implementation

Services implement the `AbstractService` trait and follow a consistent lifecycle:

```rust
use runar_node::services::{AbstractService, LifecycleContext};
use anyhow::Result;
use async_trait::async_trait;

#[derive(Clone)]
pub struct MyService {
    name: String,
    path: String,
}

#[async_trait]
impl AbstractService for MyService {
    fn name(&self) -> &str { &self.name }
    fn version(&self) -> &str { "1.0.0" }
    fn path(&self) -> &str { &self.path }
    fn description(&self) -> &str { "My example service" }
    fn network_id(&self) -> Option<String> { None }
    fn set_network_id(&mut self, _network_id: String) {}

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        // Register action handlers, set up connections, etc.
        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        // Start background tasks, timers, etc.
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        // Clean up resources, cancel tasks, etc.
        Ok(())
    }
}
```

## Configuration

The `NodeConfig` struct provides all configuration options:

```rust
use runar_node::{NodeConfig, config::LoggingConfig, network::network_config::NetworkConfig};

// Basic configuration
let config = NodeConfig::new("my-node", "my-network");

// Advanced configuration with networking
let config = NodeConfig::new("my-node", "my-network")
    .with_network_config(NetworkConfig::default())
    .with_request_timeout(5000)
    .with_additional_networks(vec!["backup-network".to_string()])
    .with_logging_config(LoggingConfig::default_info());
```

## Networking

Enable peer-to-peer communication by configuring networking:

```rust
use runar_node::network::{NetworkConfig, DiscoveryOptions, TransportOptions};

let network_config = NetworkConfig::default()
    .with_discovery(DiscoveryOptions::multicast("224.0.0.1:8888"))
    .with_transport(TransportOptions::quic(8889));

let config = NodeConfig::new("my-node", "my-network")
    .with_network_config(network_config);
```

## Topic Routing

The routing system provides hierarchical addressing for services and events:

```rust
use runar_node::routing::TopicPath;

// Create topic paths
let service_path = TopicPath::new("math", "my-network")?;
let action_path = TopicPath::new("math/add", "my-network")?;
let event_path = TopicPath::new("math/result", "my-network")?;

// Use wildcards for pattern matching
let pattern = TopicPath::new("math/*", "my-network")?;
assert!(pattern.matches(&action_path));

// Use template parameters for dynamic routing
let template = TopicPath::new("users/{user_id}/profile", "my-network")?;
let params = template.extract_parameters("users/123/profile")?;
assert_eq!(params.get("user_id"), Some("123"));
```

## Request Handling

Services can handle requests by registering action handlers:

```rust
use runar_node::services::{RequestContext, LifecycleContext};
use runar_serializer::ArcValue;

async fn init(&self, context: LifecycleContext) -> Result<()> {
    // Register action handlers
    context.register_action("add", |params, ctx| {
        Box::pin(async move {
            let a: f64 = params.get("a")?.as_primitive()?;
            let b: f64 = params.get("b")?.as_primitive()?.as_primitive()?;
            Ok(ArcValue::new_primitive(a + b))
        })
    }).await?;
    
    Ok(())
}
```

## Event Publishing

Services can publish events and subscribe to them:

```rust
use runar_node::services::{EventContext, PublishOptions};
use std::time::Duration;

// Publish an event
let options = PublishOptions {
    broadcast: true,
    guaranteed_delivery: false,
    retain_for: Some(Duration::from_secs(60)),
    target: None,
};

context.publish("math/result", Some(result_value), options).await?;

// Subscribe to events
context.subscribe("math/result", |ctx, data| {
    Box::pin(async move {
        println!("Received math result: {data:?}");
        Ok(())
    })
}).await?;
```

## Error Handling

The crate uses `anyhow::Result` for error handling throughout:

```rust
use anyhow::{Result, Context};

async fn my_service_method(&self) -> Result<()> {
    let result = some_operation()
        .context("Failed to perform operation")?;
    
    Ok(())
}
```

## Logging

The crate provides structured logging with context:

```rust
use runar_common::logging::{log_info, log_debug, log_error};

log_info!(logger, "Service started successfully");
log_debug!(logger, "Processing request: {request_id}");
log_error!(logger, "Operation failed: {error}");
```

## Thread Safety

All public types are designed to be shared across multiple threads and async tasks. The Node and its components use `Arc` for shared ownership and `DashMap` for concurrent access.

## Performance Considerations

- **Zero-copy local calls**: Services in the same binary communicate via in-memory function calls
- **Connection pooling**: Network connections are reused efficiently
- **Async operations**: All I/O operations are asynchronous
- **Lock-free reads**: Uses `DashMap` for concurrent read access

## Security Features

- **End-to-end encryption**: All network communication is encrypted
- **Selective field access**: Fine-grained control over data visibility
- **Key management**: Secure key storage and rotation
- **Network isolation**: Services can be isolated to specific networks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and ensure all tests pass before submitting a pull request.

## Support

For questions and support, please open an issue on GitHub or join our community discussions.
