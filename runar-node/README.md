Runar Node
==========

The core runtime for the Runar framework. A Node manages service lifecycles,
routes requests, publishes/consumes events, and coordinates networking.

Core principles
---------------

- **Service-first design**: clear lifecycle (init → start → stop), strong service boundaries
- **Typed requests/events**: explicit schemas; predictable extraction and routing
- **Secure by default**: QUIC/TLS, X.509 (P-256), envelope encryption integrations
- **Distributed by design**: discovery, remote handlers, load balancing
- **Observability**: structured logging with component/context

Features
--------

- Service registry and lifecycle management
- Local and remote request routing with load balancing
- Event publish/subscribe with retained delivery options
- QUIC networking with strict certificate validation
- Peer discovery (multicast) and capability propagation
- Retained event store and wildcard subscriptions
- Pluggable label resolver and keystore integrations

Quick start
-----------

```rust
use runar_node::{Node, NodeConfig};

# async fn run() -> anyhow::Result<()> {
let config = NodeConfig::new("my-node", "default-network");
let  node = Node::new(config).await?;

// Add your services here (see runar-macros for easy definitions)
// node.add_service(MyService::new()).await?;

node.start().await?;
node.wait_for_services_to_start().await?;

// Make a local request (service must register an action at this path)
// let resp = node.request::<()> ("my-service/ping", None).await?;

node.stop().await?;
Ok(())
# }
```

Defining services (with macros)
-------------------------------

Use `runar_macros` to declare services and actions succinctly. See that crate’s
README for a full example. Conceptually:

```rust
use anyhow::Result;
use runar_macros::{service, action};

#[service(name = "EchoService", path = "echo-service", description = "Echo", version = "1.0.0")]
struct EchoService;

#[service]
impl EchoService {
    #[action]
    async fn ping(&self) -> Result<String> { Ok("pong".to_string()) }
}
```

Networking
----------

- QUIC transport with TLS certificates issued by the mobile CA (P-256)
- Discovery providers (e.g., multicast) to find peers and exchange capabilities
- Remote services automatically registered via capabilities propagation

Security
--------

- Certificates generated/validated by `runar-keys` (X.509, P-256)
- Optional envelope encryption for payloads via `runar-serializer`
- Strict server-name verification and time-bounded cert validation

Logging
-------

Structured logging via `runar_common::logging` with component prefixes and
context (action/event paths). Use the provided macros in `runar_macros_common`.

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


