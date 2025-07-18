# Runar ‑ Build Privacy Preserving Applications

Runar is a lightweight, high-performance framework for building **end-to-end encrypted, modular, and developer-friendly** applications. Due to its architecture it also makes it easy to build peer-to-peer (P2P) applications.

Runar's design blends battle-tested cryptography with an ergonomic API surface and mobile-wallet key management, enabling small teams to ship production-grade back-ends without a dedicated DevOps or security department.

We are currently working on the Rust version, but the plan is to support also TypeScript, Python and Golang.

---

## Why Runar?

* **End-to-End Encryption with Self-Custodied Keys** – Data stays encrypted from producer to consumer. Keys live in user-controlled mobile wallets or hardware (e.g. Ledger), and Runar automates exchange & rotation so developers get Signal-level security with almost zero extra code — and users enjoy password-less crypto they already trust.
* **Great Developer UX** – Clean request/response APIs, a zero-boilerplate pub/sub system, and sensible defaults mean you can sketch an idea in minutes and iterate fast.
* **Modular Architecture** – Enable only what you need. First-party modules include:
  * **Web Gateway** → REST, GraphQL, and WebSocket endpoints out-of-the-box
  * **Encrypted Storage** → blazing-fast SQLite with transparent encryption
* **Mobile-first Embedding** – The core can be linked directly into iOS/Android apps, powering fully offline-capable P2P experiences.
* **Zero-Ops Deployments** – Ship a single static binary; no external DB or message broker required.
* **Zero-Copy Local Calls** – Services compiled into the same binary talk via plain in-memory function calls. No cloning, no serialization, identical performance to native Rust.

---

### Quick Example

Runar's declarative macros let you expose functionality with just a few lines of code:

```rust
use anyhow::{anyhow, Result};
use runar_common::{hmap, types::ArcValue};
use runar_macros::{action, publish, service, subscribe};
use runar_node::{
    services::{EventContext, RequestContext},
    Node, NodeConfig,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct MathService;

#[service(
    name = "Math Service",
    path = "math",
    description = "Simple arithmetic API",
    version = "0.1.0"
)]
impl MathService {
    /// Add two numbers and publish the total to `math/added`.
    #[publish(path = "added")]
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(format!("Adding {a} + {b}"));
        Ok(a + b)
    }
}

#[derive(Clone)]
pub struct StatsService {
    values: Arc<Mutex<Vec<f64>>>,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            values: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[service(path = "stats")]
impl StatsService {
    /// Record a value
    #[action]
    async fn record(&self, value: f64, _ctx: &RequestContext) -> Result<()> {
        self.values.lock().unwrap().push(value);
        Ok(())
    }

    /// Return number of recorded values
    #[action]
    async fn count(&self, _ctx: &RequestContext) -> Result<usize> {
        Ok(self.values.lock().unwrap().len())
    }

    /// React to math/added events
    #[subscribe(path = "math/added")]
    async fn on_math_added(&self, total: f64, ctx: &EventContext) -> Result<()> {
        let _: () = ctx
            .request("stats/record", Some(ArcValue::new_primitive(total)))
            .await
            .expect("Call to stats/record failed");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create a minimal Node configuration
    let config = NodeConfig::new_test_config("node-test", "default_network");
    let mut node = Node::new(config).await?;

    // Register services
    node.add_service(MathService).await?;
    node.add_service(StatsService::default()).await?;

    // call math/add
    let params = ArcValue::new_map(hmap! { "a" => 1.0, "b" => 2.0 });
    let sum: f64 = node.request("math/add", Some(params)).await?;
    assert_eq!(sum, 3.0);

    // Query stats count
    let count: usize = node.request("stats/count", None::<ArcValue>).await?;
    assert_eq!(count, 1);
    println!("All good – stats recorded {count} value(s)");
    Ok(())
}
```

### Monolith → Microservices – Local-First, Network-Transparent

Runar routes a request the fastest way possible, deciding at **runtime** whether it can stay in-process or must cross the network:

* **Single binary (monolith)** – When all services are linked together, arguments are forwarded by reference; nothing is cloned or serialized.
* **Separate binaries/containers (microservices)** – When you later split a service out, the *same* code keeps working. You only change the `NodeConfig` transport and let Runar handle encrypted serialization under the hood.

This lets you start with a blazing-fast monolith and migrate to microservices gradually, as real-world traffic or organizational boundaries demand – no premature architecture decisions required.

```rust
// In tests or local tooling – everything lives in one process
let mut node = Node::new(NodeConfig::new_test_config("test-node", "test-network")).await?;
node.add_service(MathService).await?;
let sum: f64 = node.request("math/add", Some(ArcValue::new_map(hmap!{"a"=>1.0,"b"=>2.0}))).await?;
```

Later, in production:

```rust
// math-service now runs remotely; only wiring changes
use runar_node::network::network_config::{NetworkConfig, QuicTransportOptions};

let quic_options = QuicTransportOptions::new();
let network_config = NetworkConfig::with_quic(quic_options)
    .with_multicast_discovery();

let mut node = Node::new(
    NodeConfig::new_test_config("prod-node", "prod-network")
        .with_network_config(network_config)
).await?;
let sum: f64 = node.request("math/add", None::<ArcValue>).await?;
```

Same service implementation, same API call – just a different deployment topology.

## Core Feature Matrix

| Feature | Status | Notes |
| ------- | ------ | ----- |
| Declarative service & action macros | ✅ | `runar-macros` crate (`service`, `action`, `publish`, `subscribe`) |
| Event-driven pub/sub | ✅ | Built into `runar-node` with topic routing |
| Typed zero-copy serializer (`ArcValue`) | ✅ | Binary & JSON conversion, runtime type registry |
| Enhanced serialization with field encryption | ✅ | `runar-serializer` with selective field encryption and envelope encryption |
| Encrypted SQLite storage | ✅ | CRUD service in `runar-services::sqlite` |
| HTTP REST gateway | ✅ | Axum-based, auto-exposes registered actions |
| QUIC P2P transport & discovery | ✅ | Secure QUIC + multicast discovery in `runar-node::network` |
| Key management & encryption | ✅ | Complete PKI system with X.509 certificates, envelope encryption, and mobile key management |
| Configurable logging/tracing | ✅ | Structured logs via `runar-node::config` |
| iOS embeddings (FFI) | 🟡 | iOS bindings work-in-progress |
| Android embeddings (FFI) | 🟡 | Android bindings work-in-progress |
| Web UI dashboard | 🟡 | Node Setup and Management Screen `node_webui` SPA |
| Node CLI | ⚪ | Command-line interface for node management |
| GraphQL & WebSocket gateway | ⚪ | Planned extension of gateway service |
| Mobile App for Keys management | ⚪ | Planned |

> 🟡 Work-in-progress  |  ⚪ Planned

---

## Documentation

Comprehensive guides live inside the repo under [`rust-docs/markdown/`](rust-docs/markdown/).
Start with [`index.md`](rust-docs/markdown/index.md) to explore concepts, tutorials, and design rationale.

---

## Contributing

We welcome early contributors who share our vision of **secure, self-hosted software**.

1. Read the [architecture & guidelines](rust-docs/markdown/core/architecture.md).
2. Discuss sizeable changes in a GitHub issue before opening a PR.
3. Follow the *Documentation-First* workflow (update docs & tests **before** code).
4. Ensure `cargo test` passes and `cargo fmt` shows no diff.

Not sure where to start? Check `rust-docs/markdown/development/` for good first issues and the current roadmap.

---

## License

Runar is released under the MIT License – see the [LICENSE](LICENSE) file for details.
