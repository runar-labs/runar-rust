# Runar ‑ Rust Backend Framework

Runar is a lightweight, high-performance Rust framework for building **secure, modular, and developer-friendly** back-end services and peer-to-peer (P2P) applications.

Runar’s design combines battle-tested cryptography with an ergonomic API surface, enabling small teams to ship production-grade back-ends without dedicating a separate DevOps or security department.

---

## Why Runar?

* **Security from first principles** – All data is encrypted at rest and in transit using state-of-the-art algorithms.  Key material can be stored in user-controlled mobile wallets or hardware security modules (e.g. Ledger), following the same “self-custody” model that keeps crypto assets safe.
* **Great Developer UX** – Clean request/response APIs, a zero-boilerplate pub/sub system, and sensible defaults mean you can sketch an idea in minutes and iterate fast.
* **Modular Architecture** – Enable only what you need.  First-party modules include:
  * **Web Gateway** → REST, GraphQL, and WebSocket endpoints out-of-the-box
  * **Encrypted Storage** → blazing-fast SQLite with transparent encryption
* **Mobile-first Embedding** – The core can be linked directly into iOS/Android apps, powering fully offline-capable P2P experiences.
* **Zero-Ops Deployments** – Ship a single static binary; no external DB or message broker required.

---

### Quick Example

Runar’s declarative macros let you expose functionality with just a few lines of code:

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
    let config = NodeConfig::new_with_generated_id("default_network");
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

## Core Feature Matrix

| Feature | Status | Notes |
| ------- | ------ | ----- |
| Declarative service & action macros | ✅ | `runar-macros` crate (`service`, `action`, `publish`, `subscribe`) |
| Event-driven pub/sub | ✅ | Built into `runar-node` with topic routing |
| Typed zero-copy serializer (`ArcValue`) | ✅ | Binary & JSON conversion, runtime type registry |
| Encrypted SQLite storage | ✅ | CRUD service in `runar-services::sqlite` |
| HTTP REST gateway | ✅ | Axum-based, auto-exposes registered actions |
| QUIC P2P transport & discovery | ✅ | Secure QUIC + multicast discovery in `runar-node::network` |
| Key management & encryption | ✅ | HD wallets, token & AES helpers in `runar-keys` |
| Configurable logging/tracing | ✅ | Structured logs via `runar-node::config` |
| Mobile embeddings (FFI) | 🟡 | iOS/Android bindings work-in-progress |
| Web UI dashboard | 🟡 | Experimental `node_webui` SPA |
| GraphQL & WebSocket gateway | ⚪ | Planned extension of gateway service |

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

Not sure where to start?  Check `rust-docs/markdown/development/` for good first issues and the current roadmap.

---

## License

Runar is released under the MIT License – see the [LICENSE](LICENSE) file for details.
