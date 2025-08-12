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

### Quick Examples

#### Basic Math Service

Runar's declarative macros let you expose functionality with just a few lines of code. Note that macros are now applied to both the struct and impl blocks:

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
#[service(
    name = "Math Service",
    path = "math",
    description = "Simple arithmetic API",
    version = "0.1.0"
)]
pub struct MathService;

#[service]
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
#[service(path = "stats")]
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

#[service]
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

#### Encrypted Data Service

Here's an example of a service that handles encrypted data using Runar's selective field encryption system:

```rust
use anyhow::Result;
use runar_common::{hmap, types::ArcValue};
use runar_macros::{action, service};
use runar_node::{
    services::RequestContext,
    Node, NodeConfig,
};
use runar_serializer::{traits::RunarEncrypt, ArcValue as SerializerArcValue};
use runar_serializer_macros::Encrypt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Define an encrypted note structure with selective field encryption
#[derive(Clone, Debug, Serialize, Deserialize, Encrypt)]
pub struct SecureNote {
    pub id: String,                    // Plain text - always visible
    pub title: String,                 // Plain text - always visible
    #[runar(user)]                     // Encrypted with user's profile key
    pub content: String,               // Only accessible to the user
    #[runar(user)]                     // Encrypted with user's profile key  
    pub tags: Vec<String>,             // Only accessible to the user
    #[runar(system)]                   // Encrypted with network key
    pub metadata: String,              // Accessible to network nodes
    #[runar(system_only)]              // Only accessible to network nodes
    pub audit_log: String,             // Never accessible to users
}

#[derive(Clone, Default)]
#[service(
    name = "Secure Notes Service",
    path = "notes",
    description = "Encrypted notes storage with selective field encryption",
    version = "0.1.0"
)]
pub struct SecureNotesService {
    notes: HashMap<String, SerializerArcValue>,
}

#[service]
impl SecureNotesService {
    /// Store an encrypted note with selective field encryption
    #[action]
    async fn store_note(
        &self,
        note: SecureNote,
        _ctx: &RequestContext,
    ) -> Result<String> {
        // The Encrypt derive macro automatically handles encryption
        // based on the #[runar(label)] attributes on fields
        let encrypted_note = note.encrypt_with_keystore(
            &ctx.keystore,
            &ctx.resolver,
        )?;
        
        // Store the encrypted note
        let note_id = note.id.clone();
        self.notes.insert(note_id.clone(), SerializerArcValue::new_struct(encrypted_note));
        
        Ok(note_id)
    }

    /// Retrieve and decrypt a note (access level depends on keystore)
    #[action]
    async fn get_note(
        &self,
        note_id: String,
        ctx: &RequestContext,
    ) -> Result<Option<SecureNote>> {
        if let Some(encrypted_note) = self.notes.get(&note_id) {
            // Decrypt based on current keystore access level
            let encrypted_struct: Arc<SecureNote::Encrypted> = encrypted_note.as_struct_ref()?;
            let decrypted_note = encrypted_struct.decrypt_with_keystore(&ctx.keystore)?;
            Ok(Some(decrypted_note))
        } else {
            Ok(None)
        }
    }

    /// List all note IDs (metadata only)
    #[action]
    async fn list_notes(&self, _ctx: &RequestContext) -> Result<Vec<String>> {
        Ok(self.notes.keys().cloned().collect())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = NodeConfig::new_test_config("secure-notes-node", "default_network");
    let mut node = Node::new(config).await?;

    node.add_service(SecureNotesService::default()).await?;

    // Create a secure note
    let note = SecureNote {
        id: "personal-1".to_string(),
        title: "My Secret Note".to_string(),
        content: "This is very sensitive information that will be encrypted".to_string(),
        tags: vec!["personal".to_string(), "secret".to_string()],
        metadata: "Created by user".to_string(),
        audit_log: "User created note at 2024-01-01".to_string(),
    };
    
    // Store the encrypted note
    let params = ArcValue::new_struct(note);
    let note_id: String = node.request("notes/store_note", Some(params)).await?;
    
    println!("Stored encrypted note with ID: {note_id}");
    
    // Retrieve the note (access level depends on keystore)
    let note_params = ArcValue::new_map(hmap! { "note_id" => note_id });
    let retrieved_note: Option<SecureNote> = node.request("notes/get_note", Some(note_params)).await?;
    
    if let Some(note) = retrieved_note {
        println!("Retrieved note: {note:?}");
        // Note: Some fields may be empty depending on keystore access level
    }
    
    Ok(())
}
```

**Key Features of Runar's Encryption System:**

- **Selective Field Encryption**: Use `#[runar(label)]` attributes to specify which fields get encrypted
- **Label-based Access Control**: Different labels (`user`, `system`, `system_only`) provide different access levels
- **Automatic Encryption/Decryption**: The `Encrypt` derive macro handles all encryption logic
- **Context-aware Access**: The same encrypted data provides different access levels based on the keystore
- **Network Transparency**: Works seamlessly in both local and distributed deployments

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
| Declarative service & action macros | ✓ | `runar-macros` crate (`service`, `action`, `publish`, `subscribe`) |
| Event-driven pub/sub | ✓ | Built into `runar-node` with topic routing |
| Typed zero-copy serializer (`ArcValue`) | ✓ | Binary & JSON conversion, runtime type registry |
| Enhanced serialization with field encryption | ✓ | `runar-serializer` with selective field encryption and envelope encryption |
| Encrypted SQLite storage | ✓ | CRUD service in `runar-services::sqlite` |
| HTTP REST gateway | ✓ | Axum-based, auto-exposes registered actions |
| QUIC P2P transport & discovery | ✓ | Secure QUIC + multicast discovery in `runar-node::network` |
| Key management & encryption | ✓ | Complete PKI system with X.509 certificates, envelope encryption, and mobile key management |
| Configurable logging/tracing | ✓ | Structured logs via `runar-node::config` |
| runar-swift (iOS/macOS) | 🔄 | Full Runar implementation in Swift - 70% complete, work-in-progress |
| Android embeddings (FFI) | ○ | Planned |
| Web UI dashboard | 🔄 | Node Setup and Management Screen `node_webui` SPA |
| Node CLI | ○ | Command-line interface for node management |
| GraphQL & WebSocket gateway | ○ | Planned extension of gateway service |
| Mobile App for Keys management | ○ | Planned |

> ✓ Complete  |  🔄 Work-in-progress  |  ○ Planned

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
