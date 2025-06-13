# Runar Macros

Procedural macros that power the declarative developer-experience of the Runar framework.

* `service`  – turn an ordinary Rust `impl` block into a fully-fledged Runar service
* `action`   – expose an async method as a request/response API endpoint
* `publish`   – automatically publish the action result to an event topic
* `subscribe` – register an event handler for the given topic

These macros remove boilerplate while preserving the *first-principles* design of Runar (clear boundaries, typed data, explicit errors).

---

## Quick Start

```rust
use anyhow::Result;
use runar_common::{hmap, types::ArcValue};
use runar_macros::{service, action, publish, subscribe};

// 1️⃣ Define a struct (can hold state)
pub struct MathService;

// 2️⃣ Annotate it
#[service(path = "math", description = "Simple arithmetic API", version = "0.1.0")]
impl MathService {
    /// Add two numbers and publish the result
    #[publish(path = "added")]
    #[action] // default path is the fn name: "add"
    async fn add(&self, a: f64, b: f64) -> Result<f64> {
        Ok(a + b)
    }

    /// React to the `added` events (could be emitted by *any* service)
    #[subscribe(path = "math/added")]
    async fn on_added(&self, total: f64) -> Result<()> {
        println!("received total: {total}");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let node = runar_node::Node::default().await?;
    node.register_service(MathService);

    // Construct params with zero-copy typed container
    let params = ArcValue::new_map(hmap! { "a" => 1.0, "b" => 2.0 });
    let sum: f64 = node.request("math/add", Some(params)).await?;
    assert_eq!(sum, 3.0);
    Ok(())
}
```

---

## Macro Reference

### `service`

```rust
#[service(
    name        = "Human-readable name",   // optional, defaults to struct name
    path        = "url_path",              // required – unique service prefix
    description = "What the service does", // optional
    version     = "semver"                 // optional – default "0.1.0"
)]
impl MyService { /* … */ }
```

Generates an implementation of `runar_node::AbstractService`, wire-up of actions, clone impl (if missing) and helper getters.

### `action`

```rust
#[action(path = "custom", description = "Add numbers")]
async fn add(&self, a: f64, b: f64) -> Result<f64> { … }
```

* `path` – overrides the default (function name) when constructing the final endpoint `service_path/action_path`.
* Automatically deserialises parameters from `ArcValue`; primitive parameters are mapped positionally, complex ones by name.

### `publish`

Attach to an `action` to emit its return value as an event.

```rust
#[publish(path = "totals")]
#[action]
async fn add(&self, a: f64, b: f64) -> Result<f64> { Ok(a + b) }
```

### `subscribe`

Register a handler for events. The first argument must be the deserialised payload type.

```rust
#[subscribe(path = "math/totals")]
async fn on_total(&self, total: f64) -> Result<()> { … }
```

---

## Testing Helpers

Integration tests in `tests/` showcase advanced patterns (nested structs, automatic type-registration, event assertions). Use them as reference when building your own services.

---

## Why Macros?

* **Ergonomics** – write business logic, not boilerplate.
* **Safety** – compile-time checks ensure paths are unique and parameters serialisable.
* **Performance** – zero-copy `Arc<[u8]>` message format avoids JSON overhead.

For deeper architectural rationale consult `rust-docs/markdown/core/`.