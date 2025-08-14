Runar Common
============

Common traits and utilities shared across the Runar stack.

What’s inside
-------------

- Structured logging with component and node-id context
- Lightweight error utilities (re-exports of `anyhow` and `thiserror`)
- DNS-safe compact ID generator

Install
-------

Add to your `Cargo.toml`:

```toml
[dependencies]
runar_common = "0.1"
```

Logging
-------

```rust
use runar_common::logging::{Component, Logger};

let root = Logger::new_root(Component::Node, "node-123");
let svc = root.with_component(Component::Service);
svc.info("service started");
svc.warn("doing work");
svc.error("something went wrong");
```

Compact IDs
-----------

```rust
use runar_common::compact_ids::compact_id;

let public_key_bytes: [u8; 65] = [0u8; 65];
let id = compact_id(&public_key_bytes);
assert_eq!(id.len(), 26);
assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
```

Errors
------

```rust
use runar_common::errors::{Result, anyhow};

fn do_work() -> Result<()> {
    // ...
    Err(anyhow!("failure"))
}
```

License
-------

MIT. See `LICENSE`.


