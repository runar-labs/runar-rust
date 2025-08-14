runar_test_utils
=================

Test helpers for Runar crates: quick key setup, node configs, and a lightweight
mobile simulator for integration tests.

Install
-------

```toml
[dev-dependencies]
runar_test_utils = "0.1"
```

Quick start
-----------

```rust
use runar_test_utils::create_node_test_config;

let config = create_node_test_config()?;
// let mut node = runar_node::Node::new(config).await?;
```

Mobile simulator
----------------

```rust
use runar_test_utils::MobileSimulator;
use runar_common::logging::{Component, Logger};
use std::sync::Arc;

let logger = Arc::new(Logger::new_root(Component::System, "sim"));
let mut sim = MobileSimulator::new(logger)?;
sim.add_user_mobile("alice", &["personal", "work"])?;
let node_config = sim.create_node_config()?; // QUIC-ready config
```

Helpers
-------

- `create_test_mobile_keys()` → `(MobileKeyManager, network_id)`
- `create_test_node_keys(mobile, network_id)` → `(NodeKeyManager, node_id)`
- `create_node_test_config()` → `NodeConfig`
- `create_networked_node_test_config(n)` → `Vec<NodeConfig>` (same network)
- `create_simple_mobile_simulation()` → `MobileSimulator`
- `create_test_environment()` → `(MobileSimulator, NodeConfig)`

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


