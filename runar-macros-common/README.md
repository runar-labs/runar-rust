runar_macros_common
===================

Common helpers and logging macros used across Runar crates.

Install
-------

```toml
[dependencies]
runar_macros_common = "0.1"
```

Value map helpers
-----------------

- `vmap!{ ... }`: build an `ArcValue::Map` from primitives (values are wrapped)
- `hmap!{ ... }`: build an `ArcValue::Map` from pre-wrapped values
- `params!{ ... }`: alias to create an `ArcValue::Map` from primitives

```rust
use runar_macros_common::{vmap, hmap, params};
use runar_serializer::ArcValue;

let a = vmap! { "name" => "John", "age" => 42 };
let b = hmap! { "val" => ArcValue::new_primitive(true) };
let p = params! { "x" => 1.0, "y" => 2.0 };
```

Logging macros
--------------

- `log_debug!(logger, ...)`
- `log_info!(logger, ...)`
- `log_warn!(logger, ...)`
- `log_error!(logger, ...)`

They evaluate formatting only when the level is enabled.

```rust
use runar_common::logging::{Component, Logger};
use runar_macros_common::{log_debug, log_info, log_warn, log_error};

let logger = Logger::new_root(Component::System, "readme");
log_info!(logger, "system started");
log_debug!(logger, "x={} y={}", 1, 2);
```

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


