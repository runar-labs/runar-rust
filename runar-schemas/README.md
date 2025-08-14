runar-schemas
=============

Shared schema and metadata types for the Runar framework (e.g., `ServiceMetadata`, `ActionMetadata`, `FieldSchema`).

Install
-------

```toml
[dependencies]
runar-schemas = "0.1"
```

Usage
-----

```rust
use runar_schemas::{ServiceMetadata, ActionMetadata, FieldSchema};

let action = ActionMetadata {
    name: "add".into(),
    description: "Adds two numbers".into(),
    input_schema: Some(FieldSchema::double("a")),
    output_schema: Some(FieldSchema::double("result")),
};

let svc = ServiceMetadata {
    network_id: "default".into(),
    service_path: "math".into(),
    name: "Math".into(),
    version: "1.0.0".into(),
    description: "Basic math ops".into(),
    actions: vec![action],
    registration_time: 0,
    last_start_time: None,
};
```

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


