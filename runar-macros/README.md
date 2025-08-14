runar_macros
============

Procedural macros for the Runar framework.

Macros
------

- `#[service]`: attach to a service struct or its impl to register actions,
  schemas, and metadata.
- `#[action]`: mark a method as an invokable action; generates parameter
  extraction and output conversion glue.
- `#[subscribe]`: register an event handler for a path.
- `#[publish]`: publish the result of an action to an event path.

Usage
-----

```rust
use runar_macros::{service, action};

#[service]
impl MyService {
    #[action(path = "/hello")] // defaults to method name when omitted
    fn hello(&self, name: String) -> String {
        format!("Hello, {name}!")
    }
}
```

Feature flags
-------------

- `node_implementation` (default): hooks into `runar_node` runtime to register
  actions at startup.
- `distributed_slice`: enables registration via `linkme` distributed slices.

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


