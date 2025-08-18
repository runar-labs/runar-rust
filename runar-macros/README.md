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

Full service example
--------------------

Define a service with metadata and multiple actions, then register it on a
`runar_node::Node`. This mirrors the structure used in the gateway tests.

```rust
use anyhow::Result;
use runar_macros::{service, action};
use runar_serializer::{ArcValue, Plain};
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Plain)]
struct MyTestData { id: i32, name: String, active: bool }

#[service(
    name = "EchoService",
    path = "echo-service",
    description = "A simple service that echoes messages and pings.",
    version = "1.0.0"
)]
struct EchoService;

#[service]
impl EchoService {
    #[action]
    async fn ping(&self) -> Result<String> { Ok("pong".to_string()) }

    #[action]
    async fn echo(&self, message: String) -> Result<String> { Ok(message) }

    #[action]
    async fn echo_map(
        &self,
        params: HashMap<String, ArcValue>,
    ) -> Result<HashMap<String, ArcValue>> { Ok(params) }

    #[action]
    async fn echo_list(&self, params: Vec<ArcValue>) -> Result<Vec<ArcValue>> { Ok(params) }

    #[action]
    async fn echo_struct(&self, params: MyTestData) -> Result<MyTestData> { Ok(params) }
}
```

Register and run on a node (conceptual):

```rust
use runar_node::{Node, NodeConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure and create node
    let config = NodeConfig::new("my-node", "default-network");
    let  node = Node::new(config).await?;

    // Add service
    node.add_service(EchoService).await?;

    // Start node
    node.start().await?;
    node.wait_for_services_to_start().await?;

    // Invoke an action locally
    let resp = node.request::<()> ("echo-service/ping", None).await?;
    let pong: String = resp.as_primitive_ref()?;
    assert_eq!(pong, "pong");

    Ok(())
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


