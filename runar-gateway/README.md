Runar Gateway
=============

HTTP gateway for Runar nodes using `axum`. Exposes registered service actions
as REST endpoints and forwards requests to the local node.

Install
-------

```toml
[dependencies]
runar_gateway = "0.1"
```

Features
--------

- Maps `/{service-path}/{action}` to the corresponding service action
- JSON request/response bridging with `ArcValue`
- CORS and tracing via `tower-http`

Service example (abridged)
--------------------------

```rust
use anyhow::Result;
use runar_macros::{service, action};
use runar_serializer::{ArcValue, Plain};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Plain)]
struct MyTestData { id: i32, name: String, active: bool }

#[service(name = "EchoService", path = "echo-service", description = "Echo", version = "1.0.0")]
struct EchoService;

#[service]
impl EchoService {
    #[action]
    async fn ping(&self) -> Result<String> { Ok("pong".to_string()) }
    #[action]
    async fn echo(&self, message: String) -> Result<String> { Ok(message) }
    #[action]
    async fn echo_struct(&self, data: MyTestData) -> Result<MyTestData> { Ok(data) }
}
```

Routes (examples)
-----------------

- GET `/echo-service/ping` → `"pong"`
- POST `/echo-service/echo` with `{ "message": "hello" }` → `"hello"`
- POST `/echo-service/echo_struct` with `MyTestData` → echo back struct

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.

 