Runar Services
==============

Building blocks and utilities for writing Runar services, including SQLite
integration and replication helpers.

Install
-------

```toml
[dependencies]
runar_services = "0.1"
```

Features
--------

- `crud_sqlite`: simple CRUD service on SQLite (bundled sqlcipher)
- `replication`: helpers and example for service-level replication
- `sqlite`: low-level helpers for service persistence

Examples
--------

See `examples/replication_example.rs` and integration tests under `tests/` for
end-to-end usage with a `runar_node`.

SQLite service (basic)
----------------------

```rust
use runar_node::{Node, NodeConfig};
use runar_services::sqlite::{Schema, TableDefinition, ColumnDefinition, DataType, SqliteConfig, SqliteService};

// 1) Define schema
let schema = Schema {
    tables: vec![TableDefinition {
        name: "users".into(),
        columns: vec![
            ColumnDefinition { name: "id".into(), data_type: DataType::Integer, primary_key: true, autoincrement: true, not_null: true },
            ColumnDefinition { name: "username".into(), data_type: DataType::Text, primary_key: false, autoincrement: false, not_null: true },
        ],
    }],
    indexes: vec![],
};

// 2) Create service
let cfg = SqliteConfig::new(":memory:", schema, false);
let sqlite = SqliteService::new("users_db", "users_db", cfg);

// 3) Add to node
let  node = Node::new(NodeConfig::new("node", "default")).await?;
node.add_service(sqlite).await?;
node.start().await?;
node.wait_for_services_to_start().await?;

// 4) Execute a query
use runar_services::sqlite::{SqlQuery, Params, Value};
use runar_serializer::ArcValue;

let q = SqlQuery::new("INSERT INTO users (username) VALUES ('alice')");
let rows: i64 = *node.local_request("users_db/execute_query", Some(ArcValue::new_struct(q))).await?.as_type_ref()?;
```

CRUD over SQLite
----------------

```rust
use runar_macros_common::vmap;
use runar_serializer::ArcValue;
use runar_services::crud_sqlite::{CrudSqliteService, InsertOneRequest, FindOneRequest};
use runar_services::sqlite::{Schema, TableDefinition, ColumnDefinition, DataType, SqliteConfig, SqliteService};

// Setup SqliteService and CrudSqliteService (paths must match)
let schema = Schema { tables: vec![TableDefinition { name: "users".into(), columns: vec![
    ColumnDefinition { name: "_id".into(), data_type: DataType::Text, primary_key: true, autoincrement: false, not_null: true },
    ColumnDefinition { name: "email".into(), data_type: DataType::Text, primary_key: false, autoincrement: false, not_null: true },
]}], indexes: vec![] };
let sqlite_cfg = SqliteConfig::new(":memory:", schema.clone(), false);
let sqlite = SqliteService::new("sqlite", "sqlite", sqlite_cfg);
let crud = CrudSqliteService::new("crud", "crud", "sqlite", schema);

let  node = Node::new(NodeConfig::new("node", "default")).await?;
node.add_service(sqlite).await?;
node.add_service(crud).await?;
node.start().await?;
node.wait_for_services_to_start().await?;

// Insert
let doc = vmap! { "_id" => "user-1", "email" => "u@example.com" };
let req = InsertOneRequest { collection: "users".into(), document: (*doc.as_type_ref::<std::collections::HashMap<_,_>>()?).clone() };
let _resp: runar_services::crud_sqlite::InsertOneResponse = (*node.request("crud/insertOne", Some(ArcValue::new_struct(req))).await?.as_type_ref()?).clone();

// Find
let mut filter = std::collections::HashMap::new();
filter.insert("_id".into(), ArcValue::new_primitive("user-1"));
let find = FindOneRequest { collection: "users".into(), filter };
let found: runar_services::crud_sqlite::FindOneResponse = (*node.request("crud/findOne", Some(ArcValue::new_struct(find))).await?.as_type_ref()?).clone();
assert!(found.document.is_some());
```

Replication (two nodes)
-----------------------

```rust
use runar_services::replication::{ReplicationConfig, ConflictResolutionStrategy};
use runar_services::sqlite::{Schema, TableDefinition, ColumnDefinition, DataType, SqliteConfig, SqliteService};

fn replicated(name: &str, path: &str, startup_sync: bool) -> SqliteService {
    let schema = Schema { tables: vec![TableDefinition {
        name: "users".into(),
        columns: vec![
            ColumnDefinition { name: "id".into(), data_type: DataType::Integer, primary_key: true, autoincrement: true, not_null: true },
            ColumnDefinition { name: "username".into(), data_type: DataType::Text, primary_key: false, autoincrement: false, not_null: true },
        ],
    }], indexes: vec![] };
    let cfg = SqliteConfig::new(":memory:", schema, false).with_replication(ReplicationConfig {
        enabled_tables: vec!["users".into()],
        conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
        startup_sync,
        event_retention_days: 30,
        wait_remote_service_timeout: 25,
        past_events_window: 10,
    });
    SqliteService::new(name, path, cfg)
}

// Create two nodes (see runar_test_utils for helpers) and add services:
// node1.add_service(replicated("sqlite", "users_db", false)).await?;
// node2.add_service(replicated("sqlite", "users_db", true)).await?;
// start both; node2 will sync on startup, and live changes replicate thereafter.
```

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.
