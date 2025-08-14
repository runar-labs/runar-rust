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

Schemas
-------

- ActionMetadata
  - name: String
  - description: String
  - input_schema: Option<FieldSchema>
  - output_schema: Option<FieldSchema>

- SubscriptionMetadata
  - path: String

- ServiceMetadata
  - network_id: String
  - service_path: String
  - name: String
  - version: String
  - description: String
  - actions: Vec<ActionMetadata>
  - registration_time: u64
  - last_start_time: Option<u64>

- NodeMetadata
  - services: Vec<ServiceMetadata>
  - subscriptions: Vec<SubscriptionMetadata>

- SchemaDataType
  - String, Int32, Int64, Float, Double, Boolean, Timestamp, Binary
  - Object, Array, Reference(String), Union(Vec<SchemaDataType>), Any

- FieldSchema
  - name: String
  - data_type: SchemaDataType
  - description: Option<String>
  - nullable: Option<bool>
  - default_value: Option<String>
  - properties: Option<HashMap<String, Box<FieldSchema>>>   // for Object
  - required: Option<Vec<String>>                           // for Object
  - items: Option<Box<FieldSchema>>                         // for Array
  - pattern: Option<String>
  - enum_values: Option<Vec<String>>
  - minimum/maximum/exclusive_minimum/exclusive_maximum: Option<..>
  - min_length/max_length/min_items/max_items: Option<..>
  - example: Option<String>

Constructors
------------

```rust
use runar_schemas::{FieldSchema, SchemaDataType};
use std::collections::HashMap;

// Primitives
let s = FieldSchema::string("name");
let i = FieldSchema::integer("age");
let l = FieldSchema::long("count");
let f = FieldSchema::float("ratio");
let d = FieldSchema::double("score");
let b = FieldSchema::boolean("active");
let t = FieldSchema::timestamp("created_at");

// Object with properties and required fields
let mut props = HashMap::new();
props.insert("id".into(), Box::new(FieldSchema::integer("id")));
props.insert("name".into(), Box::new(FieldSchema::string("name")));
let obj = FieldSchema::object("User", props, Some(vec!["id".into(), "name".into()]));

// Array of strings
let arr = FieldSchema::array("tags", Box::new(FieldSchema::string("tag")));

// Reference and union
let r = FieldSchema::reference("user", "User");
let u = FieldSchema::union("value", vec![SchemaDataType::String, SchemaDataType::Int32]);
```

MSRV
----

Rust 1.70.0

License
-------

MIT. See `LICENSE`.


