use runar_node::ValueType;
use runar_node::{vjson, vmap};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[test]
fn test_vjson_macro() {
    // Test creating a ValueType using the vjson! macro
    let value = vjson!({
        "name": "John",
        "age": 30,
        "is_active": true,
        "address": {
            "street": "123 Main St",
            "city": "Anytown"
        },
        "skills": ["Rust", "JavaScript", "Python"]
    });

    // Convert to JSON value for easier testing
    let json = value.to_json();
    assert_eq!(json["name"], "John");
    assert_eq!(json["age"], 30);
    assert_eq!(json["is_active"], true);
    assert_eq!(json["address"]["street"], "123 Main St");
    assert_eq!(json["address"]["city"], "Anytown");
    assert_eq!(json["skills"][0], "Rust");
    assert_eq!(json["skills"][1], "JavaScript");
    assert_eq!(json["skills"][2], "Python");
}

#[test]
fn test_vmap_macro() {
    // Test creating a ValueType using the vmap! macro
    let value = vmap! {
        "name" => "John",
        "age" => 30,
        "is_active" => true,
        "address" => vmap! {
            "street" => "123 Main St",
            "city" => "Anytown"
        }
    };

    // Now use the ValueType API to interact with it
    let map = match &value {
        ValueType::Map(m) => m,
        _ => panic!("Expected a Map ValueType"),
    };

    // Check top-level fields
    match &map["name"] {
        ValueType::String(s) => assert_eq!(s, "John"),
        _ => panic!("Expected a String ValueType for name"),
    }

    match &map["age"] {
        ValueType::Number(n) => assert_eq!(*n, 30.0),
        _ => panic!("Expected a Number ValueType for age"),
    }

    match &map["is_active"] {
        ValueType::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected a Bool ValueType for is_active"),
    }

    // Check nested map
    match &map["address"] {
        ValueType::Map(addr) => {
            match &addr["street"] {
                ValueType::String(s) => assert_eq!(s, "123 Main St"),
                _ => panic!("Expected a String ValueType for street"),
            }
            match &addr["city"] {
                ValueType::String(s) => assert_eq!(s, "Anytown"),
                _ => panic!("Expected a String ValueType for city"),
            }
        }
        _ => panic!("Expected a Map ValueType for address"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    name: String,
    age: u32,
    is_active: bool,
}

#[test]
fn test_struct_to_value_type() {
    // Create a struct
    let user = User {
        name: "John".to_string(),
        age: 30,
        is_active: true,
    };

    // Convert to a ValueType
    let value = runar_node::services::to_value_type(user);

    // Get as JSON and verify
    let json = value.to_json();
    assert_eq!(json["name"], "John");
    assert_eq!(json["age"], 30.0);
    assert_eq!(json["is_active"], true);
}

#[test]
fn test_value_type_access() {
    // Create a complex value
    let mut map = HashMap::new();
    map.insert("name".to_string(), ValueType::String("John".to_string()));
    map.insert("age".to_string(), ValueType::Number(30.0));
    map.insert("is_active".to_string(), ValueType::Bool(true));
    
    let complex = ValueType::Map(map);
    
    // Test getting values using match statements
    match &complex {
        ValueType::Map(m) => {
            match &m["name"] {
                ValueType::String(s) => assert_eq!(s, "John"),
                _ => panic!("Expected a String ValueType for name"),
            }
            
            match &m["age"] {
                ValueType::Number(n) => assert_eq!(*n, 30.0),
                _ => panic!("Expected a Number ValueType for age"),
            }
            
            match &m["is_active"] {
                ValueType::Bool(b) => assert_eq!(*b, true),
                _ => panic!("Expected a Bool ValueType for is_active"),
            }
            
            assert!(m.get("not_exist").is_none());
        },
        _ => panic!("Expected a Map ValueType"),
    }
}

#[test]
fn test_array_value_type() {
    // Create an array ValueType
    let array = ValueType::Array(vec![
        ValueType::String("one".to_string()),
        ValueType::Number(2.0),
        ValueType::Bool(true),
    ]);
    
    // Test array access
    match &array {
        ValueType::Array(a) => {
            assert_eq!(a.len(), 3);
            
            match &a[0] {
                ValueType::String(s) => assert_eq!(s, "one"),
                _ => panic!("Expected a String ValueType"),
            }
            
            match &a[1] {
                ValueType::Number(n) => assert_eq!(*n, 2.0),
                _ => panic!("Expected a Number ValueType"),
            }
            
            match &a[2] {
                ValueType::Bool(b) => assert_eq!(*b, true),
                _ => panic!("Expected a Bool ValueType"),
            }
        },
        _ => panic!("Expected an Array ValueType"),
    }
}

#[test]
fn test_bytes_value_type() {
    // Create a bytes ValueType
    let bytes = ValueType::Bytes(vec![1, 2, 3, 4, 5]);
    
    // Test bytes access
    match &bytes {
        ValueType::Bytes(b) => {
            assert_eq!(b.len(), 5);
            assert_eq!(b, &vec![1, 2, 3, 4, 5]);
        },
        _ => panic!("Expected a Bytes ValueType"),
    }
}

#[test]
fn test_complex_data_structures() {
    // Test more complex data structures with nested objects and arrays
    let complex = vjson!({
        "user": {
            "name": "John",
            "contact": {
                "email": "john@example.com",
                "phone": "555-1234"
            },
            "roles": ["admin", "user"],
            "settings": {
                "theme": "dark",
                "notifications": true,
                "preferences": {
                    "language": "en",
                    "timezone": "UTC"
                }
            }
        },
        "stats": {
            "visits": 42,
            "actions": [
                {"type": "click", "count": 10},
                {"type": "view", "count": 32}
            ]
        }
    });
    
    // Verify the complex structure
    let json = complex.to_json();
    
    // Check user info
    assert_eq!(json["user"]["name"], "John");
    assert_eq!(json["user"]["contact"]["email"], "john@example.com");
    assert_eq!(json["user"]["contact"]["phone"], "555-1234");
    
    // Check roles array
    assert_eq!(json["user"]["roles"][0], "admin");
    assert_eq!(json["user"]["roles"][1], "user");
    
    // Check nested settings
    assert_eq!(json["user"]["settings"]["theme"], "dark");
    assert_eq!(json["user"]["settings"]["notifications"], true);
    assert_eq!(json["user"]["settings"]["preferences"]["language"], "en");
    assert_eq!(json["user"]["settings"]["preferences"]["timezone"], "UTC");
    
    // Check stats and nested actions
    assert_eq!(json["stats"]["visits"], 42);
    assert_eq!(json["stats"]["actions"][0]["type"], "click");
    assert_eq!(json["stats"]["actions"][0]["count"], 10);
    assert_eq!(json["stats"]["actions"][1]["type"], "view");
    assert_eq!(json["stats"]["actions"][1]["count"], 32);
} 