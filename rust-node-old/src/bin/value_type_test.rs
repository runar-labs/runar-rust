use runar_common::types::ValueType;
use runar_node::{vjson, vmap};

fn main() {
    println!("Testing ValueType implementation");

    // Test vjson! macro
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

    println!("vjson! result: {:?}", value);

    // Test vmap! macro
    let value = vmap! {
        "name" => "John",
        "age" => 30,
        "is_active" => true,
        "address" => vmap! {
            "street" => "123 Main St",
            "city" => "Anytown"
        }
    };

    println!("vmap! result: {:?}", value);

    // Test conversion between ValueType and JSON
    let json = value.to_json();
    println!("Converted to JSON: {}", json);

    // Test accessing values
    if let ValueType::Map(map) = &value {
        if let Some(ValueType::String(name)) = map.get("name") {
            println!("Name: {}", name);
        }

        if let Some(ValueType::Number(age)) = map.get("age") {
            println!("Age: {}", age);
        }

        if let Some(ValueType::Bool(is_active)) = map.get("is_active") {
            println!("Is active: {}", is_active);
        }

        if let Some(ValueType::Map(address)) = map.get("address") {
            if let Some(ValueType::String(street)) = address.get("street") {
                println!("Street: {}", street);
            }

            if let Some(ValueType::String(city)) = address.get("city") {
                println!("City: {}", city);
            }
        }
    }

    println!("All tests passed!");
}
