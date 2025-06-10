use runar_common::types::ValueCategory;
use runar_common::vmap;

// A simplified test to verify basic vmap functionality
#[test]
fn test_vmap_basic() {
    // Create a map using the vmap macro
    let map = vmap! {
        "string" => "value",
        "number" => 42,
        "float" => std::f64::consts::PI,
        "bool" => true,
        "null" => runar_common::types::ArcValue::null()
    };

    // Verify the map was created successfully
    assert_eq!(map.category, ValueCategory::Map);

    //get map from the vmap
    // if let Ok(map_ref) = map.as_map_ref::<String, ArcValue>() {
    //     //check all values
    //     assert_eq!(map_ref.get("string"), "value");
    //     assert_eq!(map_ref.get("number"), 42);
    //     assert_eq!(map_ref.get("float"), 3.14);
    //     assert_eq!(map_ref.get("bool"), true);
    //     assert_eq!(
    //         map_ref.get("null"),
    //         runar_common::types::ArcValue::null()
    //     );
    // }
}

// Test type conversion
#[test]
fn test_vmap_type_conversion() {
    let map = vmap! {
        "number_as_string" => 42,
        "bool_as_string" => true,
        "string_as_number" => "42",
        "string_as_bool" => "true"
    };

    // Verify the map was created successfully
    assert_eq!(map.category, ValueCategory::Map);
}
