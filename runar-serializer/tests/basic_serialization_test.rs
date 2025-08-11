use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_serializer::{ArcValue, ValueCategory};
use serde_json::{json, Value as JsonValue};

#[test]
fn test_primitive_string_serialization() -> Result<()> {
    let original = "hello".to_string();
    let val = ArcValue::new_primitive(original.clone());
    assert_eq!(val.category(), ValueCategory::Primitive);

    // Test the new simplified serialization approach
    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<String> = reconstructed.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_i64_serialization() -> Result<()> {
    let original = 42i64;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category(), ValueCategory::Primitive);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<i64> = reconstructed.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_bool_serialization() -> Result<()> {
    let original = true;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category(), ValueCategory::Primitive);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<bool> = reconstructed.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_list_serialization() -> Result<()> {
    let original = vec![
        ArcValue::new_primitive(1i64),
        ArcValue::new_primitive("two".to_string()),
    ];
    let val = ArcValue::new_list(original.clone());
    assert_eq!(val.category(), ValueCategory::List);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<Vec<ArcValue>> = reconstructed.as_list_ref()?;
    assert_eq!(resolved.len(), 2);

    let item0 = resolved[0].clone();
    assert_eq!(*item0.as_type_ref::<i64>()?, 1);
    let item1 = resolved[1].clone();
    assert_eq!(*item1.as_type_ref::<String>()?, "two");
    Ok(())
}

#[test]
fn test_map_serialization() -> Result<()> {
    let mut original = HashMap::new();
    original.insert("key1".to_string(), ArcValue::new_primitive(42i64));
    original.insert(
        "key2".to_string(),
        ArcValue::new_primitive("value".to_string()),
    );
    let val = ArcValue::new_map(original.clone());
    assert_eq!(val.category(), ValueCategory::Map);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<HashMap<String, ArcValue>> = reconstructed.as_map_ref()?;
    assert_eq!(resolved.len(), 2);

    let val1 = resolved.get("key1").unwrap().clone();
    assert_eq!(*val1.as_type_ref::<i64>()?, 42);
    let val2 = resolved.get("key2").unwrap().clone();
    assert_eq!(*val2.as_type_ref::<String>()?, "value");
    Ok(())
}

#[test]
fn test_bytes_serialization() -> Result<()> {
    let original = vec![1u8, 2, 3];
    let val = ArcValue::new_bytes(original.clone());
    assert_eq!(val.category(), ValueCategory::Bytes);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<Vec<u8>> = reconstructed.as_bytes_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_json_serialization() -> Result<()> {
    let original = json!({"key": "value"});
    let val = ArcValue::new_json(original.clone());
    assert_eq!(val.category(), ValueCategory::Json);

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    let resolved: Arc<JsonValue> = reconstructed.as_json_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_null_serialization() -> Result<()> {
    let val = ArcValue::null();
    assert_eq!(val.category(), ValueCategory::Null);
    assert!(val.is_null());

    let serialized = val.serialize(None)?;
    let reconstructed = ArcValue::deserialize(serialized.as_ref(), None)?;
    assert_eq!(reconstructed.category(), ValueCategory::Null);
    assert!(reconstructed.is_null());
    Ok(())
}
