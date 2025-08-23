use anyhow::Result;
use runar_serializer::{runar, ArcValue, Encrypt, Plain};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::f64::consts;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Plain)]
pub struct PlainUser {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encrypt)]
#[runar(name = "vectors.TestProfile")]
pub struct TestProfile {
    pub id: String,
    #[runar(user)]
    pub secret: String,
}

fn write_bytes(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut p = path.to_path_buf();
    p.push(name);
    fs::write(p, bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    // Output directory
    let out = PathBuf::from("target/serializer-vectors");
    fs::create_dir_all(&out)?;

    // Primitives
    write_bytes(
        &out,
        "prim_string.bin",
        &ArcValue::new_primitive("hello".to_string()).serialize(None)?,
    )?;
    write_bytes(
        &out,
        "prim_bool.bin",
        &ArcValue::new_primitive(true).serialize(None)?,
    )?;
    write_bytes(
        &out,
        "prim_i64.bin",
        &ArcValue::new_primitive(42i64).serialize(None)?,
    )?;
    write_bytes(
        &out,
        "prim_u64.bin",
        &ArcValue::new_primitive(7u64).serialize(None)?,
    )?;

    // Bytes
    write_bytes(
        &out,
        "bytes.bin",
        &ArcValue::new_bytes(vec![1, 2, 3]).serialize(None)?,
    )?;

    // JSON
    let json = serde_json::json!({"a": 1, "b": [true, "x"]});
    write_bytes(&out, "json.bin", &ArcValue::new_json(json).serialize(None)?)?;

    // Heterogeneous list/map
    let list_any = ArcValue::new_list(vec![
        ArcValue::new_primitive(1i64),
        ArcValue::new_primitive("two".to_string()),
    ]);
    write_bytes(&out, "list_any.bin", &list_any.serialize(None)?)?;

    let mut map_any: HashMap<String, ArcValue> = HashMap::new();
    map_any.insert("x".into(), ArcValue::new_primitive(10i64));
    map_any.insert("y".into(), ArcValue::new_primitive("ten".to_string()));
    let map_any = ArcValue::new_map(map_any);
    write_bytes(&out, "map_any.bin", &map_any.serialize(None)?)?;

    // Typed containers (no element encryption)
    let list_typed = ArcValue::new_list::<i64>(vec![1, 2, 3]);
    write_bytes(&out, "list_i64.bin", &list_typed.serialize(None)?)?;

    let mut map_typed: HashMap<String, i64> = HashMap::new();
    map_typed.insert("a".into(), 1);
    map_typed.insert("b".into(), 2);
    let map_typed = ArcValue::new_map::<i64>(map_typed);
    write_bytes(&out, "map_string_i64.bin", &map_typed.serialize(None)?)?;

    // Struct plain (derive Plain so it's allowed in ArcValue::new_struct)
    let user = PlainUser {
        id: "u1".into(),
        name: "Alice".into(),
    };
    let av_user = ArcValue::new_struct(user);
    write_bytes(&out, "struct_plain.bin", &av_user.serialize(None)?)?;

    // === COMPREHENSIVE TEST SCENARIOS ===

    println!("Generating comprehensive test scenarios...");

    // 1. LARGE COLLECTIONS
    // Large list with many elements
    let large_list = ArcValue::new_list::<i64>((1..=100).collect());
    write_bytes(&out, "list_large.bin", &large_list.serialize(None)?)?;

    // Large map with many key-value pairs
    let mut large_map: HashMap<String, i64> = HashMap::new();
    for i in 0..50 {
        large_map.insert(format!("key{i}"), (i * 2) as i64);
    }
    let large_map = ArcValue::new_map::<i64>(large_map);
    write_bytes(&out, "map_large.bin", &large_map.serialize(None)?)?;

    // 2. NESTED STRUCTURES - List of Maps
    let mut alice_map: HashMap<String, ArcValue> = HashMap::new();
    alice_map.insert("name".into(), ArcValue::new_primitive("Alice".to_string()));
    alice_map.insert("age".into(), ArcValue::new_primitive(30i64));

    let mut bob_map: HashMap<String, ArcValue> = HashMap::new();
    bob_map.insert("name".into(), ArcValue::new_primitive("Bob".to_string()));
    bob_map.insert("age".into(), ArcValue::new_primitive(25i64));

    let mut charlie_map: HashMap<String, ArcValue> = HashMap::new();
    charlie_map.insert(
        "name".into(),
        ArcValue::new_primitive("Charlie".to_string()),
    );
    charlie_map.insert("age".into(), ArcValue::new_primitive(35i64));

    let list_of_maps = ArcValue::new_list(vec![
        ArcValue::new_map(alice_map),
        ArcValue::new_map(bob_map),
        ArcValue::new_map(charlie_map),
    ]);
    write_bytes(&out, "list_of_maps.bin", &list_of_maps.serialize(None)?)?;

    // 3. NESTED STRUCTURES - Map with Lists as Values
    let mut map_with_lists: HashMap<String, ArcValue> = HashMap::new();
    map_with_lists.insert(
        "numbers".into(),
        ArcValue::new_list::<i64>(vec![1, 2, 3, 4, 5]),
    );
    map_with_lists.insert(
        "strings".into(),
        ArcValue::new_list::<String>(vec!["hello".into(), "world".into(), "test".into()]),
    );
    map_with_lists.insert(
        "booleans".into(),
        ArcValue::new_list::<bool>(vec![true, false, true]),
    );
    map_with_lists.insert(
        "mixed".into(),
        ArcValue::new_list(vec![
            ArcValue::new_primitive(42i64),
            ArcValue::new_primitive("text".to_string()),
            ArcValue::new_primitive(true),
        ]),
    );
    let map_with_lists = ArcValue::new_map(map_with_lists);
    write_bytes(&out, "map_with_lists.bin", &map_with_lists.serialize(None)?)?;

    // 4. COMPLEX NESTED COMBINATIONS
    // Map containing lists of maps
    let mut user1_profile: HashMap<String, ArcValue> = HashMap::new();
    user1_profile.insert("verified".into(), ArcValue::new_primitive(true));
    user1_profile.insert("premium".into(), ArcValue::new_primitive(false));

    let mut user1: HashMap<String, ArcValue> = HashMap::new();
    user1.insert("id".into(), ArcValue::new_primitive(1i64));
    user1.insert("profile".into(), ArcValue::new_map(user1_profile));

    let mut user2_profile: HashMap<String, ArcValue> = HashMap::new();
    user2_profile.insert("verified".into(), ArcValue::new_primitive(false));
    user2_profile.insert("premium".into(), ArcValue::new_primitive(true));

    let mut user2: HashMap<String, ArcValue> = HashMap::new();
    user2.insert("id".into(), ArcValue::new_primitive(2i64));
    user2.insert("profile".into(), ArcValue::new_map(user2_profile));

    let users_list = ArcValue::new_list(vec![ArcValue::new_map(user1), ArcValue::new_map(user2)]);

    let mut metadata_map: HashMap<String, ArcValue> = HashMap::new();
    metadata_map.insert("version".into(), ArcValue::new_primitive("1.0".to_string()));
    metadata_map.insert(
        "features".into(),
        ArcValue::new_list::<String>(vec!["auth".into(), "profile".into(), "settings".into()]),
    );

    let mut complex_nested: HashMap<String, ArcValue> = HashMap::new();
    complex_nested.insert("users".into(), users_list);
    complex_nested.insert("metadata".into(), ArcValue::new_map(metadata_map));

    let complex_nested = ArcValue::new_map(complex_nested);
    write_bytes(&out, "complex_nested.bin", &complex_nested.serialize(None)?)?;

    // 5. EDGE CASES - Empty Collections
    let empty_list = ArcValue::new_list::<i64>(vec![]);
    write_bytes(&out, "list_empty.bin", &empty_list.serialize(None)?)?;

    let empty_map: HashMap<String, i64> = HashMap::new();
    let empty_map = ArcValue::new_map::<i64>(empty_map);
    write_bytes(&out, "map_empty.bin", &empty_map.serialize(None)?)?;

    // 6. EDGE CASES - Single Element Collections
    let single_list = ArcValue::new_list::<i64>(vec![42]);
    write_bytes(&out, "list_single.bin", &single_list.serialize(None)?)?;

    let mut single_map: HashMap<String, String> = HashMap::new();
    single_map.insert("key".into(), "value".into());
    let single_map = ArcValue::new_map::<String>(single_map);
    write_bytes(&out, "map_single.bin", &single_map.serialize(None)?)?;

    // 7. DEEP NESTING - Multiple Levels
    let level4_map = ArcValue::new_map({
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("level4".into(), "deepest value".into());
        m
    });

    let level3_list = ArcValue::new_list(vec![level4_map]);

    let level3_map = ArcValue::new_map({
        let mut m: HashMap<String, ArcValue> = HashMap::new();
        m.insert("level3".into(), level3_list);
        m
    });

    let level2_list = ArcValue::new_list(vec![level3_map]);

    let level2_map = ArcValue::new_map({
        let mut m: HashMap<String, ArcValue> = HashMap::new();
        m.insert("level2".into(), level2_list);
        m
    });

    let level1_list = ArcValue::new_list(vec![level2_map]);

    let level1_map = ArcValue::new_map({
        let mut m: HashMap<String, ArcValue> = HashMap::new();
        m.insert("level1".into(), level1_list);
        m
    });

    let deep_nesting = ArcValue::new_list(vec![level1_map]);
    write_bytes(&out, "deep_nesting.bin", &deep_nesting.serialize(None)?)?;

    // 8. LARGE DATA - Big Strings and Numbers
    let large_string = "x".repeat(1000); // 1KB string
    write_bytes(
        &out,
        "large_string.bin",
        &ArcValue::new_primitive(large_string).serialize(None)?,
    )?;

    let big_number: i64 = i64::MAX;
    write_bytes(
        &out,
        "big_number.bin",
        &ArcValue::new_primitive(big_number).serialize(None)?,
    )?;

    // 9. MIXED TYPE COMPLEXITY
    let mut mixed_complexity: HashMap<String, ArcValue> = HashMap::new();

    mixed_complexity.insert(
        "primitives".into(),
        ArcValue::new_list(vec![
            ArcValue::new_primitive(42i64),
            ArcValue::new_primitive("string".to_string()),
            ArcValue::new_primitive(true),
            ArcValue::new_primitive(consts::PI),
        ]),
    );

    mixed_complexity.insert(
        "bytes".into(),
        ArcValue::new_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    );
    mixed_complexity.insert(
        "json".into(),
        ArcValue::new_json(serde_json::json!({"complex": {"nested": {"object": [1, 2, 3]}}})),
    );
    mixed_complexity.insert(
        "struct".into(),
        ArcValue::new_struct(PlainUser {
            id: "test".into(),
            name: "TestUser".into(),
        }),
    );

    let mixed_complexity = ArcValue::new_map(mixed_complexity);
    write_bytes(
        &out,
        "mixed_complexity.bin",
        &mixed_complexity.serialize(None)?,
    )?;

    // 10. RECURSIVE STRUCTURES
    let recursive_user1 = PlainUser {
        id: "1".into(),
        name: "Alice".into(),
    };
    let recursive_user2 = PlainUser {
        id: "2".into(),
        name: "Bob".into(),
    };
    let recursive_user3 = PlainUser {
        id: "3".into(),
        name: "Charlie".into(),
    };

    let recursive_users = ArcValue::new_list(vec![
        ArcValue::new_struct(recursive_user1),
        ArcValue::new_struct(recursive_user2),
        ArcValue::new_struct(recursive_user3),
    ]);
    write_bytes(
        &out,
        "recursive_structs.bin",
        &recursive_users.serialize(None)?,
    )?;

    // 11. HETEROGENEOUS COLLECTIONS WITH ALL TYPES
    let all_types_list = ArcValue::new_list(vec![
        ArcValue::new_primitive(42i64),                          // integer
        ArcValue::new_primitive("string".to_string()),           // string
        ArcValue::new_primitive(true),                           // boolean
        ArcValue::new_primitive(consts::PI),                     // float
        ArcValue::new_bytes(vec![1, 2, 3]),                      // bytes
        ArcValue::new_json(serde_json::json!({"key": "value"})), // json
        ArcValue::new_struct(PlainUser {
            id: "test".into(),
            name: "Test".into(),
        }), // struct
        ArcValue::new_list::<i64>(vec![1, 2, 3]),                // nested list
        ArcValue::new_map({
            // nested map
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert("k".into(), "v".into());
            m
        }),
    ]);
    write_bytes(&out, "all_types_list.bin", &all_types_list.serialize(None)?)?;

    // 12. MAP WITH COMPLEX KEYS AND VALUES
    let mut complex_map: HashMap<String, ArcValue> = HashMap::new();

    complex_map.insert(
        "simple_string".into(),
        ArcValue::new_primitive("value".to_string()),
    );
    complex_map.insert("simple_number".into(), ArcValue::new_primitive(123i64));

    complex_map.insert(
        "nested_list".into(),
        ArcValue::new_list(vec![ArcValue::new_map({
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert("inner".into(), "data".into());
            m
        })]),
    );

    let mut nested_map_level1: HashMap<String, ArcValue> = HashMap::new();
    let mut nested_map_level2: HashMap<String, ArcValue> = HashMap::new();
    nested_map_level2.insert("level2".into(), ArcValue::new_primitive("deep".to_string()));
    nested_map_level1.insert("level1".into(), ArcValue::new_map(nested_map_level2));
    complex_map.insert("nested_map".into(), ArcValue::new_map(nested_map_level1));

    complex_map.insert(
        "mixed_array".into(),
        ArcValue::new_list(vec![
            ArcValue::new_primitive("string".to_string()),
            ArcValue::new_primitive(42i64),
            ArcValue::new_primitive(true),
            ArcValue::new_primitive("nested".to_string()),
        ]),
    );

    let complex_map = ArcValue::new_map(complex_map);
    write_bytes(&out, "complex_map.bin", &complex_map.serialize(None)?)?;

    // 13. PERFORMANCE TEST - Very Large Collections
    let very_large_list = ArcValue::new_list::<i64>((0..1000).collect());
    write_bytes(
        &out,
        "very_large_list.bin",
        &very_large_list.serialize(None)?,
    )?;

    let mut very_large_map: HashMap<String, i64> = HashMap::new();
    for i in 0..500 {
        very_large_map.insert(format!("key_{i}"), i as i64);
    }
    let very_large_map = ArcValue::new_map::<i64>(very_large_map);
    write_bytes(&out, "very_large_map.bin", &very_large_map.serialize(None)?)?;

    // 14. NULL AND UNDEFINED HANDLING - Using JSON for null values
    write_bytes(
        &out,
        "null_value.bin",
        &ArcValue::new_json(serde_json::json!(null)).serialize(None)?,
    )?;
    write_bytes(
        &out,
        "undefined_like.bin",
        &ArcValue::new_json(serde_json::json!(null)).serialize(None)?,
    )?;

    // 15. SPECIAL CHARACTERS AND UNICODE
    let unicode_string = "Hello 世界 🌍 Test: áéíóú ñ";
    write_bytes(
        &out,
        "unicode_string.bin",
        &ArcValue::new_primitive(unicode_string.to_string()).serialize(None)?,
    )?;

    let mut special_chars: HashMap<String, String> = HashMap::new();
    special_chars.insert("normal".into(), "value".into());
    special_chars.insert("with spaces".into(), "spaced value".into());
    special_chars.insert("with-dashes".into(), "dashed-value".into());
    special_chars.insert("with_underscores".into(), "underscore_value".into());
    special_chars.insert("with.dots".into(), "dotted.value".into());
    special_chars.insert("with/slashes".into(), "slashed/value".into());
    special_chars.insert("with\\backslashes".into(), "backslashed\\value".into());

    let special_chars_map = ArcValue::new_map::<String>(special_chars);
    write_bytes(
        &out,
        "special_chars_map.bin",
        &special_chars_map.serialize(None)?,
    )?;

    println!("Wrote serializer vectors to {}", out.display());
    Ok(())
}
