use anyhow::Result;
use runar_serializer::{runar, ArcValue, Encrypt, Plain};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    println!("Wrote serializer vectors to {}", out.display());
    Ok(())
}
