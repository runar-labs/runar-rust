//! Global decryptor registry used by ArcValue.
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor::{from_slice, to_vec};
use serde_json::{to_value, Map, Value as JsonValue};

use crate::traits::{KeyStore, LabelResolver, RunarDecrypt, RunarEncrypt};
use crate::ArcValue;

/// Function pointer stored in the registry.
pub type DecryptFn = fn(&[u8], &Arc<KeyStore>) -> Result<Box<dyn Any + Send + Sync>>;

/// Function pointer for JSON conversion stored in the registry.
pub type ToJsonFn = fn(&[u8]) -> Result<JsonValue>;

/// Global, thread-safe map: PlainTypeId -> decrypt function.
static STRUCT_REGISTRY: Lazy<DashMap<TypeId, DecryptFn>> = Lazy::new(DashMap::new);

/// Function pointer for element encryption stored in the registry.
/// Receives a reference to a Plain value erased as &dyn Any, and returns CBOR bytes of Enc.
pub type EncryptFn = fn(&dyn Any, &Arc<KeyStore>, &LabelResolver) -> Result<Vec<u8>>;

/// Global, thread-safe map: PlainTypeId -> encrypt function.
static ENCRYPT_REGISTRY: Lazy<DashMap<TypeId, EncryptFn>> = Lazy::new(DashMap::new);

/// Global, thread-safe map: Type name (&'static str) -> JSON conversion function.
/// Using &'static str avoids per-registration heap allocations.
static JSON_REGISTRY: Lazy<DashMap<&'static str, ToJsonFn>> = Lazy::new(DashMap::new);

/// Wire-name registry (platform-neutral names)
/// rust_name -> wire_name
static TYPE_NAME_RUST_TO_WIRE: Lazy<DashMap<&'static str, &'static str>> = Lazy::new(DashMap::new);

/// wire_name -> JSON conversion function
static WIRE_NAME_JSON_REGISTRY: Lazy<DashMap<&'static str, ToJsonFn>> = Lazy::new(DashMap::new);

/// wire_name -> TypeId (for dynamic flows)
static WIRE_NAME_TO_TYPEID: Lazy<DashMap<&'static str, TypeId>> = Lazy::new(DashMap::new);

/// wire_name -> rust_name (diagnostics only)
static WIRE_NAME_TO_RUST: Lazy<DashMap<&'static str, &'static str>> = Lazy::new(DashMap::new);

/// Register a decryptor for `Plain` using the encrypted representation `Enc`.
///
/// This is intended to be invoked automatically by the `Encrypt` derive macro
/// through a `#[ctor]`-annotated function, so user code never calls it
/// directly.
pub fn register_decrypt<Plain, Enc>()
where
    Plain: 'static + Send + Sync,
    Enc: 'static + RunarDecrypt<Decrypted = Plain> + DeserializeOwned,
{
    // Mono-morphise a concrete decryptor function and insert it.
    fn decrypt_impl<Plain, Enc>(
        bytes: &[u8],
        ks: &Arc<KeyStore>,
    ) -> Result<Box<dyn Any + Send + Sync>>
    where
        Plain: 'static + Send + Sync,
        Enc: 'static + RunarDecrypt<Decrypted = Plain> + DeserializeOwned,
    {
        let enc: Enc = from_slice(bytes)?;
        let plain = enc.decrypt_with_keystore(ks)?;
        Ok(Box::new(plain))
    }

    STRUCT_REGISTRY.insert(
        TypeId::of::<Plain>(),
        decrypt_impl::<Plain, Enc> as DecryptFn,
    );
}

/// Register an encryptor for `Plain` producing encrypted representation `Enc`.
/// This is intended to be invoked automatically by the `Encrypt` derive macro.
pub fn register_encrypt<Plain, Enc>()
where
    Plain: 'static + RunarEncrypt<Encrypted = Enc>,
    Enc: 'static + Serialize,
{
    fn encrypt_impl<Plain, Enc>(
        value_any: &dyn Any,
        ks: &Arc<KeyStore>,
        resolver: &LabelResolver,
    ) -> Result<Vec<u8>>
    where
        Plain: 'static + RunarEncrypt<Encrypted = Enc>,
        Enc: 'static + Serialize,
    {
        let plain = value_any
            .downcast_ref::<Plain>()
            .ok_or_else(|| anyhow::anyhow!("Encrypt downcast failed"))?;
        let enc = plain.encrypt_with_keystore(ks, resolver)?;
        let bytes = to_vec(&enc)?;
        Ok(bytes)
    }

    ENCRYPT_REGISTRY.insert(
        TypeId::of::<Plain>(),
        encrypt_impl::<Plain, Enc> as EncryptFn,
    );
}

/// Lookup an encryptor function by the element TypeId.
pub fn lookup_encryptor_by_typeid(type_id: TypeId) -> Option<EncryptFn> {
    ENCRYPT_REGISTRY.get(&type_id).map(|e| *e.value())
}

/// Register a JSON conversion function for type `T`.
///
/// This is intended to be invoked automatically by the `Plain` and `Encrypt` derive macros
/// through a `#[ctor]`-annotated function, so user code never calls it directly.
pub fn register_to_json<T>()
where
    T: 'static + Serialize + DeserializeOwned,
{
    // Mono-morphise a concrete JSON conversion function and insert it.
    fn to_json_impl<T>(bytes: &[u8]) -> Result<JsonValue>
    where
        T: 'static + Serialize + DeserializeOwned,
    {
        let value: T = from_slice(bytes)?;
        to_value(&value).map_err(AnyhowError::from)
    }

    let type_name: &'static str = std::any::type_name::<T>();
    let func = to_json_impl::<T>;

    JSON_REGISTRY.insert(type_name, func);

    // If a wire name is already registered for this type, bind the JSON converter by wire name too
    if let Some(wire) = TYPE_NAME_RUST_TO_WIRE.get(type_name) {
        WIRE_NAME_JSON_REGISTRY.insert(*wire.value(), func);
    }
}

/// Register wire name for type `T` and bind its JSON converter under the wire name.
pub fn register_type_name<T>(wire_name: &'static str)
where
    T: 'static + Serialize + DeserializeOwned,
{
    let rust_name: &'static str = std::any::type_name::<T>();

    // First-registration wins. If already present, warn and return.
    if let Some(existing) = TYPE_NAME_RUST_TO_WIRE.get(rust_name) {
        if *existing == wire_name {
            return;
        }
    }

    if let Some(first) = WIRE_NAME_TO_RUST.get(wire_name) {
        // Keep first registration, ignore the later
        log::warn!(
            "duplicate_wire_name name={} first_type={} second_type={}",
            wire_name,
            *first,
            rust_name
        );
        return;
    }

    TYPE_NAME_RUST_TO_WIRE.insert(rust_name, wire_name);
    WIRE_NAME_TO_RUST.insert(wire_name, rust_name);
    WIRE_NAME_TO_TYPEID.insert(wire_name, TypeId::of::<T>());

    // If there's a JSON converter registered for this Rust type, bind it by wire name too
    if let Some(conv) = JSON_REGISTRY.get(rust_name) {
        WIRE_NAME_JSON_REGISTRY.insert(wire_name, *conv.value());
    }
}

/// Look up wire name by Rust type name
pub fn lookup_wire_name(rust_name: &str) -> Option<&'static str> {
    TYPE_NAME_RUST_TO_WIRE.get(rust_name).map(|e| *e.value())
}

/// Get a JSON conversion function for a wire name
pub fn get_json_converter_by_wire_name(wire_name: &str) -> Option<ToJsonFn> {
    if let Some(entry) = WIRE_NAME_JSON_REGISTRY.get(wire_name) {
        return Some(*entry.value());
    }
    // Support parameterized container names like list<...> and map<string,...>
    if let Some((base, _)) = wire_name.split_once('<') {
        match base {
            "list" => return Some(to_json_list_wire as ToJsonFn),
            "map" => return Some(to_json_map_wire as ToJsonFn),
            _ => {}
        }
    }
    None
}

/// Look up TypeId by wire name (for dynamic flows)
pub fn lookup_type_id_by_wire_name(wire_name: &str) -> Option<TypeId> {
    WIRE_NAME_TO_TYPEID.get(wire_name).map(|e| *e.value())
}

/// Look up Rust type name by wire name (diagnostics)
pub fn lookup_rust_name_by_wire_name(wire_name: &str) -> Option<&'static str> {
    WIRE_NAME_TO_RUST.get(wire_name).map(|e| *e.value())
}

/// Attempt to decrypt the payload into `T` using the registered decryptor.
/// Returns an error if no decryptor is found.
pub fn try_decrypt_into<T>(bytes: &[u8], ks: &Arc<KeyStore>) -> Result<T>
where
    T: 'static + Send + Sync,
{
    // Minimize time under the map lock: copy out the function pointer, then drop guard.
    let decrypt_fn: DecryptFn = {
        let entry = STRUCT_REGISTRY.get(&TypeId::of::<T>()).ok_or_else(|| {
            anyhow::anyhow!(
                "No decryptor registered for type {}",
                std::any::type_name::<T>()
            )
        })?;
        *entry.value()
    };

    let any_plain = (decrypt_fn)(bytes, ks)?;
    // Downcast into the concrete type we need.
    any_plain.downcast::<T>().map(|boxed| *boxed).map_err(|_| {
        anyhow::anyhow!(
            "Decryptor returned wrong type for {}",
            std::any::type_name::<T>()
        )
    })
}

/// Get a JSON conversion function for a type name.
/// Returns None if no converter is registered for the type name.
pub fn get_json_converter(type_name: &str) -> Option<ToJsonFn> {
    // DashMap supports borrowed lookups; this avoids allocating a String key
    JSON_REGISTRY.get(type_name).map(|entry| *entry.value())
}

// -------------------------------------------------------------
// Wire-name JSON converters for containers: list/map/json
// -------------------------------------------------------------

fn to_json_list_wire(bytes: &[u8]) -> Result<JsonValue> {
    // Prefer Vec<ArcValue> to allow nested struct conversion
    if let Ok(vec_av) = from_slice::<Vec<ArcValue>>(bytes) {
        let mut out = Vec::with_capacity(vec_av.len());
        for v in vec_av.iter() {
            out.push(v.to_json()?);
        }
        return Ok(JsonValue::Array(out));
    }

    // Fallback: direct CBOR -> JSON
    let value: JsonValue = from_slice(bytes)?;
    Ok(value)
}

fn to_json_map_wire(bytes: &[u8]) -> Result<JsonValue> {
    // Prefer HashMap<String, ArcValue> to allow nested struct conversion
    if let Ok(map_av) = from_slice::<std::collections::HashMap<String, ArcValue>>(bytes) {
        let mut obj = Map::with_capacity(map_av.len());
        for (k, v) in map_av.iter() {
            obj.insert(k.clone(), v.to_json()?);
        }
        return Ok(JsonValue::Object(obj));
    }

    // Fallback: direct CBOR -> JSON
    let value: JsonValue = from_slice(bytes)?;
    Ok(value)
}

fn to_json_json_wire(bytes: &[u8]) -> Result<JsonValue> {
    let value: JsonValue = from_slice(bytes)?;
    Ok(value)
}

// Common JSON converters for Vec<V> and HashMap<K, V>
// Using all primitive variants of K and V where V can be Vec and Map also.
// Use CTOR to register the converters

#[ctor::ctor]
fn register_vec_arcvalue_converter() {
    register_to_json::<Vec<ArcValue>>();
    register_to_json::<HashMap<String, ArcValue>>();
    register_to_json::<Vec<HashMap<String, ArcValue>>>();
    register_to_json::<HashMap<String, Vec<ArcValue>>>();
    register_to_json::<HashMap<String, HashMap<String, ArcValue>>>();
    register_to_json::<Vec<Vec<ArcValue>>>();
    register_to_json::<Vec<HashMap<String, ArcValue>>>();
    register_to_json::<HashMap<String, Vec<ArcValue>>>();
    register_to_json::<HashMap<String, HashMap<String, ArcValue>>>();
}

// Pre-register wire names for primitives and containers
#[ctor::ctor]
fn register_wire_names_and_converters() {
    // Primitives
    register_to_json::<String>();
    register_type_name::<String>("string");

    register_to_json::<bool>();
    register_type_name::<bool>("bool");

    register_to_json::<char>();
    register_type_name::<char>("char");

    register_to_json::<i8>();
    register_type_name::<i8>("i8");
    register_to_json::<i16>();
    register_type_name::<i16>("i16");
    register_to_json::<i32>();
    register_type_name::<i32>("i32");
    register_to_json::<i64>();
    register_type_name::<i64>("i64");
    register_to_json::<i128>();
    register_type_name::<i128>("i128");

    register_to_json::<u8>();
    register_type_name::<u8>("u8");
    register_to_json::<u16>();
    register_type_name::<u16>("u16");
    register_to_json::<u32>();
    register_type_name::<u32>("u32");
    register_to_json::<u64>();
    register_type_name::<u64>("u64");
    register_to_json::<u128>();
    register_type_name::<u128>("u128");

    register_to_json::<f32>();
    register_type_name::<f32>("f32");
    register_to_json::<f64>();
    register_type_name::<f64>("f64");

    register_to_json::<Vec<u8>>();
    register_type_name::<Vec<u8>>("bytes");

    // Containers: bind JSON converters under wire names
    WIRE_NAME_JSON_REGISTRY.insert("list", to_json_list_wire as ToJsonFn);
    WIRE_NAME_JSON_REGISTRY.insert("map", to_json_map_wire as ToJsonFn);
    WIRE_NAME_JSON_REGISTRY.insert("json", to_json_json_wire as ToJsonFn);
}

// Vec converters for primitive types
#[ctor::ctor]
fn register_vec_primitive_converters() {
    // Vec of primitive types - ALL combinations
    register_to_json::<Vec<i8>>();
    register_to_json::<Vec<i16>>();
    register_to_json::<Vec<i32>>();
    register_to_json::<Vec<i64>>();
    register_to_json::<Vec<i128>>();
    register_to_json::<Vec<u8>>();
    register_to_json::<Vec<u16>>();
    register_to_json::<Vec<u32>>();
    register_to_json::<Vec<u64>>();
    register_to_json::<Vec<u128>>();
    register_to_json::<Vec<f32>>();
    register_to_json::<Vec<f64>>();
    register_to_json::<Vec<bool>>();
    register_to_json::<Vec<char>>();
    register_to_json::<Vec<String>>();
    register_to_json::<Vec<Vec<u8>>>();
}

// HashMap converters for primitive types
#[ctor::ctor]
fn register_hashmap_primitive_converters() {
    // HashMap<String, primitive> converters - ALL combinations
    register_to_json::<HashMap<String, i8>>();
    register_to_json::<HashMap<String, i16>>();
    register_to_json::<HashMap<String, i32>>();
    register_to_json::<HashMap<String, i64>>();
    register_to_json::<HashMap<String, i128>>();
    register_to_json::<HashMap<String, u8>>();
    register_to_json::<HashMap<String, u16>>();
    register_to_json::<HashMap<String, u32>>();
    register_to_json::<HashMap<String, u64>>();
    register_to_json::<HashMap<String, u128>>();
    register_to_json::<HashMap<String, f32>>();
    register_to_json::<HashMap<String, f64>>();
    register_to_json::<HashMap<String, bool>>();
    register_to_json::<HashMap<String, char>>();
    register_to_json::<HashMap<String, String>>();
    register_to_json::<HashMap<String, Vec<u8>>>();
}

// Nested container converters - ALL combinations
#[ctor::ctor]
fn register_nested_container_converters() {
    // Vec of Vec - ALL primitive combinations
    register_to_json::<Vec<Vec<i8>>>();
    register_to_json::<Vec<Vec<i16>>>();
    register_to_json::<Vec<Vec<i32>>>();
    register_to_json::<Vec<Vec<i64>>>();
    register_to_json::<Vec<Vec<i128>>>();
    register_to_json::<Vec<Vec<u8>>>();
    register_to_json::<Vec<Vec<u16>>>();
    register_to_json::<Vec<Vec<u32>>>();
    register_to_json::<Vec<Vec<u64>>>();
    register_to_json::<Vec<Vec<u128>>>();
    register_to_json::<Vec<Vec<f32>>>();
    register_to_json::<Vec<Vec<f64>>>();
    register_to_json::<Vec<Vec<bool>>>();
    register_to_json::<Vec<Vec<char>>>();
    register_to_json::<Vec<Vec<String>>>();
    register_to_json::<Vec<Vec<Vec<u8>>>>();

    // Vec of HashMap - ALL primitive combinations
    register_to_json::<Vec<HashMap<String, i8>>>();
    register_to_json::<Vec<HashMap<String, i16>>>();
    register_to_json::<Vec<HashMap<String, i32>>>();
    register_to_json::<Vec<HashMap<String, i64>>>();
    register_to_json::<Vec<HashMap<String, i128>>>();
    register_to_json::<Vec<HashMap<String, u8>>>();
    register_to_json::<Vec<HashMap<String, u16>>>();
    register_to_json::<Vec<HashMap<String, u32>>>();
    register_to_json::<Vec<HashMap<String, u64>>>();
    register_to_json::<Vec<HashMap<String, u128>>>();
    register_to_json::<Vec<HashMap<String, f32>>>();
    register_to_json::<Vec<HashMap<String, f64>>>();
    register_to_json::<Vec<HashMap<String, bool>>>();
    register_to_json::<Vec<HashMap<String, char>>>();
    register_to_json::<Vec<HashMap<String, String>>>();
    register_to_json::<Vec<HashMap<String, Vec<u8>>>>();

    // HashMap of Vec - ALL primitive combinations
    register_to_json::<HashMap<String, Vec<i8>>>();
    register_to_json::<HashMap<String, Vec<i16>>>();
    register_to_json::<HashMap<String, Vec<i32>>>();
    register_to_json::<HashMap<String, Vec<i64>>>();
    register_to_json::<HashMap<String, Vec<i128>>>();
    register_to_json::<HashMap<String, Vec<u8>>>();
    register_to_json::<HashMap<String, Vec<u16>>>();
    register_to_json::<HashMap<String, Vec<u32>>>();
    register_to_json::<HashMap<String, Vec<u64>>>();
    register_to_json::<HashMap<String, Vec<u128>>>();
    register_to_json::<HashMap<String, Vec<f32>>>();
    register_to_json::<HashMap<String, Vec<f64>>>();
    register_to_json::<HashMap<String, Vec<bool>>>();
    register_to_json::<HashMap<String, Vec<char>>>();
    register_to_json::<HashMap<String, Vec<String>>>();
    register_to_json::<HashMap<String, Vec<Vec<u8>>>>();

    // HashMap of HashMap - ALL primitive combinations
    register_to_json::<HashMap<String, HashMap<String, i8>>>();
    register_to_json::<HashMap<String, HashMap<String, i16>>>();
    register_to_json::<HashMap<String, HashMap<String, i32>>>();
    register_to_json::<HashMap<String, HashMap<String, i64>>>();
    register_to_json::<HashMap<String, HashMap<String, i128>>>();
    register_to_json::<HashMap<String, HashMap<String, u8>>>();
    register_to_json::<HashMap<String, HashMap<String, u16>>>();
    register_to_json::<HashMap<String, HashMap<String, u32>>>();
    register_to_json::<HashMap<String, HashMap<String, u64>>>();
    register_to_json::<HashMap<String, HashMap<String, u128>>>();
    register_to_json::<HashMap<String, HashMap<String, f32>>>();
    register_to_json::<HashMap<String, HashMap<String, f64>>>();
    register_to_json::<HashMap<String, HashMap<String, bool>>>();
    register_to_json::<HashMap<String, HashMap<String, char>>>();
    register_to_json::<HashMap<String, HashMap<String, String>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u8>>>>();
}

// Triple nested container converters - ALL combinations
#[ctor::ctor]
fn register_triple_nested_container_converters() {
    // Vec of Vec of Vec - ALL primitive combinations
    register_to_json::<Vec<Vec<Vec<i8>>>>();
    register_to_json::<Vec<Vec<Vec<i16>>>>();
    register_to_json::<Vec<Vec<Vec<i32>>>>();
    register_to_json::<Vec<Vec<Vec<i64>>>>();
    register_to_json::<Vec<Vec<Vec<i128>>>>();
    register_to_json::<Vec<Vec<Vec<u8>>>>();
    register_to_json::<Vec<Vec<Vec<u16>>>>();
    register_to_json::<Vec<Vec<Vec<u32>>>>();
    register_to_json::<Vec<Vec<Vec<u64>>>>();
    register_to_json::<Vec<Vec<Vec<u128>>>>();
    register_to_json::<Vec<Vec<Vec<f32>>>>();
    register_to_json::<Vec<Vec<Vec<f64>>>>();
    register_to_json::<Vec<Vec<Vec<bool>>>>();
    register_to_json::<Vec<Vec<Vec<char>>>>();
    register_to_json::<Vec<Vec<Vec<String>>>>();
    register_to_json::<Vec<Vec<Vec<Vec<u8>>>>>();

    // Vec of Vec of HashMap - ALL primitive combinations
    register_to_json::<Vec<Vec<HashMap<String, i8>>>>();
    register_to_json::<Vec<Vec<HashMap<String, i16>>>>();
    register_to_json::<Vec<Vec<HashMap<String, i32>>>>();
    register_to_json::<Vec<Vec<HashMap<String, i64>>>>();
    register_to_json::<Vec<Vec<HashMap<String, i128>>>>();
    register_to_json::<Vec<Vec<HashMap<String, u8>>>>();
    register_to_json::<Vec<Vec<HashMap<String, u16>>>>();
    register_to_json::<Vec<Vec<HashMap<String, u32>>>>();
    register_to_json::<Vec<Vec<HashMap<String, u64>>>>();
    register_to_json::<Vec<Vec<HashMap<String, u128>>>>();
    register_to_json::<Vec<Vec<HashMap<String, f32>>>>();
    register_to_json::<Vec<Vec<HashMap<String, f64>>>>();
    register_to_json::<Vec<Vec<HashMap<String, bool>>>>();
    register_to_json::<Vec<Vec<HashMap<String, char>>>>();
    register_to_json::<Vec<Vec<HashMap<String, String>>>>();
    register_to_json::<Vec<Vec<HashMap<String, Vec<u8>>>>>();

    // Vec of HashMap of Vec - ALL primitive combinations
    register_to_json::<Vec<HashMap<String, Vec<i8>>>>();
    register_to_json::<Vec<HashMap<String, Vec<i16>>>>();
    register_to_json::<Vec<HashMap<String, Vec<i32>>>>();
    register_to_json::<Vec<HashMap<String, Vec<i64>>>>();
    register_to_json::<Vec<HashMap<String, Vec<i128>>>>();
    register_to_json::<Vec<HashMap<String, Vec<u8>>>>();
    register_to_json::<Vec<HashMap<String, Vec<u16>>>>();
    register_to_json::<Vec<HashMap<String, Vec<u32>>>>();
    register_to_json::<Vec<HashMap<String, Vec<u64>>>>();
    register_to_json::<Vec<HashMap<String, Vec<u128>>>>();
    register_to_json::<Vec<HashMap<String, Vec<f32>>>>();
    register_to_json::<Vec<HashMap<String, Vec<f64>>>>();
    register_to_json::<Vec<HashMap<String, Vec<bool>>>>();
    register_to_json::<Vec<HashMap<String, Vec<char>>>>();
    register_to_json::<Vec<HashMap<String, Vec<String>>>>();
    register_to_json::<Vec<HashMap<String, Vec<Vec<u8>>>>>();

    // Vec of HashMap of HashMap - ALL primitive combinations
    register_to_json::<Vec<HashMap<String, HashMap<String, i8>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, i16>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, i32>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, i64>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, i128>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, u8>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, u16>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, u32>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, u64>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, u128>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, f32>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, f64>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, bool>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, char>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, String>>>>();
    register_to_json::<Vec<HashMap<String, HashMap<String, Vec<u8>>>>>();

    // HashMap of Vec of Vec - ALL primitive combinations
    register_to_json::<HashMap<String, Vec<Vec<i8>>>>();
    register_to_json::<HashMap<String, Vec<Vec<i16>>>>();
    register_to_json::<HashMap<String, Vec<Vec<i32>>>>();
    register_to_json::<HashMap<String, Vec<Vec<i64>>>>();
    register_to_json::<HashMap<String, Vec<Vec<i128>>>>();
    register_to_json::<HashMap<String, Vec<Vec<u8>>>>();
    register_to_json::<HashMap<String, Vec<Vec<u16>>>>();
    register_to_json::<HashMap<String, Vec<Vec<u32>>>>();
    register_to_json::<HashMap<String, Vec<Vec<u64>>>>();
    register_to_json::<HashMap<String, Vec<Vec<u128>>>>();
    register_to_json::<HashMap<String, Vec<Vec<f32>>>>();
    register_to_json::<HashMap<String, Vec<Vec<f64>>>>();
    register_to_json::<HashMap<String, Vec<Vec<bool>>>>();
    register_to_json::<HashMap<String, Vec<Vec<char>>>>();
    register_to_json::<HashMap<String, Vec<Vec<String>>>>();
    register_to_json::<HashMap<String, Vec<Vec<Vec<u8>>>>>();

    // HashMap of Vec of HashMap - ALL primitive combinations
    register_to_json::<HashMap<String, Vec<HashMap<String, i8>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, i16>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, i32>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, i64>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, i128>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, u8>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, u16>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, u32>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, u64>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, u128>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, f32>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, f64>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, bool>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, char>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, String>>>>();
    register_to_json::<HashMap<String, Vec<HashMap<String, Vec<u8>>>>>();

    // HashMap of HashMap of Vec - ALL primitive combinations
    register_to_json::<HashMap<String, HashMap<String, Vec<i8>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<i16>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<i32>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<i64>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<i128>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u8>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u16>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u32>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u64>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<u128>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<f32>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<f64>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<bool>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<char>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<String>>>>();
    register_to_json::<HashMap<String, HashMap<String, Vec<Vec<u8>>>>>();

    // HashMap of HashMap of HashMap - ALL primitive combinations
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, i8>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, i16>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, i32>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, i64>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, i128>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, u8>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, u16>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, u32>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, u64>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, u128>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, f32>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, f64>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, bool>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, char>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, String>>>>();
    register_to_json::<HashMap<String, HashMap<String, HashMap<String, Vec<u8>>>>>();
}
