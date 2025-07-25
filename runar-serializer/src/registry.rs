//! Global decryptor registry used by ArcValue.
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;

use crate::traits::{KeyStore, RunarDecrypt};
use crate::ArcValue;
use serde::de::DeserializeOwned;

/// Function pointer stored in the registry.
pub type DecryptFn = fn(&[u8], &Arc<KeyStore>) -> Result<Box<dyn Any + Send + Sync>>;

/// Function pointer for JSON conversion stored in the registry.
pub type ToJsonFn = fn(&[u8]) -> Result<JsonValue>;

/// Global, thread-safe map: PlainTypeId -> decrypt function.
static STRUCT_REGISTRY: Lazy<DashMap<TypeId, DecryptFn>> = Lazy::new(DashMap::new);

/// Global, thread-safe map: Type name string -> JSON conversion function.
static JSON_REGISTRY: Lazy<DashMap<String, ToJsonFn>> = Lazy::new(DashMap::new);

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
        let enc: Enc = serde_cbor::from_slice(bytes)?;
        let plain = enc.decrypt_with_keystore(ks)?;
        Ok(Box::new(plain))
    }

    STRUCT_REGISTRY.insert(
        TypeId::of::<Plain>(),
        decrypt_impl::<Plain, Enc> as DecryptFn,
    );
}

/// Register a JSON conversion function for type `T`.
///
/// This is intended to be invoked automatically by the `Plain` and `Encrypt` derive macros
/// through a `#[ctor]`-annotated function, so user code never calls it directly.
pub fn register_to_json<T>()
where
    T: 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    // Mono-morphise a concrete JSON conversion function and insert it.
    fn to_json_impl<T>(bytes: &[u8]) -> Result<JsonValue>
    where
        T: 'static + serde::Serialize + serde::de::DeserializeOwned,
    {
        let value: T = serde_cbor::from_slice(bytes)?;
        serde_json::to_value(&value).map_err(anyhow::Error::from)
    }

    let type_name = std::any::type_name::<T>();
    let func = to_json_impl::<T>;

    JSON_REGISTRY.insert(type_name.to_string(), func);
}

/// Attempt to decrypt the payload into `T` using the registered decryptor.
/// Returns an error if no decryptor is found.
pub fn try_decrypt_into<T>(bytes: &[u8], ks: &Arc<KeyStore>) -> Result<T>
where
    T: 'static + Send + Sync,
{
    let func = STRUCT_REGISTRY.get(&TypeId::of::<T>()).ok_or_else(|| {
        anyhow::anyhow!(
            "No decryptor registered for type {}",
            std::any::type_name::<T>()
        )
    })?;

    let any_plain = (func.value())(bytes, ks)?;
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
    JSON_REGISTRY.get(type_name).map(|entry| *entry.value())
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
