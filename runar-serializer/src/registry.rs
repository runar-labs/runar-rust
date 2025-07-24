//! Global decryptor registry used by ArcValue.
use std::any::{Any, TypeId};
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;

use crate::traits::{KeyStore, RunarDecrypt};
use serde::de::DeserializeOwned;

/// Function pointer stored in the registry.
pub type DecryptFn = fn(&[u8], &Arc<KeyStore>) -> Result<Box<dyn Any + Send + Sync>>;

/// Function pointer for JSON conversion stored in the registry.
pub type ToJsonFn = fn(&[u8]) -> Result<JsonValue>;

/// Global, thread-safe map: PlainTypeId -> decrypt function.
static REGISTRY: Lazy<DashMap<TypeId, DecryptFn>> = Lazy::new(DashMap::new);

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

    REGISTRY.insert(
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
    let func = REGISTRY.get(&TypeId::of::<T>()).ok_or_else(|| {
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
