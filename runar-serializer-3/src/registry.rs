//! Global decryptor registry used by ArcValue.
use std::any::{Any, TypeId};
use std::sync::Arc;

use anyhow::Result;
use once_cell::sync::Lazy;
use dashmap::DashMap;

use crate::traits::{KeyStore, RunarDecrypt};
use serde::de::DeserializeOwned;

/// Function pointer stored in the registry.
pub type DecryptFn = fn(&[u8], &Arc<KeyStore>) -> Result<Box<dyn Any + Send + Sync>>;

/// Global, thread-safe map: PlainTypeId -> decrypt function.
static REGISTRY: Lazy<DashMap<TypeId, DecryptFn>> = Lazy::new(DashMap::new);

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
    fn decrypt_impl<Plain, Enc>(bytes: &[u8], ks: &Arc<KeyStore>) -> Result<Box<dyn Any + Send + Sync>>
    where
        Plain: 'static + Send + Sync,
        Enc: 'static + RunarDecrypt<Decrypted = Plain> + DeserializeOwned,
    {
        let enc: Enc = serde_cbor::from_slice(bytes)?;
        let plain = enc.decrypt_with_keystore(ks)?;
        Ok(Box::new(plain))
    }

    REGISTRY.insert(TypeId::of::<Plain>(), decrypt_impl::<Plain, Enc> as DecryptFn);
}

/// Attempt to decrypt the payload into `T` using the registered decryptor.
/// Returns an error if no decryptor is found.
pub fn try_decrypt_into<T>(bytes: &[u8], ks: &Arc<KeyStore>) -> Result<T>
where
    T: 'static + Send + Sync,
{
    let func = REGISTRY
        .get(&TypeId::of::<T>())
        .ok_or_else(|| anyhow::anyhow!("No decryptor registered for type {}", std::any::type_name::<T>()))?;

    let any_plain = (func.value())(bytes, ks)?;
    // Downcast into the concrete type we need.
    any_plain
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| anyhow::anyhow!("Decryptor returned wrong type for {}", std::any::type_name::<T>()))
} 