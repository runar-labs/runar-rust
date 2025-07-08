use crate::traits::{KeyStore, LabelResolver, RunarDecrypt, RunarEncrypt};
use anyhow::{anyhow, Result};
use prost::Message;
use runar_common::logging::Logger;
use runar_common::types::arc_value::{
    DeserializerFnWrapper, SerializerRegistry as BaseSerializerRegistry, ValueCategory,
};
use runar_common::types::erased_arc::ErasedArc;
use runar_common::types::ArcValue;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Enhanced SerializerRegistry with encryption support
pub struct SerializerRegistry {
    /// Base registry from runar-common
    base_registry: BaseSerializerRegistry,
    /// Key store for encryption/decryption operations
    keystore: Option<Arc<KeyStore>>,
    /// Label resolver for mapping labels to public keys
    label_resolver: Option<Arc<dyn LabelResolver>>,
}

impl SerializerRegistry {
    /// Create a new registry with default logger
    pub fn new(logger: Arc<Logger>) -> Self {
        Self {
            base_registry: BaseSerializerRegistry::new(logger),
            keystore: None,
            label_resolver: None,
        }
    }

    /// Create a new registry with keystore and label resolver
    pub fn with_keystore(
        logger: Arc<Logger>,
        keystore: Arc<KeyStore>,
        label_resolver: Arc<dyn LabelResolver>,
    ) -> Self {
        Self {
            base_registry: BaseSerializerRegistry::new(logger),
            keystore: Some(keystore),
            label_resolver: Some(label_resolver),
        }
    }

    /// Initialize with default types
    pub fn with_defaults(logger: Arc<Logger>) -> Self {
        let mut registry = Self::new(logger);
        registry.register_defaults();
        registry
    }

    /// Register default type handlers
    fn register_defaults(&mut self) {
        // Register primitive types
        self.register::<i32>().unwrap();
        self.register::<i64>().unwrap();
        self.register::<f32>().unwrap();
        self.register::<f64>().unwrap();
        self.register::<bool>().unwrap();
        self.register::<String>().unwrap();

        // Register common container types
        self.register::<Vec<i32>>().unwrap();
        self.register::<Vec<i64>>().unwrap();
        self.register::<Vec<f32>>().unwrap();
        self.register::<Vec<f64>>().unwrap();
        self.register::<Vec<bool>>().unwrap();
        self.register::<Vec<String>>().unwrap();

        // Register common map types
        self.register_map::<String, String>().unwrap();
        self.register_map::<String, i32>().unwrap();
        self.register_map::<String, i64>().unwrap();
        self.register_map::<String, f64>().unwrap();
        self.register_map::<String, bool>().unwrap();
    }

    /// Seal the registry to prevent further modifications
    pub fn seal(&mut self) {
        self.base_registry.seal();
    }

    /// Check if the registry is sealed
    pub fn is_sealed(&self) -> bool {
        self.base_registry.is_sealed()
    }

    /// Register a non-encryptable type (plaintext serialization)
    pub fn register<T>(&mut self) -> Result<()>
    where
        T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync,
    {
        self.register_without_encryption::<T>()
    }

    /// Register an encryptable type that implements RunarEncrypt / RunarDecrypt
    pub fn register_encryptable<T>(&mut self) -> Result<()>
    where
        T: 'static
            + prost::Message
            + crate::traits::RunarEncrypt
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + prost::Message
            + Default,
        T::Encrypted: 'static
            + prost::Message
            + crate::traits::RunarDecrypt<Decrypted = T>
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + prost::Message
            + Default,
    {
        self.register_with_encryption::<T>()
    }

    /// Register a type with encryption support
    fn register_with_encryption<T>(&mut self) -> Result<()>
    where
        T: 'static
            + prost::Message
            + RunarEncrypt
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + prost::Message
            + Default,
        T::Encrypted: 'static
            + prost::Message
            + RunarDecrypt<Decrypted = T>
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + prost::Message
            + Default,
    {
        let type_name = std::any::type_name::<T>();

        // Prepare serializer that performs encryption
        let keystore = self.keystore.clone();
        let label_resolver = self.label_resolver.clone();
        let serializer_closure = Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(typed_value) = value.downcast_ref::<T>() {
                if let (Some(ref ks), Some(ref lr)) = (&keystore, &label_resolver) {
                    let encrypted = typed_value.encrypt_with_keystore(ks.as_ref(), lr.as_ref())?;
                    let mut buf = Vec::new();
                    Message::encode(&encrypted, &mut buf)?;
                    Ok(buf)
                } else {
                    let mut buf = Vec::new();
                    Message::encode(typed_value, &mut buf)?;
                    Ok(buf)
                }
            } else {
                Err(anyhow!("Type mismatch during serialization"))
            }
        });

        // Register custom serializer
        self.base_registry
            .register_custom_serializer(type_name, serializer_closure)?;

        // ---------- Encrypted< T > direct serializer/deserializer ----------
        let encrypted_type_name = std::any::type_name::<T::Encrypted>();

        // Serializer for EncryptedT (no decryption, plain prost encode)
        let enc_name_clone = encrypted_type_name.to_string();
        let enc_serializer = Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(enc) = value.downcast_ref::<T::Encrypted>() {
                let mut buf = Vec::new();
                prost::Message::encode(enc, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during encrypted serialization for {}",
                    enc_name_clone
                ))
            }
        });

        self.base_registry
            .register_custom_serializer(encrypted_type_name, enc_serializer)?;

        // Deserializer for EncryptedT (prost decode only, no decryption)
        let enc_deser_wrapper = DeserializerFnWrapper::new(|bytes: &[u8]| {
            let decoded = T::Encrypted::decode(bytes)?;
            Ok(Box::new(decoded))
        });

        self.base_registry
            .register_custom_deserializer(encrypted_type_name, enc_deser_wrapper)?;

        // Prepare deserializer that tries encrypted first
        let keystore_for_deser = self.keystore.clone();
        let deserializer_wrapper =
            DeserializerFnWrapper::new(move |bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                // Attempt encrypted deserialization
                if let Ok(enc_obj) = T::Encrypted::decode(bytes) {
                    if let Some(ref ks) = keystore_for_deser {
                        let dec = enc_obj.decrypt_with_keystore(ks.as_ref())?;
                        return Ok(Box::new(dec));
                    }
                }
                // Fallback to plaintext
                let obj: T = T::decode(bytes)?;
                Ok(Box::new(obj))
            });

        self.base_registry
            .register_custom_deserializer(type_name, deserializer_wrapper)?;

        // Ensure encrypted version itself is also registered for defaults (helps generic code)
        self.base_registry.register::<T::Encrypted>()?;

        Ok(())
    }

    /// Register a type without encryption
    fn register_without_encryption<T>(&mut self) -> Result<()>
    where
        T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync,
    {
        self.base_registry.register::<T>()
    }

    /// Register a map type
    pub fn register_map<K, V>(&mut self) -> Result<()>
    where
        K: 'static
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + Eq
            + std::hash::Hash,
        V: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync,
    {
        self.register::<HashMap<K, V>>()
    }

    /// Serialize a value to bytes, returning an Arc<[u8]>
    pub fn serialize_value(&self, value: &ArcValue) -> Result<Arc<[u8]>> {
        // Check if this is an encryptable type and we have keystore
        if let (Some(ref _keystore), Some(ref _resolver)) = (&self.keystore, &self.label_resolver) {
            // Try to encrypt if possible
            if let Some(erased_arc) = &value.value {
                if !erased_arc.is_lazy {
                    // Check if this is an encryptable type
                    let type_name = erased_arc.type_name();
                    if self.is_encryptable_type_by_name(type_name) {
                        // This is a simplified approach - in practice, we would need to
                        // downcast and encrypt here
                        log::warn!("Encryption not yet implemented for type: {type_name}");
                    }
                }
            }
        }

        self.base_registry.serialize_value(value)
    }

    /// Deserialize bytes to an ArcValue
    pub fn deserialize_value(&self, bytes_arc: Arc<[u8]>) -> Result<ArcValue> {
        // Fast-path: attempt to parse header and eagerly run our own registered deserializer.
        if bytes_arc.is_empty() {
            return Err(anyhow!("Empty byte slice"));
        }

        let category_byte = bytes_arc[0];
        let category = match category_byte {
            0x01 => ValueCategory::Primitive,
            0x02 => ValueCategory::List,
            0x03 => ValueCategory::Map,
            0x04 => ValueCategory::Struct,
            0x05 => ValueCategory::Null,
            0x06 => ValueCategory::Bytes,
            0x07 => ValueCategory::Json,
            _ => return Err(anyhow!(format!("Unknown category byte: {category_byte}"))),
        };

        if category == ValueCategory::Null {
            return Ok(ArcValue::null());
        }

        if bytes_arc.len() < 2 {
            return Err(anyhow!("Byte slice too short for header"));
        }
        let type_len = bytes_arc[1] as usize;
        if bytes_arc.len() < 2 + type_len {
            return Err(anyhow!("Byte slice too short for stated type length"));
        }
        let type_name_bytes = &bytes_arc[2..2 + type_len];
        let type_name = std::str::from_utf8(type_name_bytes)?.to_string();

        let payload_start = 2 + type_len;

        if let Some(wrapper) = self.get_deserializer_arc(&type_name) {
            // Build a lazy ArcValue that carries the wrapper so it can decrypt later.
            use runar_common::types::arc_value::LazyDataWithOffset;

            let lazy = LazyDataWithOffset {
                type_name: type_name.clone(),
                original_buffer: bytes_arc.clone(),
                start_offset: payload_start,
                end_offset: bytes_arc.len(),
                deserializer: Some(wrapper),
            };

            let erased = ErasedArc::from_value(lazy);
            return Ok(ArcValue::new(erased, category));
        }

        // Fallback to base behaviour (lazy path)
        self.base_registry.deserialize_value(bytes_arc)
    }

    /// Directly deserialize raw bytes into a concrete type `T` using the registered deserializer logic.
    /// This bypasses the ArcValue lazy layer and is encryption-aware (i.e. handles `T::Encrypted`).
    pub fn deserialize_bytes_to<T>(&self, bytes: &[u8]) -> Result<T>
    where
        T: 'static + Clone + Send + Sync,
    {
        // Parse header to locate actual payload bytes
        if bytes.is_empty() {
            return Err(anyhow!("Empty byte slice"));
        }

        // Category byte (we currently ignore it, but validate minimal length)
        let _category = bytes[0];
        if bytes.len() < 2 {
            return Err(anyhow!("Byte slice too short for header"));
        }
        let type_len = bytes[1] as usize;
        if bytes.len() < 2 + type_len {
            return Err(anyhow!("Byte slice too short for stated type length"));
        }
        let type_name_in_bytes = &bytes[2..2 + type_len];
        let type_name_in_header = std::str::from_utf8(type_name_in_bytes)?.to_string();

        let payload_start = 2 + type_len;

        let expected_type_name = std::any::type_name::<T>();

        let deser_type_name = if type_name_in_header == expected_type_name {
            expected_type_name
        } else {
            // Header might contain encrypted variant name, but we still want to use T's deserializer.
            expected_type_name
        };

        let deser = self.get_deserializer_arc(deser_type_name).ok_or_else(|| {
            anyhow!(format!(
                "No deserializer registered for type {deser_type_name}"
            ))
        })?;
        let boxed = deser.call(bytes[payload_start..].as_ref())?;
        boxed
            .downcast::<T>()
            .map(|b| (*b).clone())
            .map_err(|_| anyhow!("Failed to downcast to {expected_type_name}"))
    }

    /// Get a stored deserializer by type name
    pub fn get_deserializer_arc(&self, type_name: &str) -> Option<DeserializerFnWrapper> {
        self.base_registry.get_deserializer_arc(type_name)
    }

    /// Print all registered deserializers for debugging
    pub fn debug_print_deserializers(&self) {
        self.base_registry.debug_print_deserializers();
    }

    /// Check if a type name represents an encryptable type
    fn is_encryptable_type_by_name(&self, _type_name: &str) -> bool {
        false // Detection now handled by explicit registration
    }

    /// Decrypt an `EncryptedLabelGroup` into its plain struct using the registry's keystore.
    pub fn decrypt_label_group<T>(
        &self,
        group: &crate::encryption::EncryptedLabelGroup,
    ) -> Result<T>
    where
        T: for<'de> serde::Deserialize<'de> + prost::Message + Default,
    {
        let ks = self
            .keystore
            .as_ref()
            .ok_or_else(|| anyhow!("SerializerRegistry has no keystore configured"))?;
        crate::encryption::decrypt_label_group::<T>(group, ks.as_ref())
    }
}
