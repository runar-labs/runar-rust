use crate::arc_value::SerializationFnInner;
use crate::erased_arc::ErasedArc;
use crate::traits::{KeyStore, LabelResolver, RunarDecrypt, RunarEncrypt};
use crate::{ArcValue, DeserializerFnWrapper, LazyDataWithOffset, ValueCategory};
use anyhow::{anyhow, Result};
use prost::Message;
use runar_common::logging::Logger;
use rustc_hash::FxHashMap;
use std::collections::HashMap;

use std::any::Any;

use std::sync::Arc;

use crate::map_types::{
    StringToArcValueMap, StringToBoolMap, StringToFloatMap, StringToInt64Map, StringToIntMap,
    StringToStringMap,
};
use crate::vec_types::{
    VecHashMapStringBool, VecHashMapStringFloat, VecHashMapStringInt, VecHashMapStringString,
};

/// Registry for type-specific serialization and deserialization handlers
pub struct SerializerRegistry {
    serializers: FxHashMap<String, SerializationFnInner>,
    deserializers: FxHashMap<String, DeserializerFnWrapper>,
    is_sealed: bool,
    /// Logger for SerializerRegistry operations
    logger: Arc<Logger>,
    /// Key store for encryption/decryption operations
    keystore: Option<Arc<KeyStore>>,
    /// Label resolver for mapping labels to public keys
    label_resolver: Option<Arc<dyn LabelResolver>>,
}

impl SerializerRegistry {
    /// Create a new registry with default logger
    pub fn new(logger: Arc<Logger>) -> Self {
        let mut registry = SerializerRegistry {
            serializers: FxHashMap::default(),
            deserializers: FxHashMap::default(),
            is_sealed: false,
            logger,
            keystore: None,
            label_resolver: None,
        };
        registry.register_builtin_types();
        registry
    }

    /// Create a new registry with keystore and label resolver
    pub fn with_keystore(
        logger: Arc<Logger>,
        keystore: Arc<KeyStore>,
        label_resolver: Arc<dyn LabelResolver>,
    ) -> Self {
        SerializerRegistry {
            serializers: FxHashMap::default(),
            deserializers: FxHashMap::default(),
            is_sealed: false,
            logger,
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
        // Register common map types
        self.register_protobuf::<crate::map_types::StringToIntMap>()
            .unwrap();
        self.register_protobuf::<crate::map_types::StringToInt64Map>()
            .unwrap();
        self.register_protobuf::<crate::map_types::StringToFloatMap>()
            .unwrap();
        self.register_protobuf::<crate::map_types::StringToBoolMap>()
            .unwrap();
        self.register_protobuf::<crate::map_types::StringToStringMap>()
            .unwrap();
        self.register_protobuf::<crate::map_types::StringToArcValueMap>()
            .unwrap();
    }

    /// Register all built-in map and vector types
    pub fn register_builtin_types(&mut self) {
        // Map types
        self.register::<StringToIntMap>().ok();
        self.register::<StringToInt64Map>().ok();
        self.register::<StringToFloatMap>().ok();
        self.register::<StringToBoolMap>().ok();
        self.register::<StringToStringMap>().ok();
        self.register::<StringToArcValueMap>().ok();
        // Vector types
        self.register::<VecHashMapStringString>().ok();
        self.register::<VecHashMapStringInt>().ok();
        self.register::<VecHashMapStringFloat>().ok();
        self.register::<VecHashMapStringBool>().ok();

        // Register custom converters for direct HashMap and Vec types
        self.register_hashmap_converters();
        self.register_vec_converters();
    }

    /// Register converters for HashMap types
    fn register_hashmap_converters(&mut self) {
        // HashMap<String, String> converter
        let type_name = std::any::type_name::<HashMap<String, String>>();

        // Serializer: HashMap<String, String> -> StringToStringMap -> bytes
        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(hashmap) = value.downcast_ref::<HashMap<String, String>>() {
                let map_type = StringToStringMap::from_hashmap(hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&map_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during HashMap<String, String> serialization"
                ))
            }
        });

        // Deserializer: bytes -> StringToStringMap -> HashMap<String, String>
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let map_type: StringToStringMap = prost::Message::decode(bytes)?;
                let hashmap = map_type.into_hashmap();
                Ok(Box::new(hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // HashMap<String, i32> converter
        let type_name = std::any::type_name::<HashMap<String, i32>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(hashmap) = value.downcast_ref::<HashMap<String, i32>>() {
                let map_type = StringToIntMap::from_hashmap(hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&map_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during HashMap<String, i32> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let map_type: StringToIntMap = prost::Message::decode(bytes)?;
                let hashmap = map_type.into_hashmap();
                Ok(Box::new(hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // HashMap<String, f64> converter
        let type_name = std::any::type_name::<HashMap<String, f64>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(hashmap) = value.downcast_ref::<HashMap<String, f64>>() {
                let map_type = StringToFloatMap::from_hashmap(hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&map_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during HashMap<String, f64> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let map_type: StringToFloatMap = prost::Message::decode(bytes)?;
                let hashmap = map_type.into_hashmap();
                Ok(Box::new(hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // HashMap<String, bool> converter
        let type_name = std::any::type_name::<HashMap<String, bool>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(hashmap) = value.downcast_ref::<HashMap<String, bool>>() {
                let map_type = StringToBoolMap::from_hashmap(hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&map_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during HashMap<String, bool> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let map_type: StringToBoolMap = prost::Message::decode(bytes)?;
                let hashmap = map_type.into_hashmap();
                Ok(Box::new(hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();
    }

    /// Register converters for Vec types
    fn register_vec_converters(&mut self) {
        // Vec<HashMap<String, String>> converter
        let type_name = std::any::type_name::<Vec<HashMap<String, String>>>();

        // Serializer: Vec<HashMap<String, String>> -> VecHashMapStringString -> bytes
        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(vec_hashmap) = value.downcast_ref::<Vec<HashMap<String, String>>>() {
                let vec_type = VecHashMapStringString::from_vec_hashmap(vec_hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&vec_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during Vec<HashMap<String, String>> serialization"
                ))
            }
        });

        // Deserializer: bytes -> VecHashMapStringString -> Vec<HashMap<String, String>>
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let vec_type: VecHashMapStringString = prost::Message::decode(bytes)?;
                let vec_hashmap = vec_type.into_vec_hashmap();
                Ok(Box::new(vec_hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // Vec<HashMap<String, i32>> converter
        let type_name = std::any::type_name::<Vec<HashMap<String, i32>>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(vec_hashmap) = value.downcast_ref::<Vec<HashMap<String, i32>>>() {
                let vec_type = VecHashMapStringInt::from_vec_hashmap(vec_hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&vec_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during Vec<HashMap<String, i32>> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let vec_type: VecHashMapStringInt = prost::Message::decode(bytes)?;
                let vec_hashmap = vec_type.into_vec_hashmap();
                Ok(Box::new(vec_hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // Vec<HashMap<String, f64>> converter
        let type_name = std::any::type_name::<Vec<HashMap<String, f64>>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(vec_hashmap) = value.downcast_ref::<Vec<HashMap<String, f64>>>() {
                let vec_type = VecHashMapStringFloat::from_vec_hashmap(vec_hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&vec_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during Vec<HashMap<String, f64>> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let vec_type: VecHashMapStringFloat = prost::Message::decode(bytes)?;
                let vec_hashmap = vec_type.into_vec_hashmap();
                Ok(Box::new(vec_hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();

        // Vec<HashMap<String, bool>> converter
        let type_name = std::any::type_name::<Vec<HashMap<String, bool>>>();

        let serializer = Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
            if let Some(vec_hashmap) = value.downcast_ref::<Vec<HashMap<String, bool>>>() {
                let vec_type = VecHashMapStringBool::from_vec_hashmap(vec_hashmap.clone());
                let mut buf = Vec::new();
                prost::Message::encode(&vec_type, &mut buf)?;
                Ok(buf)
            } else {
                Err(anyhow!(
                    "Type mismatch during Vec<HashMap<String, bool>> serialization"
                ))
            }
        });

        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let vec_type: VecHashMapStringBool = prost::Message::decode(bytes)?;
                let vec_hashmap = vec_type.into_vec_hashmap();
                Ok(Box::new(vec_hashmap))
            });

        self.register_custom_serializer(type_name, serializer).ok();
        self.register_custom_deserializer(type_name, deserializer)
            .ok();
    }

    /// Seal the registry to prevent further modifications
    pub fn seal(&mut self) {
        self.is_sealed = true;
    }

    /// Check if the registry is sealed
    pub fn is_sealed(&self) -> bool {
        self.is_sealed
    }

    /// Register a type for serialization/deserialization
    pub fn register<T: 'static + prost::Message + Clone + Send + Sync + Default>(
        &mut self,
    ) -> Result<()> {
        self.register_without_encryption::<T>()
    }

    /// Register a protobuf type for serialization/deserialization
    pub fn register_protobuf<T: 'static + prost::Message + Clone + Send + Sync + Default>(
        &mut self,
    ) -> Result<()> {
        self.register_protobuf_type::<T>()
    }

    /// Register an encryptable type that implements RunarEncrypt / RunarDecrypt
    pub fn register_encryptable<T>(&mut self) -> Result<()>
    where
        T: 'static
            + RunarEncrypt
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + Default,
        T::Encrypted: 'static
            + prost::Message
            + RunarDecrypt<Decrypted = T>
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + Default,
    {
        self.register_with_encryption::<T>()
    }

    /// Register a type without encryption
    fn register_without_encryption<T>(&mut self) -> Result<()>
    where
        T: 'static + prost::Message + Clone + Send + Sync + Default,
    {
        if self.is_sealed {
            return Err(anyhow!(
                "Cannot register new types after registry is sealed"
            ));
        }

        // Get the full and simple type names
        let type_name = std::any::type_name::<T>();
        let simple_name = if let Some(last_segment) = type_name.split("::").last() {
            last_segment.to_string()
        } else {
            type_name.to_string()
        };

        // For now, we'll use a trait bound approach. Types that implement prost::Message
        // should be registered with a different method. This keeps the current behavior
        // for non-protobuf types while allowing protobuf types to be handled separately.

        // Register serializer using protobuf (all types should be protobuf-compatible)
        self.serializers.insert(
            type_name.to_string(),
            Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    let mut buf = Vec::new();
                    prost::Message::encode(typed_value, &mut buf)?;
                    Ok(buf)
                } else {
                    Err(anyhow!("Type mismatch during serialization"))
                }
            }),
        );

        // Create a deserializer function using protobuf
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let value: T = prost::Message::decode(bytes)?;
                Ok(Box::new(value))
            });

        // Register deserializer using both full and simple type names
        self.deserializers
            .insert(type_name.to_string(), deserializer.clone());

        // Only register the simple name version if it's different and not already registered
        if simple_name != type_name && !self.deserializers.contains_key(&simple_name) {
            self.deserializers.insert(simple_name, deserializer);
        }

        Ok(())
    }

    /// Register a protobuf type for serialization/deserialization
    fn register_protobuf_type<T>(&mut self) -> Result<()>
    where
        T: 'static + prost::Message + Clone + Send + Sync + Default,
    {
        if self.is_sealed {
            return Err(anyhow!(
                "Cannot register new types after registry is sealed"
            ));
        }

        // Get the full and simple type names
        let type_name = std::any::type_name::<T>();
        let simple_name = if let Some(last_segment) = type_name.split("::").last() {
            last_segment.to_string()
        } else {
            type_name.to_string()
        };

        // Register serializer using protobuf
        self.serializers.insert(
            type_name.to_string(),
            Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    let mut buf = Vec::new();
                    prost::Message::encode(typed_value, &mut buf)?;
                    Ok(buf)
                } else {
                    Err(anyhow!("Type mismatch during protobuf serialization"))
                }
            }),
        );

        // Create a deserializer function using protobuf
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let value: T = prost::Message::decode(bytes)?;
                Ok(Box::new(value))
            });

        // Register deserializer using both full and simple type names
        self.deserializers
            .insert(type_name.to_string(), deserializer.clone());

        // Only register the simple name version if it's different and not already registered
        if simple_name != type_name && !self.deserializers.contains_key(&simple_name) {
            self.deserializers.insert(simple_name, deserializer);
        }

        Ok(())
    }

    /// Register a type with encryption support
    fn register_with_encryption<T>(&mut self) -> Result<()>
    where
        T: 'static
            + RunarEncrypt
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + Default,
        T::Encrypted: 'static
            + prost::Message
            + RunarDecrypt<Decrypted = T>
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
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
                    Err(anyhow!("Cannot serialize plain type {type_name}"))
                }
            } else {
                Err(anyhow!("Type mismatch during serialization"))
            }
        });

        // Register custom serializer
        self.register_custom_serializer(type_name, serializer_closure)?;

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

        self.register_custom_serializer(encrypted_type_name, enc_serializer)?;

        // Deserializer for EncryptedT (prost decode only, no decryption)
        let enc_deser_wrapper = DeserializerFnWrapper::new(|bytes: &[u8]| {
            let decoded = T::Encrypted::decode(bytes)?;
            Ok(Box::new(decoded))
        });

        self.register_custom_deserializer(encrypted_type_name, enc_deser_wrapper)?;

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
                Err(anyhow!("Cannot deserialize plain type {type_name}"))
            });

        self.register_custom_deserializer(type_name, deserializer_wrapper)?;

        Ok(())
    }

    // register_map method removed - all types must implement prost::Message
    // and be registered via register() or register_protobuf()

    /// Register a custom deserializer with a specific type name
    pub fn register_custom_deserializer(
        &mut self,
        type_name: &str,
        deserializer: DeserializerFnWrapper,
    ) -> Result<()> {
        if self.is_sealed {
            return Err(anyhow!(
                "Cannot register new types after registry is sealed"
            ));
        }

        // Add the custom deserializer
        self.deserializers
            .insert(type_name.to_string(), deserializer);

        Ok(())
    }

    /// Register a custom serializer with a specific type name
    pub fn register_custom_serializer(
        &mut self,
        type_name: &str,
        serializer: SerializationFnInner,
    ) -> Result<()> {
        if self.is_sealed {
            return Err(anyhow!(
                "Cannot register new types after registry is sealed"
            ));
        }

        self.serializers.insert(type_name.to_string(), serializer);
        Ok(())
    }

    /// Serialize a value using the appropriate registered handler
    pub fn serialize(&self, value: &dyn Any, type_name: &str) -> Result<Vec<u8>> {
        if let Some(serializer) = self.serializers.get(type_name) {
            serializer(value)
                .map_err(|e| anyhow!("Serialization error for type {}: {}", type_name, e))
        } else {
            Err(anyhow!("No serializer registered for type: {}", type_name))
        }
    }

    /// Helper to extract the header from serialized bytes (slice view)
    fn extract_header_from_slice<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<(ValueCategory, String, &'a [u8])> {
        if bytes.is_empty() {
            return Err(anyhow!("Empty byte array"));
        }

        // First byte is the category marker
        let category = match bytes[0] {
            0x01 => ValueCategory::Primitive,
            0x02 => ValueCategory::List,
            0x03 => ValueCategory::Map,
            0x04 => ValueCategory::Struct,
            0x05 => ValueCategory::Null,
            0x06 => ValueCategory::Bytes,
            0x07 => ValueCategory::Json,
            _ => return Err(anyhow!("Invalid category marker: {}", bytes[0])),
        };

        // For null, no type name is needed
        if category == ValueCategory::Null {
            return Ok((category, String::new(), &[]));
        }

        // Extract the type name
        if bytes.len() < 2 {
            return Err(anyhow!("Byte array too short for header"));
        }

        let type_name_len = bytes[1] as usize;
        if bytes.len() < 2 + type_name_len {
            return Err(anyhow!("Byte array too short for type name"));
        }

        let type_name_bytes = &bytes[2..2 + type_name_len];
        let type_name = String::from_utf8(type_name_bytes.to_vec())
            .map_err(|_| anyhow!("Invalid type name encoding"))?;

        // The actual data starts after the type name
        let data_start_offset = 2 + type_name_len;
        let data_bytes = &bytes[data_start_offset..];

        Ok((category, type_name, data_bytes))
    }

    /// Deserialize bytes (owned Arc) to an ArcValue
    pub fn deserialize_value(&self, bytes_arc: Arc<[u8]>) -> Result<ArcValue> {
        if bytes_arc.is_empty() {
            return Err(anyhow!("Empty byte array"));
        }

        // Extract header info using a slice view
        let (original_category, type_name, data_slice) =
            self.extract_header_from_slice(&bytes_arc)?;

        // For null, just return a null value
        if original_category == ValueCategory::Null {
            return Ok(ArcValue::null());
        }

        self.logger.debug(format!(
            "Deserializing value with type: {type_name} (category: {original_category:?})"
        ));

        // For complex types, store LazyDataWithOffset
        self.logger.debug(format!(
            "Lazy deserialization setup for complex type: {type_name}"
        ));

        // Check if a deserializer exists (even though we don't store it in LazyDataWithOffset,
        // its registration confirms the type is known)
        if self.deserializers.contains_key(&type_name) {
            // Calculate offsets relative to the original Arc buffer
            let data_start_offset = (data_slice.as_ptr() as usize) - (bytes_arc.as_ptr() as usize);
            let data_end_offset = data_start_offset + data_slice.len();

            // Capture primary and alias deserializers if available
            let primary_deser = self.get_deserializer_arc(&type_name);
            // Build alias name Encrypted<Type>
            let alias_name = if let Some(idx) = type_name.rfind("::") {
                let (prefix, last) = type_name.split_at(idx + 2);
                format!("{prefix}Encrypted{last}")
            } else {
                format!("Encrypted{type_name}")
            };
            let alias_deser = self.get_deserializer_arc(&alias_name);

            let lazy_data = LazyDataWithOffset {
                type_name: type_name.to_string(),
                original_buffer: bytes_arc.clone(), // Clone the Arc (cheap)
                start_offset: data_start_offset,
                end_offset: data_end_offset,
                deserializer: primary_deser,
                alias_deserializer: alias_deser,
            };

            // Store Arc<LazyDataWithOffset> in value, keeping original category
            let value = ErasedArc::from_value(lazy_data);
            Ok(ArcValue::new(value, original_category))
        } else {
            Err(anyhow!(
                "No deserializer registered for complex type, cannot create lazy value: {}",
                type_name
            ))
        }
    }

    /// Get a stored deserializer by type name
    pub fn get_deserializer_arc(&self, type_name: &str) -> Option<DeserializerFnWrapper> {
        self.deserializers.get(type_name).cloned()
    }

    /// Print all registered deserializers for debugging
    pub fn debug_print_deserializers(&self) {
        for key in self.deserializers.keys() {
            self.logger.debug(format!("  - {key}"));
        }
    }

    /// Serialize a value to bytes, returning an Arc<[u8]>
    pub fn serialize_value(&self, value: &ArcValue) -> Result<Arc<[u8]>> {
        match value.value.as_ref() {
            Some(erased_arc_ref) => {
                // value.value is Some(erased_arc_ref)
                if erased_arc_ref.is_lazy {
                    // LAZY PATH
                    if let Ok(lazy) = erased_arc_ref.get_lazy_data() {
                        // Use erased_arc_ref
                        self.logger.debug(format!(
                            "Serializing lazy value with type: {} (category: {:?})",
                            lazy.type_name, value.category
                        ));
                        let mut result_vec = Vec::new();
                        let category_byte = match value.category {
                            ValueCategory::Primitive => 0x01,
                            ValueCategory::List => 0x02,
                            ValueCategory::Map => 0x03,
                            ValueCategory::Struct => 0x04,
                            ValueCategory::Null => {
                                return Err(anyhow!("Cannot serialize lazy Null value"))
                            }
                            ValueCategory::Bytes => 0x06,
                            ValueCategory::Json => 0x07,
                        };
                        result_vec.push(category_byte);
                        let type_bytes = lazy.type_name.as_bytes();
                        if type_bytes.len() > 255 {
                            return Err(anyhow!("Type name too long: {}", lazy.type_name));
                        }
                        result_vec.push(type_bytes.len() as u8);
                        result_vec.extend_from_slice(type_bytes);
                        result_vec.extend_from_slice(
                            &lazy.original_buffer[lazy.start_offset..lazy.end_offset],
                        );
                        Ok(Arc::from(result_vec))
                    } else {
                        Err(anyhow!(
                            "Value's ErasedArc is lazy, but failed to extract LazyDataWithOffset"
                        ))
                    }
                } else {
                    // EAGER NON-NULL PATH (value.value is Some(erased_arc_ref) and not lazy)
                    self.logger.debug(format!(
                        "Serializing eager value with type: {} (category: {:?})",
                        erased_arc_ref.type_name(), // Use erased_arc_ref
                        value.category
                    ));
                    let mut result_vec = Vec::new();
                    let category_byte = match value.category {
                        ValueCategory::Primitive => 0x01,
                        ValueCategory::List => 0x02,
                        ValueCategory::Map => 0x03,
                        ValueCategory::Struct => 0x04,
                        ValueCategory::Null => 0x05, // Null category with Some(value) is odd, but let's follow old logic
                        ValueCategory::Bytes => 0x06,
                        ValueCategory::Json => 0x07,
                    };
                    result_vec.push(category_byte);

                    if value.category == ValueCategory::Null {
                        // Should ideally not be hit if erased_arc_ref is Some.
                        // This implies an inconsistent ArcValue state.
                        return Ok(Arc::from(result_vec));
                    }

                    let type_name = erased_arc_ref.type_name();
                    let type_bytes = type_name.as_bytes();
                    if type_bytes.len() > 255 {
                        return Err(anyhow!("Type name too long: {}", type_name));
                    }
                    result_vec.push(type_bytes.len() as u8);
                    result_vec.extend_from_slice(type_bytes);

                    let data_bytes = match value.category {
                        ValueCategory::Primitive
                        | ValueCategory::List
                        | ValueCategory::Map
                        | ValueCategory::Struct => {
                            let any_ref = erased_arc_ref.as_any()?;
                            self.serialize(any_ref, type_name)?
                        }
                        ValueCategory::Bytes => {
                            if let Ok(bytes_arc) = erased_arc_ref.as_arc::<Vec<u8>>() {
                                bytes_arc.to_vec()
                            } else {
                                return Err(anyhow!(
                                    "Value has Bytes category but doesn't contain Arc<Vec<u8>> (actual: {})",
                                    erased_arc_ref.type_name()
                                ));
                            }
                        }
                        ValueCategory::Json => {
                            if let Ok(json_arc) = erased_arc_ref.as_arc::<serde_json::Value>() {
                                serde_json::to_vec(&*json_arc).map_err(|e| {
                                    anyhow!("Failed to serialize Json value to bytes: {}", e)
                                })?
                            } else {
                                return Err(anyhow!(
                                    "Value has Json category but doesn't contain Arc<serde_json::Value> (actual: {})",
                                    erased_arc_ref.type_name()
                                ));
                            }
                        }
                        ValueCategory::Null => {
                            unreachable!("Handled by category check or inconsistent state")
                        }
                    };
                    result_vec.extend_from_slice(&data_bytes);
                    Ok(Arc::from(result_vec))
                }
            }
            None => {
                // value.value is None
                // EAGER NULL PATH
                if value.category != ValueCategory::Null {
                    return Err(anyhow!(
                        "Inconsistent state for serialization: ArcValue.value is None but category is {:?}",
                        value.category
                    ));
                }
                self.logger.debug(format!(
                    "Serializing null value (category: {:?}, value is None)",
                    value.category
                ));
                let result_vec = vec![0x05]; // Null category marker
                Ok(Arc::from(result_vec))
            }
        }
    }
}
