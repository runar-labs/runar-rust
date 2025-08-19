use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::RunarEncrypt;

use super::encryption::decrypt_bytes;

use super::erased_arc::ErasedArc;
use super::traits::{KeyStore, LabelResolver, SerializationContext};

// Type alias to simplify very complex function pointer type used for serialization functions.
type SerializeFn = dyn Fn(&ErasedArc, Option<&Arc<KeyStore>>, Option<&dyn LabelResolver>) -> Result<Vec<u8>>
    + Send
    + Sync;

type ToJsonFn = dyn Fn(&ErasedArc) -> Result<JsonValue> + Send + Sync;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueCategory {
    Null = 0,
    Primitive = 1,
    List = 2,
    Map = 3,
    Struct = 4,
    Bytes = 5,
    Json = 6,
}

impl ValueCategory {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ValueCategory::Null),
            1 => Some(ValueCategory::Primitive),
            2 => Some(ValueCategory::List),
            3 => Some(ValueCategory::Map),
            4 => Some(ValueCategory::Struct),
            5 => Some(ValueCategory::Bytes),
            6 => Some(ValueCategory::Json),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct ArcValue {
    category: ValueCategory,
    value: Option<ErasedArc>,
    serialize_fn: Option<Arc<SerializeFn>>,
    to_json_fn: Option<Arc<ToJsonFn>>,
}

impl fmt::Debug for ArcValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArcValue")
            .field("category", &self.category)
            .field("value", &self.value)
            .field(
                "serialize_fn",
                &if self.serialize_fn.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl PartialEq for ArcValue {
    fn eq(&self, other: &Self) -> bool {
        if self.category != other.category {
            return false;
        }
        match (&self.value, &other.value) {
            (Some(v1), Some(v2)) => v1.eq_value(v2),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for ArcValue {}

#[derive(Clone)]
pub struct LazyDataWithOffset {
    pub type_name: String,
    pub original_buffer: Arc<[u8]>,
    pub start_offset: usize,
    pub end_offset: usize,
    pub keystore: Option<Arc<KeyStore>>,
    pub encrypted: bool,
}

impl fmt::Debug for LazyDataWithOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyDataWithOffset")
            .field("type_name", &self.type_name)
            .field("original_buffer_len", &self.original_buffer.len())
            .field("data_segment_len", &(self.end_offset - self.start_offset))
            .field("start_offset", &self.start_offset)
            .field("end_offset", &self.end_offset)
            .finish()
    }
}

impl ArcValue {
    fn parse_generic_params(rust_type_name: &str) -> Option<Vec<String>> {
        let start = rust_type_name.find('<')?;
        let end = rust_type_name.rfind('>')?;
        if end <= start + 1 {
            return Some(Vec::new());
        }
        let inside = &rust_type_name[start + 1..end];
        // Naive split on commas, sufficient for Vec<T> and HashMap<K, V>
        let params = inside
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>();
        Some(params)
    }

    fn wire_name_for_container(inner: &ErasedArc, is_list: bool) -> Result<String> {
        let rust_type_name = inner.type_name();
        // If container holds ArcValue elements, it's heterogeneous
        if is_list {
            if rust_type_name.contains("ArcValue") {
                return Ok("list<any>".to_string());
            }
            if let Some(params) = Self::parse_generic_params(rust_type_name) {
                if let Some(elem_rust) = params.first() {
                    if elem_rust.contains("ArcValue") {
                        return Ok("list<any>".to_string());
                    }
                    if let Some(wire) = crate::registry::lookup_wire_name(elem_rust) {
                        return Ok(format!("list<{wire}>"));
                    }
                    // If primitive, registry must already have it; error otherwise
                    return Err(anyhow!(
                        "Missing wire-name registration for list element type: {}",
                        elem_rust
                    ));
                }
            }
            // Unknown format
            Err(anyhow!(
                "Unable to determine element type for list: {}",
                rust_type_name
            ))
        } else {
            // Map
            if rust_type_name.contains("ArcValue") {
                return Ok("map<string,any>".to_string());
            }
            if let Some(params) = Self::parse_generic_params(rust_type_name) {
                if params.len() != 2 {
                    return Err(anyhow!(
                        "Expected two generic params for map, got {} in {}",
                        params.len(),
                        rust_type_name
                    ));
                }
                let key_rust = &params[0];
                let val_rust = &params[1];
                if !is_string(key_rust)
                    && key_rust != "alloc::string::String"
                    && key_rust != "std::string::String"
                {
                    return Err(anyhow!("Map key must be String, got {}", key_rust));
                }
                if val_rust.contains("ArcValue") {
                    return Ok("map<string,any>".to_string());
                }
                if let Some(wire) = crate::registry::lookup_wire_name(val_rust) {
                    return Ok(format!("map<string,{wire}>"));
                }
                return Err(anyhow!(
                    "Missing wire-name registration for map value type: {}",
                    val_rust
                ));
            }
            Err(anyhow!(
                "Unable to determine key/value types for map: {}",
                rust_type_name
            ))
        }
    }

    /// Category of this value
    pub fn category(&self) -> ValueCategory {
        self.category
    }

    /// Whether this ArcValue currently holds an inner value
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }

    /// Best-effort type name for the contained value (if present)
    pub fn type_name(&self) -> Option<&str> {
        self.value.as_ref().map(|v| v.type_name())
    }

    pub fn null() -> Self {
        Self {
            category: ValueCategory::Null,
            value: None,
            serialize_fn: None,
            to_json_fn: None,
        }
    }

    pub fn is_null(&self) -> bool {
        self.category == ValueCategory::Null && self.value.is_none()
    }

    pub fn new_primitive<T>(value: T) -> Self
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        let type_name = std::any::type_name::<T>();
        if !is_primitive(type_name) {
            panic!("Not a primitive");
        }
        let arc = Arc::new(value);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, _, _| {
            let val = erased.as_arc::<T>()?;
            serde_cbor::to_vec(&*val).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::Primitive,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: None,
        }
    }

    pub fn new_list<T>(list: Vec<T>) -> Self
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        let arc = Arc::new(list);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, keystore, resolver| {
            let list = erased.as_arc::<Vec<T>>()?;
            if let (Some(ks), Some(res)) = (keystore, resolver) {
                // Try element-level encryption via registry
                if let Some(enc_fn) =
                    crate::registry::lookup_encryptor_by_typeid(std::any::TypeId::of::<T>())
                {
                    let mut out: Vec<Vec<u8>> = Vec::with_capacity(list.len());
                    for item in list.iter() {
                        let bytes = enc_fn(item as &dyn std::any::Any, ks, res)?;
                        out.push(bytes);
                    }
                    return serde_cbor::to_vec(&out).map_err(anyhow::Error::from);
                }
            }
            // No context or no encryptor: plain encode
            serde_cbor::to_vec(list.as_ref()).map_err(anyhow::Error::from)
        });
        let to_json_fn: Arc<ToJsonFn> = Arc::new(move |erased| {
            let list = erased.as_arc::<Vec<T>>()?;
            serde_json::to_value(list.as_ref()).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::List,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: Some(to_json_fn),
        }
    }

    pub fn new_map<T>(map: HashMap<String, T>) -> Self
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        let arc = Arc::new(map);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, keystore, resolver| {
            let map = erased.as_arc::<HashMap<String, T>>()?;
            if let (Some(ks), Some(res)) = (keystore, resolver) {
                if let Some(enc_fn) =
                    crate::registry::lookup_encryptor_by_typeid(std::any::TypeId::of::<T>())
                {
                    let mut out: HashMap<String, Vec<u8>> = HashMap::with_capacity(map.len());
                    for (k, v) in map.iter() {
                        let bytes = enc_fn(v as &dyn std::any::Any, ks, res)?;
                        out.insert(k.clone(), bytes);
                    }
                    return serde_cbor::to_vec(&out).map_err(anyhow::Error::from);
                }
            }
            serde_cbor::to_vec(map.as_ref()).map_err(anyhow::Error::from)
        });
        let to_json_fn: Arc<ToJsonFn> = Arc::new(move |erased| {
            let map = erased.as_arc::<HashMap<String, T>>()?;
            serde_json::to_value(map.as_ref()).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::Map,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: Some(to_json_fn),
        }
    }

    pub fn new_struct<T>(value: T) -> Self
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned + RunarEncrypt,
    {
        let arc = Arc::new(value);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, keystore, resolver| {
            let val = erased.as_arc::<T>()?;
            if let (Some(ks), Some(res)) = (keystore, resolver) {
                let result = val.encrypt_with_keystore(ks, res)?;
                serde_cbor::to_vec(&result).map_err(anyhow::Error::from)
            } else {
                serde_cbor::to_vec(&*val).map_err(anyhow::Error::from)
            }
        });
        let to_json_fn: Arc<ToJsonFn> = Arc::new(move |erased| {
            let val = erased.as_arc::<T>()?;
            serde_json::to_value(val.as_ref().clone()).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::Struct,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: Some(to_json_fn),
        }
    }

    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        let arc = Arc::new(bytes);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, _, _| {
            let bytes = erased.as_arc::<Vec<u8>>()?;
            Ok((*bytes).clone())
        });
        Self {
            category: ValueCategory::Bytes,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: None,
        }
    }

    pub fn new_json(json: JsonValue) -> Self {
        let arc = Arc::new(json);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, _, _| {
            let json = erased.as_arc::<JsonValue>()?;
            Ok(serde_cbor::to_vec(&*json)?)
        });
        Self {
            category: ValueCategory::Json,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: None,
        }
    }

    pub fn deserialize(bytes: &[u8], keystore: Option<Arc<KeyStore>>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(anyhow!("Empty bytes for deserialization"));
        }

        let category_byte = bytes[0];
        let category = match category_byte {
            0 => ValueCategory::Null,
            1 => ValueCategory::Primitive,
            2 => ValueCategory::List,
            3 => ValueCategory::Map,
            4 => ValueCategory::Struct,
            5 => ValueCategory::Bytes,
            6 => ValueCategory::Json,
            _ => return Err(anyhow!("Invalid category byte: {}", category_byte)),
        };

        if category == ValueCategory::Null {
            return Ok(Self::null());
        }

        let is_encrypted_byte = bytes[1];
        let is_encrypted = is_encrypted_byte == 0x01;

        let type_name_len = bytes[2] as usize;
        if type_name_len + 3 > bytes.len() {
            return Err(anyhow!("Invalid type name length"));
        }
        let type_name_bytes = &bytes[3..3 + type_name_len];
        let type_name = std::str::from_utf8(type_name_bytes)
            .map_err(|e| anyhow!("Invalid UTF-8 in type name: {e}"))?
            .to_string();

        let data_start = 3 + type_name_len;
        let data_bytes = &bytes[data_start..];

        match category {
            ValueCategory::Primitive => {
                // Eagerly deserialize primitives without unnecessary copies
                let bytes_cow: Cow<[u8]> = if is_encrypted {
                    Cow::Owned(decrypt_bytes(
                        data_bytes,
                        keystore
                            .as_ref()
                            .ok_or(anyhow!("Keystore required for decryption"))?,
                    )?)
                } else {
                    Cow::Borrowed(data_bytes)
                };

                // Try to deserialize primitives using wire names
                match type_name.as_str() {
                    "string" => {
                        let value: String = serde_cbor::from_slice(bytes_cow.as_ref())?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "bool" => {
                        let value: bool = serde_cbor::from_slice(bytes_cow.as_ref())?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "bytes" => {
                        let value: Vec<u8> = serde_cbor::from_slice(bytes_cow.as_ref())?;
                        Ok(ArcValue::new_bytes(value))
                    }
                    "char" => {
                        let value: char = serde_cbor::from_slice(bytes_cow.as_ref())?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "i8" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<i8>(
                        bytes_cow.as_ref(),
                    )?)),
                    "i16" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<i16>(
                        bytes_cow.as_ref(),
                    )?)),
                    "i32" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<i32>(
                        bytes_cow.as_ref(),
                    )?)),
                    "i64" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<i64>(
                        bytes_cow.as_ref(),
                    )?)),
                    "i128" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<i128>(
                        bytes_cow.as_ref(),
                    )?)),
                    "u8" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<u8>(
                        bytes_cow.as_ref(),
                    )?)),
                    "u16" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<u16>(
                        bytes_cow.as_ref(),
                    )?)),
                    "u32" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<u32>(
                        bytes_cow.as_ref(),
                    )?)),
                    "u64" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<u64>(
                        bytes_cow.as_ref(),
                    )?)),
                    "u128" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<u128>(
                        bytes_cow.as_ref(),
                    )?)),
                    "f32" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<f32>(
                        bytes_cow.as_ref(),
                    )?)),
                    "f64" => Ok(ArcValue::new_primitive(serde_cbor::from_slice::<f64>(
                        bytes_cow.as_ref(),
                    )?)),
                    other => Err(anyhow!("Unknown primitive wire type: {}", other)),
                }
            }
            ValueCategory::Bytes => {
                // Bytes can also be eagerly deserialized
                if is_encrypted {
                    let decrypted = decrypt_bytes(
                        data_bytes,
                        keystore
                            .as_ref()
                            .ok_or(anyhow!("Keystore required for decryption"))?,
                    )?;
                    Ok(ArcValue::new_bytes(decrypted))
                } else {
                    Ok(ArcValue::new_bytes(data_bytes.to_vec()))
                }
            }
            _ => {
                // For complex types (List, Map, Struct, Json), create lazy structure
                let lazy = LazyDataWithOffset {
                    type_name,
                    original_buffer: Arc::from(bytes),
                    start_offset: data_start,
                    end_offset: bytes.len(),
                    keystore,
                    encrypted: is_encrypted,
                };

                Ok(Self {
                    category,
                    value: Some(ErasedArc::from_value(lazy)),
                    serialize_fn: None,
                    to_json_fn: None,
                })
            }
        }
    }

    /// Serialize using consolidated SerializationContext
    pub fn serialize(&self, context: Option<&SerializationContext>) -> Result<Vec<u8>> {
        if self.is_null() {
            return Ok(vec![0]);
        }

        let inner = self
            .value
            .as_ref()
            .ok_or(anyhow!("No value to serialize"))?;
        let type_name = inner.type_name();
        let category_byte = match self.category {
            ValueCategory::Null => 0,
            ValueCategory::Primitive => 1,
            ValueCategory::List => 2,
            ValueCategory::Map => 3,
            ValueCategory::Struct => 4,
            ValueCategory::Bytes => 5,
            ValueCategory::Json => 6,
        };

        let mut buf = vec![category_byte];

        // Resolve wire name (parameterized for containers)
        let wire_name: String = match self.category {
            ValueCategory::Primitive => {
                let rust_name = type_name;
                let Some(wire) = crate::registry::lookup_wire_name(rust_name) else {
                    return Err(anyhow!(
                        "Missing wire-name registration for primitive: {}",
                        rust_name
                    ));
                };
                wire.to_string()
            }
            ValueCategory::List => Self::wire_name_for_container(inner, true)?,
            ValueCategory::Map => Self::wire_name_for_container(inner, false)?,
            ValueCategory::Json => "json".to_string(),
            ValueCategory::Bytes => "bytes".to_string(),
            ValueCategory::Struct => {
                if let Some(wire) = crate::registry::lookup_wire_name(type_name) {
                    wire.to_string()
                } else {
                    return Err(anyhow!(
                        "Missing wire-name registration for struct: {}",
                        type_name
                    ));
                }
            }
            ValueCategory::Null => "null".to_string(),
        };

        let type_name_bytes = wire_name.as_bytes();
        if type_name_bytes.len() > 255 {
            return Err(anyhow!("Wire type name too long: {}", wire_name));
        }

        if let Some(ctx) = context {
            let ks = &ctx.keystore;
            let network_id = &ctx.network_id;
            let profile_public_key = &ctx.profile_public_key;
            let resolver = &ctx.resolver;

            let bytes = if let Some(ser_fn) = &self.serialize_fn {
                // Container-aware encryption for list/map: delegate to ser_fn with context
                ser_fn(inner, Some(ks), Some(resolver.as_ref()))
            } else {
                return Err(anyhow!("No serialize function available"));
            }?;

            let recipients: Vec<Vec<u8>> = match profile_public_key.as_ref() {
                Some(pk) => vec![pk.clone()],
                None => Vec::new(),
            };
            let data = ks.encrypt_with_envelope(&bytes, Some(network_id.as_str()), recipients)?;
            let is_encrypted_byte = 0x01;
            buf.push(is_encrypted_byte);
            buf.push(type_name_bytes.len() as u8);
            buf.extend_from_slice(type_name_bytes);
            buf.extend(serde_cbor::to_vec(&data).map_err(|e| anyhow!(e))?);
        } else {
            let bytes = if let Some(ser_fn) = &self.serialize_fn {
                ser_fn(inner, None, None)
            } else {
                return Err(anyhow!("No serialize function available"));
            }?;
            let is_encrypted_byte = 0x00;
            // Pre-allocate to avoid growth during pushes
            buf.reserve_exact(3 + type_name_bytes.len() + bytes.len());
            buf.push(is_encrypted_byte);
            buf.push(type_name_bytes.len() as u8);
            buf.extend_from_slice(type_name_bytes);
            buf.extend(bytes);
        }

        Ok(buf)
    }

    pub fn as_type<T>(&self) -> Result<T>
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        let ref_value = self.as_type_ref::<T>()?;
        Ok((*ref_value).clone())
    }

    // ============================================================
    // Generic getter with automatic decrypt fallback via registry
    // ============================================================
    pub fn as_type_ref<T>(&self) -> Result<Arc<T>>
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        let inner = self.value.as_ref().ok_or_else(|| anyhow!("No value"))?;

        let target_name = std::any::type_name::<T>();

        // Fast path – already materialised object stored inside ErasedArc.
        if !inner.is_lazy {
            // if is not lazy.. and is of categoty JSON and the requested type is not JSON..
            // then we need to convert from the json to ArcValue and then to the requested type
            if self.category == ValueCategory::Json && target_name != "serde_json::value::Value" {
                let json_value = inner.as_arc::<JsonValue>()?;
                if target_name.contains("ArcValue") {
                    let converted_arc = Self::json_to_arc_value(json_value.as_ref());
                    return converted_arc.as_type_ref::<T>();
                } else {
                    let result: T = serde_json::from_value::<T>(json_value.as_ref().clone())?;
                    return Ok(Arc::new(result));
                }
            }

            return inner.as_arc::<T>();
        }

        // Use unified lazy data handling
        self.handle_lazy_data(|payload, type_name| {
            //handle the case when the serialized type is JSON and the requested type is not JSON
            if type_name == "serde_json::value::Value" && target_name != type_name {
                if let Ok(json_value) = serde_cbor::from_slice::<serde_json::value::Value>(payload)
                {
                    if target_name.contains("ArcValue") {
                        let converted_arc = Self::json_to_arc_value(&json_value);
                        return converted_arc.as_type_ref::<T>();
                    } else {
                        let result: T = serde_json::from_value::<T>(json_value)?;
                        return Ok(Arc::new(result));
                    }
                } else {
                    return Err(anyhow!("Failed to deserialize JSON from CBOR"));
                }
            }

            // Attempt direct deserialisation (primitives, Plain structs, or when
            // the caller asked for the *encrypted* representation itself).
            if let Ok(val) = serde_cbor::from_slice::<T>(payload) {
                return Ok(Arc::new(val));
            }

            // Registry fallback – decrypt into the requested plain type.
            // We need to get the keystore from the lazy data for this
            let lazy = inner.get_lazy_data()?;
            let ks = lazy
                .keystore
                .as_ref()
                .ok_or_else(|| anyhow!("Keystore required for decryptor"))?;
            let plain: T = crate::registry::try_decrypt_into::<T>(payload, ks)?;
            Ok(Arc::new(plain))
        })
    }

    pub fn as_typed_list_ref<T>(&self) -> Result<Vec<Arc<T>>>
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        if self.category != ValueCategory::List {
            return Err(anyhow!("Not a list"));
        }

        let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;
        if inner.is_lazy {
            // Handle lazy list with parameterized wire names
            // Capture optional keystore for potential element-level decrypt
            let ks_opt = inner.get_lazy_data()?.keystore.clone();

            return self.handle_lazy_data(|payload, type_name| {
                if type_name.starts_with("list<") {
                    // Try encrypted-bytes element container
                    if let Ok(vec_bytes) = serde_cbor::from_slice::<Vec<Vec<u8>>>(payload) {
                        let ks = ks_opt
                            .as_ref()
                            .ok_or_else(|| anyhow!("Keystore required for decryptor"))?;
                        let mut out: Vec<Arc<T>> = Vec::with_capacity(vec_bytes.len());
                        for b in vec_bytes.iter() {
                            let plain: T = crate::registry::try_decrypt_into::<T>(b, ks)?;
                            out.push(Arc::new(plain));
                        }
                        return Ok(out);
                    }
                    // Try plain Vec<T>
                    if let Ok(vec_plain) = serde_cbor::from_slice::<Vec<T>>(payload) {
                        let out: Vec<Arc<T>> = vec_plain.into_iter().map(|v| Arc::new(v)).collect();
                        return Ok(out);
                    }
                    // Try heterogeneous Vec<ArcValue> then map to T
                    if let Ok(vec_av) = serde_cbor::from_slice::<Vec<ArcValue>>(payload) {
                        let mut out: Vec<Arc<T>> = Vec::with_capacity(vec_av.len());
                        for v in vec_av.iter() {
                            out.push(v.as_type_ref::<T>()?);
                        }
                        return Ok(out);
                    }
                    return Err(anyhow!(
                        "Unsupported list payload for declared wire name: {type_name}"
                    ));
                }
                // Not a parameterized list wire name
                Err(anyhow!("Invalid list wire name: {type_name}"))
            });
        }

        // Non-lazy path: expect Vec<ArcValue>
        let list_arc = inner.as_arc::<Vec<ArcValue>>()?;
        let list_of_type: Vec<Arc<T>> = list_arc
            .iter()
            .map(|entry| {
                entry
                    .as_type_ref::<T>()
                    .expect("can't convert list entry to type")
            })
            .collect();
        Ok(list_of_type)
    }

    pub fn as_list_ref(&self) -> Result<Arc<Vec<ArcValue>>> {
        if self.category != ValueCategory::List {
            return Err(anyhow!("Not a list"));
        }
        self.as_type_ref::<Vec<ArcValue>>()
    }

    pub fn as_typed_map_ref<T>(&self) -> Result<HashMap<String, Arc<T>>>
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        if self.category != ValueCategory::Map {
            return Err(anyhow!("Not a map"));
        }

        let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;
        if inner.is_lazy {
            let ks_opt = inner.get_lazy_data()?.keystore.clone();

            return self.handle_lazy_data(|payload, type_name| {
                if type_name.starts_with("map<") {
                    // Try encrypted-bytes values
                    if let Ok(map_bytes) =
                        serde_cbor::from_slice::<HashMap<String, Vec<u8>>>(payload)
                    {
                        let ks = ks_opt
                            .as_ref()
                            .ok_or_else(|| anyhow!("Keystore required for decryptor"))?;
                        let mut out: HashMap<String, Arc<T>> =
                            HashMap::with_capacity(map_bytes.len());
                        for (k, vbytes) in map_bytes.iter() {
                            let plain: T = crate::registry::try_decrypt_into::<T>(vbytes, ks)?;
                            out.insert(k.clone(), Arc::new(plain));
                        }
                        return Ok(out);
                    }
                    // Try plain map<String, T>
                    if let Ok(map_plain) = serde_cbor::from_slice::<HashMap<String, T>>(payload) {
                        let out: HashMap<String, Arc<T>> = map_plain
                            .into_iter()
                            .map(|(k, v)| (k, Arc::new(v)))
                            .collect();
                        return Ok(out);
                    }
                    // Try heterogeneous map<String, ArcValue>
                    if let Ok(map_av) = serde_cbor::from_slice::<HashMap<String, ArcValue>>(payload)
                    {
                        let mut out: HashMap<String, Arc<T>> = HashMap::with_capacity(map_av.len());
                        for (k, v) in map_av.iter() {
                            out.insert(k.clone(), v.as_type_ref::<T>()?);
                        }
                        return Ok(out);
                    }
                    return Err(anyhow!(
                        "Unsupported map payload for declared wire name: {type_name}"
                    ));
                }
                Err(anyhow!("Invalid map wire name: {type_name}"))
            });
        }

        // Non-lazy path: expect HashMap<String, ArcValue>
        let map_arc = inner.as_arc::<HashMap<String, ArcValue>>()?;
        let map_of_type: HashMap<String, Arc<T>> = map_arc
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_type_ref::<T>()
                        .expect("can't convert map entry to type"),
                )
            })
            .collect();
        Ok(map_of_type)
    }

    pub fn as_map_ref(&self) -> Result<Arc<HashMap<String, ArcValue>>> {
        if self.category != ValueCategory::Map {
            return Err(anyhow!("Not a map"));
        }
        self.as_type_ref::<HashMap<String, ArcValue>>()
    }

    pub fn as_struct_ref<T>(&self) -> Result<Arc<T>>
    where
        T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        if self.category != ValueCategory::Struct {
            return Err(anyhow!("Not a struct"));
        }
        self.as_type_ref::<T>()
    }

    pub fn as_bytes_ref(&self) -> Result<Arc<Vec<u8>>> {
        if self.category != ValueCategory::Bytes {
            return Err(anyhow!("Not bytes"));
        }
        let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;
        if inner.is_lazy {
            self.handle_lazy_data(|payload, _type_name| Ok(Arc::new(payload.to_vec())))
        } else {
            inner.as_arc::<Vec<u8>>()
        }
    }

    pub fn as_json_ref(&self) -> Result<Arc<JsonValue>> {
        if self.category != ValueCategory::Json {
            return Err(anyhow!("Not JSON"));
        }
        self.as_type_ref::<JsonValue>()
    }

    /// Unified lazy data handling helper that extracts and processes lazy data.
    /// This centralizes all lazy data logic to avoid duplication.
    fn handle_lazy_data<F, R>(&self, process_fn: F) -> Result<R>
    where
        F: FnOnce(&[u8], &str) -> Result<R>,
    {
        let inner = self.value.as_ref().ok_or_else(|| anyhow!("No value"))?;

        // Fast path – already materialised object stored inside ErasedArc.
        if !inner.is_lazy {
            return Err(anyhow!("Not lazy data"));
        }

        // Lazy path – must reconstruct from serialized bytes.
        let lazy = inner.get_lazy_data()?;
        let mut payload: Vec<u8> =
            lazy.original_buffer[lazy.start_offset..lazy.end_offset].to_vec();

        // If the outer envelope is present, unwrap it first.
        if lazy.encrypted {
            let ks = lazy
                .keystore
                .as_ref()
                .ok_or_else(|| anyhow!("Keystore required for outer decryption"))?;
            payload = crate::encryption::decrypt_bytes(&payload, ks)?;
        }

        // Process the payload using the provided function
        process_fn(&payload, &lazy.type_name)
    }

    fn json_to_arc_value(json: &JsonValue) -> Self {
        match json {
            JsonValue::Null => Self::null(),
            JsonValue::Bool(b) => Self::new_primitive(*b),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::new_primitive(i)
                } else if let Some(f) = n.as_f64() {
                    Self::new_primitive(f)
                } else {
                    Self::null()
                }
            }
            JsonValue::String(s) => Self::new_primitive(s.clone()),
            JsonValue::Array(arr) => {
                Self::new_list(arr.iter().map(Self::json_to_arc_value).collect())
            }
            JsonValue::Object(obj) => Self::new_map(
                obj.clone()
                    .into_iter()
                    .map(|(k, v)| (k, Self::json_to_arc_value(&v)))
                    .collect(),
            ),
        }
    }

    pub fn to_json(&self) -> Result<JsonValue> {
        match self.category {
            ValueCategory::Null => Ok(JsonValue::Null),
            ValueCategory::Primitive => {
                let inner = self.value.as_ref().ok_or_else(|| anyhow!("No value"))?;
                let type_name = inner.type_name();

                if is_string(type_name) {
                    let value = inner.as_arc::<String>()?;
                    Ok(JsonValue::String(value.as_ref().clone()))
                } else if is_number(type_name) {
                    to_json_number(inner, type_name)
                } else if is_bool(type_name) {
                    let value = inner.as_arc::<bool>()?;
                    Ok(JsonValue::Bool(*value))
                } else if is_char(type_name) {
                    let value = inner.as_arc::<char>()?;
                    Ok(JsonValue::String(value.to_string()))
                } else if is_bytes(type_name) {
                    let value = inner.as_arc::<Vec<u8>>()?;
                    Ok(JsonValue::String(
                        base64::engine::general_purpose::STANDARD.encode(value.as_ref()),
                    ))
                } else {
                    Err(anyhow!(
                        "Unsupported primitive type for JSON conversion: {}",
                        type_name
                    ))
                }
            }
            ValueCategory::Json => Ok(self.as_json_ref()?.as_ref().clone()),
            ValueCategory::Struct | ValueCategory::List | ValueCategory::Map => {
                // First try the stored to_json_fn if available
                if let Some(json_fn) = &self.to_json_fn {
                    let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;
                    let json_value = json_fn(inner)?;
                    return Ok(json_value);
                }

                // Fallback to registry lookup for deserialized structs
                let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;
                if inner.is_lazy {
                    self.handle_lazy_data(|payload, type_name| {
                        // Try wire-name keyed converters first (list/map/json/struct wire names)
                        if let Some(json_fn) =
                            crate::registry::get_json_converter_by_wire_name(type_name)
                        {
                            return json_fn(payload);
                        }
                        // No rust-name fallback: only wire-name converters are supported
                        // Final fallback: attempt generic CBOR -> JSON value
                        if let Ok(value) = serde_cbor::from_slice::<serde_json::Value>(payload) {
                            return Ok(value);
                        }
                        // If everything fails, return a specific error
                        Err(anyhow!(
                            "No JSON converter available for type: {}",
                            type_name
                        ))
                    })
                } else {
                    Err(anyhow!(
                        "No to_json function available and no registry fallback"
                    ))
                }
            }
            _ => Err(anyhow!("Unsupported category for JSON")),
        }
    }

    pub fn serialize_serde<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Check if this is JSON serialization by checking the serializer type
        let is_json = std::any::type_name::<S>().contains("serde_json");

        if is_json {
            // For JSON, use the to_json() method to get proper JSON representation
            match self.to_json() {
                Ok(json_value) => json_value.serialize(serializer),
                Err(e) => Err(serde::ser::Error::custom(format!(
                    "JSON conversion failed: {e}",
                ))),
            }
        } else {
            // For CBOR and other formats, use the original struct-based serialization
            use serde::ser::SerializeStruct;

            let mut state = serializer.serialize_struct("ArcValue", 3)?;

            // Serialize category as integer using the enum directly
            let category_int = self.category as u8;
            state.serialize_field("category", &category_int)?;

            let inner = self
                .value
                .as_ref()
                .ok_or(serde::ser::Error::custom("No value to serialize"))?;
            let rust_type_name = inner.type_name();

            // Use the same wire-name resolution as the top-level header
            let wire_name: String = match self.category {
                ValueCategory::Primitive => {
                    // For primitives we rely on pre-registered mappings
                    let Some(wire) = crate::registry::lookup_wire_name(rust_type_name) else {
                        return Err(serde::ser::Error::custom(format!(
                            "Missing wire-name registration for primitive: {rust_type_name}",
                        )));
                    };
                    wire.to_string()
                }
                ValueCategory::List => "list".to_string(),
                ValueCategory::Map => "map".to_string(),
                ValueCategory::Json => "json".to_string(),
                ValueCategory::Bytes => "bytes".to_string(),
                ValueCategory::Struct => {
                    // Prefer registry mapping; if absent, use simple ident of the Rust type as default
                    if let Some(wire) = crate::registry::lookup_wire_name(rust_type_name) {
                        wire.to_string()
                    } else {
                        rust_type_name
                            .rsplit("::")
                            .next()
                            .unwrap_or(rust_type_name)
                            .to_string()
                    }
                }
                ValueCategory::Null => "null".to_string(),
            };

            state.serialize_field("typename", &wire_name)?;

            // Serialize the actual value using the existing serialize_fn
            if let Some(inner) = &self.value {
                if let Some(ser_fn) = &self.serialize_fn {
                    let serialized_data =
                        ser_fn(inner, None, None).map_err(serde::ser::Error::custom)?;
                    state.serialize_field("value", &serialized_data)?;
                } else {
                    return Err(serde::ser::Error::custom("No serialize function available"));
                }
            } else {
                // For null values
                state.serialize_field("value", &serde_json::Value::Null)?;
            }

            state.end()
        }
    }

    pub fn deserialize_serde<'de, D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Check if this is JSON deserialization by checking the deserializer type
        let is_json = std::any::type_name::<D>().contains("serde_json");

        if is_json {
            // For JSON, deserialize as a JsonValue and convert to ArcValue
            let json_value = JsonValue::deserialize(deserializer)?;
            Ok(Self::json_to_arc_value(&json_value))
        } else {
            // For CBOR and other formats, use the original struct-based deserialization
            use serde::de::{self, MapAccess, Visitor};
            use std::fmt;

            #[derive(Deserialize)]
            #[serde(field_identifier, rename_all = "lowercase")]
            enum Field {
                Category,
                Value,
                TypeName,
            }

            struct ArcValueVisitor;

            impl<'de> Visitor<'de> for ArcValueVisitor {
                type Value = ArcValue;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("struct ArcValue")
                }

                fn visit_map<V>(self, mut map: V) -> Result<ArcValue, V::Error>
                where
                    V: MapAccess<'de>,
                {
                    let mut category = None;
                    let mut value = None;
                    let mut type_name: Option<String> = None;
                    while let Some(key) = map.next_key()? {
                        match key {
                            Field::Category => {
                                if category.is_some() {
                                    return Err(de::Error::duplicate_field("category"));
                                }
                                let category_int: u8 = map.next_value()?;
                                category = Some(ValueCategory::from_u8(category_int).ok_or_else(
                                    || {
                                        de::Error::unknown_variant(
                                            &category_int.to_string(),
                                            &["0", "1", "2", "3", "4", "5", "6"],
                                        )
                                    },
                                )?);
                            }
                            Field::Value => {
                                if value.is_some() {
                                    return Err(de::Error::duplicate_field("value"));
                                }
                                value = Some(map.next_value()?);
                            }
                            Field::TypeName => {
                                if type_name.is_some() {
                                    return Err(de::Error::duplicate_field("typename"));
                                }
                                type_name = Some(map.next_value()?);
                            }
                        }
                    }

                    let category = category.ok_or_else(|| de::Error::missing_field("category"))?;
                    let type_name =
                        type_name.ok_or_else(|| de::Error::missing_field("typename"))?;

                    match category {
                        ValueCategory::Null => Ok(ArcValue::null()),
                        ValueCategory::Primitive => {
                            // Eagerly deserialize primitives using the wire name
                            let value: Vec<u8> =
                                value.ok_or_else(|| de::Error::missing_field("value"))?;

                            match type_name.as_str() {
                                "string" => serde_cbor::from_slice::<String>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "bool" => serde_cbor::from_slice::<bool>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "bytes" => serde_cbor::from_slice::<Vec<u8>>(&value)
                                    .map(ArcValue::new_bytes)
                                    .map_err(de::Error::custom),
                                "char" => serde_cbor::from_slice::<char>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "i8" => serde_cbor::from_slice::<i8>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "i16" => serde_cbor::from_slice::<i16>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "i32" => serde_cbor::from_slice::<i32>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "i64" => serde_cbor::from_slice::<i64>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "i128" => serde_cbor::from_slice::<i128>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "u8" => serde_cbor::from_slice::<u8>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "u16" => serde_cbor::from_slice::<u16>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "u32" => serde_cbor::from_slice::<u32>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "u64" => serde_cbor::from_slice::<u64>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "u128" => serde_cbor::from_slice::<u128>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "f32" => serde_cbor::from_slice::<f32>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                "f64" => serde_cbor::from_slice::<f64>(&value)
                                    .map(ArcValue::new_primitive)
                                    .map_err(de::Error::custom),
                                // No legacy fallback
                                _ => Err(de::Error::custom("Unknown primitive wire type")),
                            }
                        }
                        ValueCategory::Bytes => {
                            // Bytes can also be eagerly deserialized
                            let value: Vec<u8> =
                                value.ok_or_else(|| de::Error::missing_field("value"))?;
                            Ok(ArcValue::new_bytes(value))
                        }
                        _ => {
                            // For complex types (List, Map, Struct, Json), create lazy structure
                            let value: Vec<u8> =
                                value.ok_or_else(|| de::Error::missing_field("value"))?;
                            let value_len = value.len();
                            // Create LazyDataWithOffset structure for complex types
                            let lazy_data = LazyDataWithOffset {
                                type_name: type_name.to_string(),
                                original_buffer: Arc::from(value),
                                start_offset: 0,
                                end_offset: value_len,
                                keystore: None,
                                encrypted: false,
                            };

                            Ok(ArcValue {
                                category,
                                value: Some(ErasedArc::from_value(lazy_data)),
                                serialize_fn: None,
                                to_json_fn: None,
                            })
                        }
                    }
                }
            }

            deserializer.deserialize_struct(
                "ArcValue",
                &["category", "value", "typename"],
                ArcValueVisitor,
            )
        }
    }
}

impl serde::Serialize for ArcValue {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.serialize_serde(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ArcValue {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_serde(deserializer)
    }
}

// ---------------------------------------------------------------------------
// Trait: AsArcValue
// ---------------------------------------------------------------------------
/// Bidirectional conversion between concrete Rust values and `ArcValue`.
///
/// * `as_arc_value` consumes `self` and produces an `ArcValue` for serialization.
/// * `from_arc_value` attempts to reconstruct `Self` from the given `ArcValue`.
///
/// `from_arc_value` has a default implementation that works for any type
/// implementing [`RunarSerializer`].  This covers the vast majority of cases
/// once the `#[derive(Serializable)]` macro is applied.  Custom/value-category
/// specific impls can still be provided to optimise the binary layout (e.g.
/// primitives vs. structs).
pub trait AsArcValue: Sized + Clone {
    /// Convert `self` into an [`ArcValue`].
    fn into_arc_value(self) -> ArcValue;

    /// Attempt to reconstruct `Self` from the provided [`ArcValue`].
    fn from_arc_value(value: ArcValue) -> Result<Self>
    where
        Self: 'static + Debug + Send + Sync + Serialize + DeserializeOwned,
    {
        value.as_type_ref::<Self>().map(|arc| (*arc).clone())
    }
}

impl Default for ArcValue {
    fn default() -> Self {
        ArcValue::null()
    }
}

impl<T> AsArcValue for T
where
    T: 'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned + RunarEncrypt,
{
    fn into_arc_value(self) -> ArcValue {
        ArcValue::new_struct(self)
    }

    fn from_arc_value(value: ArcValue) -> Result<Self> {
        value.as_type_ref::<T>().map(|arc| (*arc).clone())
    }
}

// Make ArcValue implement AsArcValue for direct usage
impl AsArcValue for ArcValue {
    fn into_arc_value(self) -> ArcValue {
        self
    }

    fn from_arc_value(value: ArcValue) -> Result<Self> {
        Ok(value)
    }
}

fn is_primitive(type_name: &str) -> bool {
    is_string(type_name)
        || is_number(type_name)
        || is_bool(type_name)
        || is_char(type_name)
        || is_bytes(type_name)
}

fn is_string(type_name: &str) -> bool {
    type_name.starts_with("alloc::string::String") || type_name.starts_with("std::string::String")
}

fn is_number(type_name: &str) -> bool {
    type_name == "i8"
        || type_name == "i16"
        || type_name == "i32"
        || type_name == "i64"
        || type_name == "i128"
        || type_name == "u8"
        || type_name == "u16"
        || type_name == "u32"
        || type_name == "u64"
        || type_name == "u128"
        || type_name == "f32"
        || type_name == "f64"
}

fn to_json_number(inner: &ErasedArc, type_name: &str) -> Result<JsonValue> {
    match type_name {
        "i8" => {
            let value = inner.as_arc::<i8>()?;
            Ok(JsonValue::Number((*value as i64).into()))
        }
        "i16" => {
            let value = inner.as_arc::<i16>()?;
            Ok(JsonValue::Number((*value as i64).into()))
        }
        "i32" => {
            let value = inner.as_arc::<i32>()?;
            Ok(JsonValue::Number((*value as i64).into()))
        }
        "i64" => {
            let value = inner.as_arc::<i64>()?;
            Ok(JsonValue::Number((*value).into()))
        }
        "i128" => {
            let value = inner.as_arc::<i128>()?;
            Ok(JsonValue::String(value.to_string()))
        }
        "u8" => {
            let value = inner.as_arc::<u8>()?;
            Ok(JsonValue::Number((*value as u64).into()))
        }
        "u16" => {
            let value = inner.as_arc::<u16>()?;
            Ok(JsonValue::Number((*value as u64).into()))
        }
        "u32" => {
            let value = inner.as_arc::<u32>()?;
            Ok(JsonValue::Number((*value as u64).into()))
        }
        "u64" => {
            let value = inner.as_arc::<u64>()?;
            Ok(JsonValue::Number((*value).into()))
        }
        "u128" => {
            let value = inner.as_arc::<u128>()?;
            Ok(JsonValue::String(value.to_string()))
        }
        "f32" => {
            let value = inner.as_arc::<f32>()?;
            Ok(JsonValue::Number(
                serde_json::Number::from_f64(*value as f64)
                    .ok_or_else(|| anyhow!("Invalid f32 value for JSON: {value}"))?,
            ))
        }
        "f64" => {
            let value = inner.as_arc::<f64>()?;
            Ok(JsonValue::Number(
                serde_json::Number::from_f64(*value)
                    .ok_or_else(|| anyhow!("Invalid f64 value for JSON: {value}"))?,
            ))
        }
        _ => Err(anyhow!("Unsupported number type: {}", type_name)),
    }
}

fn is_bool(type_name: &str) -> bool {
    type_name == "bool"
}

fn is_char(type_name: &str) -> bool {
    type_name == "char"
}

fn is_bytes(type_name: &str) -> bool {
    type_name == "alloc::vec::Vec<u8>"
}
