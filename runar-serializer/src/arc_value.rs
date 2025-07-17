// New file content starting from scratch

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use prost::Message;
use serde_json::Value as JsonValue;

use super::encryption::decrypt_bytes;
use super::erased_arc::ErasedArc;
use super::traits::{CustomFromBytes, KeyStore, LabelResolver};
use crate::map_types;
use crate::vec_types;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueCategory {
    Primitive,
    List,
    Map,
    Struct,
    Null,
    Bytes,
    Json,
}

#[derive(Clone)]
pub struct ArcValue {
    pub category: ValueCategory,
    pub value: Option<ErasedArc>,
    serialize_fn: Option<
        Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        >,
    >,
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
    pub fn null() -> Self {
        Self {
            category: ValueCategory::Null,
            value: None,
            serialize_fn: None,
        }
    }

    pub fn is_null(&self) -> bool {
        self.category == ValueCategory::Null && self.value.is_none()
    }

    pub fn new_primitive<T: 'static + Clone + Debug + Send + Sync + CustomFromBytes>(
        value: T,
    ) -> Self {
        let arc = Arc::new(value);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, keystore, resolver, network_id| {
            let val = erased.as_arc::<T>()?;
            T::to_binary(&*val, keystore, resolver, network_id)
        });
        Self {
            category: ValueCategory::Primitive,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
        }
    }

    pub fn new_list(list: Vec<ArcValue>) -> Self {
        let arc = Arc::new(list);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, keystore, resolver, network_id| {
            let list = erased.as_arc::<Vec<ArcValue>>()?;
            let mut proto = vec_types::VecArcValue::default();
            for item in list.iter() {
                proto
                    .entries
                    .push(item.serialize(keystore.cloned(), resolver, network_id)?);
            }
            Ok(proto.encode_to_vec())
        });
        Self {
            category: ValueCategory::List,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
        }
    }

    pub fn new_map(map: HashMap<String, ArcValue>) -> Self {
        let arc = Arc::new(map);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, keystore, resolver, network_id| {
            let map = erased.as_arc::<HashMap<String, ArcValue>>()?;
            let mut proto = map_types::StringToArcValueMap::default();
            for (k, v) in map.iter() {
                let bytes = v.serialize(keystore.cloned(), resolver, network_id)?;
                proto.entries.insert(k.clone(), bytes);
            }
            Ok(proto.encode_to_vec())
        });
        Self {
            category: ValueCategory::Map,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
        }
    }

    pub fn new_struct<T: 'static + Clone + Debug + Send + Sync + CustomFromBytes>(
        value: T,
    ) -> Self {
        let arc = Arc::new(value);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, keystore, resolver, network_id| {
            let val = erased.as_arc::<T>()?;
            T::to_binary(&*val, keystore, resolver, network_id)
        });
        Self {
            category: ValueCategory::Struct,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
        }
    }

    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        let arc = Arc::new(bytes);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, _, _, _| {
            let bytes = erased.as_arc::<Vec<u8>>()?;
            Ok((*bytes).clone())
        });
        Self {
            category: ValueCategory::Bytes,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
        }
    }

    pub fn new_json(json: JsonValue) -> Self {
        let arc = Arc::new(json);
        let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                    &String,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, _, _, _| {
            let json = erased.as_arc::<JsonValue>()?;
            Ok(serde_json::to_vec(&*json)?)
        });
        Self {
            category: ValueCategory::Json,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
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

        let type_name_len = bytes[1] as usize;
        if type_name_len + 2 > bytes.len() {
            return Err(anyhow!("Invalid type name length"));
        }
        let type_name_bytes = &bytes[2..2 + type_name_len];
        let type_name = String::from_utf8(type_name_bytes.to_vec())?;

        let data_start = 2 + type_name_len;
        let lazy = LazyDataWithOffset {
            type_name,
            original_buffer: Arc::from(bytes),
            start_offset: data_start,
            end_offset: bytes.len(),
            keystore,
        };

        Ok(Self {
            category,
            value: Some(ErasedArc::from_value(lazy)),
            serialize_fn: None, // Serialize fn will be set when resolved
        })
    }

    pub fn serialize(
        &self,
        keystore: Option<Arc<KeyStore>>,
        resolver: Option<&dyn LabelResolver>,
        network_id: &String,
    ) -> Result<Vec<u8>> {
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
        let type_name_bytes = type_name.as_bytes();
        if type_name_bytes.len() > 255 {
            return Err(anyhow!("Type name too long: {}", type_name));
        }
        buf.push(type_name_bytes.len() as u8);
        buf.extend_from_slice(type_name_bytes);

        let data = if let Some(ser_fn) = &self.serialize_fn {
            ser_fn(inner, keystore.as_ref(), resolver, network_id)
        } else {
            return Err(anyhow!("No serialize function available"));
        }?;

        // Decide if we need to envelope-encrypt the produced bytes.
        // 1. If the underlying type is already an Encrypted* wrapper we always encrypt (double layer) as before.
        // 2. If this is a plain struct *and* the caller provided both keystore & resolver (meaning encryption context)
        //    we also envelope-encrypt so that application code never sends raw struct bytes over the wire.
        let should_encrypt_entire_payload = type_name.starts_with("Encrypted")
            || (self.category == ValueCategory::Struct && keystore.is_some() && resolver.is_some());

        if should_encrypt_entire_payload {
            let ks = keystore
                .as_ref()
                .ok_or(anyhow!("Keystore required for encryption"))?;

            let env = ks.encrypt_with_envelope(&data, Some(&network_id), Vec::new())?;
            buf.extend(env.encode_to_vec());
        } else {
            buf.extend(data);
        }

        Ok(buf)
    }

    pub fn as_type_ref<T>(&self) -> Result<Arc<T>>
    where
        T: 'static + Clone + Debug + Send + Sync + CustomFromBytes,
    {
        let inner = self.value.as_ref().ok_or(anyhow!("No value"))?;

        if inner.is_lazy {
            let lazy = inner.get_lazy_data()?;
            let bytes = &lazy.original_buffer[lazy.start_offset..lazy.end_offset];
            let is_encrypted = lazy.type_name.starts_with("Encrypted<")
                || (self.category == ValueCategory::Struct && lazy.keystore.is_some());
            let bytes = if is_encrypted {
                decrypt_bytes(
                    bytes,
                    lazy.keystore
                        .as_ref()
                        .ok_or(anyhow!("Keystore required for decryption"))?,
                )?
            } else {
                bytes.to_vec()
            };

            let decoded = if is_encrypted {
                T::from_encrypted_bytes(&bytes, lazy.keystore.as_ref())?
            } else {
                T::from_plain_bytes(&bytes, lazy.keystore.as_ref())?
            };

            let arc = Arc::new(decoded);
            // *inner = ErasedArc::new(arc.clone());

            // Set serialize_fn based on category
            // self.serialize_fn = Some(Arc::new(move |erased, ks, res| {
            //     let val = erased.as_arc::<T>()?;
            //     T::to_binary(&*val, ks, res)
            // }));
            Ok(arc)
        } else {
            inner.as_arc::<T>()
        }
    }

    pub fn as_typed_list_ref<T>(&self) -> Result<Vec<Arc<T>>>
    where
        T: 'static + Clone + Debug + Send + Sync + CustomFromBytes,
    {
        if self.category != ValueCategory::List {
            return Err(anyhow!("Not a list"));
        }
        let list_arc = self.as_type_ref::<Vec<ArcValue>>()?;

        let list_of_type: Vec<Arc<T>> = list_arc
            .iter()
            .map(|entry| {
                (entry
                    .as_type_ref::<T>()
                    .expect("can't convert list entry to type"))
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
        T: 'static + Clone + Debug + Send + Sync + CustomFromBytes,
    {
        if self.category != ValueCategory::Map {
            return Err(anyhow!("Not a map"));
        }
        let map_arc = self.as_type_ref::<HashMap<String, ArcValue>>()?;

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
        T: 'static + Clone + Debug + Send + Sync + CustomFromBytes,
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
        self.as_type_ref::<Vec<u8>>()
    }

    pub fn as_json_ref(&self) -> Result<Arc<JsonValue>> {
        if self.category != ValueCategory::Json {
            return Err(anyhow!("Not JSON"));
        }
        self.as_type_ref::<JsonValue>()
    }

    pub fn from_json(json: JsonValue) -> Self {
        match json {
            JsonValue::Null => Self::null(),
            JsonValue::Bool(b) => Self::new_primitive(b),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::new_primitive(i)
                } else if let Some(f) = n.as_f64() {
                    Self::new_primitive(f)
                } else {
                    Self::null()
                }
            }
            JsonValue::String(s) => Self::new_primitive(s),
            JsonValue::Array(arr) => Self::new_list(arr.into_iter().map(Self::from_json).collect()),
            JsonValue::Object(obj) => Self::new_map(
                obj.into_iter()
                    .map(|(k, v)| (k, Self::from_json(v)))
                    .collect(),
            ),
        }
    }

    pub fn to_json(&mut self) -> Result<JsonValue> {
        match self.category {
            ValueCategory::Null => Ok(JsonValue::Null),
            ValueCategory::Primitive => {
                // Handle different primitive types
                if let Ok(arc) = self.as_type_ref::<String>() {
                    Ok(JsonValue::String(arc.as_ref().clone()))
                } else if let Ok(arc) = self.as_type_ref::<i64>() {
                    Ok(JsonValue::Number((*arc).into()))
                } else if let Ok(arc) = self.as_type_ref::<f64>() {
                    Ok(JsonValue::Number(
                        serde_json::Number::from_f64(*arc).unwrap_or(serde_json::Number::from(0)),
                    ))
                } else if let Ok(arc) = self.as_type_ref::<bool>() {
                    Ok(JsonValue::Bool(*arc))
                } else {
                    Err(anyhow!("Unsupported primitive for JSON"))
                }
            }
            ValueCategory::List => {
                let list = self.as_list_ref()?;
                let mut vec = Vec::new();
                for item in list.iter() {
                    let mut item_clone = item.clone();
                    vec.push(item_clone.to_json()?);
                }
                Ok(JsonValue::Array(vec))
            }
            ValueCategory::Map => {
                let map = self.as_map_ref()?;
                let mut json_map = serde_json::Map::new();
                for (k, v) in map.iter() {
                    let mut v_clone = v.clone();
                    json_map.insert(k.clone(), v_clone.to_json()?);
                }
                Ok(JsonValue::Object(json_map))
            }
            ValueCategory::Json => Ok(self.as_json_ref()?.as_ref().clone()),
            _ => Err(anyhow!("Unsupported category for JSON")),
        }
    }
}

impl CustomFromBytes for String {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        String::from_utf8(bytes.to_vec()).map_err(anyhow::Error::from)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}

impl CustomFromBytes for i64 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(anyhow!("Invalid byte length for i64"));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(i64::from_be_bytes(buf))
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

// Implement for other primitives like bool, f64, i32 similarly

impl CustomFromBytes for bool {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 1 {
            return Err(anyhow!("Invalid byte length for bool"));
        }
        Ok(bytes[0] != 0)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(vec![if *self { 1 } else { 0 }])
    }
}

impl CustomFromBytes for f64 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(anyhow!("Invalid byte length for f64"));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(f64::from_be_bytes(buf))
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for Vec<u8> {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        Ok(bytes.to_vec())
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        decrypt_bytes(bytes, ks)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.clone())
    }
}

impl CustomFromBytes for JsonValue {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(anyhow::Error::from)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(anyhow::Error::from)
    }
}

impl CustomFromBytes for Vec<ArcValue> {
    fn from_plain_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let proto = vec_types::VecArcValue::decode(bytes)?;
        let mut vec = Vec::with_capacity(proto.entries.len());
        for entry in proto.entries {
            vec.push(ArcValue::deserialize(&entry, keystore.cloned())?);
        }
        Ok(vec)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        keystore: Option<&Arc<KeyStore>>,
        resolver: Option<&dyn LabelResolver>,
        network_id: &String,
    ) -> Result<Vec<u8>> {
        let mut proto = vec_types::VecArcValue::default();
        for item in self {
            proto
                .entries
                .push(item.serialize(keystore.cloned(), resolver, network_id)?);
        }
        Ok(proto.encode_to_vec())
    }
}

impl CustomFromBytes for HashMap<String, ArcValue> {
    fn from_plain_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let proto = map_types::StringToArcValueMap::decode(bytes)?;
        let mut map = HashMap::with_capacity(proto.entries.len());
        for (k, entry) in proto.entries {
            map.insert(k, ArcValue::deserialize(&entry, keystore.cloned())?);
        }
        Ok(map)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(
        &self,
        keystore: Option<&Arc<KeyStore>>,
        resolver: Option<&dyn LabelResolver>,
        network_id: &String,
    ) -> Result<Vec<u8>> {
        let mut proto = map_types::StringToArcValueMap::default();
        for (k, v) in self {
            proto.entries.insert(
                k.clone(),
                v.serialize(keystore.cloned(), resolver, network_id)?,
            );
        }
        Ok(proto.encode_to_vec())
    }
}

// --- BEGIN: CustomFromBytes for all common primitives ---

impl CustomFromBytes for i8 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 1 {
            return Err(anyhow!("Invalid byte length for i8"));
        }
        Ok(bytes[0] as i8)
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(vec![*self as u8])
    }
}

impl CustomFromBytes for u8 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 1 {
            return Err(anyhow!("Invalid byte length for u8"));
        }
        Ok(bytes[0])
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(vec![*self])
    }
}

impl CustomFromBytes for i16 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 2 {
            return Err(anyhow!("Invalid byte length for i16"));
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(bytes);
        Ok(i16::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for u16 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 2 {
            return Err(anyhow!("Invalid byte length for u16"));
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(bytes);
        Ok(u16::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for i32 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 4 {
            return Err(anyhow!("Invalid byte length for i32"));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        Ok(i32::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for u32 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 4 {
            return Err(anyhow!("Invalid byte length for u32"));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        Ok(u32::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for u64 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(anyhow!("Invalid byte length for u64"));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for f32 {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 4 {
            return Err(anyhow!("Invalid byte length for f32"));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        Ok(f32::from_be_bytes(buf))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl CustomFromBytes for char {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        if bytes.len() != 4 {
            return Err(anyhow!("Invalid byte length for char"));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        let u = u32::from_be_bytes(buf);
        std::char::from_u32(u).ok_or_else(|| anyhow!("Invalid char encoding"))
    }
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self> {
        let ks = keystore.ok_or(anyhow!("Keystore required"))?;
        let decrypted = decrypt_bytes(bytes, ks)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }
    fn to_binary(
        &self,
        _keystore: Option<&Arc<KeyStore>>,
        _resolver: Option<&dyn LabelResolver>,
        _network_id: &String,
    ) -> Result<Vec<u8>> {
        Ok((*self as u32).to_be_bytes().to_vec())
    }
}
// --- END: CustomFromBytes for all common primitives ---

// ---------------------------------------------------------------------------
// Trait: AsArcValue
// ---------------------------------------------------------------------------
/// Bidirectional conversion between concrete Rust values and `ArcValue`.
///
/// * `as_arc_value` consumes `self` and produces an `ArcValue` for serialization.
/// * `from_arc_value` attempts to reconstruct `Self` from the given `ArcValue`.
///
/// `from_arc_value` has a default implementation that works for any type
/// implementing [`CustomFromBytes`].  This covers the vast majority of cases
/// once the `#[derive(Serializable)]` macro is applied.  Custom/value-category
/// specific impls can still be provided to optimise the binary layout (e.g.
/// primitives vs. structs).
pub trait AsArcValue: Sized + Clone {
    /// Convert `self` into an [`ArcValue`].
    fn as_arc_value(self) -> ArcValue;

    /// Attempt to reconstruct `Self` from the provided [`ArcValue`].
    fn from_arc_value(value: ArcValue) -> Result<Self>
    where
        Self: 'static + Debug + Send + Sync + CustomFromBytes,
    {
        value.as_type_ref::<Self>().map(|arc| (*arc).clone())
    }
}

// Identity conversion for ArcValue itself
impl AsArcValue for ArcValue {
    fn as_arc_value(self) -> ArcValue {
        self
    }

    fn from_arc_value(value: ArcValue) -> Result<Self> {
        Ok(value)
    }
}

// Unit type maps to / from a `Null` ArcValue.
impl AsArcValue for () {
    fn as_arc_value(self) -> ArcValue {
        ArcValue::null()
    }

    fn from_arc_value(value: ArcValue) -> Result<Self> {
        if value.is_null() {
            Ok(())
        } else {
            Err(anyhow!("Expected null ArcValue for unit type"))
        }
    }
}

// Blanket impl leveraging `CustomFromBytes` for all other types.  This must be
// **after** the concrete impls above to avoid overlap.
impl<T> AsArcValue for T
where
    T: 'static + Clone + Debug + Send + Sync + CustomFromBytes,
{
    fn as_arc_value(self) -> ArcValue {
        ArcValue::new_struct(self)
    }

    fn from_arc_value(value: ArcValue) -> Result<Self> {
        value.as_type_ref::<T>().map(|arc| (*arc).clone())
    }
}
