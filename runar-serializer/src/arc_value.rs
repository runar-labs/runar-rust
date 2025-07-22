use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use prost::Message;
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
    pub category: ValueCategory,
    pub value: Option<ErasedArc>,
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

    pub fn new_list(list: Vec<ArcValue>) -> Self {
        let arc = Arc::new(list);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, _, _| {
            let list = erased.as_arc::<Vec<ArcValue>>()?;
            serde_cbor::to_vec(list.as_ref()).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::List,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: None,
        }
    }

    pub fn new_map(map: HashMap<String, ArcValue>) -> Self {
        let arc = Arc::new(map);
        let ser_fn: Arc<SerializeFn> = Arc::new(move |erased, _, _| {
            let map = erased.as_arc::<HashMap<String, ArcValue>>()?;
            serde_cbor::to_vec(map.as_ref()).map_err(anyhow::Error::from)
        });
        Self {
            category: ValueCategory::Map,
            value: Some(ErasedArc::new(arc)),
            serialize_fn: Some(ser_fn),
            to_json_fn: None,
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
        let type_name = String::from_utf8(type_name_bytes.to_vec())?;

        let data_start = 3 + type_name_len;
        let data_bytes = &bytes[data_start..];

        match category {
            ValueCategory::Primitive => {
                // Eagerly deserialize primitives
                let bytes = if is_encrypted {
                    decrypt_bytes(
                        data_bytes,
                        keystore
                            .as_ref()
                            .ok_or(anyhow!("Keystore required for decryption"))?,
                    )?
                } else {
                    data_bytes.to_vec()
                };

                // Try to deserialize as different primitive types based on type_name
                match type_name.as_str() {
                    "alloc::string::String" => {
                        let value: String = serde_cbor::from_slice(&bytes)?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "i64" => {
                        let value: i64 = serde_cbor::from_slice(&bytes)?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "f64" => {
                        let value: f64 = serde_cbor::from_slice(&bytes)?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    "bool" => {
                        let value: bool = serde_cbor::from_slice(&bytes)?;
                        Ok(ArcValue::new_primitive(value))
                    }
                    _ => Err(anyhow!("Unknown primitive type: {}", type_name)),
                }
            }
            ValueCategory::Bytes => {
                // Bytes can also be eagerly deserialized
                let bytes = if is_encrypted {
                    decrypt_bytes(
                        data_bytes,
                        keystore
                            .as_ref()
                            .ok_or(anyhow!("Keystore required for decryption"))?,
                    )?
                } else {
                    data_bytes.to_vec()
                };
                Ok(ArcValue::new_bytes(bytes))
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
        let type_name_bytes = type_name.as_bytes();
        if type_name_bytes.len() > 255 {
            return Err(anyhow!("Type name too long: {}", type_name));
        }

        if let Some(ctx) = context {
            let ks = &ctx.keystore;
            let network_id = &ctx.network_id;
            let profile_public_key: &Vec<u8> = &ctx.profile_public_key;
            let resolver = &ctx.resolver;

            let bytes = if let Some(ser_fn) = &self.serialize_fn {
                ser_fn(inner, Some(ks), Some(resolver.as_ref()))
            } else {
                return Err(anyhow!("No serialize function available"));
            }?;

            let data =
                ks.encrypt_with_envelope(&bytes, Some(network_id), vec![profile_id.clone()])?;
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

        // Lazy path – must reconstruct from serialized bytes.
        let lazy = inner.get_lazy_data()?;
        let mut payload: Vec<u8> =
            lazy.original_buffer[lazy.start_offset..lazy.end_offset].to_vec();

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
        let list_arc = self.as_type_ref::<Vec<ArcValue>>()?;

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
                    // // Try to handle Vec<ArcValue> and HashMap<String, ArcValue> even if they're marked as Primitive
                    // if let Ok(vec) = self.as_type_ref::<Vec<ArcValue>>() {
                    //     let mut json_array = Vec::new();
                    //     for arc_value in vec.as_ref() {
                    //         let json_value = arc_value.to_json()?;
                    //         json_array.push(json_value);
                    //     }
                    //     Ok(JsonValue::Array(json_array))
                    // } else if let Ok(map) = self.as_type_ref::<HashMap<String, ArcValue>>() {
                    //     let mut json_object = serde_json::Map::new();
                    //     for (key, arc_value) in map.as_ref() {
                    //         let json_value = arc_value.to_json()?;
                    //         json_object.insert(key.clone(), json_value);
                    //     }
                    //     Ok(JsonValue::Object(json_object))
                    // } else {
                    Err(anyhow!("Unsupported primitive for JSON"))
                    // }
                }
            }
            ValueCategory::List => {
                let list = self.as_list_ref()?;
                let mut vec = Vec::new();
                for item in list.iter() {
                    vec.push(item.to_json()?);
                }
                Ok(JsonValue::Array(vec))
            }
            ValueCategory::Map => {
                let map = self.as_map_ref()?;
                let mut json_map = serde_json::Map::new();
                for (k, v) in map.iter() {
                    json_map.insert(k.clone(), v.to_json()?);
                }
                Ok(JsonValue::Object(json_map))
            }
            ValueCategory::Json => Ok(self.as_json_ref()?.as_ref().clone()),
            ValueCategory::Struct => {
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
                        // Try to find JSON converter by type name
                        if let Some(json_fn) = crate::registry::get_json_converter(type_name) {
                            return json_fn(payload);
                        }

                        // If registry lookup fails, return a more specific error
                        Err(anyhow!(
                            "No JSON converter available for struct type: {}",
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
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ArcValue", 3)?;

        // Serialize category as integer using the enum directly
        let category_int = self.category as u8;
        state.serialize_field("category", &category_int)?;

        let inner = self
            .value
            .as_ref()
            .ok_or(serde::ser::Error::custom("No value to serialize"))?;
        let type_name = inner.type_name();
        state.serialize_field("typename", type_name)?;

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

    pub fn deserialize_serde<'de, D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
                            category =
                                Some(ValueCategory::from_u8(category_int).ok_or_else(|| {
                                    de::Error::unknown_variant(
                                        &category_int.to_string(),
                                        &["0", "1", "2", "3", "4", "5", "6"],
                                    )
                                })?);
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
                let type_name = type_name.ok_or_else(|| de::Error::missing_field("typename"))?;

                match category {
                    ValueCategory::Null => Ok(ArcValue::null()),
                    ValueCategory::Primitive => {
                        // Eagerly deserialize primitives
                        let value: Vec<u8> =
                            value.ok_or_else(|| de::Error::missing_field("value"))?;
                        // Try to deserialize as different primitive types
                        if let Ok(s) = serde_cbor::from_slice::<String>(&value) {
                            Ok(ArcValue::new_primitive(s))
                        } else if let Ok(i) = serde_cbor::from_slice::<i64>(&value) {
                            Ok(ArcValue::new_primitive(i))
                        } else if let Ok(f) = serde_cbor::from_slice::<f64>(&value) {
                            Ok(ArcValue::new_primitive(f))
                        } else if let Ok(b) = serde_cbor::from_slice::<bool>(&value) {
                            Ok(ArcValue::new_primitive(b))
                        } else {
                            Err(de::Error::custom("Failed to deserialize primitive value"))
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
