use std::any::{Any, TypeId};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::marker::Copy;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

use super::erased_arc::ErasedArc;
use super::AsArcValue; // Added import for the trait
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

// Type alias for complex deserialization function signature
pub(crate) type DeserializationFn =
    Arc<dyn Fn(&[u8]) -> Result<Box<dyn Any + Send + Sync>> + Send + Sync>;
// Type alias for the inner part of the complex serialization function signature
pub(crate) type SerializationFnInner = Box<dyn Fn(&dyn Any) -> Result<Vec<u8>> + Send + Sync>;

// Type alias for the JSON serialization function
// Takes an ErasedArc and attempts to serialize it to serde_json::Value
pub(crate) type JsonSerializationFn =
    Arc<dyn Fn(&ErasedArc) -> Result<serde_json::Value, anyhow::Error> + Send + Sync>;

/// Wrapper struct for deserializer function that implements Debug
#[derive(Clone)]
pub struct DeserializerFnWrapper {
    // The actual deserializer function
    pub func: DeserializationFn,
}

impl std::fmt::Debug for DeserializerFnWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeserializerFn")
    }
}

impl DeserializerFnWrapper {
    pub fn new<F>(func: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Box<dyn Any + Send + Sync>> + Send + Sync + 'static,
    {
        DeserializerFnWrapper {
            func: Arc::new(func),
        }
    }

    pub fn call(&self, bytes: &[u8]) -> Result<Box<dyn Any + Send + Sync>> {
        (self.func)(bytes)
    }
}

/// Container for lazy deserialization data using Arc and offsets
#[derive(Clone)]
pub struct LazyDataWithOffset {
    /// The original type name from the serialized data
    pub type_name: String,
    /// Reference to the original shared buffer
    pub original_buffer: Arc<[u8]>,
    /// Start offset of the relevant data within the buffer
    pub start_offset: usize,
    /// End offset of the relevant data within the buffer
    pub end_offset: usize,
    /// Optional deserializer captured from SerializerRegistry (encryption-aware)
    pub deserializer: Option<super::arc_value::DeserializerFnWrapper>,
    /// Optional alternative deserializer (e.g., encrypted alias)
    pub alias_deserializer: Option<super::arc_value::DeserializerFnWrapper>,
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

/// Categorizes the value for efficient dispatch
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueCategory {
    Primitive,
    List,
    Map,
    Struct,
    Null,
    /// Raw bytes (used for Vec<u8>, not for lazy deserialization)
    Bytes,
    Json,
}

/// The canonical value type for the system, using type-erased Arcs.
#[derive(Clone)]
pub struct ArcValue {
    /// The category of the contained value
    pub category: ValueCategory,
    /// The contained type-erased value
    /// Note: ErasedArc is type-erased and requires custom serde impl. Only registered types are supported.
    pub value: Option<ErasedArc>,
    /// Optional function to directly serialize this value to serde_json::Value.
    /// This is populated for types that implement serde::Serialize.
    json_serializer_fn: Option<JsonSerializationFn>,
}

impl fmt::Debug for ArcValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArcValue")
            .field("category", &self.category)
            .field("value", &self.value)
            .field(
                "json_serializer_fn",
                &if self.json_serializer_fn.is_some() {
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

impl AsArcValue for ArcValue {
    fn into_arc_value_type(self) -> ArcValue {
        self // It already is an ArcValue
    }
}

impl AsArcValue for bool {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::new_primitive(self)
    }
}

impl AsArcValue for String {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::new_primitive(self)
    }
}

impl AsArcValue for &str {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::new_primitive(self.to_string())
    }
}

impl AsArcValue for i32 {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::new_primitive(self)
    }
}

impl AsArcValue for i64 {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::new_primitive(self)
    }
}

impl AsArcValue for () {
    fn into_arc_value_type(self) -> ArcValue {
        ArcValue::null() // Represent unit type as null payload
    }
}

impl ArcValue {
    /// Creates an `ArcValue` from a `serde_json::Value`.
    ///
    /// This function recursively converts JSON values into their corresponding `ArcValue` representations.
    /// - JSON null becomes `ArcValue::null()`.
    /// - JSON booleans become `ArcValue::new_primitive(bool)`.
    /// - JSON numbers become `ArcValue::new_primitive(i64)` or `ArcValue::new_primitive(f64)` if possible,
    ///   otherwise `ArcValue::new_primitive(String)`.
    /// - JSON strings become `ArcValue::new_primitive(String)`.
    /// - JSON arrays become `ArcValue::new_list(Vec<ArcValue>)`.
    /// - JSON objects become `ArcValue::new_map(HashMap<String, ArcValue>)`.
    pub fn from_json(json_val: JsonValue) -> Self {
        match json_val {
            JsonValue::Null => ArcValue::null(),
            JsonValue::Bool(b) => ArcValue::new_primitive(b),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    ArcValue::new_primitive(i)
                } else if let Some(f) = n.as_f64() {
                    ArcValue::new_primitive(f)
                } else {
                    // Fallback to string representation for complex numbers not fitting i64/f64
                    ArcValue::new_primitive(n.to_string())
                }
            }
            JsonValue::String(s) => ArcValue::new_primitive(s),
            JsonValue::Array(arr) => {
                let values: Vec<ArcValue> = arr
                    .into_iter()
                    .map(ArcValue::from_json) // Recursive call to Self::from_json
                    .collect();
                ArcValue::new_list(values)
            }
            JsonValue::Object(obj) => {
                // Store the raw JSON object lazily; conversion happens on demand
                ArcValue::new_json(JsonValue::Object(obj))
            }
        }
    }

    /// Create a new ArcValue
    pub fn new(value: ErasedArc, category: ValueCategory) -> Self {
        Self {
            category,
            value: Some(value),
            json_serializer_fn: None, // Default to None, specific constructors will populate
        }
    }

    /// Create a new primitive value
    pub fn new_primitive<T>(value: T) -> Self
    where
        T: 'static + fmt::Debug + Send + Sync + Serialize,
    {
        let arc = Arc::new(value);
        let serializer_fn: Option<JsonSerializationFn> = Some(Arc::new(
            move |erased_arc: &ErasedArc| -> Result<serde_json::Value, anyhow::Error> {
                let typed_arc = erased_arc.as_arc::<T>().map_err(|e| {
                    anyhow!(
                        "Failed to downcast ErasedArc to Arc<{}> for JSON serialization: {}",
                        std::any::type_name::<T>(),
                        e
                    )
                })?;
                serde_json::to_value(&*typed_arc).map_err(|e| {
                    anyhow!(
                        "Failed to serialize <{}> to JSON: {}",
                        std::any::type_name::<T>(),
                        e
                    )
                })
            },
        ));

        Self {
            category: ValueCategory::Primitive,
            value: Some(ErasedArc::new(arc)),
            json_serializer_fn: serializer_fn,
        }
    }

    /// Create a new struct value
    pub fn from_struct<T>(value: T) -> Self
    where
        T: 'static + fmt::Debug + Send + Sync + Serialize,
    {
        let arc = Arc::new(value);
        let serializer_fn: Option<JsonSerializationFn> = Some(Arc::new(
            move |erased_arc: &ErasedArc| -> Result<serde_json::Value, anyhow::Error> {
                let typed_arc = erased_arc.as_arc::<T>().map_err(|e| {
                    anyhow!(
                        "Failed to downcast ErasedArc to Arc<{}> for JSON serialization: {}",
                        std::any::type_name::<T>(),
                        e
                    )
                })?;
                serde_json::to_value(&*typed_arc).map_err(|e| {
                    anyhow!(
                        "Failed to serialize <{}> to JSON: {}",
                        std::any::type_name::<T>(),
                        e
                    )
                })
            },
        ));

        Self {
            category: ValueCategory::Struct,
            value: Some(ErasedArc::new(arc)),
            json_serializer_fn: serializer_fn,
        }
    }

    /// Create a new bytes value (Vec<u8>)
    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        let arc_bytes = Arc::new(bytes);
        let serializer_fn: Option<JsonSerializationFn> = Some(Arc::new(
            move |erased_arc: &ErasedArc| -> Result<serde_json::Value, anyhow::Error> {
                let typed_arc = erased_arc.as_arc::<Vec<u8>>().map_err(|e| {
                    anyhow!(
                        "Failed to downcast ErasedArc to Arc<Vec<u8>> for JSON serialization: {}",
                        e
                    )
                })?;
                Ok(serde_json::Value::String(STANDARD.encode(&**typed_arc)))
            },
        ));

        Self {
            category: ValueCategory::Bytes,
            value: Some(ErasedArc::new(arc_bytes)),
            json_serializer_fn: serializer_fn,
        }
    }

    /// Create a new list value
    pub fn new_list<T: 'static + fmt::Debug + Send + Sync>(values: Vec<T>) -> Self {
        let arc = Arc::new(values);
        Self {
            category: ValueCategory::List,
            value: Some(ErasedArc::new(arc)),
            json_serializer_fn: None,
        }
    }

    /// Create a new list from existing vector
    pub fn from_list<T: 'static + fmt::Debug + Send + Sync>(values: Vec<T>) -> Self {
        Self::new_list(values)
    }

    /// Create a new map value
    pub fn new_map<K, V>(map: HashMap<K, V>) -> Self
    where
        K: 'static + fmt::Debug + Send + Sync,
        V: 'static + fmt::Debug + Send + Sync,
    {
        let arc = Arc::new(map);
        Self {
            category: ValueCategory::Map,
            value: Some(ErasedArc::new(arc)),
            json_serializer_fn: None,
        }
    }

    /// Create a new map from existing map
    pub fn from_map<K, V>(map: HashMap<K, V>) -> Self
    where
        K: 'static + fmt::Debug + Send + Sync,
        V: 'static + fmt::Debug + Send + Sync,
    {
        Self::new_map(map)
    }

    /// Create a null value
    pub fn null() -> Self {
        Self {
            category: ValueCategory::Null,
            value: None,
            json_serializer_fn: None,
        }
    }

    /// Create a new JSON value
    pub fn new_json(value: serde_json::Value) -> Self {
        let arc = Arc::new(value.clone());
        let serializer_fn: Option<JsonSerializationFn> = Some(Arc::new(
            move |erased_arc: &ErasedArc| -> Result<serde_json::Value, anyhow::Error> {
                let typed_arc = erased_arc.as_arc::<serde_json::Value>().map_err(|e| {
                    anyhow!("Failed to downcast ErasedArc to Arc<serde_json::Value> for JSON serialization: {}", e)
                })?;
                Ok((*typed_arc).clone())
            },
        ));

        Self {
            category: ValueCategory::Json,
            value: Some(ErasedArc::new(arc)),
            json_serializer_fn: serializer_fn,
        }
    }

    /// Check if this value is null
    pub fn is_null(&self) -> bool {
        self.value.is_none() && self.category == ValueCategory::Null
    }

    /// Get list as a reference of the specified element type
    pub fn as_list_ref<T>(&mut self) -> Result<Arc<Vec<T>>>
    where
        T: 'static + Clone + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        if self.category != ValueCategory::List {
            return Err(anyhow!(
                "Value is not a list (category: {:?})",
                self.category
            ));
        }

        match &mut self.value {
            Some(ref mut actual_value) => {
                if actual_value.is_lazy {
                    let type_name_clone: String;
                    let original_buffer_clone: Arc<[u8]>;
                    let start_offset_val: usize;
                    let end_offset_val: usize;

                    {
                        let lazy_data_arc = actual_value.get_lazy_data().map_err(|e| {
                            anyhow!("Failed to get lazy data despite is_lazy flag: {}", e)
                        })?;
                        type_name_clone = lazy_data_arc.type_name.clone();
                        original_buffer_clone = lazy_data_arc.original_buffer.clone();
                        start_offset_val = lazy_data_arc.start_offset;
                        end_offset_val = lazy_data_arc.end_offset;
                    }

                    let expected_list_type_name = std::any::type_name::<Vec<T>>();
                    if !super::erased_arc::compare_type_names(
                        expected_list_type_name,
                        &type_name_clone,
                    ) {
                        return Err(anyhow!(
                            "Lazy list data type mismatch: expected compatible with Vec<{}> (is {}), but stored type is {}",
                            std::any::type_name::<T>(),
                            expected_list_type_name,
                            type_name_clone
                        ));
                    }

                    let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];

                    // Get the lazy data again to access the deserializer
                    let lazy_data_arc = actual_value.get_lazy_data().map_err(|e| {
                        anyhow!("Failed to get lazy data despite is_lazy flag: {}", e)
                    })?;

                    // Use registry deserializer - this is the only path
                    let deserializer = lazy_data_arc.deserializer.as_ref().ok_or_else(|| {
                        anyhow!(
                            "No deserializer available for lazy list type {}",
                            type_name_clone
                        )
                    })?;

                    let boxed = deserializer
                        .call(data_slice)
                        .map_err(|e| anyhow!("Registry deserializer error: {e}"))?;
                    let concrete = boxed.downcast::<Vec<T>>().map_err(|_| {
                        anyhow!(
                            "Registry deserializer returned unexpected type (expected Vec<{}>)",
                            std::any::type_name::<T>()
                        )
                    })?;
                    let deserialized_list: Vec<T> = *concrete;

                    *actual_value = ErasedArc::new(Arc::new(deserialized_list));
                }
                actual_value.as_arc::<Vec<T>>().map_err(|e| {
                    anyhow!("Failed to cast eager value to list: {}. Expected Vec<{}>, got {}. Category: {:?}", 
                        e, std::any::type_name::<T>(), actual_value.type_name(), self.category)
                })
            }
            None => Err(anyhow!(
                "Cannot get list reference from a null ArcValue (category: {:?})",
                self.category
            )),
        }
    }

    /// Get map as a reference of the specified key/value types.
    /// If the value is lazy, it will be deserialized and made eager in-place.
    pub fn as_map_ref<K, V>(&mut self) -> Result<Arc<HashMap<K, V>>>
    where
        K: 'static
            + Clone
            + Serialize
            + for<'de> Deserialize<'de>
            + Eq
            + std::hash::Hash
            + fmt::Debug
            + Send
            + Sync,
        V: 'static + Clone + Serialize + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        if self.category != ValueCategory::Map {
            // Special fallback: if the value is still in lazy JSON form, but the caller
            // expects a HashMap<String, ArcValue>, attempt on-the-fly conversion by
            // delegating to as_type_ref. This mirrors the logic that already exists in
            // `as_type_ref`, but exposes it for the `as_map_ref` convenience API which
            // callers (e.g. the single-parameter extraction logic in the `action` macro)
            // rely on.
            if self.category == ValueCategory::Json
                && std::any::TypeId::of::<K>() == std::any::TypeId::of::<String>()
                && std::any::TypeId::of::<V>() == std::any::TypeId::of::<ArcValue>()
            {
                // Attempt conversion; `as_type_ref` will update `self.category` → Map on success.
                let arc_map_sa = self.as_type_ref::<HashMap<String, ArcValue>>()?;
                // SAFETY: We just verified that K==String and V==ArcValue.
                let arc_map_typed = unsafe {
                    std::mem::transmute::<Arc<HashMap<String, ArcValue>>, Arc<HashMap<K, V>>>(
                        arc_map_sa,
                    )
                };
                return Ok(arc_map_typed);
            }

            return Err(anyhow!(
                "Category mismatch: Expected Map, found {:?}",
                self.category
            ));
        }

        match &mut self.value {
            Some(ref mut actual_value) => {
                if actual_value.is_lazy {
                    let type_name_clone: String;
                    let original_buffer_clone: Arc<[u8]>;
                    let start_offset_val: usize;
                    let end_offset_val: usize;

                    {
                        let lazy_data_arc = actual_value.get_lazy_data().map_err(|e| {
                            anyhow!(
                                "Failed to get lazy data from ErasedArc despite is_lazy flag: {}",
                                e
                            )
                        })?;
                        type_name_clone = lazy_data_arc.type_name.clone();
                        original_buffer_clone = lazy_data_arc.original_buffer.clone();
                        start_offset_val = lazy_data_arc.start_offset;
                        end_offset_val = lazy_data_arc.end_offset;
                    }

                    // Perform type name check before deserialization
                    let expected_type_name = std::any::type_name::<HashMap<K, V>>();
                    if !super::erased_arc::compare_type_names(expected_type_name, &type_name_clone)
                    {
                        self.value = Some(actual_value.clone()); // Put the original lazy value back
                        return Err(anyhow!(
                            "Lazy data type mismatch: expected compatible with {}, but stored type is {}",
                            expected_type_name,
                            type_name_clone
                        ));
                    }

                    let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];

                    // Get the lazy data again to access the deserializer
                    let lazy_data_arc = actual_value.get_lazy_data().map_err(|e| {
                        anyhow!("Failed to get lazy data despite is_lazy flag: {}", e)
                    })?;

                    // Use registry deserializer - this is the only path
                    let deserializer = lazy_data_arc.deserializer.as_ref().ok_or_else(|| {
                        anyhow!(
                            "No deserializer available for lazy map type {}",
                            type_name_clone
                        )
                    })?;

                    let boxed = deserializer
                        .call(data_slice)
                        .map_err(|e| anyhow!("Registry deserializer error: {e}"))?;
                    let concrete = boxed.downcast::<HashMap<K, V>>()
                        .map_err(|_| anyhow!("Registry deserializer returned unexpected type (expected HashMap<{}, {}>)", std::any::type_name::<K>(), std::any::type_name::<V>()))?;
                    let deserialized_map: HashMap<K, V> = *concrete;

                    *actual_value = ErasedArc::new(Arc::new(deserialized_map));
                }
                // Explicitly assign and return
                actual_value.as_arc::<HashMap<K, V>>().map_err(|e| {
                    anyhow!("Failed to cast eager value to map: {}. Expected HashMap<{},{}>, got {}. Category: {:?}", 
                        e, std::any::type_name::<K>(), std::any::type_name::<V>(), actual_value.type_name(), self.category)
                }) // Return the result
            }
            None => Err(anyhow!(
                "Cannot get map reference from a null ArcValue (category: {:?})",
                self.category
            )),
        }
    }

    /// Get value as the specified type (makes a clone).
    pub fn as_type<T>(&mut self) -> Result<T>
    where
        T: 'static + Clone + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        let arc_ref = self.as_type_ref::<T>()?;
        Ok((*arc_ref).clone())
    }

    /// Get struct as a reference of the specified type.
    /// If the value is lazy, it will be deserialized and made eager in-place.
    pub fn as_struct_ref<T>(&mut self) -> Result<Arc<T>>
    where
        T: 'static + Clone + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        if self.category != ValueCategory::Struct {
            return Err(anyhow!(
                "Category mismatch: Expected Struct, found {:?}",
                self.category
            ));
        }

        match &mut self.value {
            Some(ref mut actual_value) => {
                if actual_value.is_lazy {
                    let type_name_clone: String;
                    let original_buffer_clone: Arc<[u8]>;
                    let start_offset_val: usize;
                    let end_offset_val: usize;

                    {
                        let lazy_data_arc = actual_value.get_lazy_data().map_err(|e| {
                            anyhow!("Failed to get lazy data despite is_lazy flag: {}", e)
                        })?;
                        type_name_clone = lazy_data_arc.type_name.clone();
                        original_buffer_clone = lazy_data_arc.original_buffer.clone();
                        start_offset_val = lazy_data_arc.start_offset;
                        end_offset_val = lazy_data_arc.end_offset;
                    }

                    let expected_type_name = std::any::type_name::<T>();
                    let names_match = {
                        if expected_type_name == type_name_clone {
                            true
                        } else {
                            let expected_last =
                                expected_type_name.rsplit("::").next().unwrap_or("");
                            let header_last = type_name_clone.rsplit("::").next().unwrap_or("");
                            expected_last == header_last && !expected_last.starts_with("Encrypted")
                        }
                    };

                    let alias_match = {
                        // plain last segment
                        let header_last = type_name_clone.rsplit("::").next().unwrap_or("");
                        let expected_last = expected_type_name.rsplit("::").next().unwrap_or("");
                        expected_last == format!("Encrypted{header_last}")
                    };

                    if !names_match && !alias_match {
                        return Err(anyhow!(
                            "Lazy data type mismatch: expected {expected_type_name} / alias, but stored type is {type_name_clone}"
                        ));
                    }

                    let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];
                    if names_match {
                        let lazy_data_arc = actual_value.get_lazy_data()?;
                        if let Some(wrapper) = &lazy_data_arc.deserializer {
                            let boxed = wrapper
                                .call(data_slice)
                                .map_err(|e| anyhow!("Lazy deserializer error: {e}"))?;

                            let concrete = boxed.downcast::<T>().map_err(|_| {
                                anyhow!(
                                    "Lazy deserializer returned unexpected type (expected {})",
                                    std::any::type_name::<T>()
                                )
                            })?;

                            *actual_value = ErasedArc::new(Arc::new(*concrete));
                        } else {
                            return Err(anyhow!(
                                "No deserializer available for lazy struct type {}",
                                type_name_clone
                            ));
                        }
                    } else if alias_match {
                        // Use alias deserializer if provided (expected to decode Encrypted<T>)
                        let lazy_data_arc = actual_value.get_lazy_data()?;
                        if let Some(wrapper) = &lazy_data_arc.alias_deserializer {
                            let boxed = wrapper
                                .call(data_slice)
                                .map_err(|e| anyhow!("Alias deserializer error: {e}"))?;
                            let concrete = boxed.downcast::<T>().map_err(|_| {
                                anyhow!(
                                    "Alias deserializer returned unexpected type (expected {})",
                                    std::any::type_name::<T>()
                                )
                            })?;
                            *actual_value = ErasedArc::new(Arc::new(*concrete));
                        } else {
                            return Err(anyhow!(
                                "No alias deserializer available for type {}",
                                type_name_clone
                            ));
                        }
                    } else {
                        // Should not reach here due to earlier check
                    }
                }
                // Explicitly assign and return
                actual_value.as_arc::<T>().map_err(|e| {
                    anyhow!("Failed to cast eager value to struct: {}. Expected {}, got {}. Category: {:?}", 
                        e, std::any::type_name::<T>(), actual_value.type_name(), self.category)
                }) // Return the result
            }
            None => Err(anyhow!(
                "Cannot get struct reference from a null ArcValue (category: {:?})",
                self.category
            )),
        }
    }

    pub fn to_json_value(&mut self) -> Result<serde_json::Value> {
        // If a direct JSON serializer function is available, use it.
        if let Some(serializer) = &self.json_serializer_fn {
            if let Some(erased_arc) = &self.value {
                return serializer(erased_arc);
            } else {
                return Err(anyhow!(
                    "Cannot serialize value: ArcValue has a serializer but no value (category: {:?})",
                    self.category
                ));
            }
        }

        // Fallback logic for types without a direct serializer (e.g., composite types).
        match self.category {
            ValueCategory::Null => Ok(serde_json::Value::Null),
            ValueCategory::List => {
                let list_arc = self.as_list_ref::<ArcValue>()?;
                let mut json_array = Vec::new();
                for item_avt in list_arc.iter() {
                    let mut cloned_item = item_avt.clone();
                    json_array.push(cloned_item.to_json_value()?);
                }
                Ok(serde_json::Value::Array(json_array))
            }
            ValueCategory::Map => {
                let map_arc = self.as_map_ref::<String, ArcValue>()?;
                let mut json_map = serde_json::Map::new();
                for (key, value_avt) in map_arc.iter() {
                    let mut cloned_value = value_avt.clone();
                    json_map.insert(key.clone(), cloned_value.to_json_value()?);
                }
                Ok(serde_json::Value::Object(json_map))
            }
            // Primitives, Structs, and Bytes should have a json_serializer_fn if they are serializable.
            // If we reach here, it means they were constructed without one.
            _ => {
                let type_name = self
                    .value
                    .as_ref()
                    .map_or_else(|| "N/A".to_string(), |v| v.type_name().to_string());
                Err(anyhow!(
                    "The type '{}' (category: {:?}) does not support JSON serialization.",
                    type_name,
                    self.category
                ))
            }
        }
    }
}

struct ArcValueVisitor;

impl<'de> Visitor<'de> for ArcValueVisitor {
    type Value = ArcValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::null())
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::new_primitive(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::new_primitive(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Prefer signed 64-bit representation when the unsigned value fits into i64.
        // This avoids downstream numeric type mismatches (e.g. expecting i64) when
        // deserialising JSON numbers, while still preserving full range support for
        // larger values by falling back to u64.
        if value <= i64::MAX as u64 {
            Ok(ArcValue::new_primitive(value as i64))
        } else {
            Ok(ArcValue::new_primitive(value))
        }
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::new_primitive(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::new_primitive(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ArcValue::new_primitive(value))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec: Vec<ArcValue> = Vec::new();
        while let Some(elem) = seq.next_element()? {
            vec.push(elem);
        }
        Ok(ArcValue::new_list(vec))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result_map: HashMap<String, ArcValue> = HashMap::new();
        while let Some((key, value)) = map.next_entry()? {
            result_map.insert(key, value);
        }
        Ok(ArcValue::new_map(result_map))
    }
}

impl<'de> Deserialize<'de> for ArcValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ArcValueVisitor)
    }
}

impl Serialize for ArcValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut owned_self = self.clone(); // Clone to satisfy to_json_value's &mut self
        match owned_self.to_json_value() {
            Ok(json_value) => json_value.serialize(serializer),
            Err(e) => {
                // Fallback serialization for types that can't be easily converted to JSON by to_json_value
                let mut state = serializer.serialize_struct("ArcValueFallback", 2)?;
                state.serialize_field("category", &self.category)?;
                state.serialize_field("error", &format!("Failed to convert to full JSON: {e}"))?;
                state.end()
            }
        }
    }
}

impl ArcValue {
    /// Get value as a reference of the specified type
    pub fn as_type_ref<T>(&mut self) -> Result<Arc<T>>
    where
        T: 'static + Clone + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        let mut current_erased_arc = match self.value.take() {
            Some(ea) => ea,
            None => {
                return Err(anyhow!(
                    "Cannot get type ref: ArcValue's internal value is None (category: {:?})",
                    self.category
                ));
            }
        };

        if current_erased_arc.is_lazy {
            let type_name_clone: String;
            let original_buffer_clone: Arc<[u8]>;
            let start_offset_val: usize;
            let end_offset_val: usize;

            {
                let lazy_data_arc = current_erased_arc.get_lazy_data().map_err(|e| {
                    anyhow!(
                        "Failed to get lazy data from ErasedArc despite is_lazy flag: {}",
                        e
                    )
                })?;
                type_name_clone = lazy_data_arc.type_name.clone();
                original_buffer_clone = lazy_data_arc.original_buffer.clone();
                start_offset_val = lazy_data_arc.start_offset;
                end_offset_val = lazy_data_arc.end_offset;
            }

            // Perform type name check before deserialization
            let expected_type_name = std::any::type_name::<T>();
            if !super::erased_arc::compare_type_names(expected_type_name, &type_name_clone) {
                self.value = Some(current_erased_arc); // Put the original lazy value back
                return Err(anyhow!(
                    "Lazy data type mismatch: expected compatible with {}, but stored type is {}",
                    expected_type_name,
                    type_name_clone
                ));
            }

            let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];

            // Get the lazy data again to access the deserializer
            let lazy_data_arc = current_erased_arc
                .get_lazy_data()
                .map_err(|e| anyhow!("Failed to get lazy data despite is_lazy flag: {}", e))?;

            // Use registry deserializer - this is the only path
            let deserializer = lazy_data_arc.deserializer.as_ref().ok_or_else(|| {
                anyhow!(
                    "No deserializer available for lazy type {}",
                    type_name_clone
                )
            })?;

            let boxed = deserializer
                .call(data_slice)
                .map_err(|e| anyhow!("Registry deserializer error: {e}"))?;
            let concrete = boxed.downcast::<T>().map_err(|_| {
                anyhow!(
                    "Registry deserializer returned unexpected type (expected {})",
                    std::any::type_name::<T>()
                )
            })?;
            let deserialized_value: T = *concrete;

            // Replace internal lazy value with the eager one
            current_erased_arc = ErasedArc::new(Arc::new(deserialized_value));
        }

        self.value = Some(current_erased_arc.clone()); // Put the (potentially updated) ErasedArc back

        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<ArcValue>() {
            let arc_value = Arc::new(self.clone());
            return Ok(unsafe { std::mem::transmute::<Arc<ArcValue>, Arc<T>>(arc_value) });
        }

        // Check if T is serde_json::Value, using TypeId for robustness
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<serde_json::Value>() {
            //if let Some(serializer) = &self.json_serializer_fn {
            // let arc_of_json_value: std::sync::Arc<serde_json::Value> = std::sync::Arc::new(
            //     serializer(&current_erased_arc).expect("Failed to serialize value to JSON"),
            // );
            let arc_of_json_value = Arc::new(
                self.to_json_value()
                    .expect("Failed to serialize value to JSON"),
            );

            // Cast Arc<serde_json::Value> to Arc<dyn Any + Send + Sync>.
            // This upcast is safe because serde_json::Value is 'static + Send + Sync,
            // and T is bounded by 'static + Send + Sync (assumed for as_type_ref).
            let any_arc: std::sync::Arc<dyn std::any::Any + Send + Sync> = arc_of_json_value;

            // Attempt to downcast to Arc<T>. This will succeed if T is indeed serde_json::Value.
            match any_arc.downcast::<T>() {
                Ok(arc_t) => return Ok(arc_t),
                Err(_) => {
                    // This case should be unreachable if the TypeId check is correct and T is 'static.
                    // The type_name::<T>() is included for debugging the panic message.
                    unreachable!(
                        "Internal logic error: TypeId::of::<T>() ({}) matched TypeId::of::<serde_json::Value>(), but Arc::downcast failed.",
                        std::any::type_name::<T>()
                    );
                }
            }
            // }
        }

        if self.category == ValueCategory::List {
            // Fallback for List category: attempt to convert Vec<ArcValue> -> Vec<T_elem>
            if let Ok(vec_arcvalue) = current_erased_arc.as_arc::<Vec<ArcValue>>() {
                // Attempt to build a JSON array from the inner ArcValues, then deserialize into T
                let mut json_elems: Vec<serde_json::Value> = Vec::with_capacity(vec_arcvalue.len());
                for av in vec_arcvalue.iter() {
                    let mut av_clone = av.clone();
                    match av_clone.to_json_value() {
                        Ok(jv) => json_elems.push(jv),
                        Err(e) => {
                            // If any element fails, abort this fallback path
                            return Err(anyhow!(
                                "Failed to convert list element to JSON during list lazy conversion: {}",
                                e
                            ));
                        }
                    }
                }
                let list_json_value = serde_json::Value::Array(json_elems);
                if let Ok(deser_vec) = serde_json::from_value::<T>(list_json_value) {
                    let arc_vec_t = Arc::new(deser_vec);

                    // Replace internal value with eager vector
                    self.value = Some(ErasedArc::new(arc_vec_t.clone()));
                    // Ensure category is List (should already be)
                    self.category = ValueCategory::List;
                    return Ok(arc_vec_t);
                }
            }
        }

        if self.category == ValueCategory::Json {
            // Lazy JSON conversion path
            // Attempt to deserialize/convert JSON to requested type T
            // Retrieve the stored JSON value
            let json_arc = current_erased_arc
                .as_arc::<serde_json::Value>()
                .map_err(|e| {
                    anyhow!(
                        "Expected serde_json::Value in ArcValue::Json but found {}",
                        e
                    )
                })?;
            let json_clone = (*json_arc).clone();

            // Attempt generic serde_json conversion first
            if let Ok(deser_t) = serde_json::from_value::<T>(json_clone.clone()) {
                let arc_t = Arc::new(deser_t);

                // Replace internal erased value with the newly materialised concrete value
                self.value = Some(ErasedArc::new(arc_t.clone()));
                // Update category heuristically
                self.category = if json_clone.is_array() {
                    ValueCategory::List
                } else if json_clone.is_object() {
                    // If the target type is HashMap<String, ArcValue> treat as Map, otherwise Struct
                    if TypeId::of::<T>() == TypeId::of::<HashMap<String, ArcValue>>() {
                        ValueCategory::Map
                    } else {
                        ValueCategory::Struct
                    }
                } else if json_clone.is_null() {
                    ValueCategory::Null
                } else {
                    ValueCategory::Primitive
                };

                return Ok(arc_t);
            }

            // Fallback: if T is HashMap<String, ArcValue> and json is object, build manually
            if json_clone.is_object()
                && TypeId::of::<T>() == TypeId::of::<HashMap<String, ArcValue>>()
            {
                if let serde_json::Value::Object(map_obj) = json_clone {
                    let converted: HashMap<String, ArcValue> = map_obj
                        .into_iter()
                        .map(|(k, v)| (k, ArcValue::from_json(v)))
                        .collect();
                    let arc_hm = Arc::new(converted);
                    self.value = Some(ErasedArc::new(arc_hm.clone()));
                    self.category = ValueCategory::Map;
                    // SAFETY: TypeId matches
                    return Ok(unsafe {
                        std::mem::transmute::<Arc<HashMap<String, ArcValue>>, Arc<T>>(arc_hm)
                    });
                }
            }

            // If none succeeded
            return Err(anyhow!(
                "Failed to lazily convert JSON ArcValue to requested type: {}",
                std::any::type_name::<T>()
            ));
        }

        current_erased_arc.as_arc::<T>()
    }
}

impl fmt::Display for ArcValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(actual_value) => {
                if actual_value.is_lazy {
                    // Attempt to get LazyDataWithOffset details
                    // Note: get_lazy_data() returns Result<Arc<LazyDataWithOffset>>
                    // For Display, we might not want to propagate errors, so we handle it gracefully.
                    match actual_value.get_lazy_data() {
                        Ok(lazy) => write!(
                            f,
                            "Lazy<{}>(size: {} bytes)",
                            lazy.type_name,
                            lazy.end_offset - lazy.start_offset
                        ),
                        Err(_) => write!(f, "Lazy<Error Retrieving Details>"),
                    }
                } else {
                    // Handle eager values
                    match self.category {
                        ValueCategory::Null => write!(f, "null"),
                        ValueCategory::Primitive => {
                            // Attempt to downcast and display common primitives
                            let any_val = actual_value.as_any().map_err(|_| fmt::Error)?;
                            if let Some(s) = any_val.downcast_ref::<String>() {
                                write!(f, "\"{s}\"")
                            } else if let Some(i) = any_val.downcast_ref::<i32>() {
                                write!(f, "{i}")
                            } else if let Some(i) = any_val.downcast_ref::<i64>() {
                                write!(f, "{i}")
                            } else if let Some(fl) = any_val.downcast_ref::<f32>() {
                                write!(f, "{fl}")
                            } else if let Some(fl) = any_val.downcast_ref::<f64>() {
                                write!(f, "{fl}")
                            } else if let Some(b) = any_val.downcast_ref::<bool>() {
                                write!(f, "{b}")
                            } else {
                                write!(f, "Primitive<{}>", actual_value.type_name())
                            }
                        }
                        ValueCategory::List => {
                            // For lists, try to get a summary. Need to access Arc<Vec<T>>.
                            // This is tricky for Display without knowing T.
                            // We'll provide a generic summary.
                            // Getting actual count would require downcasting to specific Vec types.
                            write!(f, "List<{}>", actual_value.type_name())
                        }
                        ValueCategory::Map => {
                            // Similar for maps.
                            write!(f, "Map<{}>", actual_value.type_name())
                        }
                        ValueCategory::Struct => {
                            write!(f, "Struct<{}>", actual_value.type_name())
                        }
                        ValueCategory::Bytes => {
                            if let Ok(bytes_arc) = actual_value.as_arc::<Vec<u8>>() {
                                write!(f, "Bytes(size: {} bytes)", bytes_arc.len())
                            } else {
                                write!(f, "Bytes<Error Retrieving Size>")
                            }
                        }
                        ValueCategory::Json => {
                            if let Ok(json_arc) = actual_value.as_arc::<serde_json::Value>() {
                                write!(f, "Json({json_arc})")
                            } else {
                                write!(f, "Json<Error Retrieving Value>")
                            }
                        }
                    }
                }
            }
            None => {
                if self.category == ValueCategory::Null {
                    write!(f, "null")
                } else {
                    // This case should ideally not happen if category Null is always paired with value None
                    write!(f, "Error<ValueIsNoneButCategoryNotNul:{:?}>", self.category)
                }
            }
        }
    }
}

impl<T> super::AsArcValue for Option<T>
where
    T: super::AsArcValue,
{
    fn into_arc_value_type(self) -> ArcValue {
        match self {
            Some(value) => value.into_arc_value_type(),
            None => ArcValue::null(),
        }
    }
}
