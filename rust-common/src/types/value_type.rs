// runar_common/src/types/value_type.rs
//
// Canonical value type for all value representations in the system.
// As of [2024-06]: ArcValueType is the only supported value type.
// All previous ValueType usages must be migrated to ArcValueType.
// Architectural boundary: No other value type is permitted for serialization, API, or macro use.
// See documentation in mod.rs and rust-docs/specs/ for rationale.

use std::any::Any;
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::marker::Copy;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::erased_arc::ErasedArc;
use crate::logging::Logger;
use crate::types::AsArcValueType; // Added import for the trait

// Type alias for complex deserialization function signature
pub(crate) type DeserializationFn =
    Arc<dyn Fn(&[u8]) -> Result<Box<dyn Any + Send + Sync>> + Send + Sync>;
// Type alias for the inner part of the complex serialization function signature
pub(crate) type SerializationFnInner = Box<dyn Fn(&dyn Any) -> Result<Vec<u8>> + Send + Sync>;

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
    // NOTE: We no longer store the deserializer function here, as we use direct bincode
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
}

/// Registry for type-specific serialization and deserialization handlers
pub struct SerializerRegistry {
    serializers: FxHashMap<String, SerializationFnInner>,
    deserializers: FxHashMap<String, DeserializerFnWrapper>,
    is_sealed: bool,
    /// Logger for SerializerRegistry operations
    logger: Arc<Logger>,
}

impl SerializerRegistry {
    /// Create a new registry with default logger
    pub fn new(logger: Arc<Logger>) -> Self {
        SerializerRegistry {
            serializers: FxHashMap::default(),
            deserializers: FxHashMap::default(),
            is_sealed: false,
            logger,
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
        self.is_sealed = true;
    }

    /// Check if the registry is sealed
    pub fn is_sealed(&self) -> bool {
        self.is_sealed
    }

    /// Register a type for serialization/deserialization
    pub fn register<T: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync>(
        &mut self,
    ) -> Result<()> {
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

        // Register serializer using the full type name
        self.serializers.insert(
            type_name.to_string(),
            Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    bincode::serialize(typed_value)
                        .map_err(|e| anyhow!("Serialization error: {}", e))
                } else {
                    Err(anyhow!("Type mismatch during serialization"))
                }
            }),
        );

        // Create a deserializer function using DeserializerFnWrapper
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let value: T = bincode::deserialize(bytes)?;
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

    /// Register a map type for serialization/deserialization
    pub fn register_map<K, V>(&mut self) -> Result<()>
    where
        K: 'static
            + Serialize
            + for<'de> Deserialize<'de>
            + Clone
            + Send
            + Sync
            + Eq
            + std::hash::Hash,
        V: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        if self.is_sealed {
            return Err(anyhow!(
                "Cannot register new types after registry is sealed"
            ));
        }

        // Get the full and simple type names
        let type_name = std::any::type_name::<HashMap<K, V>>();
        let simple_name = if let Some(last_segment) = type_name.split("::").last() {
            last_segment.to_string()
        } else {
            type_name.to_string()
        };

        // Register serializer using the full type name
        self.serializers.insert(
            type_name.to_string(),
            Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(map) = value.downcast_ref::<HashMap<K, V>>() {
                    bincode::serialize(map).map_err(|e| anyhow!("Map serialization error: {}", e))
                } else {
                    Err(anyhow!("Type mismatch during map serialization"))
                }
            }),
        );

        // Create a deserializer function using DeserializerFnWrapper
        let deserializer =
            DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let map: HashMap<K, V> = bincode::deserialize(bytes)?;
                Ok(Box::new(map))
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

    /// Deserialize bytes (owned Arc) to an ArcValueType
    pub fn deserialize_value(&self, bytes_arc: Arc<[u8]>) -> Result<ArcValueType> {
        if bytes_arc.is_empty() {
            return Err(anyhow!("Empty byte array"));
        }

        // Extract header info using a slice view
        let (original_category, type_name, data_slice) =
            self.extract_header_from_slice(&bytes_arc)?;

        // For null, just return a null value
        if original_category == ValueCategory::Null {
            return Ok(ArcValueType::null());
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

            let lazy_data = LazyDataWithOffset {
                type_name: type_name.to_string(),
                original_buffer: bytes_arc.clone(), // Clone the Arc (cheap)
                start_offset: data_start_offset,
                end_offset: data_end_offset,
            };

            // Store Arc<LazyDataWithOffset> in value, keeping original category
            let value = ErasedArc::from_value(lazy_data);
            Ok(ArcValueType {
                category: original_category, // Keep original category (Map, Struct, etc.)
                value: Some(value),
            })
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
    pub fn serialize_value(&self, value: &ArcValueType) -> Result<Arc<[u8]>> {
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
                    };
                    result_vec.push(category_byte);

                    if value.category == ValueCategory::Null {
                        // Should ideally not be hit if erased_arc_ref is Some.
                        // This implies an inconsistent ArcValueType state.
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
                        "Inconsistent state for serialization: ArcValueType.value is None but category is {:?}",
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

/// A type-erased value container with Arc preservation
/// Note: This type is NOT serializable because it contains an ErasedArc field.
/// Any attempt to serialize/deserialize ArcValueType will skip the value field.
#[derive(Debug, Clone)]
pub struct ArcValueType {
    /// Categorizes the value for dispatch
    pub category: ValueCategory,
    /// The contained type-erased value
    /// Note: ErasedArc is type-erased and requires custom serde impl. Only registered types are supported.
    pub value: Option<ErasedArc>,
}

impl PartialEq for ArcValueType {
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

impl Eq for ArcValueType {}

impl AsArcValueType for ArcValueType {
    fn into_arc_value_type(self) -> ArcValueType {
        self // It already is an ArcValueType
    }
}

impl AsArcValueType for bool {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::new_primitive(self)
    }
}

impl AsArcValueType for String {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::new_primitive(self)
    }
}

impl AsArcValueType for &str {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::new_primitive(self.to_string())
    }
}

impl AsArcValueType for i32 {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::new_primitive(self)
    }
}

impl AsArcValueType for i64 {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::new_primitive(self)
    }
}

impl AsArcValueType for () {
    fn into_arc_value_type(self) -> ArcValueType {
        ArcValueType::null() // Represent unit type as null payload
    }
}

impl ArcValueType {
    /// Create a new ArcValueType
    pub fn new(value: ErasedArc, category: ValueCategory) -> Self {
        Self {
            category,
            value: Some(value),
        }
    }

    /// Create a new primitive value
    pub fn new_primitive<T: 'static + fmt::Debug + Send + Sync>(value: T) -> Self {
        let arc = Arc::new(value);
        Self {
            category: ValueCategory::Primitive,
            value: Some(ErasedArc::new(arc)),
        }
    }

    /// Create a new struct value
    pub fn from_struct<T: 'static + fmt::Debug + Send + Sync>(value: T) -> Self {
        let arc = Arc::new(value);
        Self {
            category: ValueCategory::Struct,
            value: Some(ErasedArc::new(arc)),
        }
    }

    /// Create a new list value
    pub fn new_list<T: 'static + fmt::Debug + Send + Sync>(values: Vec<T>) -> Self {
        let arc = Arc::new(values);
        Self {
            category: ValueCategory::List,
            value: Some(ErasedArc::new(arc)),
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
        }
    }

    /// Check if this value is null
    pub fn is_null(&self) -> bool {
        self.value.is_none() && self.category == ValueCategory::Null
    }

    /// Get value as a reference of the specified type
    pub fn as_type_ref<T>(&mut self) -> Result<Arc<T>>
    where
        T: 'static + Clone + for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
    {
        let mut current_erased_arc = match self.value.take() {
            Some(ea) => ea,
            None => {
                return Err(anyhow!(
                    "Cannot get type ref: ArcValueType's internal value is None (category: {:?})",
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
            if !crate::types::erased_arc::compare_type_names(expected_type_name, &type_name_clone) {
                self.value = Some(current_erased_arc); // Put the original lazy value back
                return Err(anyhow!(
                    "Lazy data type mismatch: expected compatible with {}, but stored type is {}",
                    expected_type_name,
                    type_name_clone
                ));
            }

            let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];
            let deserialized_value: T = bincode::deserialize(data_slice).map_err(|e| {
                // Note: Consider if current_erased_arc should be put back into self.value on deserialize error.
                // Original code didn't, so maintaining that behavior for now.
                anyhow!(
                    "Failed to deserialize lazy struct data for type '{}' into {}: {}",
                    type_name_clone,
                    std::any::type_name::<T>(),
                    e
                )
            })?;

            // Replace internal lazy value with the eager one
            current_erased_arc = ErasedArc::new(Arc::new(deserialized_value));
        }

        let result = current_erased_arc.as_arc::<T>();
        self.value = Some(current_erased_arc); // Put the (potentially updated) ErasedArc back
        result
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

        let mut current_erased_arc = match self.value.take() {
            Some(ea) => ea,
            None => {
                return Err(anyhow!(
                    "Cannot get list ref: ArcValueType's internal value is None despite List category"
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
                        "Failed to get lazy data from ErasedArc for list despite is_lazy flag: {}",
                        e
                    )
                })?;
                type_name_clone = lazy_data_arc.type_name.clone();
                original_buffer_clone = lazy_data_arc.original_buffer.clone();
                start_offset_val = lazy_data_arc.start_offset;
                end_offset_val = lazy_data_arc.end_offset;
            }

            let expected_list_type_name = std::any::type_name::<Vec<T>>();
            if !crate::types::erased_arc::compare_type_names(
                expected_list_type_name,
                &type_name_clone,
            ) {
                self.value = Some(current_erased_arc); // Put the original lazy value back
                return Err(anyhow!(
                    "Lazy list data type mismatch: expected compatible with Vec<{}> (is {}), but stored type is {}",
                    std::any::type_name::<T>(),
                    expected_list_type_name,
                    type_name_clone
                ));
            }

            let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];
            let deserialized_list: Vec<T> = bincode::deserialize(data_slice).map_err(|e| {
                anyhow!(
                    "Failed to deserialize lazy list data for type '{}' into Vec<{}>: {}",
                    type_name_clone,
                    std::any::type_name::<T>(),
                    e
                )
            })?;

            current_erased_arc = ErasedArc::new(Arc::new(deserialized_list));
        }

        let result = current_erased_arc.as_arc::<Vec<T>>();
        self.value = Some(current_erased_arc);
        result
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
        HashMap<K, V>: 'static + fmt::Debug + Send + Sync,
    {
        if self.category != ValueCategory::Map {
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
                            anyhow!("Failed to get lazy data despite is_lazy flag: {}", e)
                        })?;
                        type_name_clone = lazy_data_arc.type_name.clone();
                        original_buffer_clone = lazy_data_arc.original_buffer.clone();
                        start_offset_val = lazy_data_arc.start_offset;
                        end_offset_val = lazy_data_arc.end_offset;
                    }

                    let expected_type_name = std::any::type_name::<HashMap<K, V>>();
                    if !crate::types::erased_arc::compare_type_names(
                        expected_type_name,
                        &type_name_clone,
                    ) {
                        return Err(anyhow!(
                            "Lazy data type mismatch: expected compatible with {}, but stored type is {}",
                            expected_type_name,
                            type_name_clone
                        ));
                    }

                    let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];
                    let deserialized_map: HashMap<K, V> =
                        bincode::deserialize(data_slice).map_err(|e| {
                            anyhow!(
                                "Failed to deserialize lazy map data for type '{}' into HashMap<{}, {}>: {}",
                                type_name_clone, std::any::type_name::<K>(), std::any::type_name::<V>(), e
                            )
                        })?;

                    *actual_value = ErasedArc::new(Arc::new(deserialized_map));
                }
                actual_value.as_arc::<HashMap<K, V>>().map_err(|e|
                    anyhow!("Failed to cast eager value to map: {}. Expected HashMap<{},{}>, got {}. Category: {:?}", 
                        e, std::any::type_name::<K>(), std::any::type_name::<V>(), actual_value.type_name(), self.category)
                )
            }
            None => Err(anyhow!(
                "Cannot get map reference from a null ArcValueType (category: {:?})",
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
                    if !crate::types::erased_arc::compare_type_names(
                        expected_type_name,
                        &type_name_clone,
                    ) {
                        return Err(anyhow!(
                            "Lazy data type mismatch: expected compatible with {}, but stored type is {}",
                            expected_type_name,
                            type_name_clone
                        ));
                    }

                    let data_slice = &original_buffer_clone[start_offset_val..end_offset_val];
                    let deserialized_struct: T = bincode::deserialize(data_slice).map_err(|e| {
                        anyhow!(
                            "Failed to deserialize lazy struct data for type '{}' into {}: {}",
                            type_name_clone,
                            std::any::type_name::<T>(),
                            e
                        )
                    })?;

                    *actual_value = ErasedArc::new(Arc::new(deserialized_struct));
                }
                // Explicitly assign and return
                actual_value.as_arc::<T>().map_err(|e| {
                    anyhow!(
                        "Failed to cast eager value to struct: {}. Expected {}, got {}. Category: {:?}",
                        e,
                        std::any::type_name::<T>(),
                        actual_value.type_name(),
                        self.category
                    )
                }) // Return the result
            }
            None => Err(anyhow!(
                "Cannot get struct reference from a null ArcValueType (category: {:?})",
                self.category
            )),
        }
    }
}

impl Serialize for ArcValueType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.category.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArcValueType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let category = ValueCategory::deserialize(deserializer)?;
        Ok(ArcValueType {
            category,
            value: None, // Placeholder, SerializerRegistry should hydrate if non-null category
        })
    }
}
// Custom Display implementation
impl fmt::Display for ArcValueType {
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

impl<T> super::AsArcValueType for Option<T>
where
    T: super::AsArcValueType,
{
    fn into_arc_value_type(self) -> ArcValueType {
        match self {
            Some(value) => value.into_arc_value_type(),
            None => ArcValueType::null(),
        }
    }
}
