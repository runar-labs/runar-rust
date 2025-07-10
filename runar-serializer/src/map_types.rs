use std::collections::HashMap;

/// Map type for String -> i32
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToIntMap {
    #[prost(map = "string, int32", tag = "1")]
    pub entries: HashMap<String, i32>,
}

/// Map type for String -> i64
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToInt64Map {
    #[prost(map = "string, int64", tag = "1")]
    pub entries: HashMap<String, i64>,
}

/// Map type for String -> f64
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToFloatMap {
    #[prost(map = "string, double", tag = "1")]
    pub entries: HashMap<String, f64>,
}

/// Map type for String -> bool
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToBoolMap {
    #[prost(map = "string, bool", tag = "1")]
    pub entries: HashMap<String, bool>,
}

/// Map type for String -> String
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToStringMap {
    #[prost(map = "string, string", tag = "1")]
    pub entries: HashMap<String, String>,
}

/// Map type for String -> ArcValue (stored as serialized bytes)
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToArcValueMap {
    #[prost(map = "string, bytes", tag = "1")]
    pub entries: HashMap<String, Vec<u8>>,
}

/// Map type for String -> bytes (Vec<u8>)
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToBytesMap {
    #[prost(map = "string, bytes", tag = "1")]
    pub entries: HashMap<String, Vec<u8>>,
}

// Helper functions to convert between HashMap and our map types
impl StringToIntMap {
    pub fn from_hashmap(map: HashMap<String, i32>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, i32> {
        self.entries
    }
}

impl StringToInt64Map {
    pub fn from_hashmap(map: HashMap<String, i64>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, i64> {
        self.entries
    }
}

impl StringToFloatMap {
    pub fn from_hashmap(map: HashMap<String, f64>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, f64> {
        self.entries
    }
}

impl StringToBoolMap {
    pub fn from_hashmap(map: HashMap<String, bool>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, bool> {
        self.entries
    }
}

impl StringToStringMap {
    pub fn from_hashmap(map: HashMap<String, String>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, String> {
        self.entries
    }
}

impl StringToArcValueMap {
    pub fn from_hashmap_with_registry(
        map: HashMap<String, crate::ArcValue>,
        registry: &crate::SerializerRegistry,
    ) -> Result<Self, anyhow::Error> {
        let mut entries = HashMap::new();
        for (key, value) in map {
            // Use ArcValue's proper protobuf serialization through the registry
            let bytes = registry.serialize_value(&value)?;
            entries.insert(key, bytes.to_vec());
        }
        Ok(Self { entries })
    }

    pub fn into_hashmap_with_registry(
        self,
        registry: &crate::SerializerRegistry,
    ) -> Result<HashMap<String, crate::ArcValue>, anyhow::Error> {
        let mut entries = HashMap::new();

        for (key, bytes) in self.entries {
            // Use ArcValue's proper protobuf deserialization through the registry
            let arc_bytes = std::sync::Arc::from(bytes);
            let value = registry.deserialize_value(arc_bytes)?;
            entries.insert(key, value);
        }
        Ok(entries)
    }
}

impl StringToBytesMap {
    pub fn from_hashmap(map: HashMap<String, Vec<u8>>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, Vec<u8>> {
        self.entries
    }
}
