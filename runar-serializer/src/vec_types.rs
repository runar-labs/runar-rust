use crate::map_types::{StringToBytesMap, StringToStringMap};
use std::collections::HashMap;

/// Vector type for Vec<HashMap<String, String>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringString {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<StringToStringMap>,
}

// Helper functions to convert between Vec<HashMap<String, String>> and our vector type
impl VecHashMapStringString {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, String>>) -> Self {
        let entries = vec
            .into_iter()
            .map(StringToStringMap::from_hashmap)
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, String>> {
        self.entries
            .into_iter()
            .map(|map_type| map_type.into_hashmap())
            .collect()
    }
}

/// Vector type for Vec<HashMap<String, i32>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringInt {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<crate::map_types::StringToIntMap>,
}

impl VecHashMapStringInt {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, i32>>) -> Self {
        let entries = vec
            .into_iter()
            .map(crate::map_types::StringToIntMap::from_hashmap)
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, i32>> {
        self.entries
            .into_iter()
            .map(|map_type| map_type.into_hashmap())
            .collect()
    }
}

/// Vector type for Vec<HashMap<String, f64>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringFloat {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<crate::map_types::StringToFloatMap>,
}

impl VecHashMapStringFloat {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, f64>>) -> Self {
        let entries = vec
            .into_iter()
            .map(crate::map_types::StringToFloatMap::from_hashmap)
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, f64>> {
        self.entries
            .into_iter()
            .map(|map_type| map_type.into_hashmap())
            .collect()
    }
}

/// Vector type for Vec<HashMap<String, bool>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringBool {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<crate::map_types::StringToBoolMap>,
}

impl VecHashMapStringBool {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, bool>>) -> Self {
        let entries = vec
            .into_iter()
            .map(crate::map_types::StringToBoolMap::from_hashmap)
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, bool>> {
        self.entries
            .into_iter()
            .map(|map_type| map_type.into_hashmap())
            .collect()
    }
}

/// Vector type for Vec<HashMap<String, Vec<u8>>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringBytes {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<StringToBytesMap>,
}

impl VecHashMapStringBytes {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, Vec<u8>>>) -> Self {
        let entries = vec
            .into_iter()
            .map(StringToBytesMap::from_hashmap)
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, Vec<u8>>> {
        self.entries.into_iter().map(|m| m.into_hashmap()).collect()
    }
}

#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecArcValue {
    #[prost(bytes, repeated, tag = "1")]
    pub entries: Vec<Vec<u8>>,
}
