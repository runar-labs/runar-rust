//
// This file contains macros for working with ArcValue maps and raw HashMap operations.
// As of [2024-06], ArcValue is the only supported value type for all macros and value maps.
// All legacy ValueType logic has been removed. See rust-docs/specs/ for migration details.

/// Create a HashMap with ValueType values
///
/// This macro allows for easy creation of parameter maps for service requests.
/// Note: This macro requires runar-serializer to be available in the calling crate.
///
/// # Examples
///
/// ```ignore
/// use runar_macros_common::vmap;
/// use runar_serializer::ArcValue;
///
/// let map = vmap! {
///     "name" => "John Doe".to_string(),
///     "age" => 30,
///     "is_admin" => true
/// };
///
/// // Create an empty map
/// let empty = vmap! {};
/// ```
#[macro_export]
macro_rules! vmap {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            let map: HashMap<String, runar_serializer::ArcValue> = HashMap::new();
            runar_serializer::ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), runar_serializer::ArcValue::new_primitive($value));
            )*
            runar_serializer::ArcValue::new_map(map)
        }
    };
}

/// Create an ArcValue::Map with key-value pairs
///
/// This macro allows you to create an ArcValue::Map with key-value pairs.
/// The keys are converted to strings, and the values are converted to ArcValue.
/// Note: This macro requires runar-serializer to be available in the calling crate.
///
/// ## Map Creation Usage:
///
#[macro_export]
macro_rules! hmap {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            let map: HashMap<String, _> = HashMap::new();
            runar_serializer::ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            let mut map = HashMap::new();
            $(map.insert($key.to_string(), $value);)*
            runar_serializer::ArcValue::new_map(map)
        }
    };
}

/// Create an `ArcValue::Map` from key\u2011value pairs.
///
/// This macro is intended as a more ergonomic wrapper around the
/// combination `ArcValue::new_map(hmap!{ ... })` that is commonly
/// required when invoking service requests. Each value on the right
/// hand side is automatically wrapped with `ArcValue::new_primitive` so
/// primitive Rust values such as numbers, booleans or strings can be
/// written directly.
/// Note: This macro requires runar-serializer to be available in the calling crate.
///
/// # Examples
/// ```ignore
/// use runar_macros::{params, runar_serializer::ArcValue};
/// let args = params! { "a" => 1.0, "b" => 2.0 };
/// // `args` is an `ArcValue::Map` containing the provided key/value pairs.
/// assert_eq!(args.category(), ArcValue::Map.category());
/// ```
#[macro_export]
macro_rules! params {
    // Empty param map
    {} => {
        {
            use std::collections::HashMap;
            let map: HashMap<String, runar_serializer::ArcValue> = HashMap::new();
            runar_serializer::ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), runar_serializer::ArcValue::new_primitive($value));
            )*
            runar_serializer::ArcValue::new_map(map)
        }
    };
}

// Note: Logging macros have been moved to the dedicated runar-logging crate.
// Import logging macros directly from runar_logging.

/// CBOR byte string serialization support
///
/// This module provides utilities for proper CBOR byte string encoding
/// of Vec<u8> and Vec<Vec<u8>> fields to ensure Swift compatibility.
pub mod cbor_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteBuf;
    use serde_with::As;

    /// Serialize Vec<Vec<u8>> as an array of CBOR byte strings
    ///
    /// This ensures that each inner Vec<u8> is encoded as a proper CBOR byte string
    /// instead of an array of integers, providing Swift compatibility.
    ///
    /// # Usage
    ///
    /// ```rust
    /// use serde::{Deserialize, Serialize};
    /// use runar_macros_common::cbor_bytes::VecVecBytes;
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct MyStruct {
    ///     #[serde(with = "VecVecBytes")]
    ///     pub profile_public_keys: Vec<Vec<u8>>,
    /// }
    /// ```
    pub struct VecVecBytes;

    impl VecVecBytes {
        pub fn serialize<S>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let byte_bufs: Vec<ByteBuf> =
                value.iter().map(|v| ByteBuf::from(v.as_slice())).collect();
            byte_bufs.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let byte_bufs: Vec<ByteBuf> = Vec::deserialize(deserializer)?;
            Ok(byte_bufs.into_iter().map(|b| b.into_vec()).collect())
        }
    }

    /// Alternative approach using serde_with for more ergonomic usage
    ///
    /// # Usage
    ///
    /// ```rust
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    /// use runar_macros_common::cbor_bytes::VecVecBytesAs;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct MyStruct {
    ///     #[serde_as(as = "VecVecBytesAs")]
    ///     pub profile_public_keys: Vec<Vec<u8>>,
    /// }
    /// ```
    pub type VecVecBytesAs = As<VecVecBytes>;
}

/// Re-export commonly used types for convenience
pub use cbor_bytes::{VecVecBytes, VecVecBytesAs};

#[cfg(test)]
mod cbor_test;
