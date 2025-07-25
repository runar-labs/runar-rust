//
// This file contains macros for working with ArcValue maps and raw HashMap operations.
// As of [2024-06], ArcValue is the only supported value type for all macros and value maps.
// All legacy ValueType logic has been removed. See rust-docs/specs/ for migration details.

/// Create a HashMap with ValueType values
///
/// This macro allows for easy creation of parameter maps for service requests.
///
/// # Examples
///
/// ```
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
///
/// ```ignore
/// // Extract a value from a map with default
/// let payload = ArcValue::new_map(std::collections::HashMap::new());
/// let data = vmap!(payload, "data" => String::new());
///
/// // Extract a direct value with default
/// let response = ArcValue::new_primitive("test");
/// let value = vmap!(response, => "default");
/// ```
/// Create or extract from an ArcValue map.
#[macro_export]
macro_rules! vmap {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            use runar_serializer::ArcValue;
            let map: HashMap<String, ArcValue> = HashMap::new();
            ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use runar_serializer::ArcValue;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), ArcValue::new_primitive($value));
            )*
            ArcValue::new_map(map)
        }
    };

    // NOTE: Legacy extraction arms removed in serializer redesign.  Use ArcValue
    // accessors (`as_type_ref`, `as_map_ref`, etc.) directly when reading
    // values from a map.
}

/// Create an ArcValue::Map with key-value pairs
///
/// This macro allows you to create an ArcValue::Map with key-value pairs.
/// The keys are converted to strings, and the values are converted to ArcValue.
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
            ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use runar_serializer::ArcValue;
            let mut map = HashMap::new();
            $(map.insert($key.to_string(), $value);)*
            ArcValue::new_map(map)
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
///
/// # Examples
/// ```ignore
/// use runar_macros::{params, runar_serializer::ArcValue};
/// let args = params! { "a" => 1.0, "b" => 2.0 };
/// // `args` is an `ArcValue::Map` containing the provided key/value pairs.
/// assert_eq!(args.category, ArcValue::Map.category());
/// ```
#[macro_export]
macro_rules! params {
    // Empty param map
    {} => {
        {
            use std::collections::HashMap;
            use runar_serializer::ArcValue;
            let map: HashMap<String, ArcValue> = HashMap::new();
            ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use runar_serializer::ArcValue;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), ArcValue::new_primitive($value));
            )*
            ArcValue::new_map(map)
        }
    };
}
