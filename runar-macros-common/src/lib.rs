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
///     "name" => "John Doe",
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

    // Extract a value from a map with default
    ($map:expr, $key:expr => $default:expr) => {
        {
            match &$map {
                runar_serializer::ArcValue::Map(map_data) => {
                    match map_data.get($key) {
                        Some(value_type) => match value_type {
                            runar_serializer::ArcValue::String(s) => {
                                let default_type = std::any::type_name_of_val(&$default);
                                if default_type.ends_with("&str") || default_type.ends_with("String") {
                                    s.clone()
                                } else {
                                    $default
                                }
                            },
                            runar_serializer::ArcValue::Number(n) => {
                                let default_type = std::any::type_name_of_val(&$default);
                                if default_type.ends_with("f64") {
                                    *n
                                } else if default_type.ends_with("i32") {
                                    *n as i32
                                } else if default_type.ends_with("u32") {
                                    *n as u32
                                } else if default_type.ends_with("i64") {
                                    *n as i64
                                } else if default_type.ends_with("String") || default_type.ends_with("&str") {
                                    n.to_string()
                                } else {
                                    $default
                                }
                            },
                            runar_serializer::ArcValue::Bool(b) => {
                                let default_type = std::any::type_name_of_val(&$default);
                                if default_type.ends_with("bool") {
                                    *b
                                } else if default_type.ends_with("String") || default_type.ends_with("&str") {
                                    b.to_string()
                                } else {
                                    $default
                                }
                            },
                            _ => $default,
                        },
                        None => $default,
                    }
                },
                _ => $default,
            }
        }
    };

    // Extract a direct value with default
    ($value:expr, => $default:expr) => {
        match &$value {
            runar_serializer::ArcValue::String(s) => s.clone(),
            runar_serializer::ArcValue::Number(n) => {
                // Use type_name_of_val to detect default type
                let default_type = std::any::type_name_of_val(&$default);
                if default_type.ends_with("&str") || default_type.ends_with("String") {
                    n.to_string()
                } else if default_type.ends_with("f64") {
                    *n
                } else if default_type.ends_with("i32") {
                    *n as i32
                } else if default_type.ends_with("u32") {
                    *n as u32
                } else if default_type.ends_with("i64") {
                    *n as i64
                } else {
                    $default
                }
            },
            runar_serializer::ArcValue::Bool(b) => {
                // Use type_name_of_val to detect default type
                let default_type = std::any::type_name_of_val(&$default);
                if default_type.ends_with("bool") {
                    *b
                } else if default_type.ends_with("String") || default_type.ends_with("&str") {
                    b.to_string()
                } else {
                    $default
                }
            },
            _ => $default,
        }
    };

    // Simple key extraction without default
    ($map:expr, $key:expr) => {
        {
            match &$map {
                runar_serializer::ArcValue::Map(map_data) => {
                    match map_data.get($key) {
                        Some(value_type) => value_type.clone(),
                        None => runar_serializer::ArcValue::null(),
                    }
                },
                _ => runar_serializer::ArcValue::null(),
            }
        }
    };
}

/// Create an ArcValue::Map with key-value pairs
///
/// This macro allows you to create an ArcValue::Map with key-value pairs.
/// The keys are converted to strings, and the values are converted to ArcValue.
///
/// ## Map Creation Usage:
///
/// ```
/// use runar_macros_common::hmap;
/// use runar_serializer::ArcValue;
/// // Create a HashMap<String, ArcValue> with heterogeneous primitive values:
/// let params = hmap!(
///     "name"   => ArcValue::new_primitive("John"),
///     "age"    => ArcValue::new_primitive(30),
///     "active" => ArcValue::new_primitive(true)
/// );
/// ```
///
/// ## Empty Map:
///
/// ```
/// use runar_macros_common::hmap;
/// use runar_serializer::ArcValue;
/// use std::collections::HashMap;
/// // Create an empty map (explicit type so inference succeeds)
/// let empty: HashMap<String, ArcValue> = hmap!{};
/// ```
#[macro_export]
macro_rules! hmap {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            let map: HashMap<String, _> = HashMap::new();
            map
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            let mut map = HashMap::new();
            $(map.insert($key.to_string(), $value);)*
            map
        }
    };
}

// Define and export the vjson macro (JSON to ArcValue)
#[macro_export]
macro_rules! vjson {
    ($($json:tt)+) => {
        runar_serializer::ArcValue::from(serde_json::json!($($json)+))
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
            use runar_serializer::ArcValue;
            ArcValue::new_map(hmap! {})
        }
    };

    // Non-empty param map
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use runar_serializer::ArcValue;
            ArcValue::new_map(hmap! {
                $( $key => ArcValue::new_primitive($value) ),*
            })
        }
    };
}
