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
/// use runar_common::vmap;
/// use runar_common::types::ArcValue;
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
            use $crate::types::ArcValue;
            let map: HashMap<String, ArcValue> = HashMap::new();
            ArcValue::new_map(map)
        }
    };

    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use $crate::types::ArcValue;
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
                $crate::types::ArcValue::Map(map_data) => {
                    match map_data.get($key) {
                        Some(value_type) => match value_type {
                            $crate::types::ArcValue::String(s) => {
                                let default_type = std::any::type_name_of_val(&$default);
                                if default_type.ends_with("&str") || default_type.ends_with("String") {
                                    s.clone()
                                } else {
                                    $default
                                }
                            },
                            $crate::types::ArcValue::Number(n) => {
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
                            $crate::types::ArcValue::Bool(b) => {
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
            $crate::types::ArcValue::String(s) => s.clone(),
            $crate::types::ValueType::Number(n) => {
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
            $crate::types::ValueType::Bool(b) => {
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
                $crate::types::ArcValue::Map(map_data) => {
                    match map_data.get($key) {
                        Some(value_type) => value_type.clone(),
                        None => $crate::types::ArcValue::null(),
                    }
                },
                _ => $crate::types::ArcValue::null(),
            }
        }
    };
}
