// utils/src/lib.rs
//
// This crate provides utility macros and functions for the KAGI system.

/// Create a HashMap with ValueType values
/// 
/// This macro allows for easy creation of parameter maps for service requests.
/// 
/// # Examples
/// 
/// ```
/// // Create a map with key-value pairs
/// let map = vmap! {
///     "name" => "John Doe",
///     "age" => 30,
///     "is_admin" => true
/// };
/// 
/// // Create an empty map
/// let empty = vmap! {};
/// 
/// // Extract a value from a map with default
/// let data = vmap!(payload, "data" => String::new());
///
/// // Extract a direct value with default
/// let value = vmap!(response.data, => "default");
/// ```
#[macro_export]
macro_rules! vmap {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            use kagi_node::services::ValueType;
            let map: HashMap<String, ValueType> = HashMap::new();
            ValueType::Map(map)
        }
    };
    
    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use kagi_node::services::ValueType;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), ValueType::from($value));
            )*
            ValueType::Map(map)
        }
    };
    
    // Extract a value from a map with default
    ($map:expr, $key:expr => $default:expr) => {
        {
            match &$map {
                kagi_node::services::ValueType::Map(map_data) => {
                    match map_data.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::String(s) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: &str => s.clone(),
                                    _: String => s.clone(),
                                    _ => $default
                                }
                            },
                            kagi_node::services::ValueType::Number(n) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: f64 => *n,
                                    _: i32 => *n as i32,
                                    _: u32 => *n as u32,
                                    _: i64 => *n as i64,
                                    _: String => n.to_string(),
                                    _: &str => n.to_string(),
                                    _ => $default
                                }
                            },
                            kagi_node::services::ValueType::Bool(b) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: bool => *b,
                                    _: String => b.to_string(),
                                    _: &str => b.to_string(),
                                    _ => $default
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
            kagi_node::services::ValueType::String(s) => s.clone(),
            kagi_node::services::ValueType::Number(n) => {
                match &$default {
                    _ if false => unreachable!(), // This is a hack to make typechecking work
                    _: f64 => *n,
                    _: i32 => *n as i32,
                    _: u32 => *n as u32, 
                    _: i64 => *n as i64,
                    _: String => n.to_string(),
                    _: &str => n.to_string(),
                    _ => $default
                }
            },
            kagi_node::services::ValueType::Bool(b) => {
                match &$default {
                    _ if false => unreachable!(), // This is a hack to make typechecking work
                    _: bool => *b,
                    _: String => b.to_string(),
                    _: &str => b.to_string(),
                    _ => $default
                }
            },
            _ => $default,
        }
    };
}

/// Create an optional HashMap with ValueType values
/// 
/// This macro is similar to `vmap!` but wraps the result in Some().
/// 
/// # Examples
/// 
/// ```
/// // Create an optional map with key-value pairs
/// let map = vmap_opt! {
///     "name" => "John Doe",
///     "age" => 30
/// };
/// 
/// // Create an empty optional map
/// let empty = vmap_opt! {};
/// ```
#[macro_export]
macro_rules! vmap_opt {
    // Empty map
    {} => {
        {
            use std::collections::HashMap;
            use kagi_node::services::ValueType;
            let map: HashMap<String, ValueType> = HashMap::new();
            None
        }
    };
    
    // Map with key-value pairs
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use std::collections::HashMap;
            use kagi_node::services::ValueType;
            let mut map = HashMap::new();
            $(
                map.insert($key.to_string(), ValueType::from($value));
            )*
            Some(ValueType::Map(map))
        }
    };
}

/// Extract values from ValueType with defaults
/// 
/// This macro allows extracting values from a ValueType with default values
/// if the key is not found or the value has the wrong type.
/// 
/// # Examples
/// 
/// ```
/// // Extract a string from a ValueType
/// let name = vmap_extract!(value, "name", "Anonymous");
/// 
/// // Extract a number from a ValueType
/// let age = vmap_extract!(value, "age", 0);
/// ```
#[macro_export]
macro_rules! vmap_extract {
    // Extract a value from a ValueType with default
    ($value:expr, $key:expr, $default:expr) => {
        {
            match &$value {
                kagi_node::services::ValueType::Map(map) => {
                    match map.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::String(s) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: &str => s.clone(),
                                    _: String => s.clone(),
                                    _: i32 => s.parse::<i32>().unwrap_or($default),
                                    _: i64 => s.parse::<i64>().unwrap_or($default),
                                    _: f64 => s.parse::<f64>().unwrap_or($default),
                                    _: u32 => s.parse::<u32>().unwrap_or($default),
                                    _: bool => s.parse::<bool>().unwrap_or($default),
                                    _ => $default
                                }
                            },
                            kagi_node::services::ValueType::Number(n) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: f64 => *n,
                                    _: i32 => *n as i32,
                                    _: u32 => *n as u32,
                                    _: i64 => *n as i64,
                                    _: String => n.to_string(),
                                    _: &str => n.to_string(),
                                    _ => $default
                                }
                            },
                            kagi_node::services::ValueType::Bool(b) => {
                                match &$default {
                                    _ if false => unreachable!(), // This is a hack to make typechecking work
                                    _: bool => *b,
                                    _: i32 => if *b { 1 } else { 0 },
                                    _: i64 => if *b { 1 } else { 0 },
                                    _: u32 => if *b { 1 } else { 0 },
                                    _: f64 => if *b { 1.0 } else { 0.0 },
                                    _: String => b.to_string(),
                                    _: &str => b.to_string(),
                                    _ => $default
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
        $crate::vmap!($value, => $default)
    };
}

/// Extract a string value from a ValueType with default
/// 
/// # Examples
/// 
/// ```
/// let name = vmap_extract_string!(data, "name", "Anonymous");
/// ```
#[macro_export]
macro_rules! vmap_extract_string {
    ($value:expr, $key:expr, $default:expr) => {
        {
            match &$value {
                kagi_node::services::ValueType::Map(map) => {
                    match map.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::String(s) => s.clone(),
                            kagi_node::services::ValueType::Number(n) => n.to_string(),
                            kagi_node::services::ValueType::Bool(b) => b.to_string(),
                            _ => $default.to_string(),
                        },
                        None => $default.to_string(),
                    }
                },
                _ => $default.to_string(),
            }
        }
    };
    
    ($value:expr, => $default:expr) => {
        match &$value {
            kagi_node::services::ValueType::String(s) => s.clone(),
            kagi_node::services::ValueType::Number(n) => n.to_string(),
            kagi_node::services::ValueType::Bool(b) => b.to_string(),
            _ => $default.to_string(),
        }
    };
}

/// Extract an i32 value from a ValueType with default
/// 
/// # Examples
/// 
/// ```
/// let age = vmap_extract_i32!(data, "age", 0);
/// ```
#[macro_export]
macro_rules! vmap_extract_i32 {
    ($value:expr, $key:expr, $default:expr) => {
        {
            match &$value {
                kagi_node::services::ValueType::Map(map) => {
                    match map.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::Number(n) => *n as i32,
                            kagi_node::services::ValueType::String(s) => s.parse::<i32>().unwrap_or($default),
                            kagi_node::services::ValueType::Bool(b) => if *b { 1 } else { 0 },
                            _ => $default,
                        },
                        None => $default,
                    }
                },
                _ => $default,
            }
        }
    };
    
    ($value:expr, => $default:expr) => {
        match &$value {
            kagi_node::services::ValueType::Number(n) => *n as i32,
            kagi_node::services::ValueType::String(s) => s.parse::<i32>().unwrap_or($default),
            kagi_node::services::ValueType::Bool(b) => if *b { 1 } else { 0 },
            _ => $default,
        }
    };
}

/// Extract an f64 value from a ValueType with default
/// 
/// # Examples
/// 
/// ```
/// let score = vmap_extract_f64!(data, "score", 0.0);
/// ```
#[macro_export]
macro_rules! vmap_extract_f64 {
    ($value:expr, $key:expr, $default:expr) => {
        {
            match &$value {
                kagi_node::services::ValueType::Map(map) => {
                    match map.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::Number(n) => *n,
                            kagi_node::services::ValueType::String(s) => s.parse::<f64>().unwrap_or($default),
                            kagi_node::services::ValueType::Bool(b) => if *b { 1.0 } else { 0.0 },
                            _ => $default,
                        },
                        None => $default,
                    }
                },
                _ => $default,
            }
        }
    };
    
    ($value:expr, => $default:expr) => {
        match &$value {
            kagi_node::services::ValueType::Number(n) => *n,
            kagi_node::services::ValueType::String(s) => s.parse::<f64>().unwrap_or($default),
            kagi_node::services::ValueType::Bool(b) => if *b { 1.0 } else { 0.0 },
            _ => $default,
        }
    };
}

/// Extract a bool value from a ValueType with default
/// 
/// # Examples
/// 
/// ```
/// let is_admin = vmap_extract_bool!(data, "is_admin", false);
/// ```
#[macro_export]
macro_rules! vmap_extract_bool {
    ($value:expr, $key:expr, $default:expr) => {
        {
            match &$value {
                kagi_node::services::ValueType::Map(map) => {
                    match map.get($key) {
                        Some(value_type) => match value_type {
                            kagi_node::services::ValueType::Bool(b) => *b,
                            kagi_node::services::ValueType::Number(n) => *n != 0.0,
                            kagi_node::services::ValueType::String(s) => {
                                let lower = s.to_lowercase();
                                lower == "true" || lower == "yes" || lower == "1"
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
    
    ($value:expr, => $default:expr) => {
        match &$value {
            kagi_node::services::ValueType::Bool(b) => *b,
            kagi_node::services::ValueType::Number(n) => *n != 0.0,
            kagi_node::services::ValueType::String(s) => {
                let lower = s.to_lowercase();
                lower == "true" || lower == "yes" || lower == "1"
            },
            _ => $default,
        }
    };
} 