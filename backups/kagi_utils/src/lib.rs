use kagi_node::services::ValueType;

/// Extract a string value from a ValueType::Map or Option<ValueType>
/// 
/// # Example
/// 
/// ```
/// use kagi_utils::vmap_extract_string;
/// use kagi_node::services::ValueType;
/// use std::collections::HashMap;
/// 
/// let mut map = HashMap::new();
/// map.insert("name".to_string(), ValueType::String("John".to_string()));
/// let value = ValueType::Map(map);
/// 
/// let name = vmap_extract_string!(value, "name", "default");
/// assert_eq!(name, "John");
/// ```
#[macro_export]
macro_rules! vmap_extract_string {
    ($value:expr, $key:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Map(map)) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::String(value)) => value.clone(),
                    _ => $default,
                }
            },
            kagi_node::services::ValueType::Map(map) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::String(value)) => value.clone(),
                    _ => $default,
                }
            },
            _ => $default,
        }
    }};
    
    ($value:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::String(value)) => value.clone(),
            kagi_node::services::ValueType::String(value) => value.clone(),
            _ => $default,
        }
    }};
}

/// Extract an i32 value from a ValueType::Map
#[macro_export]
macro_rules! vmap_extract_i32 {
    ($value:expr, $key:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Map(map)) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Integer(value)) => *value as i32,
                    _ => $default,
                }
            },
            kagi_node::services::ValueType::Map(map) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Integer(value)) => *value as i32,
                    _ => $default,
                }
            },
            _ => $default,
        }
    }};
    
    ($value:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Integer(value)) => *value as i32,
            kagi_node::services::ValueType::Integer(value) => *value as i32,
            _ => $default,
        }
    }};
}

/// Extract an f64 value from a ValueType::Map
#[macro_export]
macro_rules! vmap_extract_f64 {
    ($value:expr, $key:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Map(map)) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Float(value)) => *value,
                    _ => $default,
                }
            },
            kagi_node::services::ValueType::Map(map) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Float(value)) => *value,
                    _ => $default,
                }
            },
            _ => $default,
        }
    }};
    
    ($value:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Float(value)) => *value,
            kagi_node::services::ValueType::Float(value) => *value,
            _ => $default,
        }
    }};
}

/// Extract a boolean value from a ValueType::Map
#[macro_export]
macro_rules! vmap_extract_bool {
    ($value:expr, $key:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Map(map)) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Boolean(value)) => *value,
                    _ => $default,
                }
            },
            kagi_node::services::ValueType::Map(map) => {
                match map.get($key) {
                    Some(kagi_node::services::ValueType::Boolean(value)) => *value,
                    _ => $default,
                }
            },
            _ => $default,
        }
    }};
    
    ($value:expr, $default:expr) => {{
        match &$value {
            Some(kagi_node::services::ValueType::Boolean(value)) => *value,
            kagi_node::services::ValueType::Boolean(value) => *value,
            _ => $default,
        }
    }};
} 