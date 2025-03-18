pub mod node;
pub mod services;

/// Create a ValueType::Map with the given key-value pairs
/// 
/// # Example
/// 
/// ```
/// use kagi_node::vmap;
/// use kagi_node::services::ValueType;
/// 
/// let params = vmap! {
///     "name" => "John",
///     "age" => 30,
///     "is_active" => true,
///     "scores" => vec![95, 87, 91]
/// };
/// ```
#[macro_export]
macro_rules! vmap {
    // Empty map
    () => {
        $crate::services::ValueType::Map(std::collections::HashMap::new())
    };
    
    // Map with key-value pairs
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut map = std::collections::HashMap::new();
        $(
            map.insert($key.to_string(), $crate::vmap_value!($value));
        )*
        $crate::services::ValueType::Map(map)
    }};
}

/// Helper macro to convert Rust values to ValueType
#[macro_export]
macro_rules! vmap_value {
    // String values
    ($value:expr) => {{
        $crate::vmap_value_internal!($value)
    }};
}

/// Internal helper macro for vmap_value
#[macro_export]
macro_rules! vmap_value_internal {
    // String values
    ($value:expr) => {{
        let val = $value;
        $crate::vmap_convert_value!(val)
    }};
}

/// Convert values to ValueType based on type
#[macro_export]
macro_rules! vmap_convert_value {
    // Match based on type
    ($value:expr) => {{
        use $crate::services::ValueType;
        
        // Try to infer the right type based on the value
        match &$value {
            val if stringify!(type_of($value)) == "String" || stringify!(type_of($value)) == "&str" => {
                ValueType::String(val.to_string())
            },
            val if stringify!(type_of($value)) == "i32" || stringify!(type_of($value)) == "i64" => {
                ValueType::Integer(val as i64)
            },
            val if stringify!(type_of($value)) == "f32" || stringify!(type_of($value)) == "f64" => {
                ValueType::Float(val as f64)
            },
            val if stringify!(type_of($value)) == "bool" => {
                ValueType::Boolean(val)
            },
            val if stringify!(type_of($value)).starts_with("Vec<") => {
                // Try to convert the vector to an array
                let vec_values: Vec<ValueType> = val.iter()
                    .map(|v| $crate::vmap_convert_value!(v))
                    .collect();
                ValueType::Array(vec_values)
            },
            val if stringify!(type_of($value)).starts_with("HashMap<") => {
                // Try to convert the HashMap to a map
                let mut map = std::collections::HashMap::new();
                for (k, v) in val {
                    map.insert(k.to_string(), $crate::vmap_convert_value!(v));
                }
                ValueType::Map(map)
            },
            _ => {
                // Default to string representation
                ValueType::String(format!("{:?}", $value))
            }
        }
    }};
}

/// Optional version of vmap that returns None for empty maps
#[macro_export]
macro_rules! vmap_opt {
    // Empty map
    () => {
        None
    };
    
    // Map with key-value pairs
    ($($key:expr => $value:expr),* $(,)?) => {
        Some($crate::vmap!($($key => $value),*))
    };
} 