// runar_common/src/macros/mod.rs
//
// Common macros that don't require procedural macro functionality

// This module will contain macros that are used commonly but don't require
// the complexity of procedural macros. These include simple utility macros,
// helper macros, and formatting macros.

// Note: Most complex macros should go in the rust-macros crate instead.

/// Simple macro to create a HashMap with ValueType values
/// 
/// This is a simplified version of the vmap! macro that will be defined in rust-macros.
/// This version only supports the basic creation of a map, without the extraction functionality.
/// 
/// # Examples
/// 
/// ```
/// use runar_common::simple_vmap;
/// use runar_common::types::ValueType;
/// 
/// // Create a map with key-value pairs
/// let map = simple_vmap! {
///     "name" => "John Doe",
///     "age" => 30,
///     "is_admin" => true
/// };
/// 
/// // Create an empty map
/// let empty = simple_vmap! {};
/// ```
#[macro_export]
macro_rules! simple_vmap {
    // Empty map
    {} => {
        {
            let map: std::collections::HashMap<String, $crate::types::ValueType> = std::collections::HashMap::new();
            $crate::types::ValueType::Map(map)
        }
    };

    // Map with entries
    {
        $($key:expr => $value:expr),* $(,)?
    } => {
        {
            let mut map = std::collections::HashMap::new();
            $(
                map.insert($key.to_string(), $crate::types::ValueType::from($value));
            )*
            $crate::types::ValueType::Map(map)
        }
    };
}

/// Create a ValueType::Map with key-value pairs
///
/// This macro allows you to create a ValueType::Map with key-value pairs.
/// The keys are converted to strings, and the values are converted to ValueType.
///
/// ## Map Creation Usage:
///
/// ```rust
/// // Create a new ValueType::Map:
/// let params = vmap!{"name" => "John", "age" => 30, "active" => true};
/// ```
///
/// ## Empty Map:
///
/// ```rust
/// // Create an empty map
/// let empty = vmap!{};
/// ```
#[macro_export]
macro_rules! vmap {
    // Create a map with entries
    { $($key:expr => $value:expr),* $(,)? } => {{
        use $crate::types::ValueType;
        let mut map = std::collections::HashMap::new();
        $(
            map.insert($key.to_string(), ValueType::from($value));
        )*
        ValueType::Map(map)
    }};
    
    // Create an empty map
    { } => {{
        use $crate::types::ValueType;
        ValueType::Map(std::collections::HashMap::new())
    }};
}

// Define and export the vjson macro (JSON to ValueType)
#[macro_export]
macro_rules! vjson {
    ($($json:tt)+) => {
        $crate::types::ValueType::from(serde_json::json!($($json)+))
    };
} 