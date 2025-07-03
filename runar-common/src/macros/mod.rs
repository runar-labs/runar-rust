// runar_common/src/macros/mod.rs
//
// Common macros that don't require procedural macro functionality

// This module will contain macros that are used commonly but don't require
// the complexity of procedural macros. These include simple utility macros,
// helper macros, and formatting macros.

// Note: Most complex macros should go in the runar-macros crate instead.

// Import additional macro modules
mod vmap_macros;

// Re-export macros from other modules
// These macros are already #[macro_export] marked, which means they
// are automatically available at the crate root namespace
// We don't need to re-export them specifically

/// Create an ArcValue::Map with key-value pairs
///
/// This macro allows you to create an ArcValue::Map with key-value pairs.
/// The keys are converted to strings, and the values are converted to ArcValue.
///
/// ## Map Creation Usage:
///
/// ```
/// use runar_common::vmap;
/// use runar_common::types::ArcValue;
/// // Create a new ArcValue::Map:
/// let params = vmap!("name" => "John", "age" => 30, "active" => true);
/// ```
///
/// ## Empty Map:
///
/// ```
/// use runar_common::vmap;
/// use runar_common::types::ArcValue;
/// // Create an empty map
/// let empty = vmap!{};
/// ```
// vmap! is defined in vmap_macros.rs
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
        $crate::types::ValueType::from(serde_json::json!($($json)+))
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
/// use runar_common::{params, types::ArcValue};
/// let args = params! { "a" => 1.0, "b" => 2.0 };
/// // `args` is an `ArcValue::Map` containing the provided key/value pairs.
/// assert_eq!(args.category, ArcValue::Map.category());
/// ```
#[macro_export]
macro_rules! params {
    // Empty param map
    {} => {
        {
            use $crate::types::ArcValue;
            ArcValue::new_map($crate::hmap! {})
        }
    };

    // Non-empty param map
    { $($key:expr => $value:expr),* $(,)? } => {
        {
            use $crate::types::ArcValue;
            ArcValue::new_map($crate::hmap! {
                $( $key => ArcValue::new_primitive($value) ),*
            })
        }
    };
}
