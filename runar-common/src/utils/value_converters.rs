// runar_common/src/utils/value_converters.rs
//
// Utility functions for working with ArcValue

use crate::types::ArcValue;

/// Create a null/empty ArcValue
pub fn null_value() -> ArcValue {
    ArcValue::null()
}

/// Create an ArcValue from a string
pub fn string_value(s: impl Into<String>) -> ArcValue {
    ArcValue::new_primitive(s.into())
}

/// Create an ArcValue from a number
pub fn number_value(n: f64) -> ArcValue {
    ArcValue::new_primitive(n)
}

/// Create an ArcValue from a boolean
pub fn bool_value(b: bool) -> ArcValue {
    ArcValue::new_primitive(b)
}
