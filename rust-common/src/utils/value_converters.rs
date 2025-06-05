// runar_common/src/utils/value_converters.rs
//
// Utility functions for working with ArcValueType

use crate::types::ArcValueType;

/// Create a null/empty ArcValueType
pub fn null_value() -> ArcValueType {
    ArcValueType::null()
}

/// Create an ArcValueType from a string
pub fn string_value(s: impl Into<String>) -> ArcValueType {
    ArcValueType::new_primitive(s.into())
}

/// Create an ArcValueType from a number
pub fn number_value(n: f64) -> ArcValueType {
    ArcValueType::new_primitive(n)
}

/// Create an ArcValueType from a boolean
pub fn bool_value(b: bool) -> ArcValueType {
    ArcValueType::new_primitive(b)
}
