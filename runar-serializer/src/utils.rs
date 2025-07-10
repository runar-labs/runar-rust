// Utility functions for runar-serializer

use super::ArcValue;

/// Convert an error to a string value
pub fn error_to_string_value(error: impl std::fmt::Display) -> ArcValue {
    // Just use the error message as a string for simplicity
    let error_message = error.to_string();

    // Return as string value
    ArcValue::new_primitive(error_message)
}

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
