// Re-export frequently-used items.
pub use runar_common::types::arc_value::{
    ArcValue,      // The core value container
    ValueCategory, // Enum describing the stored payload kind
};

// Re-export ancillary helper types so callers don't have to reach into
// runar_common directly.
pub use runar_common::types::arc_value::DeserializerFnWrapper;
