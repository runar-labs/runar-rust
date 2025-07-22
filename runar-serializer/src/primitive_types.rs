// Type aliases for primitive serialization
// These are now simple aliases since we use serde_cbor directly

/// Type alias for String values (no longer needs wrapper)
pub type StringValue = String;

/// Type alias for i64 values (no longer needs wrapper)
pub type Int64Value = i64;

/// Type alias for u64 values (no longer needs wrapper)
pub type Uint64Value = u64;

/// Type alias for i32 values (no longer needs wrapper)
pub type Int32Value = i32;

/// Type alias for u32 values (no longer needs wrapper)
pub type Uint32Value = u32;

/// Type alias for f64 values (no longer needs wrapper)
pub type DoubleValue = f64;

/// Type alias for f32 values (no longer needs wrapper)
pub type FloatValue = f32;

/// Type alias for bool values (no longer needs wrapper)
pub type BoolValue = bool;

/// Type alias for char values (no longer needs wrapper)
pub type CharValue = char;
