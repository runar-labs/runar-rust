// Protocol Buffer message types for primitive serialization
// These ensure cross-platform and cross-language compatibility

use prost::Message;

/// Protocol Buffer wrapper for String values
#[derive(Clone, PartialEq, Message)]
pub struct StringValue {
    #[prost(string, tag = "1")]
    pub value: String,
}

/// Protocol Buffer wrapper for i64 values
#[derive(Clone, PartialEq, Message)]
pub struct Int64Value {
    #[prost(int64, tag = "1")]
    pub value: i64,
}

/// Protocol Buffer wrapper for u64 values
#[derive(Clone, PartialEq, Message)]
pub struct Uint64Value {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}

/// Protocol Buffer wrapper for i32 values
#[derive(Clone, PartialEq, Message)]
pub struct Int32Value {
    #[prost(int32, tag = "1")]
    pub value: i32,
}

/// Protocol Buffer wrapper for u32 values
#[derive(Clone, PartialEq, Message)]
pub struct Uint32Value {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}

/// Protocol Buffer wrapper for f64 values
#[derive(Clone, PartialEq, Message)]
pub struct DoubleValue {
    #[prost(double, tag = "1")]
    pub value: f64,
}

/// Protocol Buffer wrapper for f32 values
#[derive(Clone, PartialEq, Message)]
pub struct FloatValue {
    #[prost(float, tag = "1")]
    pub value: f32,
}

/// Protocol Buffer wrapper for bool values
#[derive(Clone, PartialEq, Message)]
pub struct BoolValue {
    #[prost(bool, tag = "1")]
    pub value: bool,
}

/// Protocol Buffer wrapper for char values
#[derive(Clone, PartialEq, Message)]
pub struct CharValue {
    #[prost(uint32, tag = "1")] // Store char as UTF-32 code point
    pub value: u32,
}
