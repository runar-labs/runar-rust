//! Enhanced serialization with selective field encryption for Runar
//!
//! This crate provides:
//! - Derive macros for selective field encryption
//! - Enhanced SerializerRegistry with encryption support
//! - Integration with runar-keys for envelope encryption
//! - Label-based key resolution system

pub mod encryption;
pub mod registry;
pub mod traits;

pub use encryption::*;
pub use registry::*;
pub use traits::*;

// Re-export macros
pub use runar_serializer_macros::*;

#[cfg(test)]
mod tests;
