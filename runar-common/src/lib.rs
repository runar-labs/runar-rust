// runar_common/src/lib.rs
//
// Common traits and utilities for the Runar P2P stack

// Export modules
pub mod errors;
pub mod logging;
pub mod macros;
pub mod service_info;
pub mod types;
pub mod utils;

// Re-export traits and types at the root level
pub use logging::{Component, Logger, LoggingContext};
pub use service_info::ServiceInfo;

// Note: The logging macros have been removed in favor of direct logger usage.
// See runar-common/src/logging/macros.rs for details on the recommended approach.

// Re-export the macros so they can be used with `use runar_common::vmap;` syntax
// These macros are already automatically available at the crate root namespace with #[macro_export]
// This is just to make imports cleaner and more intuitive
