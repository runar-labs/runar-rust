// registry.rs - Refactored to eliminate duplication
// This file now re-exports ServiceRegistry from services/service_registry.rs

// Re-export the ServiceRegistry
pub use crate::services::service_registry::ServiceRegistry;
pub use crate::services::service_registry::*;
