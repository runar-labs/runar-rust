//! iOS/macOS FFI bindings for Runar distributed system
//!
//! This crate provides C-compatible bindings for the Runar node and services,
//! enabling native iOS and macOS applications to integrate with the Runar
//! distributed system.

pub mod callbacks;
pub mod error;
pub mod memory;
pub mod node;
pub mod runtime;
pub mod services;
pub mod types;

pub mod keychain;
pub mod lifecycle;

// Re-export main types for convenience
pub use callbacks::*;
pub use error::*;
pub use memory::*;
pub use node::*;
pub use runtime::*;
pub use services::*;
pub use types::*;

// FFI exports
pub use error::ffi::*;
pub use lifecycle::ffi::*;
pub use memory::ffi::*;
pub use node::ffi::*;
pub use services::ffi::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = CError::new(RunarErrorCode::Success, "Test message".to_string(), None);
        assert_eq!(error.code, RunarErrorCode::Success as i32);
    }

    #[test]
    fn test_memory_manager() {
        let manager = get_memory_manager();
        let stats = manager.get_stats();
        assert_eq!(stats.allocated_strings, 0);
        assert_eq!(stats.allocated_data_blocks, 0);
    }

    #[test]
    fn test_runtime_manager() {
        let manager = get_runtime_manager();
        assert!(!manager.is_running());
        assert!(manager.is_foreground());
    }

    #[test]
    fn test_node_config() {
        let config = NodeConfig::new("test-node".to_string(), "test-network".to_string());
        assert_eq!(config.node_id, "test-node");
        assert_eq!(config.default_network_id, "test-network");
    }
}
