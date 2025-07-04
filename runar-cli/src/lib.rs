//! Runar CLI Library
//!
//! This library provides the core functionality for the Runar CLI, including
//! node initialization, configuration management, and node startup.

pub mod config;
pub mod init;
pub mod key_store;
pub mod setup_server;
pub mod start;

// Re-export main types for convenience
pub use config::NodeConfig;
pub use init::InitCommand;
pub use key_store::OsKeyStore;
pub use start::StartCommand;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
