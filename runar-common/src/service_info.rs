// WARNING: THIS FILE IS DEPRECATED AND SHOULD BE DELETED
// The ServiceInfo trait functionality has been merged into AbstractService trait
// to reduce duplication and simplify the codebase.
// All service implementations should now directly implement AbstractService
// with the required metadata methods (name, path, description, version) instead.
// This file is kept temporarily for backward compatibility but will be removed.

/// The ServiceInfo trait defines the interface for accessing
/// basic information about a service.
pub trait ServiceInfo {
    /// Returns the service name
    fn service_name(&self) -> &str;

    /// Returns the service path
    fn service_path(&self) -> &str;

    /// Returns the service description
    fn service_description(&self) -> &str;

    /// Returns the service version
    fn service_version(&self) -> &str;
}

/// Utility module to help implement ServiceInfo for AbstractService implementors
#[cfg(feature = "abstract_service")]
pub mod utils {
    use super::ServiceInfo;

    /// Helper trait to get metadata from a type
    pub trait MetadataProvider {
        /// Get the service name
        fn name(&self) -> &str;

        /// Get the service path
        fn path(&self) -> &str;

        /// Get a description of the service
        fn description(&self) -> &str;

        /// Get the service version
        fn version(&self) -> &str;
    }

    /// Implement ServiceInfo for any type that provides metadata
    impl<T: MetadataProvider> ServiceInfo for T {
        fn service_name(&self) -> &str {
            self.name()
        }

        fn service_path(&self) -> &str {
            self.path()
        }

        fn service_description(&self) -> &str {
            self.description()
        }

        fn service_version(&self) -> &str {
            self.version()
        }
    }
}
