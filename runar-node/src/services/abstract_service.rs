// Abstract Service Definition Module
//!
//! This module defines the core AbstractService trait that all services must implement,
//! along with its associated types and enumerations. It establishes the foundation
//! for service implementation, lifecycle management, and communication patterns.
//!
//! # Architectural Principles
//! 1. Interface-First Design - All services must implement a consistent interface
//! 2. Lifecycle Management - Services follow a predictable lifecycle (init, start, stop)
//! 3. Consistent Communication - All services use the same request/response patterns
//! 4. Self-Describing Services - Services provide metadata about their capabilities
//! 5. Asynchronous Operations - All service methods are async for performance

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::services::LifecycleContext;
use runar_serializer_macros::Plain;

/// Represents the current lifecycle state of a service.
///
/// This enum tracks the lifecycle stage of a service to ensure proper
/// initialization and operational management. The state transitions
/// follow a predictable pattern: Created → Initialized → Running → Stopped.
///
/// # State Transitions
///
/// The service lifecycle follows this pattern:
/// - Created -> Initialized -> Running -> Stopped
/// - Error states can occur at any stage
///
/// # Examples
///
/// ```rust
/// use runar_node::services::abstract_service::ServiceState;
///
/// // Check if a service is ready to handle requests
/// let service_state = ServiceState::Running;
/// if service_state == ServiceState::Running {
///     // Service is operational
/// }
///
/// // Check if a service needs to be started
/// let service_state = ServiceState::Initialized;
/// if service_state == ServiceState::Initialized {
///     // Service is ready to start
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Plain)]
pub enum ServiceState {
    /// Service is created but not initialized.
    ///
    /// This is the initial state after service creation. The service
    /// exists but hasn't been set up for operation yet.
    Created,

    /// Service has been initialized and is ready to start.
    ///
    /// The service has completed its setup phase and registered
    /// its action handlers. It's ready to begin active operations.
    Initialized,

    /// Service is running and actively handling requests.
    ///
    /// This is the normal operational state. The service is fully
    /// functional and can handle requests, publish events, and
    /// perform its intended operations.
    Running,

    /// Service has been stopped and is no longer operational.
    ///
    /// The service has been gracefully shut down and has released
    /// all its resources. It cannot handle requests in this state.
    Stopped,

    /// Service has been paused and is temporarily inactive.
    ///
    /// The service is in a suspended state where it maintains
    /// its resources but doesn't handle requests. It can be resumed.
    Paused,

    /// Service has encountered an error and cannot operate.
    ///
    /// The service has failed during initialization, startup, or
    /// operation. It requires intervention to recover or restart.
    Error,

    /// Service state is unknown or indeterminate.
    ///
    /// This state indicates that the service's current status
    /// cannot be determined. It may indicate a system issue.
    Unknown,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceState::Created => write!(f, "Created"),
            ServiceState::Initialized => write!(f, "Initialized"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::Paused => write!(f, "Paused"),
            ServiceState::Error => write!(f, "Error"),
            ServiceState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Abstract service interface that all services must implement.
///
/// This trait defines a common interface for all services, enabling uniform
/// management of service lifecycle and request handling. It establishes the
/// foundation for the service architecture and ensures consistent behavior
/// across all service implementations.
///
/// # Architectural Principles
///
/// - **Consistent Lifecycle**: All services follow the same init/start/stop pattern
/// - **Resource Management**: Proper resource allocation and cleanup
/// - **Predictable State**: Well-defined state transitions
/// - **Async Operations**: All lifecycle methods are asynchronous
/// - **Self-Describing**: Services provide metadata about their capabilities
///
/// # Lifecycle Methods
///
/// 1. **`init`**: Set up the service for operation
/// 2. **`start`**: Begin active operations
/// 3. **`stop`**: Gracefully shut down the service
///
/// # Examples
///
/// ```rust
/// use runar_node::services::{abstract_service::AbstractService, LifecycleContext};
/// use anyhow::Result;
/// use async_trait::async_trait;
///
/// #[derive(Clone)]
/// pub struct MyService {
///     name: String,
///     path: String,
/// }
///
/// #[async_trait]
/// impl AbstractService for MyService {
///     fn name(&self) -> &str { &self.name }
///     fn version(&self) -> &str { "1.0.0" }
///     fn path(&self) -> &str { &self.path }
///     fn description(&self) -> &str { "My example service" }
///     fn network_id(&self) -> Option<String> { None }
///     fn set_network_id(&mut self, network_id: String) { /* implementation */ }
///
///     async fn init(&self, context: LifecycleContext) -> Result<()> {
///         // Register action handlers, set up connections, etc.
///         Ok(())
///     }
///
///     async fn start(&self, context: LifecycleContext) -> Result<()> {
///         // Start background tasks, timers, etc.
///         Ok(())
///     }
///
///     async fn stop(&self, context: LifecycleContext) -> Result<()> {
///         // Clean up resources, cancel tasks, etc.
///         Ok(())
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// All services must be `Send + Sync` to ensure they can be safely shared
/// across multiple threads and async tasks.
#[async_trait::async_trait]
pub trait AbstractService: Send + Sync {
    /// Get service name
    fn name(&self) -> &str;

    /// Get service version
    fn version(&self) -> &str;

    /// Get service path
    fn path(&self) -> &str;

    /// Get service description
    fn description(&self) -> &str;

    /// Get service description
    fn network_id(&self) -> Option<String>;

    /// Set service network id
    fn set_network_id(&mut self, network_id: String);

    /// Initialize the service
    ///
    /// INTENTION: Set up the service for operation, register handlers,
    /// establish connections to dependencies, and prepare internal state.
    ///
    /// This is where services should register their action handlers using
    /// the context's registration methods. The service should not perform
    /// any active operations during initialization.
    ///
    /// Initialization errors should be propagated to enable reporting and
    /// proper error handling.
    async fn init(&self, context: LifecycleContext) -> Result<()>;

    /// Start the service
    ///
    /// INTENTION: Begin active operations after initialization is complete.
    /// This is where the service should start any background tasks, timers,
    /// or active processing activities.
    ///
    /// The service should be fully initialized before this method is called.
    async fn start(&self, context: LifecycleContext) -> Result<()>;

    /// Stop the service
    ///
    /// INTENTION: Gracefully terminate all active operations, cancel background
    /// tasks, and release resources. This method should ensure that the service
    /// can be cleanly shut down without data loss or corruption.
    async fn stop(&self, context: LifecycleContext) -> Result<()>;
}
