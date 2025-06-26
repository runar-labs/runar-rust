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

/// Represents a service's current state
///
/// INTENTION: Track the lifecycle stage of a service
/// for proper initialization and operational management.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Service is created but not initialized
    Created,
    /// Service has been initialized
    Initialized,
    /// Service is running
    Running,
    /// Service has been stopped
    Stopped,
    /// Service has been paused
    Paused,
    /// Service has encountered an error
    Error,
    /// Service state is unknown
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

/// Abstract service interface
///
/// INTENTION: Define a common interface for all services, enabling
/// uniform management of service lifecycle and request handling.
///
/// ARCHITECTURAL PRINCIPLE:
/// Services follow a consistent lifecycle pattern with well-defined
/// initialization, startup, and shutdown phases. This ensures proper
/// resource management and predictable state transitions.
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
