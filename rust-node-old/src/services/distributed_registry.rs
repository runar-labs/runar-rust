//! Registry module for distributed slices
//! 
//! This module defines the registry types and distributed slices used by the macros
//! like `action`, `process`, and `subscribe`. These are used to register handlers
//! with the node system at compile time.

use crate::services::{RequestContext, ServiceResponse, ValueType};
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

// Re-export from linkme
#[cfg(feature = "distributed_slice")]
pub use linkme::distributed_slice;

/// Type alias for an asynchronous handler function
pub type AsyncHandler<T, R> = 
    fn(T) -> Pin<Box<dyn Future<Output = R> + Send + 'static>>;

/// Type alias for an action handler function
pub type ActionHandlerFn = 
    for<'a> fn(&'a RequestContext, ValueType) -> Pin<Box<dyn Future<Output = Result<ServiceResponse>> + Send + 'a>>;

/// Type alias for a process handler function
pub type ProcessHandlerFn = 
    for<'a> fn(&'a RequestContext, &'a str, &'a ValueType) -> Pin<Box<dyn Future<Output = Result<ServiceResponse>> + Send + 'a>>;

/// Type alias for a subscription handler function
pub type SubscriptionHandlerFn = 
    fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

/// Registry for action handlers
#[cfg(feature = "distributed_slice")]
#[linkme::distributed_slice]
pub static ACTION_REGISTRY: [fn() -> ActionHandler] = [..];

/// Registry for process handlers
#[cfg(feature = "distributed_slice")]
#[linkme::distributed_slice]
pub static PROCESS_REGISTRY: [fn() -> ProcessHandler] = [..];

/// Registry for subscription handlers
#[cfg(feature = "distributed_slice")]
#[linkme::distributed_slice]
pub static SUBSCRIPTION_REGISTRY: [fn() -> EventSubscription] = [..];

/// Registry for publication handlers
#[cfg(feature = "distributed_slice")]
#[linkme::distributed_slice]
pub static PUBLICATION_REGISTRY: [fn() -> PublicationInfo] = [..];

/// Dummy implementation for when distributed_slice feature is not enabled
#[cfg(not(feature = "distributed_slice"))]
#[allow(non_upper_case_globals)]
pub static ACTION_REGISTRY: [fn() -> ActionHandler; 0] = [];

/// Dummy implementation for when distributed_slice feature is not enabled
#[cfg(not(feature = "distributed_slice"))]
#[allow(non_upper_case_globals)]
pub static PROCESS_REGISTRY: [fn() -> ProcessHandler; 0] = [];

/// Dummy implementation for when distributed_slice feature is not enabled
#[cfg(not(feature = "distributed_slice"))]
#[allow(non_upper_case_globals)]
pub static SUBSCRIPTION_REGISTRY: [fn() -> EventSubscription; 0] = [];

/// Dummy implementation for when distributed_slice feature is not enabled
#[cfg(not(feature = "distributed_slice"))]
#[allow(non_upper_case_globals)]
pub static PUBLICATION_REGISTRY: [fn() -> PublicationInfo; 0] = [];

/// Handler for service actions
#[derive(Clone, Debug)]
pub struct ActionHandler {
    /// Name of the action
    pub name: String,
    /// Name of the service this action belongs to
    pub service: String,
    /// Timeout for this action in milliseconds
    pub timeout: Duration,
    /// Handler function
    pub handler: ActionHandlerFn,
}

/// Handler for service processes
#[derive(Clone, Debug)]
pub struct ProcessHandler {
    /// Name of the service this process belongs to
    pub service: String,
    /// Handler function
    pub handler: ProcessHandlerFn,
}

/// Information about event subscriptions
#[derive(Clone, Debug)]
pub struct EventSubscription {
    /// Topic to subscribe to
    pub topic: String,
    /// Name of the service this subscription belongs to
    pub service: String,
    /// Handler function
    pub handler: SubscriptionHandlerFn,
}

/// Information about event publications
#[derive(Clone, Debug)]
pub struct PublicationInfo {
    /// Topic to publish to
    pub topic: String,
    /// Name of the service this publication belongs to
    pub service: String,
    /// Description of the publication
    pub description: String,
} 