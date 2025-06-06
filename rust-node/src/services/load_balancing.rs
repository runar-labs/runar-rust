// Load Balancing Strategy Implementation
//
// This module provides load balancing strategies for distributing requests
// across multiple action handlers.

use crate::services::ActionHandler;
use crate::services::RequestContext;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Define the load balancing strategy trait
///
/// INTENTION: Provide a common interface for different load balancing
/// strategies that can be plugged into the Node for selecting remote handlers.
pub trait LoadBalancingStrategy: Send + Sync {
    /// Select a handler from the list of handlers
    ///
    /// This method is called when a remote request needs to be routed to one
    /// of multiple available handlers. The implementation should choose a handler
    /// based on its strategy (round-robin, random, weighted, etc.)
    fn select_handler(&self, handlers: &[ActionHandler], context: &RequestContext) -> usize;
}

/// Simple round-robin load balancer
///
/// INTENTION: Provide a basic load balancing strategy that distributes
/// requests evenly across all available handlers in a sequential fashion.
#[derive(Debug)]
pub struct RoundRobinLoadBalancer {
    /// The current index for round-robin selection
    current_index: Arc<AtomicUsize>,
}

impl Default for RoundRobinLoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinLoadBalancer {
    /// Create a new round-robin load balancer
    pub fn new() -> Self {
        RoundRobinLoadBalancer {
            current_index: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl LoadBalancingStrategy for RoundRobinLoadBalancer {
    fn select_handler(&self, handlers: &[ActionHandler], _context: &RequestContext) -> usize {
        if handlers.is_empty() {
            return 0;
        }

        // Get the next index in a thread-safe way
        self.current_index.fetch_add(1, Ordering::SeqCst) % handlers.len()
    }
}
