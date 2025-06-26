// Registry Service Implementation
//
// INTENTION: Provide a consistent API for accessing service metadata through the
// standard request interface, eliminating the need for direct methods and aligning
// with the architectural principle of using the service request pattern for all operations.
//
// This service provides access to service metadata like states, actions, events, etc.
// through standard request paths like:
// - internal/registry/services/list
// - internal/registry/services/{service_path}
// - internal/registry/services/{service_path}/state

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use crate::services::{KeysDelegate, LifecycleContext, RequestContext};
use crate::AbstractService;
use runar_common::logging::Logger;
use runar_common::types::ArcValue;

/// Registry Info Service - provides information about registered services without holding state
pub struct KeysService {
    /// Logger instance
    logger: Arc<Logger>,

    /// Registry delegate for accessing node registry information
    keys_delegate: Arc<dyn KeysDelegate>,
}

impl KeysService {
    /// Create a new Registry Service
    pub fn new(logger: Arc<Logger>, delegate: Arc<dyn KeysDelegate>) -> Self {
        KeysService {
            logger,
            keys_delegate: delegate,
        }
    }

    /// Register the ensure_symetric_key action
    async fn register_ensure_symetric_key_action(&self, context: &LifecycleContext) -> Result<()> {
        let self_clone = self.clone();

        context
            .register_action(
                "ensure_symetric_key",
                Arc::new(move |params, ctx| {
                    let inner_self = self_clone.clone();
                    let key_name: String = params
                        .expect("key_name parameter is required")
                        .as_type()
                        .expect("key_name parameter must be a string");
                    Box::pin(
                        async move { inner_self.handle_ensure_symetric_key(key_name, ctx).await },
                    )
                }),
            )
            .await?;
        context.logger.debug("Registered services/list action");
        Ok(())
    }

    /// Handler for listing all services
    async fn handle_ensure_symetric_key(
        &self,
        key_name: String,
        ctx: RequestContext,
    ) -> Result<ArcValue> {
        ctx.logger.debug("Listing all services");
        self.keys_delegate.ensure_symetric_key(&key_name).await
    }
}

#[async_trait]
impl AbstractService for KeysService {
    fn name(&self) -> &str {
        "runar keys"
    }

    fn path(&self) -> &str {
        "$keys"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Keys service for key management"
    }

    // internal services is not bound to any specificy network
    fn network_id(&self) -> Option<String> {
        None
    }
    fn set_network_id(&mut self, _network_id: String) {}

    /// Initialize the Keys Service by registering all handlers
    ///
    /// INTENTION: Set up all the action handlers for the keys service,
    /// following the path template pattern for consistent parameter extraction.
    /// Each path template defines a specific API endpoint with parameters.
    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Initializing keys Service");

        // Register all actions with their template patterns
        context
            .logger
            .debug("Registering keys Service action handlers");

        // Services list does not require parameters
        self.register_ensure_symetric_key_action(&context).await?;
        context
            .logger
            .debug("Registered handler for listing all services");

        context.logger.info("Keys Service initialization complete");

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Starting keys Service");
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Stopping keys Service");
        Ok(())
    }
}

// Implement Clone manually since we can't derive it due to async_trait
impl Clone for KeysService {
    fn clone(&self) -> Self {
        Self {
            logger: self.logger.clone(),
            keys_delegate: self.keys_delegate.clone(),
        }
    }
}
