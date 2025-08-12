// Registry Service Implementation
//
// INTENTION: Provide a consistent API for accessing service metadata through the
// standard request interface, eliminating the need for direct methods and aligning
// with the architectural principle of using the service request pattern for all operations.
//
// This service provides access to service metadata like states, actions, events, etc.
// through standard request paths like:
// - $registry/services/list
// - $registry/services/{service_path}
// - $registry/services/{service_path}/state

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use crate::services::{KeysDelegate, LifecycleContext, RequestContext};
use crate::AbstractService;
use runar_common::logging::Logger;
use runar_macros_common::{log_debug, log_info};
use runar_serializer::ArcValue;

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

    /// Register the ensure_symmetric_key action
    async fn register_ensure_symmetric_key_action(&self, context: &LifecycleContext) -> Result<()> {
        let self_clone = self.clone();

        context
            .register_action(
                "ensure_symmetric_key",
                Arc::new(move |params, ctx| {
                    let inner_self = self_clone.clone();
                    let key_name: String = params
                        .expect("key_name parameter is required")
                        .as_type_ref::<String>()
                        .expect("key_name parameter must be a string")
                        .as_ref()
                        .clone();
                    Box::pin(
                        async move { inner_self.handle_ensure_symmetric_key(key_name, ctx).await },
                    )
                }),
            )
            .await?;
        log_debug!(context.logger, "Registered ensure_symmetric_key action");
        Ok(())
    }

    /// Handler for ensuring symmetric key exists
    async fn handle_ensure_symmetric_key(
        &self,
        key_name: String,
        ctx: RequestContext,
    ) -> Result<ArcValue> {
        log_debug!(ctx.logger, "ensure_symmetric_key");
        self.keys_delegate.ensure_symmetric_key(&key_name).await
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
        log_info!(context.logger, "Initializing keys Service");

        // Register all actions with their template patterns
        log_debug!(context.logger, "Registering keys Service action handlers");

        // Register symmetric key action
        self.register_ensure_symmetric_key_action(&context).await?;
        log_debug!(context.logger, "Registered handler for ensure_symmetric_key action");

        log_info!(context.logger, "Keys Service initialization complete");

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        log_info!(context.logger, "Starting keys Service");
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        log_info!(context.logger, "Stopping keys Service");
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
