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

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;

use crate::routing::TopicPath;
use crate::services::abstract_service::ServiceState;
use crate::services::{LifecycleContext, RegistryDelegate, RequestContext};
use crate::AbstractService;
use runar_common::logging::Logger;
use runar_serializer::ArcValue;

/// Registry Info Service - provides information about registered services without holding state
pub struct RegistryService {
    /// Logger instance
    logger: Arc<Logger>,

    /// Registry delegate for accessing node registry information
    registry_delegate: Arc<dyn RegistryDelegate>,
}

impl RegistryService {
    /// Create a new Registry Service
    pub fn new(logger: Arc<Logger>, delegate: Arc<dyn RegistryDelegate>) -> Self {
        RegistryService {
            logger,
            registry_delegate: delegate,
        }
    }

    /// Extract the service path parameter from the request context
    ///
    /// INTENTION: Extract the target service path (the service we want info about)
    /// from the path parameters extracted from the URL template.
    ///
    /// This is NOT about getting the context's handler service path.
    /// It's about extracting the service name from the URL pattern like:
    /// "$registry/services/math" where "math" is the service we want information about.
    /// it uses the context path_params which contains the extracted parameters from the template
    fn extract_service_path(&self, ctx: &RequestContext) -> Result<String> {
        // Look for the path parameter that was extracted during template matching
        if let Some(path) = ctx.path_params.get("service_path") {
            ctx.logger
                .debug(format!("Using service_path '{path}' from path parameters"));
            return Ok(path.clone());
        }

        // If we get here, we couldn't find the target service path
        ctx.logger
            .error("Missing required 'service_path' parameter");
        Err(anyhow!("Missing required 'service_path' parameter"))
    }

    /// Register the list services action
    async fn register_list_services_action(&self, context: &LifecycleContext) -> Result<()> {
        let self_clone = self.clone();
        // Add debug to see what is registered
        context
            .logger
            .debug("Registering list_services handler with path: services/list");
        context
            .register_action(
                "services/list",
                Arc::new(move |params, ctx| {
                    let inner_self = self_clone.clone();
                    Box::pin(async move {
                        inner_self
                            .handle_list_services(params.unwrap_or_else(ArcValue::null), ctx)
                            .await
                    })
                }),
            )
            .await?;
        context.logger.debug("Registered services/list action");
        Ok(())
    }

    /// Register the service info action
    async fn register_service_info_action(&self, context: &LifecycleContext) -> Result<()> {
        let self_clone = self.clone();

        // Add debug to see what is registered
        context
            .logger
            .debug("Registering service_info handler with path: services/{service_path}");

        context
            .register_action(
                "services/{service_path}",
                Arc::new(move |params, ctx| {
                    let inner_self = self_clone.clone();
                    Box::pin(async move {
                        inner_self
                            .handle_service_info(params.unwrap_or_else(ArcValue::null), ctx)
                            .await
                    })
                }),
            )
            .await?;

        context
            .logger
            .debug("Registered services/{service_path} action");
        Ok(())
    }

    /// Register the service state action
    async fn register_service_state_action(&self, context: &LifecycleContext) -> Result<()> {
        let self_clone = self.clone();

        // Add debug to see what is registered
        context
            .logger
            .debug("Registering service_state handler with path: services/{service_path}/state");

        context
            .register_action(
                "services/{service_path}/state",
                Arc::new(move |_params, ctx| {
                    let inner_self = self_clone.clone();
                    Box::pin(async move { inner_self.handle_service_state(ctx).await })
                }),
            )
            .await?;

        context
            .logger
            .debug("Registered services/{service_path}/state action");
        Ok(())
    }

    /// Handler for listing all services
    async fn handle_list_services(
        &self,
        _params: ArcValue,
        ctx: RequestContext,
    ) -> Result<ArcValue> {
        ctx.logger.debug("Listing all services");

        // Get all service metadata directly
        let service_metadata = self.registry_delegate.get_all_service_metadata(true).await;

        // Convert the HashMap of ServiceMetadata to a Vec
        let metadata_vec: Vec<_> = service_metadata.values().cloned().collect();

        // Return the list of service metadata
        Ok(ArcValue::from_list(metadata_vec))
    }

    /// Handler for getting detailed information about a specific service
    async fn handle_service_info(
        &self,
        _params: ArcValue,
        ctx: RequestContext,
    ) -> Result<ArcValue> {
        // Extract the service path from path parameters
        let actual_service_path = match self.extract_service_path(&ctx) {
            Ok(path) => path,
            Err(error) => return Err(error),
        };

        // Get the service metadata for the specific service path
        let network_id_string = ctx.network_id().clone();
        let service_topic = match TopicPath::new(&actual_service_path, &network_id_string) {
            Ok(topic) => topic,
            Err(e) => {
                return Err(anyhow!("Invalid service path format: {}", e));
            }
        };

        // Return the service metadata if found, or None if not found
        if let Some(service_metadata) = self
            .registry_delegate
            .get_service_metadata(&service_topic)
            .await
        {
            Ok(ArcValue::from_struct(service_metadata))
        } else {
            ctx.logger
                .debug(format!("Service '{actual_service_path}' not found"));
            Ok(ArcValue::null())
        }
    }

    /// Handler for getting just the state of a service
    async fn handle_service_state(&self, ctx: RequestContext) -> Result<ArcValue> {
        // Extract the service path from path parameters
        let service_path = match self.extract_service_path(&ctx) {
            Ok(path) => path,
            Err(error) => {
                return Err(anyhow!(
                    "Missing required 'service_path' parameter: {}",
                    error
                ));
            }
        };
        let network_id_string = ctx.network_id().clone();
        let service_topic = TopicPath::new_service(&network_id_string, &service_path);

        // Get service state directly from the registry delegate
        if let Some(service_state) = self
            .registry_delegate
            .get_service_state(&service_topic)
            .await
        {
            let state_info = ArcValue::from_struct(service_state);
            Ok(state_info)
        } else {
            ctx.logger
                .debug(format!("Service '{service_path}' not found"));
            Ok(ArcValue::null())
        }
    }
}

#[async_trait]
impl AbstractService for RegistryService {
    fn name(&self) -> &str {
        "registry"
    }

    fn path(&self) -> &str {
        "$registry"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Registry service for service discovery and metadata"
    }

    // internal services is not bound to any specificy network
    fn network_id(&self) -> Option<String> {
        None
    }
    fn set_network_id(&mut self, _network_id: String) {}

    /// Initialize the Registry Service by registering all handlers
    ///
    /// INTENTION: Set up all the action handlers for the registry service,
    /// following the path template pattern for consistent parameter extraction.
    /// Each path template defines a specific API endpoint with parameters.
    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Initializing Registry Service");

        // Register all actions with their template patterns
        context
            .logger
            .debug("Registering Registry Service action handlers");

        // Services list does not require parameters
        self.register_list_services_action(&context).await?;
        context
            .logger
            .debug("Registered handler for listing all services");

        // Service info uses the {service_path} parameter
        self.register_service_info_action(&context).await?;
        context
            .logger
            .debug("Registered handler for service info with path parameter");

        // Service state also uses the {service_path} parameter
        self.register_service_state_action(&context).await?;
        context
            .logger
            .debug("Registered handler for service state with path parameter");

        context
            .logger
            .info("Registry Service initialization complete");

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Starting Registry Service");
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.logger.info("Stopping Registry Service");
        Ok(())
    }
}

// Implement Clone manually since we can't derive it due to async_trait
impl Clone for RegistryService {
    fn clone(&self) -> Self {
        Self {
            logger: self.logger.clone(),
            registry_delegate: self.registry_delegate.clone(),
        }
    }
}
