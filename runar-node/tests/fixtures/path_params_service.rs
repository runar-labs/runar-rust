// Path Parameters Service test fixture
//
// This is a simple service implementation used for testing path parameter extraction.
// It implements template paths to demonstrate proper parameter extraction.

use anyhow::Result;
use async_trait::async_trait;
use runar_common::types::ArcValue;
use std::collections::HashMap;
use std::sync::Arc;

use runar_node::services::abstract_service::AbstractService;
use runar_node::services::{LifecycleContext, RequestContext};

/// A simple service for testing path parameters extraction
///
/// This service is used to verify the extraction of parameters from template paths
/// and their availability in the request context.
pub struct PathParamsService {
    /// Name of the service
    name: String,
    /// Version of the service
    version: String,
    /// Path of the service
    path: String,
    /// Description of the service
    description: String,
    /// Network ID of the service
    network_id: Option<String>,
}

impl Clone for PathParamsService {
    fn clone(&self) -> Self {
        PathParamsService {
            name: self.name.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            description: self.description.clone(),
            network_id: self.network_id.clone(),
        }
    }
}

impl PathParamsService {
    /// Create a new PathParamsService with the specified name and path
    pub fn new(name: &str, path: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            path: path.to_string(),
            description: "Path parameters test service".to_string(),
            network_id: None, // will be set by the node
        }
    }

    /// Handle the extract action - returns all path parameters
    async fn handle_extract(
        &self,
        _params: Option<ArcValue>,
        context: RequestContext,
    ) -> Result<ArcValue> {
        // Log that we're handling the request
        context.info("Handling extract path parameters request".to_string());

        // Convert the path parameters to ValueType::String values for the response
        let param_values: HashMap<String, String> = context.path_params.clone();

        // Log the parameters we extracted
        context.info(format!("Extracted parameters: {:?}", param_values));

        // Return the parameters
        Ok(ArcValue::from_map(param_values))
    }
}

#[async_trait]
impl AbstractService for PathParamsService {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn network_id(&self) -> Option<String> {
        self.network_id.clone()
    }

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        // Log the service information being initialized
        context.info(format!(
            "Initializing PathParamsService with name: {}, path: {}",
            self.name, self.path
        ));

        // Create an owned copy to move into the closures
        let owned_self = self.clone();

        // Register the extract action with a template path
        context.info("Registering 'extract' action with template path".to_string());
        context
            .register_action(
                "{param_1}/items/{param_2}",
                Arc::new(move |params, request_ctx| {
                    let self_clone = owned_self.clone();
                    Box::pin(async move { self_clone.handle_extract(params, request_ctx).await })
                }),
            )
            .await?;

        // Log successful initialization
        context.info("PathParamsService initialized".to_string());

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        context.info("PathParamsService started".to_string());
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.info("PathParamsService stopped".to_string());
        Ok(())
    }
}
