// Remote Service Implementation
//
// INTENTION: Implement a proxy service that represents a service running on a remote node.
// This service forwards requests to the remote node and returns responses, making
// remote services appear as local services to the node.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::network::transport::{MessageContext, NetworkTransport};
use crate::routing::TopicPath;
use crate::services::abstract_service::AbstractService;
use crate::services::{ActionHandler, LifecycleContext};
use runar_common::logging::Logger;
use runar_schemas::{ActionMetadata, ServiceMetadata};

// No direct key-store or label resolver – encryption handled by transport layer

/// Represents a service running on a remote node
#[derive(Clone)]
pub struct RemoteService {
    /// Service metadata
    pub name: String,
    pub service_topic: TopicPath,
    pub version: String,
    pub description: String,
    /// Network ID for this service
    pub network_id: String,

    /// Remote peer information
    peer_node_id: String,
    /// Shared network transport (immutable)
    network_transport: Arc<dyn NetworkTransport>,

    /// Service capabilities
    actions: Arc<RwLock<HashMap<String, ActionMetadata>>>,

    /// Logger instance
    logger: Arc<Logger>,

    /// Request timeout in milliseconds
    request_timeout_ms: u64,
}

/// Configuration for creating a RemoteService instance.
pub struct RemoteServiceConfig {
    pub name: String,
    pub service_topic: TopicPath,
    pub version: String,
    pub description: String,
    pub peer_node_id: String, // ID of the remote peer hosting the service
    pub request_timeout_ms: u64,
}

/// Dependencies required by a RemoteService instance, provided by the local node.
pub struct RemoteServiceDependencies {
    pub network_transport: Arc<dyn NetworkTransport>,
    pub local_node_id: String, // ID of the local node
    pub logger: Arc<Logger>,
}

/// Configuration for creating multiple RemoteService instances from capabilities.
pub struct CreateRemoteServicesConfig {
    pub capabilities: Vec<ServiceMetadata>,
    pub peer_node_id: String, // ID of the remote peer hosting the services
    pub request_timeout_ms: u64,
}

impl RemoteService {
    /// Create a new RemoteService instance
    pub fn new(config: RemoteServiceConfig, dependencies: RemoteServiceDependencies) -> Self {
        let network_id = config.service_topic.network_id();
        Self {
            name: config.name,
            service_topic: config.service_topic,
            version: config.version,
            description: config.description,
            network_id, // Derived from service_topic
            peer_node_id: config.peer_node_id,
            network_transport: dependencies.network_transport,
            actions: Arc::new(RwLock::new(HashMap::new())),
            logger: dependencies.logger,
            request_timeout_ms: config.request_timeout_ms,
        }
    }

    /// Create RemoteService instances from a list of service metadata.
    ///
    /// INTENTION: To instantiate multiple `RemoteService` proxies based on a list
    /// of `ServiceMetadata` (typically received from a remote peer), using shared
    /// dependencies and peer-specific configuration.
    pub async fn create_from_capabilities(
        config: CreateRemoteServicesConfig,
        dependencies: RemoteServiceDependencies,
    ) -> Result<Vec<Arc<RemoteService>>> {
        dependencies.logger.info(format!(
            "Creating RemoteServices from {} service metadata entries",
            config.capabilities.len()
        ));

        // The transport is guaranteed to be available via the dependency injection contract.

        // Create remote services for each service metadata
        let mut remote_services = Vec::new();

        for service_metadata in config.capabilities {
            // Create a topic path using the service path (not the name)
            let service_path = match TopicPath::new(
                &service_metadata.service_path,
                &service_metadata.network_id,
            ) {
                Ok(path) => path,
                Err(e) => {
                    dependencies.logger.error(format!(
                        "Invalid service path '{path}': {e}",
                        path = service_metadata.service_path
                    ));
                    continue;
                }
            };

            // Prepare config for RemoteService::new
            let rs_config = RemoteServiceConfig {
                name: service_metadata.name.clone(),
                service_topic: service_path,
                version: service_metadata.version.clone(),
                description: service_metadata.description.clone(),
                peer_node_id: config.peer_node_id.clone(),
                request_timeout_ms: config.request_timeout_ms,
            };

            // Prepare dependencies for RemoteService::new (cloning Arcs)
            let rs_dependencies = RemoteServiceDependencies {
                network_transport: dependencies.network_transport.clone(),
                // no keystore/resolver
                local_node_id: dependencies.local_node_id.clone(),
                logger: dependencies.logger.clone(),
            };

            // Create the remote service
            let service = Arc::new(Self::new(rs_config, rs_dependencies));

            // Add actions to the service
            for action in service_metadata.actions {
                service.add_action(action.name.clone(), action).await?;
            }
            // Add service to the result list
            remote_services.push(service);
        }

        let service_count = remote_services.len();
        dependencies
            .logger
            .info(format!("Created {service_count} RemoteService instances"));
        Ok(remote_services)
    }

    /// Get the remote peer identifier for this service
    pub fn peer_node_id(&self) -> &String {
        &self.peer_node_id
    }

    /// Get the network identifier for this service path
    pub fn network_id(&self) -> String {
        self.service_topic.network_id()
    }

    /// Add an action to this remote service
    pub async fn add_action(&self, action_name: String, metadata: ActionMetadata) -> Result<()> {
        self.actions.write().await.insert(action_name, metadata);
        Ok(())
    }

    /// Create a handler for a remote action
    pub fn create_action_handler(&self, action_name: String) -> ActionHandler {
        let service = self.clone();

        // Create a handler that forwards requests to the remote service
        Arc::new(move |params, request_context| {
            // let service_clone = service.clone();
            let action = action_name.clone();

            // Handle the Result explicitly instead of using the ? operator
            let action_topic_path = match service.service_topic.new_action_topic(&action) {
                Ok(path) => path,
                Err(e) => return Box::pin(async move { Err(anyhow::anyhow!(e)) }),
            };

            // Clone all necessary fields before the async block
            let peer_node_id = service.peer_node_id.clone();
            let network_transport = service.network_transport.clone();
            // no keystore/resolver
            let _request_timeout_ms = service.request_timeout_ms;
            let logger = service.logger.clone();

            Box::pin(async move {
                // Generate a unique request ID
                let request_id = Uuid::new_v4().to_string();

                logger.debug(format!(
                    "🚀 [RemoteService] Starting remote request - Action: {action}, Request ID: {request_id}, Target: {peer_node_id}"
                ));

                let profile_public_key = request_context.user_profile_public_key;

                let context = MessageContext { profile_public_key };

                // Send the request
                if let Err(e) = network_transport
                    .send_request(
                        &action_topic_path,
                        params,
                        &request_id,
                        &peer_node_id,
                        context,
                    )
                    .await
                {
                    logger.error(format!(
                        "❌ [RemoteService] Failed to send request {request_id_ref}: {e}",
                        request_id_ref = &request_id
                    ));
                    // Clean up the pending request
                    pending_requests.write().await.remove(&request_id);
                    return Err(anyhow::anyhow!("Failed to send request: {e}"));
                } else {
                    logger.info(format!(
                        "✅ [RemoteService] Request sent successfully - ID: {request_id}, waiting for response..."
                    ));
                }

                logger.info(format!(
                    "⏳ [RemoteService] Waiting for response - ID: {request_id}, Timeout: {request_timeout_ms}ms"
                ));

                // Wait for the response with a timeout
                match tokio::time::timeout(std::time::Duration::from_millis(request_timeout_ms), rx)
                    .await
                {
                    Ok(response) => {
                        logger.info(format!(
                            "✅ [RemoteService] Response received successfully - ID: {request_id}"
                        ));
                        Ok(response)
                    }
                    Err(e) => {
                        logger.error(format!(
                            "❌ [RemoteService] Remote request failed {request_id}: {e}"
                        ));
                        Err(anyhow::anyhow!("Remote service error: {e}"))
                    }
                }
            })
        })
    }

    /// Get a list of available actions this service can handle
    ///
    /// INTENTION: Provide a way to identify all actions that this remote service
    /// can handle, to be used during initialization for registering handlers.
    pub async fn get_available_actions(&self) -> Vec<String> {
        let actions = self.actions.read().await;
        actions.keys().cloned().collect()
    }

    /// Initialize the remote service and register its handlers
    ///
    /// INTENTION: Handle service initialization and register all available
    /// action handlers with the provided context.
    pub async fn init(&self, context: crate::services::RemoteLifecycleContext) -> Result<()> {
        // Get available actions
        let action_names = self.get_available_actions().await;

        // Register each action handler
        for action_name in action_names {
            if let Ok(action_topic_path) = self.service_topic.new_action_topic(&action_name) {
                // Create handler for this action
                let handler = self.create_action_handler(action_name.clone());

                context
                    .register_remote_action_handler(&action_topic_path, handler)
                    .await?;
            } else {
                self.logger.warn(format!(
                    "Failed to create topic path for action: {}/{action_name}",
                    self.service_topic
                ));
            }
        }

        Ok(())
    }

    pub async fn stop(&self, context: crate::services::RemoteLifecycleContext) -> Result<()> {
        let action_names = self.get_available_actions().await;

        for action_name in action_names {
            if let Ok(action_topic_path) = self.service_topic.new_action_topic(&action_name) {
                context
                    .remove_remote_action_handler(&action_topic_path)
                    .await?;
            } else {
                self.logger.warn(format!(
                    "Failed to create topic path for action: {}/{action_name}",
                    self.service_topic
                ));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AbstractService for RemoteService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        self.service_topic.as_str()
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn network_id(&self) -> Option<String> {
        Some(self.service_topic.network_id())
    }
    fn set_network_id(&mut self, _network_id: String) {
        // remote services cannoty change network id
    }

    async fn init(&self, _context: LifecycleContext) -> Result<()> {
        // Remote services don't need initialization since they're just proxies
        self.logger.info(format!(
            "Initialized remote service proxy for {service_topic}",
            service_topic = self.service_topic
        ));
        Ok(())
    }

    async fn start(&self, _context: LifecycleContext) -> Result<()> {
        // Remote services don't need to be started
        self.logger.info(format!(
            "Started remote service proxy for {service_topic}",
            service_topic = self.service_topic
        ));
        Ok(())
    }

    async fn stop(&self, _context: LifecycleContext) -> Result<()> {
        // Remote services don't need to be stopped
        self.logger.info(format!(
            "Stopped remote service proxy for {service_topic}",
            service_topic = self.service_topic
        ));
        Ok(())
    }
}
