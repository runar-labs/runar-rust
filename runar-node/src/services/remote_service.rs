// Remote Service Implementation
//
// INTENTION: Implement a proxy service that represents a service running on a remote node.
// This service forwards requests to the remote node and returns responses, making
// remote services appear as local services to the node.

use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::services::abstract_service::AbstractService;

use crate::services::{ActionHandler, LifecycleContext};
use runar_common::logging::Logger;
use runar_common::routing::TopicPath;
use runar_macros_common::{log_debug, log_error, log_info, log_warn};
use runar_schemas::{ActionMetadata, ServiceMetadata};
use runar_serializer::{ArcValue, SerializationContext};
use runar_transporter::transport::NetworkTransport;

// No direct key-store or label resolver – encryption handled by transport layer

/// Represents a service running on a remote node
#[derive(Clone)]
pub struct RemoteService {
    /// Service metadata
    pub name: String,
    pub service_topic: TopicPath,
    pub version: String,
    pub description: String,
    /// Network public key for this service
    pub network_public_key: Vec<u8>,

    /// Remote peer information
    peer_node_id: String,
    /// Shared network transport (immutable)
    network_transport: Arc<dyn NetworkTransport>,

    /// Service capabilities
    actions: Arc<DashMap<String, ActionMetadata>>,

    /// Logger instance
    logger: Arc<Logger>,

    /// Keystore for encryption/decryption
    keystore: Arc<dyn runar_serializer::EnvelopeCrypto>,
    /// Label resolver configuration for dynamic resolver creation
    label_resolver_config: Arc<runar_serializer::LabelResolverConfig>,
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
    pub keystore: Arc<dyn runar_serializer::EnvelopeCrypto>,
    pub label_resolver_config: Arc<runar_serializer::LabelResolverConfig>,
}

/// Configuration for creating multiple RemoteService instances from capabilities.
pub struct CreateRemoteServicesConfig {
    pub services: Vec<ServiceMetadata>,
    pub peer_node_id: String, // ID of the remote peer hosting the services
    pub request_timeout_ms: u64,
}

impl RemoteService {
    /// Create a new RemoteService instance
    pub fn new(config: RemoteServiceConfig, dependencies: RemoteServiceDependencies) -> Self {
        let _network_id = config.service_topic.network_id();
        // For now, we'll use a placeholder network public key
        // TODO: This should be resolved from the keystore or passed in
        let network_public_key = vec![0u8; 32]; // Placeholder
        Self {
            name: config.name,
            service_topic: config.service_topic,
            version: config.version,
            description: config.description,
            network_public_key, // TODO: Should be resolved from keystore
            peer_node_id: config.peer_node_id,
            network_transport: dependencies.network_transport,
            actions: Arc::new(DashMap::new()),
            logger: dependencies.logger,
            keystore: dependencies.keystore.clone(),
            label_resolver_config: dependencies.label_resolver_config.clone(),
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
        log_info!(
            dependencies.logger,
            "Creating RemoteServices from {} service metadata entries",
            config.services.len()
        );

        // The transport is guaranteed to be available via the dependency injection contract.

        // Create remote services for each service metadata
        let mut remote_services = Vec::new();

        for service_metadata in config.services {
            // Create a topic path using the service path (not the name)
            let service_path = match TopicPath::new(
                &service_metadata.service_path,
                &service_metadata.network_id,
            ) {
                Ok(path) => path,
                Err(e) => {
                    log_error!(
                        dependencies.logger,
                        "Invalid service path '{path}': {e}",
                        path = service_metadata.service_path
                    );
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
                keystore: dependencies.keystore.clone(),
                label_resolver_config: dependencies.label_resolver_config.clone(),
            };

            // Create the remote service
            let service = Arc::new(Self::new(rs_config, rs_dependencies));

            // Add actions to the service
            for action in service_metadata.actions {
                service.add_action(action.name.clone(), action)?;
            }
            // Add subscriptions to the service
            // for subscription in service_metadata.subscriptions {
            //     service.add_subscription(subscription.path.clone(), subscription).await?;
            // }
            // Add service to the result list
            remote_services.push(service);
        }

        let service_count = remote_services.len();
        log_info!(
            dependencies.logger,
            "Created {service_count} RemoteService instances"
        );
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
    pub fn add_action(&self, action_name: String, metadata: ActionMetadata) -> Result<()> {
        self.actions.insert(action_name, metadata);
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
            //let _request_timeout_ms = service.request_timeout_ms;
            let logger = service.logger.clone();
            let keystore = service.keystore.clone();
            let label_resolver_config = service.label_resolver_config.clone();
            //let network_public_key = service.network_public_key.clone();
            let network_id = service.service_topic.network_id();
            let network_public_key = match keystore.get_network_public_key(&network_id) {
                Ok(key) => key,
                Err(e) => {
                    let error_msg = format!(
                        "Failed to get network public key for network {}: {}",
                        network_id, e
                    );
                    log_error!(logger, "🔒 [RemoteService] {}", error_msg);
                    return Box::pin(async move { Err(anyhow::anyhow!(error_msg)) });
                }
            };

            Box::pin(async move {
                // Generate a unique request ID
                let correlation_id = Uuid::new_v4().to_string();

                log_debug!(
                    logger,
                    "🚀 [RemoteService] Starting remote request - Action: {action} Target: {peer_node_id}"
                );

                let profile_public_keys = request_context.user_profile_public_keys.clone();

                // Send the request
                let topic_path_str = action_topic_path.as_str();

                // Create dynamic resolver with user context
                // For request serialization, we can use a system-only resolver if no user keys are provided
                let resolver = runar_serializer::traits::create_context_label_resolver(
                    &label_resolver_config,
                    &profile_public_keys, // Empty vec is fine for system-only resolver
                )
                .map_err(|e| anyhow::anyhow!("Failed to create label resolver: {e}"))?;

                // Create serialization context with dynamic resolver
                let serialization_context = SerializationContext {
                    keystore: keystore.clone(),
                    resolver,
                    network_public_key: network_public_key.clone(),
                    profile_public_keys: profile_public_keys.clone(),
                };

                let params_to_serialize = params.unwrap_or(ArcValue::null());

                // Serialize request parameters with encryption (all external payloads must be encrypted)
                let params_bytes = params_to_serialize
                    .serialize(Some(&serialization_context))
                    .map_err(|e| {
                        log_error!(
                            logger,
                            "🔒 [RemoteService] Encryption failed for request params: {e}"
                        );
                        anyhow::anyhow!("Failed to encrypt request params: {e}")
                    })?;
                match network_transport
                    .request(
                        topic_path_str,
                        &correlation_id,
                        params_bytes,
                        &peer_node_id,
                        Some(network_public_key.clone()),
                        profile_public_keys,
                    )
                    .await
                {
                    Ok(response_bytes) => {
                        log_debug!(logger, "✅ [RemoteService] Response received successfully");
                        // Deserialize the response bytes back to ArcValue
                        match ArcValue::deserialize(
                            &response_bytes,
                            Some(Arc::clone(&serialization_context.keystore)),
                        ) {
                            Ok(response_value) => Ok(response_value),
                            Err(e) => {
                                log_error!(
                                    logger,
                                    "❌ [RemoteService] Failed to deserialize response: {e}"
                                );
                                Err(anyhow::anyhow!("Response deserialization error: {e}"))
                            }
                        }
                    }
                    Err(e) => {
                        log_error!(logger, "❌ [RemoteService] Remote request failed: {e}");
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
    pub fn get_available_actions(&self) -> Vec<String> {
        self.actions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Initialize the remote service and register its handlers
    ///
    /// INTENTION: Handle service initialization and register all available
    /// action handlers with the provided context.
    pub async fn init(&self, context: crate::services::RemoteLifecycleContext) -> Result<()> {
        // Get available actions
        let action_names = self.get_available_actions();

        // Register each action handler
        for action_name in action_names {
            if let Ok(action_topic_path) = self.service_topic.new_action_topic(&action_name) {
                // Create handler for this action
                let handler = self.create_action_handler(action_name.clone());

                context
                    .register_remote_action_handler(&action_topic_path, handler)
                    .await?;
            } else {
                log_warn!(
                    self.logger,
                    "Failed to create topic path for action: {}/{action_name}",
                    self.service_topic
                );
            }
        }

        Ok(())
    }

    pub async fn stop(&self, context: crate::services::RemoteLifecycleContext) -> Result<()> {
        let action_names = self.get_available_actions();

        for action_name in action_names {
            if let Ok(action_topic_path) = self.service_topic.new_action_topic(&action_name) {
                context
                    .remove_remote_action_handler(&action_topic_path)
                    .await?;
            } else {
                log_warn!(
                    self.logger,
                    "Failed to create topic path for action: {}/{action_name}",
                    self.service_topic
                );
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
        log_info!(
            self.logger,
            "Initialized remote service proxy for {service_topic}",
            service_topic = self.service_topic
        );
        Ok(())
    }

    async fn start(&self, _context: LifecycleContext) -> Result<()> {
        // Remote services don't need to be started
        log_info!(
            self.logger,
            "Started remote service proxy for {service_topic}",
            service_topic = self.service_topic
        );
        Ok(())
    }

    async fn stop(&self, _context: LifecycleContext) -> Result<()> {
        // Remote services don't need to be stopped
        log_info!(
            self.logger,
            "Stopped remote service proxy for {service_topic}",
            service_topic = self.service_topic
        );
        Ok(())
    }
}
