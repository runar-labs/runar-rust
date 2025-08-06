// Node Implementation
//
// This module provides the Node which is the primary entry point for the Runar system.
// The Node is responsible for managing the service registry, handling requests, and
// coordinating event publishing and subscriptions.
//
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_keys::{node::NodeKeyManagerState, NodeKeyManager};
 
use runar_schemas::{ActionMetadata, ServiceMetadata};
use runar_serializer::arc_value::AsArcValue;
use runar_serializer::traits::{ConfigurableLabelResolver, KeyMappingConfig, LabelResolver};
use runar_serializer::{ArcValue, LabelKeyInfo};
use socket2;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use tokio::time::{sleep, Duration};

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, RwLock};

use crate::network::discovery::multicast_discovery::PeerInfo;
use crate::network::discovery::{DiscoveryOptions, MulticastDiscovery, NodeDiscovery, NodeInfo};
use crate::network::transport::{
    NetworkMessage, NetworkMessagePayloadItem, NetworkTransport, QuicTransport, MESSAGE_TYPE_EVENT,
    MESSAGE_TYPE_HANDSHAKE, MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_RESPONSE,
};

pub(crate) type NodeDiscoveryList = Vec<Arc<dyn NodeDiscovery>>;
// Certificate and PrivateKey types are now imported via the cert_utils module
use crate::config::LoggingConfig;
use crate::network::network_config::{DiscoveryProviderConfig, NetworkConfig, TransportType};

use crate::routing::TopicPath;
use crate::services::keys_service::KeysService;
use crate::services::load_balancing::{LoadBalancingStrategy, RoundRobinLoadBalancer};
use crate::services::registry_service::RegistryService;
use crate::services::remote_service::{
    CreateRemoteServicesConfig, RemoteService, RemoteServiceDependencies,
};
use crate::services::service_registry::{EventHandler, ServiceEntry, ServiceRegistry};
use crate::services::NodeDelegate;
use crate::services::{
    ActionHandler,   EventRegistrationOptions,
    PublishOptions, RegistryDelegate, RemoteLifecycleContext, RequestContext,
};
use crate::services::{EventContext, KeysDelegate}; // Explicit import for EventContext
use crate::{AbstractService, ServiceState};

/// Node Configuration
///
/// INTENTION: Provide configuration options for a Node instance
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Node ID (required) - Builder method will either use provided ID or generate one
    pub node_id: String,

    /// Primary network ID this node belongs to
    pub default_network_id: String,

    /// Additional network IDs this node participates in
    pub network_ids: Vec<String>,

    /// Network configuration (None = no networking features)
    pub network_config: Option<NetworkConfig>,

    /// Logging configuration options
    pub logging_config: Option<LoggingConfig>,

    key_manager_state: Option<Vec<u8>>,

    //FIX: move this to the network config.. local sercvies shuold not have timeout checks.
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
}

impl NodeConfig {
    /// Create a new production configuration with the specified node ID and network ID
    ///
    /// This constructor is for production use and expects the key manager state
    /// to be provided separately via with_key_manager_state().
    pub fn new(node_id: impl Into<String>, default_network_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            default_network_id: default_network_id.into(),
            network_ids: Vec::new(),
            network_config: None,
            logging_config: Some(LoggingConfig::default_info()), // Default to Info logging
            key_manager_state: None, // Must be set via with_key_manager_state()
            request_timeout_ms: 30000, // 30 seconds
        }
    }

    /// Add network configuration
    pub fn with_network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    /// Add logging configuration
    pub fn with_logging_config(mut self, config: LoggingConfig) -> Self {
        self.logging_config = Some(config);
        self
    }

    /// Add additional network IDs
    pub fn with_additional_networks(mut self, network_ids: Vec<String>) -> Self {
        self.network_ids = network_ids;
        self
    }

    /// Set the request timeout in milliseconds
    pub fn with_request_timeout(mut self, timeout_ms: u64) -> Self {
        self.request_timeout_ms = timeout_ms;
        self
    }

    /// Set the key manager state from serialized bytes
    pub fn with_key_manager_state(mut self, key_state_bytes: Vec<u8>) -> Self {
        self.key_manager_state = Some(key_state_bytes);
        self
    }
}

// Implement Display for NodeConfig to enable logging it directly
impl std::fmt::Display for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodeConfig: node_id:{} network:{} request_timeout:{}ms",
            self.node_id, self.default_network_id, self.request_timeout_ms
        )?;

        // Add network configuration details if available
        if let Some(network_config) = &self.network_config {
            write!(f, " {network_config}")?;
        }

        Ok(())
    }
}

const INTERNAL_SERVICES: [&str; 2] = ["$registry", "$keys"];

/// The Node is the main entry point for the application
///
/// INTENTION: Provide a high-level interface for services to communicate
/// with each other, for registering and discovering services, and for
/// managing the lifecycle of services.
pub struct Node {
    /// Debounce state for notify_node_change.
    ///
    /// INTENTION: Ensures that rapid successive calls to notify_node_change only trigger a single
    /// notification after a 5s debounce window. This prevents unnecessary network traffic and ensures
    /// only the latest node state is broadcast. Internal use only; not exposed outside Node.
    debounce_notify_task: std::sync::Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Default network id to be used when service are added without a network ID
    pub(crate) network_id: String,

    //network_ids that this node participates in.
    pub(crate) network_ids: Vec<String>,

    /// The node ID for this node
    pub(crate) node_id: String,

    pub(crate) node_public_key: Vec<u8>,

    /// Configuration for this node
    pub(crate) config: Arc<NodeConfig>,

    /// The service registry for this node
    pub(crate) service_registry: Arc<ServiceRegistry>,

    pub(crate) known_peers: Arc<RwLock<HashMap<String, NodeInfo>>>,

    /// Logger instance
    pub(crate) logger: Arc<Logger>,

    /// Flag indicating if the node is running
    pub(crate) running: AtomicBool,

    /// Flag indicating if this node supports networking
    /// This is set when networking is enabled in the config
    pub(crate) supports_networking: bool,

    /// Network transport for connecting to remote nodes
    pub(crate) network_transport: Arc<RwLock<Option<Arc<dyn NetworkTransport>>>>,

    pub(crate) network_discovery_providers: Arc<RwLock<Option<NodeDiscoveryList>>>,

    /// Load balancer for selecting remote handlers
    pub(crate) load_balancer: Arc<RwLock<dyn LoadBalancingStrategy>>,

    /// Pending requests waiting for responses, keyed by correlation ID
    pub(crate) pending_requests: Arc<RwLock<HashMap<String, oneshot::Sender<Result<ArcValue>>>>>,

    label_resolver: Arc<dyn LabelResolver>,

    registry_version: Arc<AtomicI64>,

    keys_manager: Arc<NodeKeyManager>,

    keys_manager_mut: Arc<Mutex<NodeKeyManager>>,
}

// Implementation for Node
impl Node {
    /// Create a new Node with the given configuration
    ///
    /// INTENTION: Initialize a new Node with the specified configuration, setting up
    /// all the necessary components and internal state. This is the primary
    /// entry point for creating a Node instance.
    ///
    /// This constructor does not start services - call start() separately
    /// after registering services.
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let node_id = config.node_id.clone();
        let logger = Arc::new(Logger::new_root(Component::Node, &node_id));

        // Apply logging configuration (default to Info level if none provided)
        if let Some(logging_config) = &config.logging_config {
            logging_config.apply();
            logger.debug("Applied custom logging configuration");
        } else {
            // Apply default Info logging when no configuration is provided
            let default_config = LoggingConfig::default_info();
            default_config.apply();
            logger.debug("Applied default Info logging configuration");
        }

        // Clone fields before moving config
        let default_network_id = config.default_network_id.clone();
        //stgore this in the node struct.. will be used later features..
        let network_ids = config.network_ids.clone();
        let networking_enabled = config.network_config.is_some();

        let mut network_ids = network_ids.clone();
        network_ids.push(default_network_id.clone());
        network_ids.dedup();

        logger.info(format!(
            "Initializing node '{node_id}' in network '{default_network_id}'...",
        ));

        let service_registry = Arc::new(ServiceRegistry::new(logger.clone()));
        let _serializer_logger = Arc::new(logger.with_component(Component::Custom("Serializer")));

        // at this stage the node credentials must already exist and must be in a secure store
        let key_manager_state_bytes = config
            .key_manager_state
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Failed to load node credentials."))?;

        let key_manager_state: NodeKeyManagerState = bincode::deserialize(&key_manager_state_bytes)
            .context("Failed to deserialize node keys state")?;

        let keys_manager = NodeKeyManager::from_state(key_manager_state.clone(), logger.clone())?;
        let keys_manager_mut = NodeKeyManager::from_state(key_manager_state, logger.clone())?;

        //TODO check if we shuold use the compact ID here instead of just a hex of the key
        let node_public_key = keys_manager.get_node_public_key();
        let node_id = compact_id(&node_public_key);

        logger.info("Successfully loaded existing node credentials.");
        logger.info(format!("Node ID: {node_id}"));

        let keys_manager = Arc::new(keys_manager);
        let keys_manager_mut = Arc::new(Mutex::new(keys_manager_mut));

        // TODO Create a mechanis for this mappint to be config driven
        let label_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
            label_mappings: HashMap::from([(
                "system".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![],
                    network_id: Some(default_network_id.clone()),
                },
            )]),
        }));

        let mut node = Self {
            debounce_notify_task: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            network_id: default_network_id,
            network_ids,
            node_id,
            node_public_key,
            config: Arc::new(config),
            logger: logger.clone(),
            service_registry,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            running: AtomicBool::new(false),
            supports_networking: networking_enabled,
            network_transport: Arc::new(RwLock::new(None)),
            network_discovery_providers: Arc::new(RwLock::new(None)),
            load_balancer: Arc::new(RwLock::new(RoundRobinLoadBalancer::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            label_resolver,
            registry_version: Arc::new(AtomicI64::new(0)),
            keys_manager,
            keys_manager_mut,
        };

        // Register the registry service
        let registry_service = RegistryService::new(
            logger.clone(),
            Arc::new(node.clone()) as Arc<dyn RegistryDelegate>,
        );
        node.add_service(registry_service).await?;

        let keys_service = KeysService::new(
            logger.clone(),
            Arc::new(node.clone()) as Arc<dyn KeysDelegate>,
        );
        node.add_service(keys_service).await?;

        Ok(node)
    }

    /// Add a service to this node
    ///
    /// 1: validate service path    
    /// 2: create topic path
    /// 3: create service entry
    /// 4: register service
    /// 5: update service state to initialized
    ///
    /// INTENTION: Register a service with this node, making its actions available
    /// for requests and allowing it to receive events. This method initializes the
    /// service but does not start it - services are started when the node is started.
    pub async fn add_service<S: AbstractService + 'static>(
        &mut self,
        mut service: S,
    ) -> Result<()> {
        let default_network_id = self.network_id.to_string();
        let service_network_id = match service.network_id() {
            Some(id) => id,
            None => default_network_id.clone(),
        };
        service.set_network_id(service_network_id.clone());

        let service_path = service.path();
        let service_name = service.name();

        self.logger.info(format!(
            "Adding service '{service_name}' to node using path {service_path}",
        ));
        self.logger
            .debug(format!("network id {default_network_id}"));

        let registry = Arc::clone(&self.service_registry);
        // Create a proper topic path for the service
        let service_topic = match crate::routing::TopicPath::new(service_path, &default_network_id)
        {
            Ok(tp) => tp,
            Err(e) => {
                self.logger.error(format!(
                    "Failed to create topic path for service name:{service_name} path:{service_path} error:{e}"
                ));
                return Err(anyhow!(
                    "Failed to create topic path for service {}: {}",
                    service_name,
                    e
                ));
            }
        };

        // Create a lifecycle context for initialization
        let init_context = crate::services::LifecycleContext::new(
            &service_topic,
            Arc::new(self.clone()), // Node delegate
            Arc::new(
                self.logger
                    .clone()
                    .with_component(runar_common::Component::Service),
            ),
        );

        // Initialize the service using the context
        if let Err(e) = service.init(init_context).await {
            self.logger.error(format!(
                "Failed to initialize service: {service_name}, error: {e}",
            ));
            registry
                .update_local_service_state(&service_topic, ServiceState::Error)
                .await?;
            self.publish_with_options(format!("$registry/services/{}/state/error", service_topic.service_path()), 
                Some(ArcValue::new_primitive(service_topic.as_str().to_string())), PublishOptions::local_only()).await?;
            return Err(anyhow!("Failed to initialize service: {e}"));
        }
        registry
            .update_local_service_state(&service_topic, ServiceState::Initialized)
            .await?;
        self.publish_with_options(format!("$registry/services/{}/state/initialized", service_topic.service_path()), Some(ArcValue::new_primitive(service_topic.as_str().to_string())), PublishOptions::local_only()).await?;
        // Service initialized successfully, create the ServiceEntry and register it
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let service_entry =Arc::new( ServiceEntry {
            service: Arc::new(service),
            service_topic: service_topic.clone(),
            service_state: ServiceState::Initialized,
            registration_time: now,
            last_start_time: None, // Will be set when the service is started
        });
        registry
            .register_local_service(service_entry.clone())
            .await?;

        //if started... need to increment  -> registry_version
        if self.running.load(Ordering::SeqCst) {
            self.start_service(&service_topic, service_entry.as_ref()).await;
            self.registry_version.fetch_add(1, Ordering::SeqCst);
            let _ = self.notify_node_change().await;
        }

        Ok(())
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
 
    /// Wait for an event to occur with a timeout
    ///
    /// INTENTION: Subscribe to an event topic and wait for the first event to occur,
    /// or timeout if no event occurs within the specified duration.
    ///
    /// Handles different topic formats:
    /// - Full topic with network ID: "network:service/topic" (used as is)
    /// - Topic with service: "service/topic" (default network ID added)
    /// - Simple topic: "topic" (default network ID and service path added)
    ///
    /// Returns Ok(ArcValue) with the event payload if event occurs within timeout,
    /// or Err with timeout message if no event occurs.
    pub async fn on(&self, topic: impl Into<String>, timeout: Duration) -> Result<Option<ArcValue>>
    {
        let topic_string = topic.into();
        
        // Process the topic based on its format
        let full_topic = if topic_string.contains(':') {
            // Already has network ID, use as is
            topic_string
        } else if topic_string.contains('/') {
            // Has service/topic but no network ID
            format!(
                "{network_id}:{topic_string}",
                network_id = self.network_id
            )
        } else {
            // Simple topic name - add service path and network ID
            format!(
                "{}:{}/{}",
                self.network_id,
                "default", // Use default service path for simple topics
                topic_string
            )
        };

        self.logger.debug(format!("Waiting for event on topic: {full_topic}"));

        // Create a channel to receive the event
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<ArcValue>>(1);
        
        // Create a subscription that will send the first event to our channel
        let subscription_id = self.subscribe_with_options(
            full_topic.clone(),
            Arc::new(move |_context, data| {
                let tx = tx.clone();
                Box::pin(async move {
                    // Send the event data to our channel
                    let _ = tx.send(data).await;
                    Ok(())
                })
            }),
            EventRegistrationOptions::default(),
        ).await?;

        // Wait for the event with timeout
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(event_data)) => {
                // Event received, unsubscribe and return data
                self.unsubscribe(Some(&subscription_id)).await?;
                Ok(event_data)
            }
            Ok(None) => {
                // Channel closed
                self.unsubscribe(Some(&subscription_id)).await?;
                Err(anyhow!("Channel closed while waiting for event on topic: {full_topic}"))
            }
            Err(_) => {
                // Timeout
                self.unsubscribe(Some(&subscription_id)).await?;
                Err(anyhow!("Timeout waiting for event on topic: {full_topic}"))
            }
        }
    }

    /// Start the Node and all registered services
    ///
    /// INTENTION: Initialize the Node's internal systems and start all registered services.
    /// This method:
    /// 1. Checks if the Node is already started to ensure idempotency
    /// 2. Get all local services from the registry
    /// 3. Initialize and start each service
    /// 4. Update service state to running
    /// 5. Start networking if enabled
    ///
    /// When network functionality is added, this will also advertise services to the network.
    pub async fn start(&mut self) -> Result<()> {
        self.logger.info("Starting node...");

        if self.running.load(Ordering::SeqCst) {
            self.logger.warn("Node already running");
            return Ok(());
        }

        // Get services directly from the registry
        let registry = Arc::clone(&self.service_registry);
        let local_services = registry.get_local_services().await;

        let internal_services = local_services.iter().filter(|(_, service_entry)| INTERNAL_SERVICES.contains(&service_entry.service.path())).collect::<HashMap<_, _>>();
        let non_internal_services = local_services.iter().filter(|(_, service_entry)| !INTERNAL_SERVICES.contains(&service_entry.service.path())).collect::<HashMap<_, _>>();

        // start internal services first
        for (service_topic, service_entry) in internal_services {
            self.start_service(service_topic, service_entry).await;
        }

        // Start non-internal services in parallel to avoid blocking the loop
        let mut service_tasks = Vec::new();
        
        for (service_topic, service_entry) in non_internal_services {
            let node_clone = Arc::new(self.clone());
            let service_topic_clone = service_topic.clone();
            let service_entry_clone = service_entry.clone();
            
            let task = tokio::spawn(async move {
                node_clone.start_service(&service_topic_clone, &service_entry_clone).await;
            });
            
            service_tasks.push((service_topic.clone(), task));
        }
        
        // Wait for all service start tasks to complete
        for (service_topic, task) in service_tasks {
            match task.await {
                Ok(()) => {
                    self.logger.info(format!("Service start task completed: {service_topic}"));
                }
                Err(e) => {
                    self.logger.error(format!("Task panicked for service: {service_topic}, error: {e}"));
                    // Continue with other services even if one panics
                }
            }
        }

        // Start networking if enabled
        if self.supports_networking {
            if let Err(e) = self.start_networking().await {
                self.logger
                    .error(format!("Failed to start networking components: {e}"));
                return Err(e);
            }
        }

        self.logger.info("Node started successfully");
        self.running.store(true, Ordering::SeqCst);

        self.registry_version.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    async fn start_service(&self, service_topic: &TopicPath, service_entry: &ServiceEntry) {
        self.logger
            .info(format!("Starting service: {service_topic}"));

        let service = service_entry.service.clone();
        let registry = &self.service_registry.clone();

        // Create a lifecycle context for starting
        let start_context = crate::services::LifecycleContext::new(
            service_topic,
            Arc::new(self.clone()), // Node delegate
            Arc::new(
                self.logger
                    .clone()
                    .with_component(runar_common::Component::Service),
            ),
        );
        
        // Start the service using the context
        if let Err(e) = service.start(start_context).await {
            self.logger.error(format!(
                "Failed to start service: {service_topic}, error: {e}"
            ));
            if let Err(update_err) = registry
                .update_local_service_state(service_topic, ServiceState::Error)
                .await {
                self.logger.error(format!("Failed to update service state to Error: {update_err}"));
            }
            if let Err(publish_err) = self.publish_with_options(format!("$registry/services/{}/state/error", service_topic.service_path()), Some(ArcValue::new_primitive(service_topic.as_str().to_string())), PublishOptions::local_only()).await {
                self.logger.error(format!("Failed to publish error state: {publish_err}"));
            }
            return;
        }
        
        if let Err(update_err) = registry
            .update_local_service_state(service_topic, ServiceState::Running)
            .await {
            self.logger.error(format!("Failed to update service state to Running: {update_err}"));
        }

        if let Err(publish_err) = self.publish_with_options(format!("$registry/services/{}/state/running", service_topic.service_path()), Some(ArcValue::new_primitive(service_topic.as_str().to_string())), PublishOptions::local_only()).await {
            self.logger.error(format!("Failed to publish running state: {publish_err}"));
        }
    }

    /// Stop the Node and all registered services
    ///
    /// INTENTION: Gracefully stop the Node and all registered services. This method:
    /// 1. Transitions the Node to the Stopping state
    /// 2. Stops all registered services in the reverse order they were started
    /// 3. Updates the service state in the metadata as each service stops
    /// 4. Handles any errors during service shutdown
    /// 5. Transitions the Node to the Stopped state
    pub async fn stop(&mut self) -> Result<()> {
        self.logger.info("Stopping node...");

        if !self.running.load(Ordering::SeqCst) {
            self.logger.warn("Node already stopped");
            return Ok(());
        }

        self.running.store(false, Ordering::SeqCst);

        // Get services directly and stop them
        let registry = Arc::clone(&self.service_registry);
        let local_services = registry.get_local_services().await;

        self.logger.info("Stopping services...");
        // Stop each service
        for (service_topic, service_entry) in local_services {
            self.logger
                .info(format!("Stopping service: {service_topic}"));

            // Extract the service from the entry
            let service = service_entry.service.clone();

            // Create a lifecycle context for stopping
            let stop_context = crate::services::LifecycleContext::new(
                &service_topic,
                Arc::new(self.clone()), // Node delegate
                Arc::new(
                    self.logger
                        .clone()
                        .with_component(runar_common::Component::Service),
                ),
            );

            // Stop the service using the context
            if let Err(e) = service.stop(stop_context).await {
                self.logger.error(format!(
                    "Failed to stop service: {service_topic}, error: {e}"
                ));
                continue;
            }

            registry
                .update_local_service_state(&service_topic, ServiceState::Stopped)
                .await?;
            self.publish_with_options(format!("$registry/services/{}/state/stopped", service_topic.service_path()), Some(ArcValue::new_primitive(service_topic.as_str().to_string())), PublishOptions::local_only()).await?;   
        }

        self.logger.info("Stopping networking...");

        // Shut down networking if enabled
        if self.supports_networking {
            if let Err(e) = self.shutdown_network().await {
                self.logger
                    .error(format!("Error shutting down network: {e}"));
            }
        }

        self.logger.info("Node stopped successfully");

        Ok(())
    }

    /// Starts the networking components (transport and discovery).
    /// This should be called internally as part of the node.start process.
    async fn start_networking(&self) -> Result<()> {
        self.logger.info("Starting networking components...");

        if !self.supports_networking {
            self.logger
                .info("Networking is disabled, skipping network initialization");
            return Ok(());
        }

        // Get the configuration
        let config = &self.config;
        let network_config = config
            .network_config
            .as_ref()
            .ok_or_else(|| anyhow!("Network configuration is required"))?;

        // Log the network configuration
        self.logger
            .info(format!("Network config: {network_config}"));

        // Initialize the network transport
        if self.network_transport.read().await.is_none() {
            self.logger.info("Initializing network transport...");

            // Create network transport using the factory pattern based on transport_type
            let transport = self.create_transport(network_config).await?;

            transport.clone().start().await?;

            // Store the transport
            let mut transport_guard = self.network_transport.write().await;
            *transport_guard = Some(transport);
            //release lock
            drop(transport_guard);
        }

        // Initialize discovery if enabled
        if let Some(discovery_options) = &network_config.discovery_options {
            self.logger.info("Initializing node discovery providers...");

            // Check if any providers are configured
            if network_config.discovery_providers.is_empty() {
                return Err(anyhow!("No discovery providers configured"));
            }

            let node_arc = Arc::new(self.clone());
            let mut discovery_providers: Vec<Arc<dyn NodeDiscovery>> = Vec::new();
            // Iterate through all discovery providers and initialize each one
            for provider_config in &network_config.discovery_providers {
                // Create a discovery provider instance
                let provider_type = format!("{provider_config:?}");

                // Create network transport using the factory pattern based on transport_type
                let discovery_provider = self
                    .create_discovery_provider(provider_config, Some(discovery_options.clone()))
                    .await?;

                // // Configure discovery listener for this provider
                let node_arc = node_arc.clone();
                let provider_type_clone = provider_type.clone();

                discovery_provider
                    .set_discovery_listener(Arc::new(move |peer_info| {
                        let node_arc = node_arc.clone();
                        let provider_type_clone = provider_type_clone.clone();
                        Box::pin(async move {
                            if let Err(e) = node_arc.handle_discovered_node(peer_info).await {
                                node_arc.logger.error(format!(
                        "Failed to handle node discovered by {provider_type_clone} provider: {e}"
                    ));
                            }
                        })
                    }))
                    .await?;

                // Start announcing on this provider
                self.logger.info(format!(
                    "Starting to announce on {provider_type:?} discovery provider"
                ));
                discovery_provider.start_announcing().await?;

                discovery_providers.push(discovery_provider);
            }

            // Store the transport
            let mut discovery_guard = self.network_discovery_providers.write().await;
            *discovery_guard = Some(discovery_providers);
            //release lock
            drop(discovery_guard);
        }

        self.logger.info("Networking started successfully");

        Ok(())
    }

    /// Create a transport instance based on the transport type in the config
    async fn create_transport(
        &self,
        network_config: &NetworkConfig,
    ) -> Result<Arc<dyn NetworkTransport>> {
        // Get the local node info to pass to the transport
        let local_node_info = self.get_local_node_info().await?;
        let self_arc = Arc::new(self.clone());
        match network_config.transport_type {
            TransportType::Quic => {
                self.logger.debug("Creating QUIC transport");

                // Use bind address and options from config
                let bind_addr = network_config.transport_options.bind_address;
                let quic_options = network_config
                    .quic_options
                    .clone()
                    .ok_or_else(|| anyhow!("QUIC options not provided"))?;

                let self_arc_for_message = self_arc.clone();
                let message_handler: crate::network::transport::MessageHandler =
                    Box::new(move |message: NetworkMessage| {
                        let self_arc = self_arc_for_message.clone();
                        Box::pin(async move {
                            self_arc.handle_network_message(message).await.map_err(|e| {
                                crate::network::transport::NetworkError::TransportError(
                                    e.to_string(),
                                )
                            })
                        })
                    });

                let one_way_message_handler: crate::network::transport::OneWayMessageHandler =
                    Box::new(move |message: NetworkMessage| {
                        let self_arc = self_arc.clone();
                        Box::pin(async move {
                            // For one-way messages, we call the same handler but ignore the response
                            let _response = self_arc
                                .handle_network_message(message)
                                .await
                                .map_err(|e| {
                                    crate::network::transport::NetworkError::TransportError(
                                        e.to_string(),
                                    )
                                })?;
                            Ok(())
                        })
                    });

                let cert_config = self
                    .keys_manager
                    .get_quic_certificate_config()
                    .context("Failed to get QUIC certificates")?;

                // Configure QUIC options with certificates and private key from key manager
                // Standard QUIC/TLS will handle certificate validation using the CA certificate
                let configured_quic_options = quic_options
                    .with_certificates(cert_config.certificate_chain)
                    .with_private_key(cert_config.private_key);

                let transport_options = configured_quic_options
                    .with_local_node_info(local_node_info)
                    .with_bind_addr(bind_addr)
                    .with_message_handler(message_handler)
                    .with_one_way_message_handler(one_way_message_handler)
                    .with_logger(self.logger.clone())
                    .with_keystore(self.keys_manager.clone())
                    .with_label_resolver(self.label_resolver.clone());

                let transport = QuicTransport::new(transport_options)
                    .map_err(|e| anyhow!("Failed to create QUIC transport: {e}"))?;

                self.logger.debug("QUIC transport created");
                let transport_arc: Arc<dyn NetworkTransport> = Arc::new(transport);
                Ok(transport_arc)
            } // Add other transport types here as needed in the future
        }
    }

    /// Create a discovery provider based on the provider type
    async fn create_discovery_provider(
        &self,
        provider_config: &DiscoveryProviderConfig,
        discovery_options: Option<DiscoveryOptions>,
    ) -> Result<Arc<dyn NodeDiscovery>> {
        let node_info = self.get_local_node_info().await?;

        match provider_config {
            DiscoveryProviderConfig::Multicast(_options) => {
                self.logger
                    .info("Creating MulticastDiscovery provider with config options");
                // Use .await to properly wait for the async initialization
                let discovery = MulticastDiscovery::new(
                    node_info,
                    discovery_options.unwrap_or_default(),
                    self.logger.with_component(Component::NetworkDiscovery),
                )
                .await?;
                Ok(Arc::new(discovery))
            }
            DiscoveryProviderConfig::Static(_options) => {
                self.logger.info("Static discovery provider configured");
                // Implement static discovery when needed
                Err(anyhow!("Static discovery provider not yet implemented"))
            } // Add other discovery types as they're implemented
        }
    }

    /// Handle discovered nodes and establish connections using lexicographic ordering
    ///
    /// INTENTION: Process discovered peer information and establish connections
    /// following the rule that only the node with the lexicographically smaller
    /// peer ID initiates the connection to prevent duplicate connections.
    pub async fn handle_discovered_node(&self, peer_info: PeerInfo) -> Result<()> {
        if !self.supports_networking {
            return Ok(());
        }

        let discovered_peer_id = compact_id(&peer_info.public_key);

        self.logger.info(format!(
            "Discovery listener found node: {discovered_peer_id}",
        ));
 
        // Check if we're already connected to this peer
        let transport_guard = self.network_transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            if transport.is_connected(discovered_peer_id.clone()).await {
                self.logger.info(format!(
                    "Already connected to node: {discovered_peer_id}, ignoring discovery event",
                ));
                return Ok(());
            }

            // Attempt to connect to the discovered peer
            match transport.clone().connect_peer(peer_info).await {
                Ok(()) => {
                    self.logger
                        .info(format!("Connected to node: {discovered_peer_id}"));
                }
                Err(e) => {
                    self.logger.error(format!(
                        "Failed to connect to discovered node {discovered_peer_id}: {e}",
                    ));
                    return Err(anyhow::anyhow!("Connection failed: {e}"));
                }
            }
        } else {
            self.logger
                .warn("No network transport available for connection");
        }

        Ok(())
    }

    /// Handle a network message
    async fn handle_network_message(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        // Skip if networking is not enabled
        if !self.supports_networking {
            self.logger
                .warn("Received network message but networking is disabled");
            return Ok(None);
        }

        self.logger.debug(format!(
            "Received network message: {message_type}",
            message_type = message.message_type
        ));

        // Match on message type
        match message.message_type {
            MESSAGE_TYPE_HANDSHAKE => {
                self.logger.debug("Received handshake message");
                //save the peer node info
                let peer_node_info =
                    serde_cbor::from_slice::<NodeInfo>(&message.payloads[0].value_bytes).map_err(
                        |e| anyhow!("Could not parse peer NodeInfo from handshake response: {e}"),
                    )?;
                self.process_remote_capabilities(peer_node_info).await?;
                Ok(None)
            }
            MESSAGE_TYPE_REQUEST => {
                let response = self.handle_network_request(message).await?;
                if let Some(response_message) = response {
                    Ok(Some(response_message))
                } else {
                    Ok(None)
                }
            }
            MESSAGE_TYPE_RESPONSE => self.handle_network_response(message).await,
            MESSAGE_TYPE_EVENT => self.handle_network_event(message).await,
            _ => {
                self.logger.warn(format!(
                    "Unknown message type: {message_type}",
                    message_type = message.message_type
                ));
                Err(anyhow!("Unknown message type: {message_type}", message_type =  message.message_type))
            }
        }
    }

    /// Handle a network request
    async fn handle_network_request(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        // Skip if networking is not enabled
        if !self.supports_networking {
            self.logger
                .warn("Received network request but networking is disabled");
            return Ok(None);
        }

        self.logger.debug(format!(
            "📥 [Node] Handling network request from {} - Type: {}, Payloads: {}",
            message.source_node_id,
            message.message_type,
            message.payloads.len()
        ));

        if message.payloads.is_empty() {
            self.logger
                .error("❌ [Node] Received request message with no payloads");
            return Err(anyhow!("Received request message with no payloads"));
        }

        let mut responses: Vec<NetworkMessagePayloadItem> = Vec::new();
        let local_peer_id = self.node_id.clone();

        for payload in &message.payloads {
            let params =
                ArcValue::deserialize(&payload.value_bytes, Some(self.keys_manager.clone()))?;
            let params_option = if params.is_null() { None } else { Some(params) };

            // Process the request locally using extracted topic and params
            self.logger.debug(format!(
                "[handle_network_request] will call local_request for path {}",
                &payload.path
            ));

            let topic_path = match TopicPath::from_full_path(&payload.path) {
                Ok(tp) => tp,
                Err(e) => {
                    self.logger.error(format!(
                        "Failed to parse topic path: {path} : {e}",
                        path = &payload.path,
                        e = e
                    ));
                    continue;
                }
            };
            let network_id = topic_path.network_id();
            let profile_public_key = payload
                .context
                .as_ref()
                .map(|c| c.profile_public_key.clone())
                .context("No context found in payload")?;

            match self.local_request(&topic_path, params_option).await {
                Ok(response) => {
                    self.logger
                        .info("✅ [Node] Local request completed successfully");

                    // Create serialization context for encryption
                    let serialization_context = runar_serializer::traits::SerializationContext {
                        keystore: self.keys_manager.clone(),
                        resolver: self.label_resolver.clone(),
                        network_id: network_id.clone(),
                        profile_public_key: Some(profile_public_key.clone()),
                    };

                    // Serialize the response data
                    let serialized_data = response.serialize(Some(&serialization_context))?;

                    self.logger.info(format!(
                        "📤 [Node] Sending response - To: {}, Correlation: {}, Size: {} bytes",
                        message.source_node_id,
                        message.payloads[0].correlation_id,
                        serialized_data.len()
                    ));

                    // Create a payload item with the serialized response
                    let response_payload = NetworkMessagePayloadItem {
                        path: message.payloads[0].path.clone(),
                        value_bytes: serialized_data,
                        correlation_id: message.payloads[0].correlation_id.clone(),
                        context: payload.context.clone(),
                    };

                    responses.push(response_payload);
                }
                Err(e) => {
                    self.logger
                        .error(format!("❌ [Node] Local request failed - Error: {e}",));

                    // Create serialization context for encryption
                    let serialization_context = runar_serializer::traits::SerializationContext {
                        keystore: self.keys_manager.clone(),
                        resolver: self.label_resolver.clone(),
                        network_id: network_id.clone(),
                        profile_public_key: Some(profile_public_key.clone()),
                    };

                    // Create a map for the error response
                    let mut error_map = HashMap::new();
                    error_map.insert("error".to_string(), ArcValue::new_primitive(true));
                    error_map.insert(
                        "message".to_string(),
                        ArcValue::new_primitive(e.to_string()),
                    );
                    let error_value = ArcValue::new_map(error_map);

                    // Serialize the error value
                    let serialized_error = error_value.serialize(Some(&serialization_context))?;

                    self.logger.debug(format!(
                        "📤 [Node] Sending error response - To: {}, Size: {} bytes",
                        message.source_node_id,
                        serialized_error.len()
                    ));

                    // Create payload item with serialized error
                    let error_payload = NetworkMessagePayloadItem {
                        path: message.payloads[0].path.clone(),
                        value_bytes: serialized_error,
                        correlation_id: message.payloads[0].correlation_id.clone(),
                        context: payload.context.clone(),
                    };

                    responses.push(error_payload);
                }
            }
        }

        // Create response message - destination is the original source
        let response_message = NetworkMessage {
            source_node_id: local_peer_id, // Source is now self
            destination_node_id: message.source_node_id.clone(), // Destination is the original request source
            message_type: MESSAGE_TYPE_RESPONSE,
            payloads: responses,
        };

        // Transport will handle writing the response on the incoming stream; just return it.

        Ok(Some(response_message))
    }

    /// Handle a network response
    async fn handle_network_response(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        // Skip if networking is not enabled
        if !self.supports_networking {
            self.logger
                .warn("Received network response but networking is disabled");
            return Ok(None);
        }

        let payload_item = &message.payloads[0];
        let topic = &payload_item.path;
        let correlation_id = &payload_item.correlation_id;

        // Only process if we have an actual correlation ID
        self.logger.debug(format!(
            "Processing response for topic {topic}, correlation ID: {correlation_id}"
        ));

        // Find any pending response handlers
        if let Some(pending_request_sender) =
            self.pending_requests.write().await.remove(correlation_id)
        {
            self.logger.debug(format!(
                "Found response handler for correlation ID: {correlation_id}"
            ));

            // Deserialize the payload data
            let payload_data = ArcValue::deserialize(
                &payload_item.value_bytes,
                None, // TODO: Pass keystore from transport layer
            )?;

            // Send the response (which is ArcValue) through the oneshot channel
            // payload_data is already ArcValue. If the original response was 'None',
            // serializer.deserialize_value should produce ArcValue::null().
            match pending_request_sender.send(Ok(payload_data)) {
                Ok(_) => self.logger.debug(format!(
                    "Successfully sent response for correlation ID: {correlation_id}"
                )),
                Err(e) => self.logger.error(format!(
                    "Failed to send response data for correlation ID {correlation_id}: {e:?}"
                )),
            } // Closes match pending_request_sender.send(Ok(payload_data))
        } else {
            // This is the else for `if let Some(pending_request_sender)`
            self.logger.warn(format!(
                "No response handler found for correlation ID: {correlation_id}"
            ));
        } // Closes else block for if let Some
        Ok(None)
    } // Closes async fn handle_network_response

    /// Handle a network event
    async fn handle_network_event(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        // Skip if networking is not enabled
        if !self.supports_networking {
            self.logger
                .warn("Received network event but networking is disabled");
            return Ok(None);
        }

        self.logger
            .debug(format!("Handling network event: {message:?}"));

        // Process each payload separately
        for payload_item in &message.payloads {
            let topic = &payload_item.path;

            // Skip processing if topic is empty
            if topic.is_empty() {
                self.logger
                    .warn("Received event with empty topic, skipping");
                continue; // Continues the for loop in handle_network_event
            }

            // Create topic path
            let topic_path = match TopicPath::new(topic, &self.network_id) {
                Ok(tp) => tp,
                Err(e) => {
                    self.logger
                        .error(format!("Invalid topic path for event: {e}"));
                    continue;
                }
            };

            // Deserialize the payload data
            let payload = ArcValue::deserialize(
                &payload_item.value_bytes,
                None, // TODO: Pass keystore from transport layer
            )?;

            // Create proper event context
            let event_context = Arc::new(EventContext::new(
                &topic_path,
                Arc::new(self.clone()),
                false,
                self.logger.clone(),
            ));

            // Get subscribers for this topic
            let subscribers = self
                .service_registry
                .get_local_event_subscribers(&topic_path)
                .await;

            if subscribers.is_empty() {
                self.logger
                    .debug(format!("No subscribers found for topic: {topic}"));
                continue;
            }
            let payload_option = if payload.is_null() {
                None
            } else {
                Some(payload)
            };
            // Notify all subscribers
            for (_subscription_id, callback, _options) in subscribers {
                let ctx = event_context.clone();
                // Invoke callback. errors are logged but not propagated to avoid affecting other subscribers
                let result = callback(ctx, payload_option.clone()).await;
                if let Err(e) = result {
                    self.logger
                        .error(format!("Error in subscriber callback: {e}"));
                }
            }
        }

        Ok(None)
    }

    pub async fn local_request(
        &self,
        topic_path: &TopicPath,
        payload: Option<ArcValue>,
    ) -> Result<ArcValue> {
        self.logger
            .debug(format!("Processing request: {topic_path}"));

        // First check for local handlers
        if let Some((handler, registration_path)) = self
            .service_registry
            .get_local_action_handler(topic_path)
            .await
        {
            self.logger
                .debug(format!("Executing local handler for: {topic_path}"));

            // Create request context
            let mut context =
                RequestContext::new(topic_path, Arc::new(self.clone()), self.logger.clone());

            // Extract parameters using the original registration path
            if let Ok(params) = topic_path.extract_params(&registration_path.action_path()) {
                // Populate the path_params in the context
                context.path_params = params;
                self.logger.debug(format!(
                    "Extracted path parameters: {:?}",
                    context.path_params
                ));
            }

            // Execute the handler and return result
            return handler(payload, context).await;
        } else {
            Err(anyhow!("No local handler found for topic: {topic_path}"))
        }
    }

    /// Handle a request for a specific action - Stable API DO NOT CHANGE UNLESS EXPLICITLY ASKED TO DO SO!
    ///
    /// INTENTION: Route a request to the appropriate action handler,
    /// first checking local handlers and then remote handlers.
    /// Apply load balancing when multiple remote handlers are available.
    ///
    /// This is the central request routing mechanism for the Node.
    pub async fn request<P>(&self, path: impl Into<String>, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        let request_payload_av = payload.map(|p| p.into_arc_value());
        let path_string = path.into();
        let topic_path = match TopicPath::new(&path_string, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Failed to parse topic path: {path_string} : {e}",)),
        };

        self.logger
            .debug(format!("Processing request: {topic_path}"));

        // First check local service state - if no state exists, no local service exists
        let service_topic = TopicPath::new_service(&self.network_id, &topic_path.service_path());
        let service_state = self.service_registry.get_local_service_state(&service_topic).await;

        // If service state exists, check if it's running
        if let Some(state) = service_state {
            if state != ServiceState::Running {
                self.logger.debug(format!(
                    "Service {} is in {:?} state, trying remote handlers",
                    topic_path.service_path(),
                    state
                ));
                // Try remote handlers instead
                match self.remote_request(topic_path.as_str(), request_payload_av).await {
                    Ok(response) => return Ok(response),
                    Err(_) => {
                        // Remote request failed - return state-specific error since we know local service exists but is not running
                        return Err(anyhow!("Service is in {} state", state));
                    }
                }
            }
        }

        // Service is either running or doesn't exist locally - check for local handler
        if let Some((handler, registration_path)) = self
            .service_registry
            .get_local_action_handler(&topic_path)
            .await
        {
            self.logger
                .debug(format!("Executing local handler for: {topic_path}"));

            // Create request context
            let mut context =
                RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone());

            // Extract parameters using the original registration path
            if let Ok(path_params) = topic_path.extract_params(&registration_path.action_path()) {
                // Populate the path_params in the context
                context.path_params = path_params;
                self.logger.debug(format!(
                    "Extracted path parameters: {:?}",
                    context.path_params
                ));
            }

            // Execute the handler and return result
            let response_av = handler(request_payload_av.clone(), context).await?;
            return Ok(response_av);
        }

        // No local handler found - try remote handlers
        self.remote_request(topic_path.as_str(), request_payload_av).await
    }

    pub async fn remote_request<P>(&self, path: impl Into<String>, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        let request_payload_av = payload.map(|p| p.into_arc_value());
        let path_string = path.into();
        let topic_path = match TopicPath::new(&path_string, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Failed to parse topic path: {path_string} : {e}",)),
        };

        self.logger
            .debug(format!("Processing remote request: {topic_path}"));

        // Look for remote handlers
        let remote_handlers = self
            .service_registry
            .get_remote_action_handlers(&topic_path)
            .await;
        if !remote_handlers.is_empty() {
            self.logger.debug(format!(
                "Found {} remote handlers for: {}",
                remote_handlers.len(),
                topic_path
            ));

            // Apply load balancing strategy to select a handler
            let load_balancer = self.load_balancer.read().await;
            let handler_index = load_balancer.select_handler(
                &remote_handlers,
                &RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone()),
            );

            // Get the selected handler
            let handler = &remote_handlers[handler_index];

            self.logger.debug(format!(
                "Selected remote handler {} of {} for: {}",
                handler_index + 1,
                remote_handlers.len(),
                topic_path
            ));

            // Create request context
            let context =
                RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone());

            // For remote handlers, we don't have the registration path
            // In the future, we should enhance the remote handler registry to include registration paths

            // Execute the selected handler
            let response_av = handler(request_payload_av.clone(), context).await?;
            return Ok(response_av);
        }

        // No remote handlers found
        Err(anyhow!("No handler found for action: {topic_path}"))
    }

    /// Publish with options - Helper method to implement the publish_with_options functionality
    async fn publish_with_options(
        &self,
        topic: impl Into<String>,
        data: Option<ArcValue>,
        options: PublishOptions,
    ) -> Result<()> {
        let topic_string = topic.into();
        // Check for valid topic path
        let topic_path = match TopicPath::new(&topic_string, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Invalid topic path: {e}")),
        };

        // Publish to local subscribers
        let local_subscribers = self
            .service_registry
            .get_local_event_subscribers(&topic_path)
            .await;
        for (_subscription_id, callback, _options) in local_subscribers {
            // Create an event context for this subscriber
            let event_context = Arc::new(EventContext::new(
                &topic_path,
                Arc::new(self.clone()),
                true,
                self.logger.clone(),
            ));
            // Execute the callback with correct arguments
            if let Err(e) = callback(event_context, data.clone()).await {
                self.logger.error(format!(
                    "Error in local event handler for {topic_string}: {e}"
                ));
            }
        }

        // Broadcast to remote nodes if requested and network is available
        if options.broadcast && self.supports_networking {
            if let Some(_transport) = &*self.network_transport.read().await {
                //TODO
                // Log message since we can't implement send yet
                self.logger
                    .debug(format!("Would broadcast event {topic_string} to network"));
            }
        }

        Ok(())
    }

    /// Handle remote node capabilities
    ///
    /// INTENTION: Process capabilities from a remote node by creating
    /// RemoteService instances and making them available locally.
    async fn process_remote_capabilities(
        &self,
        new_peer: NodeInfo,
    ) -> Result<Vec<Arc<RemoteService>>> {
        let new_peer_node_id = compact_id(&new_peer.node_public_key);
        self.logger.debug(format!(
            "Processing remote capabilities from node {new_peer_node_id}"
        ));
        //check if we alrady know about this service..
        let mut known_peers = self.known_peers.write().await;
        if let Some(existing_peer) = known_peers.get(&new_peer_node_id) {
            //check if node info is older then the stored peer
            if new_peer.version > existing_peer.version {
                self.logger.debug(format!("Node {new_peer_node_id} has new version {new_peer_version}, removing and adding again", new_peer_version = new_peer.version));
                self.remove_peer_services(existing_peer).await?;
                //remove and add again
                known_peers.remove(&new_peer_node_id);
                known_peers.insert(new_peer_node_id.clone(), new_peer.clone());
                let res = self.add_new_peer(new_peer).await;
                self.publish_with_options(format!("$registry/peer/{new_peer_node_id}/updated"), Some(ArcValue::new_primitive(new_peer_node_id.clone())), PublishOptions::local_only()).await?;
                return res;
            }
        } else {
            known_peers.insert(new_peer_node_id.clone(), new_peer.clone());
            let res = self.add_new_peer(new_peer).await;
            self.publish_with_options(format!("$registry/peer/{new_peer_node_id}/discovered"), Some(ArcValue::new_primitive(new_peer_node_id.clone())), PublishOptions::local_only()).await?;
            return res;
        }
        drop(known_peers);

        Ok(Vec::new())
    }

    async fn remove_peer_services(
        &self,
        existing_peer: &NodeInfo,
    ) -> Result<Vec<Arc<RemoteService>>> {
        //remove all the services
        let services = &existing_peer.services;
        for service_to_remove in services {
            let service_path = TopicPath::new(
                &service_to_remove.service_path,
                service_to_remove.network_id.as_str(),
            )
            .unwrap();
            self.service_registry
                .remove_remote_service(&service_path)
                .await?;
        }
        Ok(Vec::new())
    }

    async fn add_new_peer(&self, node_info: NodeInfo) -> Result<Vec<Arc<RemoteService>>> {
        let capabilities = &node_info.services;
        self.logger.info(format!(
            "Processing {count} capabilities from node {peer_node_id}",
            count = capabilities.len(),
            peer_node_id = compact_id(&node_info.node_public_key)
        ));

        // Check if capabilities is empty
        if capabilities.is_empty() {
            self.logger.info("Received empty capabilities list.");
            return Ok(Vec::new()); // Nothing to process
        }

        // Get the local node ID
        let local_peer_id = self.node_id.clone();

        let peer_node_id = compact_id(&node_info.node_public_key);
        // Create RemoteService instances directly
        let rs_config = CreateRemoteServicesConfig {
            capabilities: capabilities.clone(),
            peer_node_id: peer_node_id.clone(),
            request_timeout_ms: self.config.request_timeout_ms,
        };

        // Acquire the transport (should be initialized by now)
        let transport_guard = self.network_transport.read().await;
        let transport_arc = transport_guard
            .clone()
            .ok_or_else(|| anyhow!("Network transport not available"))?;

        let rs_dependencies = RemoteServiceDependencies {
            network_transport: transport_arc,
            local_node_id: local_peer_id,
            // pending_requests: self.pending_requests.clone(),
            logger: self.logger.clone(),
        };

        let remote_services =
            match RemoteService::create_from_capabilities(rs_config, rs_dependencies).await {
                Ok(services) => services,
                Err(e) => {
                    self.logger.error(format!(
                        "Failed to create remote services from capabilities: {e}"
                    ));
                    return Err(e);
                }
            };

        // Register each service and initialize it to register its handlers
        for service in &remote_services {
            // Register the service instance with the registry
            if let Err(e) = self
                .service_registry
                .register_remote_service(service.clone())
                .await
            {
                self.logger.error(format!(
                    "Failed to register remote service '{path}': {e}",
                    path = service.path()
                ));
                continue; // Skip initialization if registration fails
            }

            // Create RemoteLifecycleContext for the service to register its handlers
            // The context needs a reference back to the registry (as RegistryDelegate)
            // The Node itself implements RegistryDelegate
            let registry_delegate: Arc<dyn RegistryDelegate + Send + Sync> = Arc::new(self.clone());

            // The TopicPath for the context should represent the service itself
            let service_topic_path =
                TopicPath::new(service.path(), &self.network_id).map_err(|e| {
                    anyhow!("Failed to create TopicPath for remote service init: {}", e)
                })?;

            // Pass TopicPath by reference
            let context = RemoteLifecycleContext::new(&service_topic_path, self.logger.clone())
                .with_registry_delegate(registry_delegate);

            // Initialize the service - this triggers handler registration via the context
            if let Err(e) = service.init(context).await {
                self.logger.error(format!(
                    "Failed to initialize remote service '{path}' (handler registration): {e}",
                    path = service.path()
                ));
            }
            self.service_registry.update_remote_service_state(&service_topic_path, ServiceState::Running).await?;
        }

        self.logger.info(format!(
            "Successfully processed {count} remote services from node {peer_node_id}",
            count = remote_services.len(),
        ));

        Ok(remote_services)
    }

    //this function is debounced since it can be called in rapid suyccession.. it is debounced for 5 seconds..
    // it will then call the notify_node_change_impl  which will use the transposter to send a handshake message with the latest node info to all known peers.
    /// Debounced notification of node change.
    ///
    /// INTENTION: This function is debounced to avoid flooding the network with repeated notifications.
    /// If called multiple times in rapid succession, only the last call within a 5 second window will
    /// trigger the actual notification. After the debounce period, it delegates to notify_node_change_impl,
    /// which sends the latest node info to all known peers via the transport.
    pub async fn notify_node_change(&self) -> Result<()> {
        let debounce_task = self.debounce_notify_task.clone();
        let this = self.clone();
        // Cancel any existing debounce task
        {
            let mut guard = debounce_task.lock().await;
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        // Spawn a new debounce task
        let handle = tokio::spawn(async move {
            sleep(Duration::from_secs(2)).await;
            // Ignore errors from notify_node_change_impl; log if needed
            if let Err(e) = this.notify_node_change_impl().await {
                this.logger.warn(format!(
                    "notify_node_change_impl failed after debounce: {e}"
                ));
            }
        });
        // Store the new handle
        {
            let mut guard = debounce_task.lock().await;
            *guard = Some(handle);
        }
        Ok(())
    }

    pub async fn notify_node_change_impl(&self) -> Result<()> {
        let local_node_info = self.get_local_node_info().await?;

        self.logger.info(format!(
            "Notifying node change - version: {version}",
            version = local_node_info.version
        ));

        let transport_guard = self.network_transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            transport.update_peers(local_node_info).await?;
            Ok(())
        } else {
            Err(anyhow!("No transport available"))
        }
    }

    /// Collect capabilities of all local services
    ///
    /// INTENTION: Gather capability information from all local services.
    /// This includes service metadata and all registered actions.
    ///
    pub async fn collect_local_service_capabilities(&self) -> Result<Vec<ServiceMetadata>> {
        // Get all local services
        let service_paths: HashMap<TopicPath, Arc<ServiceEntry>> =
            self.service_registry.get_local_services().await;
        if service_paths.is_empty() {
            return Ok(Vec::new());
        }

        // Build capability information for each service
        let mut services = Vec::new();

        for (service_path, service_entry) in service_paths {
            let service = &service_entry.service;
            // Skip internals services:
            if INTERNAL_SERVICES.contains(&service.path()) {
                continue;
            }

            // Get the service actions from registry
            if let Some(meta) = self
                .service_registry
                .get_service_metadata(&service_path)
                .await
            {
                services.push(meta);
            }
        }

        // Log all capabilities collected
        self.logger.info(format!(
            "Collected {count} services metadata",
            count = services.len()
        ));
        Ok(services)
    }

    /// Get the node's public network address
    ///
    /// This retrieves the address that other nodes should use to connect to this node.
    async fn get_node_address(&self) -> Result<String> {
        // If networking is disabled, return empty string
        if !self.supports_networking {
            return Ok(String::new());
        }

        // First, try to get the address from the network transport if available
        let transport_guard = self.network_transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            let address = transport.get_local_address();
            if !address.is_empty() {
                return Ok(address);
            }
        }

        // If transport is not available or didn't provide an address,
        if let Some(network_config) = &self.config.network_config {
            return Ok(network_config.transport_options.bind_address.to_string());
        }

        // If networking is disabled or no address is available, return empty string
        Ok(String::new())
    }

    /// Get information about the local node
    ///
    /// INTENTION: Create a complete NodeInfo structure for this node,
    /// including its network IDs, address, and capabilities.
    pub async fn get_local_node_info(&self) -> Result<NodeInfo> {
        let mut address = self.get_node_address().await?;

        // Check if address starts with 0.0.0.0 and replace with a usable IP address
        if address.starts_with("0.0.0.0") {
            // Try to get a real network interface IP address
            if let Ok(ip) = self.get_non_loopback_ip() {
                address = address.replace("0.0.0.0", &ip);
                self.logger
                    .debug(format!("Replaced 0.0.0.0 with network interface IP: {ip}"));
            } else {
                // Fall back to localhost if we can't get a real IP
                address = address.replace("0.0.0.0", "127.0.0.1");
                self.logger
                    .debug("Replaced 0.0.0.0 with localhost (127.0.0.1)");
            }
        }

        let services = self.collect_local_service_capabilities().await?;
        let node_info = NodeInfo {
            node_public_key: self.node_public_key.clone(),
            network_ids: self.network_ids.clone(),
            addresses: vec![address],
            services,
            version: self.registry_version.load(Ordering::SeqCst),
        };

        Ok(node_info)
    }

    /// Get a non-loopback IP address from the local network interfaces
    fn get_non_loopback_ip(&self) -> Result<String> {
        use socket2::{Domain, Socket, Type};
        use std::net::SocketAddr;

        // Create a UDP socket
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

        // "Connect" to a public IP (doesn't actually send anything)
        // This forces the OS to choose the correct network interface
        let addr: SocketAddr = "8.8.8.8:80".parse()?;
        socket.connect(&addr.into())?;

        // Get the local address associated with the socket
        let local_addr = socket.local_addr()?;
        let ip = match local_addr.as_socket_ipv4() {
            Some(addr) => addr.ip().to_string(),
            None => return Err(anyhow!("Failed to get IPv4 address")),
        };

        self.logger
            .debug(format!("Discovered local network interface IP: {ip}"));
        Ok(ip)
    }

    /// Shutdown the network components
    async fn shutdown_network(&self) -> Result<()> {
        // Early return if networking is disabled
        if !self.supports_networking {
            self.logger
                .debug("Network shutdown skipped - networking is disabled");
            return Ok(());
        }

        self.logger
            .info("Shutting down network discovery providers");

        //discovery stop all =discovery providers
        let discovery_guard = self.network_discovery_providers.read().await;
        if let Some(discovery) = discovery_guard.as_ref() {
            for provider in discovery {
                provider.shutdown().await?;
            }
        }

        self.logger.info("Shutting down transport");

        // transport need to be shut down properly
        let transport_guard = self.network_transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            transport.stop().await?;
        }

        Ok(())
    }
}

#[async_trait]
impl NodeDelegate for Node {
    async fn request<P>(
        &self,
        path: impl Into<String> + Send,
        payload: Option<P>,
    ) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        // Delegate directly to our (now generic) inherent implementation.
        self.request(path, payload).await
    }

    async fn publish(&self, topic: String, data: Option<ArcValue>) -> Result<()> {
        // Create default options
        let options = PublishOptions {
            broadcast: true,
            guaranteed_delivery: false,
            retention_seconds: None,
            target: None,
        };

        self.publish_with_options(topic, data, options).await
    }

    async fn subscribe(
        &self,
        topic: String,
        callback: EventHandler,
    ) -> Result<String> {
        // For the basic subscribe, create default metadata.
        // The full topic path (including network_id) is handled by subscribe_with_options.
        // Node::subscribe provides a simplified interface, using default registration options.
        self.subscribe_with_options(topic, callback, EventRegistrationOptions::default())
            .await
    }

    async fn subscribe_with_options(
        &self,
        topic: String, // This is the service-relative path, e.g., "math_service/numbers"
        callback: EventHandler, // Changed to use the type alias
        options: EventRegistrationOptions, // Changed from SubscriptionOptions
    ) -> Result<String> {
        // The `topic` parameter is the service-relative path (e.g., "service_name/event_name").
        // This will be combined with `self.network_id` to form the full TopicPath for registry storage.
        let topic_path = TopicPath::new(&topic, &self.network_id)
            .map_err(|e| anyhow!(
                "Invalid topic string for subscribe_with_options: {e}. Topic: '{topic}', Network ID: '{network_id}'", 
                network_id=self.network_id
            ))?;
 
        self.logger.debug(format!(
            "Node: subscribe_with_options called for topic_path '{topic_path}'",
            topic_path=topic_path.as_str()
        ));

        let subscription_id = self
            .service_registry
            .register_local_event_subscription(&topic_path, callback.into(), options)
            .await?;

        if self.running.load(Ordering::SeqCst) {
            self.registry_version.fetch_add(1, Ordering::SeqCst);
            self.notify_node_change().await?;
        }

        Ok(subscription_id)
    }

    async fn unsubscribe(&self, subscription_id: Option<&str>) -> Result<()> {
        if let Some(id) = subscription_id {
            self.logger
                .debug(format!("Unsubscribing from with ID: {id}"));
            // Directly forward to service registry's method
            let registry = self.service_registry.clone();
            match registry.unsubscribe_local(id).await {
                Ok(_) => {
                    self.logger.debug(format!(
                        "Successfully unsubscribed locally from  with id {id}"
                    ));
                }
                Err(e) => {
                    self.logger.error(format!(
                        "Failed to unsubscribe locally from  with id {id}: {e}"
                    ));
                    return Err(anyhow!("Failed to unsubscribe locally: {e}"));
                }
            }
            //if started... need to increment  -> registry_version
            if self.running.load(Ordering::SeqCst) {
                self.registry_version.fetch_add(1, Ordering::SeqCst);
                self.notify_node_change().await?;
            }
            Ok(())
        } else {
            Err(anyhow!("Subscription ID is required"))
        }
    }

    /// Register an action handler for a specific path
    ///
    /// INTENTION: Allow services to register handlers for actions through the NodeDelegate.
    /// This consolidates all node interactions through a single interface.
    async fn register_action_handler(
        &self,
        topic_path: TopicPath,
        handler: ActionHandler,
        metadata: Option<ActionMetadata>,
    ) -> Result<()> {
        self.service_registry
            .register_local_action_handler(&topic_path, handler, metadata)
            .await
    }
 
    /// Wait for an event to occur with a timeout
    ///
    /// INTENTION: Allow services to wait for specific events to occur
    /// before proceeding with their logic.
    ///
    /// Returns Ok(ArcValue) with the event payload if event occurs within timeout,
    /// or Err with timeout message if no event occurs.
    async fn on(&self, topic: impl Into<String> + Send, timeout: std::time::Duration) -> Result<Option<ArcValue>> {
        self.on(topic, timeout).await
    }
}

#[async_trait]
impl KeysDelegate for Node {
    async fn ensure_symmetric_key(&self, key_name: &str) -> Result<ArcValue> {
        let mut keys_manager = self.keys_manager_mut.lock().unwrap();
        let key = keys_manager.ensure_symmetric_key(key_name)?;
        Ok(ArcValue::new_bytes(key))
    }
}

#[async_trait]
impl RegistryDelegate for Node {
    /// Get service state
    async fn get_local_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.service_registry.get_local_service_state(service_path).await
    }

    async fn get_remote_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.service_registry.get_remote_service_state(service_path).await
    }

    /// Get metadata for a specific service
    async fn get_service_metadata(&self, service_path: &TopicPath) -> Option<ServiceMetadata> {
        self.service_registry
            .get_service_metadata(service_path)
            .await
    }

    /// Get metadata for all registered services with an option to filter internal services
    async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> HashMap<String, ServiceMetadata> {
        self.service_registry
            .get_all_service_metadata(include_internal_services)
            .await
    }

    /// Get metadata for all actions under a specific service path
    async fn get_actions_metadata(&self, service_topic_path: &TopicPath) -> Vec<ActionMetadata> {
        self.service_registry
            .get_actions_metadata(service_topic_path)
            .await
    }

    /// Register a remote action handler
    ///
    /// INTENTION: Delegates to the service registry to register a remote action handler.
    /// This allows RemoteLifecycleContext to register handlers without direct access
    /// to the service registry.
    async fn register_remote_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
    ) -> Result<()> {
        // Delegate to the service registry
        self.service_registry
            .register_remote_action_handler(topic_path, handler)
            .await
    }

    /// Remove a remote action handler
    async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()> {
        // Delegate to the service registry
        self.service_registry
            .remove_remote_action_handler(topic_path)
            .await
    }

    async fn register_remote_event_handler(&self, topic_path: &TopicPath, handler: EventHandler) -> Result<()> {
        self.service_registry
            .register_remote_event_handler(topic_path, handler)
            .await
    }

    async fn remove_remote_event_handler(&self, topic_path: &TopicPath) -> Result<()> {
        self.service_registry
            .remove_remote_event_handler(topic_path)
            .await
    }

    async fn update_local_service_state_if_valid(
        &self,
        service_path: &TopicPath,
        new_state: ServiceState,
        current_state: ServiceState,
    ) -> Result<()> {
        // Delegate to the service registry
        self.service_registry
            .update_local_service_state_if_valid(service_path, new_state, current_state)
            .await
    }

    async fn validate_pause_transition(&self, service_path: &TopicPath) -> Result<()> {
        // Delegate to the service registry
        self.service_registry.validate_pause_transition(service_path).await
    }

    async fn validate_resume_transition(&self, service_path: &TopicPath) -> Result<()> {
        // Delegate to the service registry
        self.service_registry.validate_resume_transition(service_path).await
    }
}

// Implement Clone for Node
impl Clone for Node {
    // The debounce_notify_task is NOT cloned (new Arc/Mutex/None) because debounce is per-instance, not shared.
    // This is intentional: cloned nodes start with no pending debounce.

    fn clone(&self) -> Self {
        Self {
            debounce_notify_task: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            network_id: self.network_id.clone(),
            network_ids: self.network_ids.clone(),
            node_id: self.node_id.clone(),
            node_public_key: self.node_public_key.clone(),
            config: self.config.clone(),
            service_registry: self.service_registry.clone(),
            known_peers: self.known_peers.clone(),
            logger: self.logger.clone(),
            running: AtomicBool::new(self.running.load(Ordering::SeqCst)),
            supports_networking: self.supports_networking,
            network_transport: self.network_transport.clone(),
            network_discovery_providers: self.network_discovery_providers.clone(),
            load_balancer: self.load_balancer.clone(),
            pending_requests: self.pending_requests.clone(),
            label_resolver: self.label_resolver.clone(),
            registry_version: self.registry_version.clone(),
            keys_manager: self.keys_manager.clone(),
            keys_manager_mut: self.keys_manager_mut.clone(),
        }
    }
}
