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
use runar_common::routing::{PathTrie, TopicPath};
use runar_keys::{node::NodeKeyManagerState, NodeKeyManager};

use runar_schemas::{ActionMetadata, NodeInfo, NodeMetadata, ServiceMetadata};
use runar_serializer::arc_value::AsArcValue;
use runar_serializer::traits::{ConfigurableLabelResolver, KeyMappingConfig, LabelResolver};
use runar_serializer::{ArcValue, LabelKeyInfo};
use runar_transporter::discovery::{DiscoveryEvent, PeerInfo};
use runar_transporter::network_config::{DiscoveryProviderConfig, NetworkConfig, TransportType};
use runar_transporter::transport::{
    GetLocalNodeInfoCallback, NetworkError, NetworkMessagePayloadItem, OneWayMessageHandler,
    PeerConnectedCallback, PeerDisconnectedCallback, MESSAGE_TYPE_EVENT, MESSAGE_TYPE_REQUEST,
    MESSAGE_TYPE_RESPONSE,
};
use runar_transporter::{
    DiscoveryOptions, MessageHandler, MulticastDiscovery, NetworkMessage, NetworkTransport,
    NodeDiscovery, QuicTransport,
};
use socket2;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Instant;
use tokio::time::{sleep, Duration};

use dashmap::DashMap;
use runar_macros_common::{log_debug, log_error, log_info, log_warn};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex, RwLock};

pub(crate) type NodeDiscoveryList = Vec<Arc<dyn NodeDiscovery>>;
// Type alias for service tasks to reduce complexity
type ServiceTask = (TopicPath, tokio::task::JoinHandle<()>);
// Certificate and PrivateKey types are now imported via the cert_utils module
use runar_common::logging::LoggingConfig;

use crate::services::keys_service::KeysService;
use crate::services::load_balancing::{LoadBalancingStrategy, RoundRobinLoadBalancer};
use crate::services::registry_service::RegistryService;
use crate::services::remote_service::{
    CreateRemoteServicesConfig, RemoteService, RemoteServiceDependencies,
};
use crate::services::service_registry::{
    is_internal_service, EventHandler, RemoteEventHandler, ServiceEntry, ServiceRegistry,
};
use crate::services::NodeDelegate;
use crate::services::{
    ActionHandler, EventRegistrationOptions, PublishOptions, RegistryDelegate,
    RemoteLifecycleContext, RequestContext,
};
use crate::services::{EventContext, KeysDelegate}; // Explicit import for EventContext
use crate::{AbstractService, ServiceState};

// Type aliases to reduce clippy type_complexity warnings
type RetainedDeque = std::collections::VecDeque<(std::time::Instant, Option<ArcValue>)>;
type RetainedEventsMap = dashmap::DashMap<String, RetainedDeque>;

/// Configuration for a Runar Node instance.
///
/// This struct provides all the configuration options needed to create and configure
/// a Node. It uses the builder pattern for easy configuration.
///
/// # Examples
///
/// ```rust
/// use runar_node::{NodeConfig, network::network_config::NetworkConfig};
///
/// // Basic configuration
/// let config = NodeConfig::new("my-node", "my-network");
///
/// // Advanced configuration with networking
/// let config = NodeConfig::new("my-node", "my-network")
///     .with_network_config(NetworkConfig::default())
///     .with_request_timeout(5000)
///     .with_additional_networks(vec!["backup-network".to_string()]);
/// ```
///
/// # Default Values
///
/// - `request_timeout_ms`: 30000 (30 seconds)
/// - `logging_config`: Info level logging
/// - `network_config`: None (networking disabled)
/// - `network_ids`: Empty (only default network)
///
/// # Security Note
///
/// The `key_manager_state` must be provided via `with_key_manager_state()` for production use.
/// This contains the node's cryptographic credentials and should be stored securely.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Unique identifier for this node.
    ///
    /// This ID is used for service discovery, routing, and network identification.
    /// Must be unique within the network.
    // pub node_id: String,

    /// Primary network identifier this node belongs to.
    ///
    /// All services registered without a specific network ID will use this as their default.
    /// This is the main network for peer discovery and service communication.
    pub default_network_id: String,

    /// Additional network IDs this node participates in.
    ///
    /// Allows the node to be part of multiple networks simultaneously.
    /// Services can be registered to specific networks or use the default.
    pub network_ids: Vec<String>,

    /// Network configuration for peer-to-peer communication.
    ///
    /// If `None`, networking features are disabled and the node operates in local-only mode.
    /// When provided, enables peer discovery, remote service calls, and distributed features.
    pub network_config: Option<NetworkConfig>,

    /// Logging configuration for the node and its services.
    ///
    /// Controls log levels, output format, and logging destinations.
    /// If `None`, default Info-level logging is applied.
    pub logging_config: Option<LoggingConfig>,

    /// Serialized key manager state containing node credentials.
    ///
    /// This field is private and must be set via `with_key_manager_state()`.
    /// Contains the node's cryptographic keys and certificates.
    key_manager_state: Option<Vec<u8>>,

    /// Request timeout in milliseconds for all service requests.
    ///
    /// This timeout applies to both local and remote service calls.
    /// Default is 30 seconds (30000ms).
    pub request_timeout_ms: u64,
}

impl NodeConfig {
    /// Create a new Node configuration with the specified node ID and network ID.
    ///
    /// This constructor creates a basic configuration suitable for development and testing.
    /// For production use, you must call `with_key_manager_state()` to provide the node's
    /// cryptographic credentials.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Unique identifier for this node
    /// * `default_network_id` - Primary network this node belongs to
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::NodeConfig;
    ///
    /// // Basic configuration
    /// let config = NodeConfig::new("my-node", "my-network");
    ///
    /// // Production configuration requires key manager state
    /// let serialized_keys = vec![1, 2, 3, 4]; // Example key data
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_key_manager_state(serialized_keys);
    /// ```
    pub fn new(default_network_id: impl Into<String>) -> Self {
        Self {
            default_network_id: default_network_id.into(),
            network_ids: Vec::new(),
            network_config: None,
            logging_config: Some(LoggingConfig::default_info()), // Default to Info logging
            key_manager_state: None, // Must be set via with_key_manager_state()
            request_timeout_ms: 30000, // 30 seconds
        }
    }

    /// Add network configuration to enable peer-to-peer communication.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration including transport settings and discovery options
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{NodeConfig, network::network_config::NetworkConfig};
    ///
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_network_config(NetworkConfig::default());
    /// ```
    pub fn with_network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    /// Configure logging behavior for the node and its services.
    ///
    /// # Arguments
    ///
    /// * `config` - Logging configuration specifying levels, format, and destinations
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{NodeConfig, config::LoggingConfig};
    ///
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_logging_config(LoggingConfig::default_info());
    /// ```
    pub fn with_logging_config(mut self, config: LoggingConfig) -> Self {
        self.logging_config = Some(config);
        self
    }

    /// Add additional network IDs for multi-network participation.
    ///
    /// This allows the node to participate in multiple networks simultaneously.
    /// Services can be registered to specific networks or use the default network.
    ///
    /// # Arguments
    ///
    /// * `network_ids` - Vector of additional network identifiers
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::NodeConfig;
    ///
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_additional_networks(vec!["backup".to_string(), "testing".to_string()]);
    /// ```
    pub fn with_additional_networks(mut self, network_ids: Vec<String>) -> Self {
        self.network_ids = network_ids;
        self
    }

    /// Set the request timeout for all service requests.
    ///
    /// This timeout applies to both local and remote service calls.
    /// The default is 30 seconds (30000ms).
    ///
    /// # Arguments
    ///
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::NodeConfig;
    ///
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_request_timeout(5000); // 5 second timeout
    /// ```
    pub fn with_request_timeout(mut self, timeout_ms: u64) -> Self {
        self.request_timeout_ms = timeout_ms;
        self
    }

    /// Set the serialized key manager state for production use.
    ///
    /// This method is required for production deployments. The key manager state
    /// contains the node's cryptographic credentials and must be provided securely.
    ///
    /// # Arguments
    ///
    /// * `key_state_bytes` - Serialized key manager state
    ///
    /// # Security Note
    ///
    /// The key manager state contains sensitive cryptographic material and should
    /// be stored securely and transmitted over secure channels.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::NodeConfig;
    ///
    /// let secure_key_bytes = vec![1, 2, 3, 4]; // Example key data
    /// let config = NodeConfig::new("my-node", "my-network")
    ///     .with_key_manager_state(secure_key_bytes);
    /// ```
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
            "NodeConfig: default_network:{} request_timeout:{}ms",
            self.default_network_id, self.request_timeout_ms
        )?;

        // Add network configuration details if available
        if let Some(network_config) = &self.network_config {
            write!(f, " {network_config}")?;
        }

        Ok(())
    }
}

/// The main runtime for the Runar system.
///
/// The Node is the central coordinator that manages services, handles networking,
/// and provides the communication infrastructure for distributed applications.
///
/// # Key Responsibilities
///
/// - **Service Management**: Register, start, stop, and manage service lifecycles
/// - **Request Routing**: Route requests to appropriate services based on topic paths
/// - **Event Publishing**: Handle publish/subscribe patterns for loose coupling
/// - **Network Coordination**: Manage peer connections and remote service discovery
/// - **Load Balancing**: Distribute requests across multiple service instances
///
/// # Lifecycle
///
/// 1. **Creation**: Node is created with configuration
/// 2. **Service Registration**: Services are added via `add_service()`
/// 3. **Startup**: `start()` initializes all services and networking
/// 4. **Operation**: Services handle requests and publish events
/// 5. **Shutdown**: Graceful shutdown of all services and connections
///
/// # Examples
///
/// ```rust
/// use runar_node::{Node, NodeConfig};
/// use runar_node::AbstractService;
///
/// // Define a simple service for the example
/// #[derive(Clone)]
/// struct MyService;
///
/// impl MyService {
///     fn new() -> Self { Self }
/// }
///
/// #[async_trait::async_trait]
/// impl AbstractService for MyService {
///     fn name(&self) -> &str { "MyService" }
///     fn version(&self) -> &str { "1.0.0" }
///     fn path(&self) -> &str { "my-service" }
///     fn description(&self) -> &str { "Example service" }
///     fn network_id(&self) -> Option<String> { None }
///     fn set_network_id(&mut self, _network_id: String) {}
///     async fn init(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
///     async fn start(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
///     async fn stop(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
/// }
///
/// // Example of how to use a node (conceptual)
/// async fn example_usage() -> anyhow::Result<()> {
///     // Note: This example shows the concept but would need proper
///     // key manager state to actually create a Node instance.
///     
///     // let config = NodeConfig::new("my-node", "my-network");
///     // let  node = Node::new(config).await?;
///     //
///     // Add services
///     // node.add_service(MyService::new()).await?;
///     //
///     // Start the node
///     // node.start().await?;
///     //
///     // Make requests (note: this would require the service to have action handlers)
///     // let result: String = node.request("my-service/action", None).await?;
///     
///     Ok(())
/// }
/// ```
///
/// # Thread Safety
///
/// The Node is designed to be shared across multiple threads and async tasks.
/// All public methods are safe to call concurrently.
pub struct Node {
    /// Debounce state for notify_node_change.
    ///
    /// INTENTION: Ensures that rapid successive calls to notify_node_change only trigger a single
    /// notification after a 1s debounce window. This prevents unnecessary network traffic and ensures
    /// only the latest node state is broadcast. Internal use only; not exposed outside Node.
    debounce_notify_task: std::sync::Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Default network id to be used when service are added without a network ID
    network_id: String,

    //network_ids that this node participates in.
    network_ids: Vec<String>,

    /// The node ID for this node
    node_id: String,

    node_public_key: Vec<u8>,

    /// Configuration for this node
    config: Arc<NodeConfig>,

    /// The service registry for this node
    service_registry: Arc<ServiceRegistry>,

    // Centralized peer directory (single source of truth)
    // peer_directory: Arc<PeerDirectory>,
    remote_node_info: Arc<DashMap<String, NodeInfo>>,

    // Debounce repeated discovery events per peer
    discovery_seen_times: Arc<DashMap<String, Instant>>,

    /// Logger instance
    logger: Arc<Logger>,

    /// Flag indicating if the node is running
    running: AtomicBool,

    /// Flag indicating if this node supports networking
    /// This is set when networking is enabled in the config
    supports_networking: bool,

    /// Network transport for connecting to remote nodes
    network_transport: Arc<RwLock<Option<Arc<dyn NetworkTransport>>>>,

    network_discovery_providers: Arc<RwLock<Option<NodeDiscoveryList>>>,

    /// Load balancer for selecting remote handlers
    load_balancer: Arc<RwLock<dyn LoadBalancingStrategy>>,

    /// Pending requests waiting for responses, keyed by correlation ID
    pending_requests: Arc<DashMap<String, oneshot::Sender<Result<ArcValue>>>>,

    label_resolver: Arc<dyn LabelResolver>,

    registry_version: Arc<AtomicI64>,

    keys_manager: Arc<NodeKeyManager>,

    keys_manager_mut: Arc<Mutex<NodeKeyManager>>,

    service_tasks: Arc<RwLock<Vec<ServiceTask>>>,

    local_node_info: Arc<RwLock<NodeInfo>>,

    /// Retained event store: exact full topic -> deque of (timestamp, data)
    /// Wrapped in Arc to ensure Node clones share the same storage
    retained_events: Arc<RetainedEventsMap>,
    /// Index of exact topics for wildcard lookups
    retained_index: Arc<RwLock<PathTrie<String>>>,
}

// Implementation for Node
impl Node {
    /// Remove retained events whose topic matches the given pattern (supports wildcards)
    pub async fn clear_retained_events_matching(&self, pattern: &str) -> Result<usize> {
        let topic_path = TopicPath::new(pattern, &self.network_id)
            .map_err(|e| anyhow!(format!("Invalid topic pattern: {e}")))?;
        // Find all exact topic keys that match the pattern via the trie
        let matched: Vec<String> = {
            let idx = self.retained_index.read().await;
            idx.find_wildcard_matches(&topic_path)
                .into_iter()
                .map(|m| m.content)
                .collect()
        };
        let mut removed = 0usize;
        for key in matched {
            if self.retained_events.remove(&key).is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Create a new Node with the given configuration.
    ///
    /// This constructor initializes a new Node instance with the specified configuration,
    /// setting up all necessary components and internal state. This is the primary
    /// entry point for creating a Node instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Node configuration including network settings and credentials
    ///
    /// # Returns
    ///
    /// Returns a new Node instance ready for service registration and startup.
    ///
    /// # Important Notes
    ///
    /// - **Services are not started**: Call `start()` separately after registering services
    /// - **Key manager state required**: Production configurations must include cryptographic credentials
    /// - **Networking disabled by default**: Enable networking via `NetworkConfig` in the configuration
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{Node, NodeConfig};
    ///
    /// // Example of how to create a node (conceptual)
    /// async fn example_usage() -> anyhow::Result<()> {
    ///     // Note: This example shows the concept but would need proper
    ///     // key manager state to actually create a Node instance.
    ///     
    ///     // let config = NodeConfig::new("my-node", "my-network");
    ///     // let _node = Node::new(config).await?;
    ///     //
    ///     // Node is ready but services aren't started yet
    ///     
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// - The configuration is invalid
    /// - Key manager state cannot be deserialized
    /// - Internal components fail to initialize
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Apply logging configuration (default to Info level if none provided)
        if let Some(logging_config) = &config.logging_config {
            logging_config.apply();
        } else {
            // Apply default Info logging when no configuration is provided
            let default_config = LoggingConfig::default_info();
            default_config.apply();
        }

        // Clone fields before moving config
        let default_network_id = config.default_network_id.clone();
        let networking_enabled = config.network_config.is_some();

        let mut network_ids = config.network_ids.clone();
        network_ids.push(default_network_id.clone());
        network_ids.dedup();

        let logger = Arc::new(Logger::new_root(Component::Node));
        let service_registry = Arc::new(ServiceRegistry::new(logger.clone()));

        // at this stage the node credentials must already exist and must be in a secure store
        let key_manager_state_bytes = config
            .key_manager_state
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Failed to load node credentials."))?;

        let key_manager_state: NodeKeyManagerState = bincode::deserialize(&key_manager_state_bytes)
            .context("Failed to deserialize node keys state")?;

        let keys_manager = NodeKeyManager::from_state(key_manager_state.clone(), logger.clone())?;
        let keys_manager_mut = NodeKeyManager::from_state(key_manager_state, logger.clone())?;

        let node_public_key = keys_manager.get_node_public_key();
        let node_id = compact_id(&node_public_key);
        logger.set_node_id(node_id.clone());

        log_info!(logger, "Successfully loaded existing node credentials.");

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

        let local_node_info = NodeInfo {
            node_public_key: node_public_key.clone(),
            network_ids: network_ids.clone(),
            addresses: vec![],
            node_metadata: NodeMetadata {
                services: vec![],
                subscriptions: vec![],
            },
            version: 0,
        };

        let node = Self {
            local_node_info: Arc::new(RwLock::new(local_node_info)),
            debounce_notify_task: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            network_id: default_network_id,
            network_ids,
            node_id,
            node_public_key,
            config: Arc::new(config),
            logger: logger.clone(),
            service_registry,
            remote_node_info: Arc::new(DashMap::new()),
            discovery_seen_times: Arc::new(DashMap::new()),
            running: AtomicBool::new(false),
            supports_networking: networking_enabled,
            network_transport: Arc::new(RwLock::new(None)),
            network_discovery_providers: Arc::new(RwLock::new(None)),
            load_balancer: Arc::new(RwLock::new(RoundRobinLoadBalancer::new())),
            pending_requests: Arc::new(DashMap::new()),
            label_resolver,
            registry_version: Arc::new(AtomicI64::new(0)),
            keys_manager,
            keys_manager_mut,
            service_tasks: Arc::new(RwLock::new(Vec::new())),
            retained_events: Arc::new(RetainedEventsMap::new()),
            retained_index: Arc::new(RwLock::new(PathTrie::new())),
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

    /// Add a service to this node.
    ///
    /// This method registers a service with the node, making its actions available
    /// for requests and allowing it to receive events. The service is initialized
    /// but not started - services are started when the node is started.
    ///
    /// # Arguments
    ///
    /// * `service` - The service to register, must implement `AbstractService`
    ///
    /// # Process
    ///
    /// 1. Validates the service path and creates a topic path
    /// 2. Initializes the service with a lifecycle context
    /// 3. Creates a service entry and registers it with the service registry
    /// 4. Updates the service state to `Initialized`
    /// 5. If the node is already running, starts the service immediately
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{Node, NodeConfig};
    /// use runar_node::AbstractService;
    ///
    /// // Define a simple service for the example
    /// #[derive(Clone)]
    /// struct MyService;
    ///
    /// impl MyService {
    ///     fn new() -> Self { Self }
    /// }
    ///
    /// #[async_trait::async_trait]
    /// impl AbstractService for MyService {
    ///     fn name(&self) -> &str { "MyService" }
    ///     fn version(&self) -> &str { "1.0.0" }
    ///     fn path(&self) -> &str { "my-service" }
    ///     fn description(&self) -> &str { "Example service" }
    ///     fn network_id(&self) -> Option<String> { None }
    ///     fn set_network_id(&mut self, _network_id: String) {}
    ///     async fn init(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    ///     async fn start(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    ///     async fn stop(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    /// }
    ///
    /// // Example of how to add a service (conceptual)
    /// async fn example_usage() -> anyhow::Result<()> {
    ///     // Note: This example shows the concept but would need proper
    ///     // key manager state to actually create a Node instance.
    ///     
    ///     // let mut config = NodeConfig::new("my-node", "my-network");
    ///     // let  node = Node::new(config).await?;
    ///     //
    ///     // Add a service
    ///     // let service = MyService::new();
    ///     // node.add_service(service).await?;
    ///     //
    ///     // Start the node to start all services
    ///     // node.start().await?;
    ///     
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// - The service path is invalid
    /// - Service initialization fails
    /// - The service registry cannot register the service
    ///
    /// # Network ID Handling
    ///
    /// If the service doesn't specify a network ID, it will use the node's default network.
    /// Services can be registered to specific networks for multi-network deployments.
    pub async fn add_service<S: AbstractService + 'static>(&self, mut service: S) -> Result<()> {
        let default_network_id = self.network_id.to_string();
        let service_network_id = match service.network_id() {
            Some(id) => id,
            None => default_network_id.clone(),
        };
        service.set_network_id(service_network_id.clone());

        let service_path = service.path();
        let service_name = service.name();

        log_info!(
            self.logger,
            "Adding service '{service_name}' to node using path {service_path}"
        );
        log_debug!(self.logger, "network id {default_network_id}");

        let registry = Arc::clone(&self.service_registry);
        // Create a proper topic path for the service
        let service_topic = match TopicPath::new(service_path, &default_network_id) {
            Ok(tp) => tp,
            Err(e) => {
                log_error!(self.logger, "Failed to create topic path for service name:{service_name} path:{service_path} error:{e}");
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
            log_error!(
                self.logger,
                "Failed to initialize service: {service_name}, error: {e}"
            );
            registry
                .update_local_service_state(&service_topic, ServiceState::Error)
                .await?;
            self.publish_with_options(
                &format!(
                    "$registry/services/{}/state/error",
                    service_topic.service_path()
                ),
                Some(ArcValue::new_primitive(service_topic.as_str().to_string())),
                PublishOptions {
                    broadcast: false,
                    guaranteed_delivery: false,
                    retain_for: Some(Duration::from_secs(10)),
                    target: None,
                },
            )
            .await?;
            return Err(anyhow!("Failed to initialize service: {e}"));
        }
        registry
            .update_local_service_state(&service_topic, ServiceState::Initialized)
            .await?;
        self.publish_with_options(
            &format!(
                "$registry/services/{}/state/initialized",
                service_topic.service_path()
            ),
            Some(ArcValue::new_primitive(service_topic.as_str().to_string())),
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(10)),
                target: None,
            },
        )
        .await?;
        // Service initialized successfully, create the ServiceEntry and register it
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let service_entry = Arc::new(ServiceEntry {
            service: Arc::new(service),
            service_topic: service_topic.clone(),
            service_state: ServiceState::Initialized,
            registration_time: now,
            last_start_time: None, // Will be set when the service is started
        });
        registry
            .register_local_service(service_entry.clone())
            .await?;

        if self.running.load(Ordering::SeqCst) {
            self.start_service(&service_topic, service_entry.as_ref(), true)
                .await;
        }

        Ok(())
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub async fn is_connected(&self, peer_node_id: &str) -> bool {
        if let Some(transport) = self.network_transport.read().await.as_ref() {
            transport.is_connected(peer_node_id).await
        } else {
            false
        }
    }

    /// Wait for an event to occur with a timeout (hot subscription).
    ///
    /// This method begins listening immediately when called, avoiding races where
    /// a one-shot event might fire before the future is awaited. It returns a
    /// `JoinHandle` that resolves when the event occurs or times out.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to listen for events on
    /// * `options` - Optional configuration for the subscription
    ///
    /// # Topic Format Handling
    ///
    /// The method automatically handles different topic formats:
    /// - **Full topic with network ID**: `"network:service/topic"` (used as-is)
    /// - **Topic with service**: `"service/topic"` (default network ID added)
    /// - **Simple topic**: `"topic"` (default network ID and service path added)
    ///
    /// # Returns
    ///
    /// Returns a `JoinHandle<Result<Option<ArcValue>>>` that resolves to:
    /// - `Ok(Some(data))` when an event is received
    /// - `Ok(None)` if the channel is closed
    /// - `Err(_)` if a timeout occurs or other error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{Node, NodeConfig};
    /// use std::time::Duration;
    ///
    /// // Example of how to use the on() method (conceptual)
    /// async fn example_usage() -> anyhow::Result<()> {
    ///     // Note: This example shows the concept but would need a running node
    ///     // with services to actually work. The on() method is typically used
    ///     // after the node is started and services are running.
    ///     
    ///     // Wait for an event with default 5-second timeout
    ///     // let handle = node.on("my-service/event", None);
    ///     
    ///     // Wait for the event
    ///     // match handle.await? {
    ///     //     Ok(Some(data)) => println!("Received event: {data:?}"),
    ///     //     Ok(None) => println!("Channel closed"),
    ///     //     Err(e) => println!("Error: {e}"),
    ///     // }
    ///     
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - The subscription is created immediately to avoid race conditions
    /// - The subscription is automatically cleaned up after the event is received
    /// - This method is optimized for one-shot event waiting
    pub fn on(
        &self,
        topic: impl Into<String>,
        options: Option<crate::services::OnOptions>,
    ) -> tokio::task::JoinHandle<Result<Option<ArcValue>>> {
        let topic_string = topic.into();

        // Build full topic path synchronously (no I/O here)
        let full_topic = if topic_string.contains(':') {
            topic_string
        } else if topic_string.contains('/') {
            format!(
                "{network_id}:{topic}",
                network_id = self.network_id,
                topic = topic_string
            )
        } else {
            format!("{}:{}/{}", self.network_id, "default", topic_string)
        };

        let node = self.clone();

        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<ArcValue>>(1);

            // Register subscription now (await inside the spawned task)
            let on_opts = options.clone().unwrap_or(crate::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            });
            let subscription_id = node
                .subscribe(
                    &full_topic,
                    Arc::new(move |_context, data| {
                        let tx = tx.clone();
                        Box::pin(async move {
                            let _ = tx.send(data).await;
                            Ok(())
                        })
                    }),
                    Some(EventRegistrationOptions {
                        include_past: on_opts.include_past,
                    }),
                )
                .await?;

            // Wait for event or timeout
            let result = match tokio::time::timeout(on_opts.timeout, rx.recv()).await {
                Ok(Some(event_data)) => Ok(event_data),
                Ok(None) => Err(anyhow!(
                    "Channel closed while waiting for event on topic: {full_topic}"
                )),
                Err(_) => Err(anyhow!("Timeout waiting for event on topic: {full_topic}")),
            };

            // Best-effort unsubscribe
            let _ = node.unsubscribe(&subscription_id).await;

            result
        })
    }

    /// Start the Node and all registered services.
    ///
    /// This method initializes the Node's internal systems and starts all registered services.
    /// It's safe to call multiple times - subsequent calls are ignored if the node is already running.
    ///
    /// # Process
    ///
    /// 1. Checks if the Node is already started to ensure idempotency
    /// 2. Retrieves all local services from the registry
    /// 3. Initializes and starts each service in parallel
    /// 4. Updates service states to `Running`
    /// 5. Starts networking if enabled in the configuration
    /// 6. Begins peer discovery and service advertisement
    ///
    /// # Examples
    ///
    /// ```rust
    /// use runar_node::{Node, NodeConfig};
    /// use runar_node::AbstractService;
    ///
    /// // Define a simple service for the example
    /// #[derive(Clone)]
    /// struct MyService;
    ///
    /// impl MyService {
    ///     fn new() -> Self { Self }
    /// }
    ///
    /// #[async_trait::async_trait]
    /// impl AbstractService for MyService {
    ///     fn name(&self) -> &str { "MyService" }
    ///     fn version(&self) -> &str { "1.0.0" }
    ///     fn path(&self) -> &str { "my-service" }
    ///     fn description(&self) -> &str { "Example service" }
    ///     fn network_id(&self) -> Option<String> { None }
    ///     fn set_network_id(&mut self, _network_id: String) {}
    ///     async fn init(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    ///     async fn start(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    ///     async fn stop(&self, _context: runar_node::services::LifecycleContext) -> anyhow::Result<()> { Ok(()) }
    /// }
    ///
    /// // Example of how to start a node (conceptual)
    /// async fn example_usage() -> anyhow::Result<()> {
    ///     // Note: This example shows the concept but would need proper
    ///     // key manager state to actually create a Node instance.
    ///     
    ///     // let mut config = NodeConfig::new("my-node", "my-network");
    ///     // let  node = Node::new(config).await?;
    ///     //
    ///     // Add services first
    ///     // node.add_service(MyService::new()).await?;
    ///     //
    ///     // Then start the node
    ///     // node.start().await?;
    ///     //
    ///     // Node is now running and ready to handle requests
    ///     
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// - Any service fails to start
    /// - Networking fails to initialize (if enabled)
    /// - Internal system components fail to start
    ///
    /// # Networking
    ///
    /// If networking is enabled in the configuration, this method will:
    /// - Start the network transport layer
    /// - Begin peer discovery
    /// - Advertise local services to the network
    /// - Accept incoming connections from peers
    pub async fn start(&self) -> Result<()> {
        log_info!(self.logger, "Starting node...");

        if self.running.load(Ordering::SeqCst) {
            log_warn!(self.logger, "Node already running");
            return Ok(());
        }

        // Get services directly from the registry
        let registry = Arc::clone(&self.service_registry);
        let local_services = registry.get_local_services().await;

        let internal_services = local_services
            .iter()
            .filter(|(_, service_entry)| is_internal_service(service_entry.service.path()))
            .collect::<HashMap<_, _>>();
        let non_internal_services = local_services
            .iter()
            .filter(|(_, service_entry)| !is_internal_service(service_entry.service.path()))
            .collect::<HashMap<_, _>>();

        // start internal services first
        for (service_topic, service_entry) in internal_services {
            self.start_service(service_topic, service_entry, false)
                .await;
        }

        // Start networking if enabled
        if self.supports_networking {
            if let Err(e) = self.start_networking().await {
                log_error!(self.logger, "Failed to start networking components: {e}");
                return Err(e);
            }
        }

        log_info!(
            self.logger,
            "Node started successfully - it will start all services now"
        );
        self.running.store(true, Ordering::SeqCst);

        // Start non-internal services in parallel to avoid blocking the loop
        let mut tasks_store = self.service_tasks.write().await;
        let service_start_timeout = Duration::from_secs(30); //TODO MOVE THIS TO A CONFIG
        for (service_topic, service_entry) in non_internal_services {
            let node_clone = Arc::new(self.clone());
            let service_topic_clone = service_topic.clone();
            let service_entry_clone = service_entry.clone();
            let task = tokio::spawn(async move {
                log_info!(
                    node_clone.logger,
                    "Starting separate thread to start service: {service_topic_clone}"
                );

                // Add timeout to the service start operation
                match tokio::time::timeout(
                    service_start_timeout,
                    node_clone.start_service(&service_topic_clone, &service_entry_clone, true),
                )
                .await
                {
                    Ok(_) => {
                        log_info!(
                            node_clone.logger,
                            "Service start completed: {service_topic_clone}"
                        );
                    }
                    Err(_) => {
                        log_error!(
                            node_clone.logger,
                            "Service start timed out after 30 seconds: {service_topic_clone}"
                        );
                    }
                }
            });
            tasks_store.push((service_topic.clone(), task));
        }

        Ok(())
    }

    pub async fn wait_for_services_to_start(&self) -> Result<()> {
        let mut service_tasks = self.service_tasks.write().await;
        for (_service_topic, task) in service_tasks.drain(..) {
            task.await?;
        }
        Ok(())
    }

    async fn start_service(
        &self,
        service_topic: &TopicPath,
        service_entry: &ServiceEntry,
        update_node_version: bool,
    ) {
        log_info!(
            self.logger,
            "[start_service] Starting service: {service_topic}"
        );

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
            log_error!(
                self.logger,
                "[start_service] Failed to start service: {service_topic}, error: {e}"
            );
            if let Err(update_err) = registry
                .update_local_service_state(service_topic, ServiceState::Error)
                .await
            {
                log_error!(
                    self.logger,
                    "[start_service] Failed to update service state to Error: {update_err}"
                );
            }
            if let Err(publish_err) = self
                .publish_with_options(
                    &format!(
                        "$registry/services/{}/state/error",
                        service_topic.service_path()
                    ),
                    Some(ArcValue::new_primitive(service_topic.as_str().to_string())),
                    PublishOptions {
                        broadcast: false,
                        guaranteed_delivery: false,
                        retain_for: Some(Duration::from_secs(10)),
                        target: None,
                    },
                )
                .await
            {
                log_error!(
                    self.logger,
                    "[start_service] Failed to publish error state: {publish_err}"
                );
            }
            return;
        }

        if let Err(update_err) = registry
            .update_local_service_state(service_topic, ServiceState::Running)
            .await
        {
            log_error!(
                self.logger,
                "[start_service] Failed to update service state to Running: {update_err}"
            );
        }

        if let Err(publish_err) = self
            .publish_with_options(
                &format!(
                    "$registry/services/{}/state/running",
                    service_topic.service_path()
                ),
                Some(ArcValue::new_primitive(service_topic.as_str().to_string())),
                PublishOptions {
                    broadcast: false,
                    guaranteed_delivery: false,
                    retain_for: Some(Duration::from_secs(120)),
                    target: None,
                },
            )
            .await
        {
            log_error!(
                self.logger,
                "[start_service] Failed to publish running state: {publish_err}"
            );
        }
        log_info!(
            self.logger,
            "[start_service] published local-only running for local service {service_topic}"
        );
        if update_node_version {
            log_info!(
                self.logger,
                "[start_service] notifying node change for service: {service_topic}"
            );
            if let Err(notify_err) = self.notify_node_change().await {
                log_error!(self.logger, "Failed to notify node change: {notify_err}");
            }
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
    pub async fn stop(&self) -> Result<()> {
        log_info!(self.logger, "Stopping node...");

        if !self.running.load(Ordering::SeqCst) {
            log_warn!(self.logger, "Node already stopped");
            return Ok(());
        }

        self.running.store(false, Ordering::SeqCst);

        //if services are still starting wait for them to finish any ongoing operation
        self.wait_for_services_to_start().await?;

        // Get services directly and stop them
        let registry = Arc::clone(&self.service_registry);
        let local_services = registry.get_local_services().await;

        log_info!(self.logger, "Stopping services...");
        // Stop each service
        for (service_topic, service_entry) in local_services {
            log_info!(self.logger, "Stopping service: {service_topic}");

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
                log_error!(
                    self.logger,
                    "Failed to stop service: {service_topic}, error: {e}"
                );
                continue;
            }

            registry
                .update_local_service_state(&service_topic, ServiceState::Stopped)
                .await?;
            self.publish_with_options(
                &format!(
                    "$registry/services/{}/state/stopped",
                    service_topic.service_path()
                ),
                Some(ArcValue::new_primitive(service_topic.as_str().to_string())),
                PublishOptions {
                    broadcast: false,
                    guaranteed_delivery: false,
                    retain_for: Some(Duration::from_secs(3)),
                    target: None,
                },
            )
            .await?;
        }

        log_info!(self.logger, "Stopping networking...");

        // Stop networking if enabled
        if self.supports_networking {
            self.shutdown_network().await?;
        }

        // Stop all service tasks
        let mut service_tasks = self.service_tasks.write().await;
        for (_, task) in service_tasks.drain(..) {
            task.abort();
        }

        log_info!(self.logger, "Node stopped successfully");

        Ok(())
    }

    /// Starts the networking components (transport and discovery).
    /// This should be called internally as part of the node.start process.
    async fn start_networking(&self) -> Result<()> {
        log_info!(self.logger, "Starting networking components...");

        if !self.supports_networking {
            log_info!(
                self.logger,
                "Networking is disabled, skipping network initialization"
            );
            return Ok(());
        }

        // Get the configuration
        let config = &self.config;
        let network_config = config
            .network_config
            .as_ref()
            .ok_or_else(|| anyhow!("Network configuration is required"))?;

        // Log the network configuration
        log_info!(self.logger, "Network config: {network_config}");

        let mut local_node_info = self.local_node_info.write().await;
        *local_node_info = self.get_local_node_info().await?;
        drop(local_node_info);

        // Initialize the network transport
        if self.network_transport.read().await.is_none() {
            log_info!(self.logger, "Initializing network transport...");

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
            log_info!(self.logger, "Initializing node discovery providers...");

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
                    .subscribe(Arc::new(move |event| {
                        let node_arc = node_arc.clone();
                        let provider_type_clone = provider_type_clone.clone();
                        Box::pin(async move {
                            match event {
                                DiscoveryEvent::Discovered(peer_info)
                                | DiscoveryEvent::Updated(peer_info) => {
                                    if let Err(e) = node_arc.handle_discovered_node(peer_info).await {
                                        log_error!(node_arc.logger, "Failed to handle node discovered by {provider_type_clone} provider: {e}");
                                    }
                                }
                                DiscoveryEvent::Lost(peer_id) => {
                                    // Treat as disconnect cleanup hint
                                    let _ = node_arc.cleanup_disconnected_peer(&peer_id).await;
                                }
                            }
                        })
                    }))
                    .await?;

                // Start announcing on this provider
                log_info!(
                    self.logger,
                    "Starting to announce on {provider_type:?} discovery provider"
                );
                discovery_provider.start_announcing().await?;

                discovery_providers.push(discovery_provider);
            }

            // Store the transport
            let mut discovery_guard = self.network_discovery_providers.write().await;
            *discovery_guard = Some(discovery_providers);
            //release lock
            drop(discovery_guard);
        }

        // Start discovery providers (clone list to avoid holding lock across await)
        let providers_to_start = {
            let guard = self.network_discovery_providers.read().await;
            guard.as_ref().cloned()
        };
        if let Some(discovery_providers) = providers_to_start {
            for provider in discovery_providers {
                provider.start_announcing().await?;
            }
        }

        log_info!(self.logger, "Networking started successfully");
        Ok(())
    }

    /// Create a transport instance based on the transport type in the config
    async fn create_transport(
        &self,
        network_config: &NetworkConfig,
    ) -> Result<Arc<dyn NetworkTransport>> {
        // Get the local node info to pass to the transport
        let local_node_info = self.local_node_info.read().await;
        let self_arc = Arc::new(self.clone());
        match network_config.transport_type {
            TransportType::Quic => {
                log_debug!(self.logger, "Creating QUIC transport");

                // Use bind address and options from config
                let bind_addr = network_config.transport_options.bind_address;

                let self_arc_for_message = self_arc.clone();
                let message_handler: MessageHandler = Box::new(move |message: NetworkMessage| {
                    let self_arc = self_arc_for_message.clone();
                    Box::pin(async move {
                        self_arc
                            .handle_network_message(message)
                            .await
                            .map_err(|e| NetworkError::TransportError(e.to_string()))
                    })
                });

                let self_arc_for_message = self_arc.clone();
                let one_way_message_handler: OneWayMessageHandler =
                    Box::new(move |message: NetworkMessage| {
                        let self_arc = self_arc_for_message.clone();
                        Box::pin(async move {
                            // For one-way messages, we call the same handler but ignore the response
                            let _response = self_arc
                                .handle_network_message(message)
                                .await
                                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                            Ok(())
                        })
                    });

                let self_arc_for_callback = self_arc.clone();
                let peer_connected_callback: PeerConnectedCallback =
                    Arc::new(move |peer_node_id: String, peer_node_info: NodeInfo| {
                        let node = self_arc_for_callback.clone();
                        Box::pin(async move {
                            let res = node
                                .handle_peer_connected(peer_node_id, peer_node_info)
                                .await;
                            if let Err(e) = res {
                                log_error!(node.logger, "Failed to handle peer connected: {e}");
                            }
                        })
                    });

                let self_arc_for_callback = self_arc.clone();
                let peer_disconnected_callback: PeerDisconnectedCallback =
                    Arc::new(move |peer_node_id: String| {
                        let node = self_arc_for_callback.clone();
                        Box::pin(async move { node.cleanup_disconnected_peer(&peer_node_id).await })
                    });

                let self_arc_for_callback = self_arc.clone();
                let get_local_node_info: GetLocalNodeInfoCallback = Arc::new(move || {
                    let node = self_arc_for_callback.clone();
                    Box::pin(async move { node.get_local_node_info().await })
                });

                let cert_config = self
                    .keys_manager
                    .get_quic_certificate_config()
                    .context("Failed to get QUIC certificates")?;

                let quic_options = network_config
                    .quic_options
                    .clone()
                    .ok_or_else(|| anyhow!("QUIC options not provided"))?;

                // Configure QUIC options with certificates and private key from key manager
                // Standard QUIC/TLS will handle certificate validation using the CA certificate
                let configured_quic_options = quic_options
                    .with_certificates(cert_config.certificate_chain)
                    .with_private_key(cert_config.private_key);

                let transport_options = configured_quic_options
                    .with_local_node_public_key(local_node_info.node_public_key.clone())
                    .with_bind_addr(bind_addr)
                    .with_message_handler(message_handler)
                    .with_one_way_message_handler(one_way_message_handler)
                    .with_peer_connected_callback(peer_connected_callback)
                    .with_peer_disconnected_callback(peer_disconnected_callback)
                    .with_get_local_node_info(get_local_node_info)
                    .with_logger(self.logger.clone())
                    .with_keystore(self.keys_manager.clone())
                    .with_label_resolver(self.label_resolver.clone());

                let transport = QuicTransport::new(transport_options)
                    .map_err(|e| anyhow!("Failed to create QUIC transport: {e}"))?;

                log_debug!(self.logger, "QUIC transport created");
                let transport_arc: Arc<dyn NetworkTransport> = Arc::new(transport);
                Ok(transport_arc)
            } // Add other transport types here as needed in the future
        }
    }

    async fn handle_peer_connected(
        &self,
        peer_node_id: String,
        peer_node_info: NodeInfo,
    ) -> Result<()> {
        // Check existing info from directory
        if let Some(existing_peer) = self.remote_node_info.get(&peer_node_id) {
            log_debug!(
                self.logger,
                "[handle_peer_connected] peer_node_id:{peer_node_id} already connected - existing version: {existing_version} - new version: {new_version}",
                existing_version = existing_peer.version,
                new_version = peer_node_info.version
            );
            // Idempotency: ignore if version is not newer
            if peer_node_info.version <= existing_peer.version {
                log_debug!(
                    self.logger,
                    "Node {peer_node_id} has older version {new_peer_version}, ignoring",
                    new_peer_version = peer_node_info.version
                );
                return Ok(());
            }

            log_debug!(
                self.logger,
                "Node {peer_node_id} exists but has new version {new_peer_version}, diffing capabilities",
                new_peer_version = peer_node_info.version
            );

            self.update_peer_capabilities(&existing_peer, &peer_node_info)
                .await?;
            // replace stored peer info
            self.publish_with_options(
                &format!("$registry/peer/{peer_node_id}/updated"),
                Some(ArcValue::new_primitive(peer_node_id.clone())),
                PublishOptions::local_only().with_retain_for(std::time::Duration::from_secs(10)),
            )
            .await?;
        } else {
            log_debug!(
                self.logger,
                "[handle_peer_connected] peer_node_id:{peer_node_id} is new"
            );
            self.add_new_peer(&peer_node_info).await?;
            self.publish_with_options(
                &format!("$registry/peer/{peer_node_id}/discovered"),
                Some(ArcValue::new_primitive(peer_node_id.clone())),
                PublishOptions::local_only().with_retain_for(std::time::Duration::from_secs(10)),
            )
            .await?;
        }
        self.remote_node_info.insert(peer_node_id, peer_node_info);
        Ok(())
    }

    /// Create a discovery provider based on the provider type
    async fn create_discovery_provider(
        &self,
        provider_config: &DiscoveryProviderConfig,
        discovery_options: Option<DiscoveryOptions>,
    ) -> Result<Arc<dyn NodeDiscovery>> {
        let peer_info = self.get_local_node_info().await?;
        let local_peer_info = PeerInfo {
            public_key: peer_info.node_public_key,
            addresses: peer_info.addresses,
        };

        match provider_config {
            DiscoveryProviderConfig::Multicast(_options) => {
                log_info!(
                    self.logger,
                    "Creating MulticastDiscovery provider with config options"
                );
                // Use .await to properly wait for the async initialization
                let discovery = MulticastDiscovery::new(
                    local_peer_info,
                    discovery_options.unwrap_or_default(),
                    self.logger.with_component(Component::NetworkDiscovery),
                )
                .await?;
                Ok(Arc::new(discovery))
            }
            DiscoveryProviderConfig::Static(_options) => {
                log_info!(self.logger, "Static discovery provider configured");
                // Implement static discovery when needed
                Err(anyhow!("Static discovery provider not yet implemented"))
            } // Add other discovery types as they're implemented
        }
    }

    /// Handle discovered nodes and establish connections
    ///
    /// INTENTION: Process discovered peer information and establish connections.
    pub async fn handle_discovered_node(&self, peer_info: PeerInfo) -> Result<()> {
        if !self.supports_networking {
            return Ok(());
        }

        let discovered_peer_id = compact_id(&peer_info.public_key);

        log_info!(
            self.logger,
            "Discovery listener found node: {discovered_peer_id}"
        );

        // Debounce rapid duplicate announcements only when not connected is false (we already checked not connected),
        // but still avoid spamming connects if multiple events arrive within a very short window.
        {
            let should_debounce =
                if let Some(last) = self.discovery_seen_times.get(&discovered_peer_id) {
                    last.elapsed() < Duration::from_millis(150)
                } else {
                    false
                };

            if should_debounce {
                log_debug!(self.logger, "Debounced discovery for {discovered_peer_id}");
                // Do not early-return; small delay then continue to connect to ensure reconnection after restart
                tokio::time::sleep(Duration::from_millis(150)).await;
            } else {
                self.discovery_seen_times
                    .insert(discovered_peer_id.clone(), Instant::now());
            }
        }

        // Proceed with idempotent connect regardless of current directory flag

        // Attempt to connect to the discovered peer (transport is expected to be idempotent)
        if let Some(transport) = self.network_transport.read().await.as_ref() {
            transport
                .clone()
                .connect_peer(peer_info)
                .await
                .map_err(|e| anyhow!("Connection failed to {discovered_peer_id}: {e}"))?;
        } else {
            log_warn!(self.logger, "No network transport available for connection");
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
            log_warn!(
                self.logger,
                "Received network message but networking is disabled"
            );
            return Ok(None);
        }

        log_debug!(
            self.logger,
            "Received network message: {}",
            message.message_type
        );

        // Match on message type
        match message.message_type {
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
                log_warn!(
                    self.logger,
                    "Unknown message type: {}",
                    message.message_type
                );
                Err(anyhow!(
                    "Unknown message type: {message_type}",
                    message_type = message.message_type
                ))
            }
        }
    }

    /// Cleanup state after a peer disconnects: remove remote services, subscriptions,
    /// and forget the peer from known_peers and discovery caches.
    async fn cleanup_disconnected_peer(&self, peer_node_id: &str) {
        log_info!(self.logger, "Cleaning up disconnected peer: {peer_node_id}");

        // 1) Remove remote subscriptions registered for this peer
        let sub_ids = self
            .service_registry
            .drain_remote_peer_subscriptions(peer_node_id)
            .await;
        for sub_id in sub_ids {
            let _ = self.service_registry.unsubscribe_remote(&sub_id).await;
        }

        // 2) Remove remote services from this peer
        if let Some(prev_info) = self.remote_node_info.get(peer_node_id) {
            for service in &prev_info.node_metadata.services {
                if let Ok(service_tp) = TopicPath::new(&service.service_path, &service.network_id) {
                    let _ = self
                        .service_registry
                        .remove_remote_service(&service_tp)
                        .await;
                } else {
                    log_error!(
                        self.logger,
                        "Failed to parse topic path: {service_path}",
                        service_path = service.service_path
                    );
                }
            }
        }

        // 3) removed from local cache
        self.remote_node_info.remove(peer_node_id);

        // 4) Publish a local-only event indicating peer removal
        if let Err(e) = self
            .publish_with_options(
                &format!("$registry/peer/{peer_node_id}/disconnected"),
                Some(ArcValue::new_primitive(peer_node_id.to_string())),
                PublishOptions::local_only(),
            )
            .await
        {
            log_error!(
                self.logger,
                "Failed to publish peer disconnected event: {e}"
            );
        }
    }

    /// Handle a network request
    async fn handle_network_request(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        // Skip if networking is not enabled
        if !self.supports_networking {
            log_warn!(
                self.logger,
                "Received network request but networking is disabled"
            );
            return Ok(None);
        }

        log_debug!(
            self.logger,
            "📥 [Node] Handling network request from {} - Type: {}, Payloads: {}",
            message.source_node_id,
            message.message_type,
            message.payloads.len()
        );

        if message.payloads.is_empty() {
            log_error!(
                self.logger,
                "❌ [Node] Received request message with no payloads"
            );
            return Err(anyhow!("Received request message with no payloads"));
        }

        let mut responses: Vec<NetworkMessagePayloadItem> =
            Vec::with_capacity(message.payloads.len());
        let local_peer_id = self.node_id.clone();

        for payload in &message.payloads {
            let params =
                ArcValue::deserialize(&payload.value_bytes, Some(self.keys_manager.clone()))?;
            let params_option = if params.is_null() { None } else { Some(params) };

            // Process the request locally using extracted topic and params
            log_debug!(
                self.logger,
                "[handle_network_request] will call local_request for path {}",
                &payload.path
            );

            let topic_path = match TopicPath::from_full_path(&payload.path) {
                Ok(tp) => tp,
                Err(e) => {
                    log_error!(
                        self.logger,
                        "Failed to parse topic path: {} : {}",
                        &payload.path,
                        e
                    );
                    continue;
                }
            };
            let network_id = topic_path.network_id();
            let profile_public_key = payload
                .context
                .as_ref()
                .map(|c| c.profile_public_key.clone())
                .context("No context found in payload")?;

            match self.local_request(topic_path.as_str(), params_option).await {
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

                    log_info!(
                        self.logger,
                        "📤 [Node] Sending response - To: {}, Correlation: {}, Size: {} bytes",
                        message.source_node_id,
                        message.payloads[0].correlation_id,
                        serialized_data.len()
                    );

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
                    log_error!(self.logger, "❌ [Node] Local request failed - Error: {e}");

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

                    log_debug!(
                        self.logger,
                        "📤 [Node] Sending error response - To: {}, Size: {} bytes",
                        message.source_node_id,
                        serialized_error.len()
                    );

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
            log_warn!(
                self.logger,
                "Received network response but networking is disabled"
            );
            return Ok(None);
        }

        let payload_item = &message.payloads[0];
        let topic = &payload_item.path;
        let correlation_id = &payload_item.correlation_id;

        // Only process if we have an actual correlation ID
        log_debug!(
            self.logger,
            "Processing response for topic {topic}, correlation ID: {correlation_id}"
        );

        // Find any pending response handlers
        if let Some((_, pending_request_sender)) = self.pending_requests.remove(correlation_id) {
            log_debug!(
                self.logger,
                "Found response handler for correlation ID: {correlation_id}"
            );

            // Deserialize the payload data
            let payload_data =
                ArcValue::deserialize(&payload_item.value_bytes, Some(self.keys_manager.clone()))?;

            // Send the response (which is ArcValue) through the oneshot channel
            // payload_data is already ArcValue. If the original response was 'None',
            // serializer.deserialize_value should produce ArcValue::null().
            match pending_request_sender.send(Ok(payload_data)) {
                Ok(_) => log_debug!(
                    self.logger,
                    "Successfully sent response for correlation ID: {correlation_id}"
                ),
                Err(e) => log_error!(
                    self.logger,
                    "Failed to send response data for correlation ID {correlation_id}: {e:?}"
                ),
            } // Closes match pending_request_sender.send(Ok(payload_data))
        } else {
            // This is the else for `if let Some((_, pending_request_sender))`
            log_warn!(
                self.logger,
                "No response handler found for correlation ID: {correlation_id}"
            );
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
            log_warn!(
                self.logger,
                "Received network event but networking is disabled"
            );
            return Ok(None);
        }

        log_debug!(
            self.logger,
            "Handling network event message_type: {}",
            message.message_type
        );

        // Process each payload separately
        for payload_item in &message.payloads {
            let topic = &payload_item.path;

            // Skip processing if topic is empty
            if topic.is_empty() {
                log_warn!(self.logger, "Received event with empty topic, skipping");
                continue; // Continues the for loop in handle_network_event
            }

            // Create topic path
            let topic_path = match TopicPath::new(topic, &self.network_id) {
                Ok(tp) => tp,
                Err(e) => {
                    log_error!(self.logger, "Invalid topic path for event: {e}");
                    continue;
                }
            };

            // Deserialize the payload data
            let payload =
                ArcValue::deserialize(&payload_item.value_bytes, Some(self.keys_manager.clone()))?;

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
                log_debug!(self.logger, "No subscribers found for topic: {topic}");
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
                    log_error!(self.logger, "Error in subscriber callback: {e}");
                }
            }
        }

        Ok(None)
    }

    pub async fn local_request(
        &self,
        path: impl Into<String>,
        payload: Option<ArcValue>,
    ) -> Result<ArcValue> {
        let path_string = path.into();
        let topic_path = match TopicPath::new(&path_string, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Failed to parse topic path: {path_string} : {e}",)),
        };

        log_debug!(self.logger, "Processing local request: {topic_path}");

        // First check for local handlers
        if let Some((handler, registration_path)) = self
            .service_registry
            .get_local_action_handler(&topic_path)
            .await
        {
            log_debug!(self.logger, "Executing local handler for: {topic_path}");

            // Create request context
            let mut context =
                RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone());

            // Extract parameters using the original registration path
            if let Ok(params) = topic_path.extract_params(&registration_path.action_path()) {
                // Populate the path_params in the context
                context.path_params = params;
                log_debug!(
                    self.logger,
                    "Extracted path parameters: {:?}",
                    context.path_params
                );
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
    pub async fn request<P>(&self, path: &str, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        let request_payload_av = payload.map(|p| p.into_arc_value());
        let topic_path = match TopicPath::new(path, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Failed to parse topic path: {path} : {e}",)),
        };

        log_debug!(self.logger, "Processing request: {topic_path}");

        // First check local service state - if no state exists, no local service exists
        let service_topic = TopicPath::new_service(&self.network_id, &topic_path.service_path());
        let service_state = self
            .service_registry
            .get_local_service_state(&service_topic)
            .await;

        // If service state exists, check if it's running
        if let Some(state) = service_state {
            if state != ServiceState::Running {
                log_debug!(
                    self.logger,
                    "Service {} is in {:?} state, trying remote handlers",
                    topic_path.service_path(),
                    state
                );
                // Try remote handlers instead
                match self
                    .remote_request(topic_path.as_str(), request_payload_av)
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(_) => {
                        // Remote request failed - return state-specific error since we know local service exists but is not running
                        return Err(anyhow!("Service is not Running - it is in {} state", state));
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
            log_debug!(self.logger, "Executing local handler for: {topic_path}");

            // Create request context
            let mut context =
                RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone());

            // Extract parameters using the original registration path
            if let Ok(path_params) = topic_path.extract_params(&registration_path.action_path()) {
                // Populate the path_params in the context
                context.path_params = path_params;
                log_debug!(
                    self.logger,
                    "Extracted path parameters: {:?}",
                    context.path_params
                );
            }

            // Execute the handler and return result
            let response_av = handler(request_payload_av.clone(), context).await?;
            return Ok(response_av);
        }

        // No local handler found - try remote handlers
        self.remote_request(topic_path.as_str(), request_payload_av)
            .await
    }

    pub async fn remote_request<P>(&self, path: &str, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        let request_payload_av = payload.map(|p| p.into_arc_value());
        let topic_path = match TopicPath::new(path, &self.network_id) {
            Ok(tp) => tp,
            Err(e) => return Err(anyhow!("Failed to parse topic path: {path} : {e}",)),
        };

        log_debug!(self.logger, "Processing remote request: {topic_path}");

        // Look for remote handlers
        let remote_handlers = self
            .service_registry
            .get_remote_action_handlers(&topic_path)
            .await;
        if !remote_handlers.is_empty() {
            log_debug!(
                self.logger,
                "Found {} remote handlers for: {}",
                remote_handlers.len(),
                topic_path
            );

            // Apply load balancing strategy to select a handler
            let load_balancer = self.load_balancer.read().await;
            let handler_index = load_balancer.select_handler(
                &remote_handlers,
                &RequestContext::new(&topic_path, Arc::new(self.clone()), self.logger.clone()),
            );

            // Get the selected handler
            let handler = &remote_handlers[handler_index];

            log_debug!(
                self.logger,
                "Selected remote handler {} of {} for: {}",
                handler_index + 1,
                remote_handlers.len(),
                topic_path
            );

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
    pub async fn publish_with_options(
        &self,
        topic: &str,
        data: Option<ArcValue>,
        options: PublishOptions,
    ) -> Result<()> {
        let topic_string = topic.to_string();
        // Check for valid topic path
        let topic_path = match TopicPath::new(topic, &self.network_id) {
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
                log_error!(
                    self.logger,
                    "Error in local event handler for {topic_string}: {e}"
                );
            }
        }

        // Retain event locally if configured
        if let Some(retain_for) = options.retain_for {
            let key = topic_path.as_str().to_string();
            let now = std::time::Instant::now();
            let expire_before = now - retain_for;
            let mut deque = self.retained_events.entry(key.clone()).or_default();
            // prune by time
            while let Some((ts, _)) = deque.front() {
                if *ts < expire_before {
                    deque.pop_front();
                } else {
                    break;
                }
            }
            // cap size
            const MAX_RETAIN_PER_TOPIC: usize = 16;
            while deque.len() >= MAX_RETAIN_PER_TOPIC {
                deque.pop_front();
            }
            deque.push_back((now, data.clone()));
            // ensure index contains the exact topic
            let mut idx = self.retained_index.write().await;
            idx.set_value(topic_path.clone(), topic_path.as_str().to_string());

            log_debug!(
                self.logger,
                "[retain] topic={} count={} window={:?}",
                key,
                deque.len(),
                retain_for
            );
        }

        // Broadcast to remote nodes if requested and network is available
        if options.broadcast && self.supports_networking {
            let remote_subscribers = self
                .service_registry
                .get_remote_event_subscribers(&topic_path)
                .await;
            for (_subscription_id, callback, _options) in remote_subscribers {
                // Execute the callback with correct arguments
                if let Err(e) = callback(data.clone()).await {
                    log_error!(
                        self.logger,
                        "Error in remote event handler for {topic_string}: {e}"
                    );
                }
            }
        }

        Ok(())
    }

    async fn update_peer_capabilities(
        &self,
        old_peer: &NodeInfo,
        new_peer: &NodeInfo,
    ) -> Result<()> {
        let peer_node_id = compact_id(&old_peer.node_public_key);

        // FIRST: Diff services
        let old_services: std::collections::HashSet<String> = old_peer
            .node_metadata
            .services
            .iter()
            .map(|s| format!("{}:{}", s.network_id, s.service_path))
            .collect();
        let new_services: std::collections::HashSet<String> = new_peer
            .node_metadata
            .services
            .iter()
            .map(|s| format!("{}:{}", s.network_id, s.service_path))
            .collect();

        // Services to add
        for service_key in new_services.difference(&old_services) {
            // Find the actual service metadata for this key
            if let Some(service_metadata) = new_peer
                .node_metadata
                .services
                .iter()
                .find(|s| format!("{}:{}", s.network_id, s.service_path) == *service_key)
            {
                log_info!(
                    self.logger,
                    "Adding new remote service: {service_key} from peer: {peer_node_id}"
                );

                // Create and register the new remote service (reuse logic from add_new_peer)
                let transport_arc = self
                    .network_transport
                    .read()
                    .await
                    .clone()
                    .ok_or_else(|| anyhow!("Network transport not available"))?;
                let local_peer_id = self.node_id.clone();

                let rs_config = CreateRemoteServicesConfig {
                    services: vec![service_metadata.clone()],
                    peer_node_id: peer_node_id.clone(),
                    request_timeout_ms: self.config.request_timeout_ms,
                };

                let rs_dependencies = RemoteServiceDependencies {
                    network_transport: transport_arc.clone(),
                    local_node_id: local_peer_id,
                    logger: self.logger.clone(),
                };

                if let Ok(remote_services) =
                    RemoteService::create_from_capabilities(rs_config, rs_dependencies).await
                {
                    for service in remote_services {
                        // Register the service instance with the registry
                        if !self
                            .service_registry
                            .register_remote_service(service.clone())
                            .await
                        {
                            continue;
                        }

                        // Initialize the service - this triggers handler registration via the context
                        let service_topic_path =
                            TopicPath::new(service.path(), &self.network_id).unwrap();
                        let registry_delegate: Arc<dyn RegistryDelegate + Send + Sync> =
                            Arc::new(self.clone());
                        let context =
                            RemoteLifecycleContext::new(&service_topic_path, self.logger.clone())
                                .with_registry_delegate(registry_delegate);

                        if let Err(e) = service.init(context).await {
                            log_error!(
                                self.logger,
                                "Failed to initialize remote service '{}': {e}",
                                service.path()
                            );
                        }
                        self.service_registry
                            .update_remote_service_state(&service_topic_path, ServiceState::Running)
                            .await?;

                        // Publish local-only running state for remote service so local components can await readiness
                        if let Err(publish_err) = self
                            .publish_with_options(
                                &format!(
                                    "$registry/services/{}/state/running",
                                    service_topic_path.service_path()
                                ),
                                Some(ArcValue::new_primitive(
                                    service_topic_path.as_str().to_string(),
                                )),
                                PublishOptions::local_only()
                                    .with_retain_for(Duration::from_secs(120)),
                            )
                            .await
                        {
                            log_error!(
                                self.logger,
                                "Failed to publish remote service running state: {publish_err}"
                            );
                        }
                        log_info!(
                            self.logger,
                            "Published local-only running for remote service {service_topic_path}"
                        );
                    }
                }
            }
        }

        // Services to remove
        for service_key in old_services.difference(&new_services) {
            // Find the actual service metadata for this key
            if let Some(service_metadata) = old_peer
                .node_metadata
                .services
                .iter()
                .find(|s| format!("{}:{}", s.network_id, s.service_path) == *service_key)
            {
                log_info!(
                    self.logger,
                    "Removing remote service: {service_key} from peer: {peer_node_id}"
                );
                let service_path =
                    TopicPath::new(&service_metadata.service_path, &service_metadata.network_id)
                        .unwrap();
                if let Err(e) = self
                    .service_registry
                    .remove_remote_service(&service_path)
                    .await
                {
                    log_warn!(
                        self.logger,
                        "Failed to remove remote service {service_key}: {e}"
                    );
                }
            }
        }

        // SECOND: Diff subscriptions
        let old_set: std::collections::HashSet<String> = old_peer
            .node_metadata
            .subscriptions
            .iter()
            .map(|s| s.path.clone())
            .collect();
        let new_set: std::collections::HashSet<String> = new_peer
            .node_metadata
            .subscriptions
            .iter()
            .map(|s| s.path.clone())
            .collect();

        log_debug!(self.logger, "Subscription diffing for peer {peer_node_id}: old_set={old_set:?}, new_set={new_set:?}");

        // Paths to add
        for path in new_set.difference(&old_set) {
            let topic_path = Arc::new(
                TopicPath::from_full_path(path)
                    .map_err(|e| anyhow!("Invalid topic path {path}: {e}"))?,
            );
            log_info!(
                self.logger,
                "Adding new remote subscription: {path} for peer: {peer_node_id}"
            );
            let tp_arc = topic_path.clone();
            // create remote handler same as add_new_peer logic (reuse closure building)
            let transport_arc = self
                .network_transport
                .read()
                .await
                .clone()
                .ok_or_else(|| anyhow!("Network transport not available"))?;
            let logger = self.logger.clone();
            let peer_clone = peer_node_id.clone();
            let tp_clone = tp_arc.clone();
            let handler: RemoteEventHandler = Arc::new(move |data: Option<ArcValue>| {
                let nt = transport_arc.clone();
                let tp = tp_clone.clone();
                let peer = peer_clone.clone();
                let logger = logger.clone();
                Box::pin(async move {
                    nt.publish(tp.as_ref(), data, &peer)
                        .await
                        .map_err(|e| anyhow!(e))?;
                    log_debug!(logger, "Forwarded event {tp} to peer {peer}");
                    Ok(())
                })
            });
            let sub_id = self
                .service_registry
                .register_remote_event_subscription(
                    tp_arc.as_ref(),
                    handler,
                    EventRegistrationOptions::default(),
                )
                .await?;
            self.service_registry
                .upsert_remote_peer_subscription(&peer_node_id, tp_arc.as_ref(), sub_id)
                .await;
        }

        // Paths to remove
        for path in old_set.difference(&new_set) {
            log_info!(
                self.logger,
                "Removing remote subscription: {path} for peer: {peer_node_id}"
            );
            let topic_path = TopicPath::from_full_path(path).unwrap();
            if let Some(sub_id) = self
                .service_registry
                .remove_remote_peer_subscription(&peer_node_id, &topic_path)
                .await
            {
                let _ = self.service_registry.unsubscribe_remote(&sub_id).await;
            }
        }
        Ok(())
    }

    async fn add_new_peer(&self, node_info: &NodeInfo) -> Result<Vec<Arc<RemoteService>>> {
        let capabilities = &node_info.node_metadata;
        log_info!(
            self.logger,
            "Processing {} services and {} subscriptions from node {}",
            capabilities.services.len(),
            capabilities.subscriptions.len(),
            compact_id(&node_info.node_public_key)
        );

        // Check if capabilities is empty
        if capabilities.services.is_empty() && capabilities.subscriptions.is_empty() {
            log_info!(self.logger, "Received empty capabilities list.");
            return Ok(Vec::new()); // Nothing to process
        }

        // Get the local node ID
        let local_peer_id = self.node_id.clone();

        let peer_node_id = compact_id(&node_info.node_public_key);
        // Create RemoteService instances directly
        let rs_config = CreateRemoteServicesConfig {
            services: capabilities.services.clone(),
            peer_node_id: peer_node_id.clone(),
            request_timeout_ms: self.config.request_timeout_ms,
        };

        // Acquire the transport (should be initialized by now)
        let transport_guard = self.network_transport.read().await;
        let transport_arc = transport_guard
            .clone()
            .ok_or_else(|| anyhow!("Network transport not available"))?;

        let rs_dependencies = RemoteServiceDependencies {
            network_transport: transport_arc.clone(),
            local_node_id: local_peer_id,
            // pending_requests: self.pending_requests.clone(),
            logger: self.logger.clone(),
        };

        let remote_services =
            match RemoteService::create_from_capabilities(rs_config, rs_dependencies).await {
                Ok(services) => services,
                Err(e) => {
                    log_error!(
                        self.logger,
                        "Failed to create remote services from capabilities: {e}"
                    );
                    return Err(e);
                }
            };

        // Register each service and initialize it to register its handlers
        for service in &remote_services {
            // Register the service instance with the registry
            if !self
                .service_registry
                .register_remote_service(service.clone())
                .await
            {
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
                log_error!(
                    self.logger,
                    "Failed to initialize remote service '{}' (handler registration): {e}",
                    service.path()
                );
            }
            self.service_registry
                .update_remote_service_state(&service_topic_path, ServiceState::Running)
                .await?;

            // Publish local-only running state for remote service so local components can await readiness
            if let Err(publish_err) = self
                .publish_with_options(
                    &format!(
                        "$registry/services/{}/state/running",
                        service_topic_path.service_path()
                    ),
                    Some(ArcValue::new_primitive(
                        service_topic_path.as_str().to_string(),
                    )),
                    PublishOptions::local_only().with_retain_for(Duration::from_secs(120)),
                )
                .await
            {
                log_error!(
                    self.logger,
                    "Failed to publish remote service running state: {publish_err}"
                );
            }
        }

        // Handle remote node subscriptions - only for services that exist locally
        {
            // Vector to store subscription IDs we register for this peer so we can remove them later

            for subscription in capabilities.subscriptions.clone() {
                let path = subscription.path.clone();
                let topic_path = match TopicPath::from_full_path(&path) {
                    Ok(tp) => Arc::new(tp),
                    Err(e) => {
                        log_warn!(
                            self.logger,
                            "Failed to parse subscription path '{path}': {e}"
                        );
                        continue;
                    }
                };

                // Skip if our node does not participate in the requested network
                if !self.network_ids.contains(&topic_path.network_id()) {
                    log_debug!(
                        self.logger,
                        "Ignoring remote subscription {path} - network id not supported"
                    );
                    continue;
                }

                // Determine if the referenced service exists locally (ignore patterns)

                let topic_path_arc = topic_path.clone();
                let peer_node_id_cloned = peer_node_id.clone();
                let network_transport_cloned = transport_arc.clone();
                let logger_cloned = self.logger.clone();
                let topic_path_handler = topic_path_arc.clone();

                // Create event handler forwarding events to remote peer
                let event_handler: RemoteEventHandler = Arc::new(
                    move |event_data: Option<ArcValue>| {
                        let logger = logger_cloned.clone();
                        let peer_node_id = peer_node_id_cloned.clone();
                        let topic_path = topic_path_handler.clone();
                        let nt = network_transport_cloned.clone();
                        Box::pin(async move {
                            log_debug!(logger, "🚀 [RemoteEvent] Sending remote event - Event: {topic_path}, Target: {peer_node_id}");
                            nt.publish(topic_path.as_ref(), event_data, &peer_node_id)
                                .await
                                .map_err(|e| anyhow!(e))?;
                            log_debug!(logger, "✅ [RemoteEvent] Event forwarded - Event: {topic_path}, Target: {peer_node_id}");
                            Ok(())
                        })
                    },
                );

                match self
                    .service_registry
                    .register_remote_event_subscription(
                        topic_path_arc.as_ref(),
                        event_handler,
                        EventRegistrationOptions::default(),
                    )
                    .await
                {
                    Ok(subscription_id) => {
                        self.service_registry
                            .upsert_remote_peer_subscription(
                                &peer_node_id,
                                topic_path_arc.as_ref(),
                                subscription_id,
                            )
                            .await;
                    }
                    Err(e) => {
                        log_warn!(self.logger, "Failed to register remote subscription {path} for peer {peer_node_id}: {e}");
                    }
                }
            }
        }

        log_info!(
            self.logger,
            "Successfully processed {} remote services and {} remote subscriptions from node {}",
            remote_services.len(),
            capabilities.subscriptions.len(),
            compact_id(&node_info.node_public_key)
        );

        Ok(remote_services)
    }

    //this function is debounced since it can be called in rapid succession.. it is debounced for 1 second..
    // it will then call the notify_node_change_impl  which will use the transposter to send a handshake message with the latest node info to all known peers.
    /// Debounced notification of node change.
    ///
    /// INTENTION: This function is debounced to avoid flooding the network with repeated notifications.
    /// If called multiple times in rapid succession, only the last call within a 5 second window will
    /// trigger the actual notification. After the debounce period, it delegates to notify_node_change_impl,
    /// which sends the latest node info to all known peers via the transport.
    pub async fn notify_node_change(&self) -> Result<()> {
        //check if network is enabled
        if !self.supports_networking {
            log_debug!(
                self.logger,
                "notify_node_change called - network is not available"
            );
            return Ok(());
        }

        log_info!(
            self.logger,
            "notify_node_change called - it will be debounced for 1 second"
        );

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
            sleep(Duration::from_secs(1)).await;
            // Ignore errors from notify_node_change_impl; log if needed
            if let Err(e) = this.notify_node_change_impl().await {
                log_warn!(
                    this.logger,
                    "notify_node_change_impl failed after debounce: {e}"
                );
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
        let previous_version = self.registry_version.fetch_add(1, Ordering::SeqCst);
        let local_node_info = self.get_local_node_info().await?;
        log_info!(self.logger, "Notifying node change - previous version: {previous_version}, new version: {new_version}", previous_version = previous_version, new_version = local_node_info.version);

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
    pub async fn collect_local_service_capabilities(&self) -> Result<NodeMetadata> {
        let services_map = self
            .service_registry
            .get_all_service_metadata(false)
            .await?;
        let services: Vec<ServiceMetadata> = services_map.values().cloned().collect();
        let subscriptions = self.service_registry.get_all_subscriptions(false).await?;

        // Log all capabilities collected
        log_info!(
            self.logger,
            "Collected {} services metadata",
            services.len()
        );
        Ok(NodeMetadata {
            services,
            subscriptions,
        })
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
                log_debug!(
                    self.logger,
                    "Replaced 0.0.0.0 with network interface IP: {ip}"
                );
            } else {
                // Fall back to localhost if we can't get a real IP
                address = address.replace("0.0.0.0", "127.0.0.1");
                log_debug!(self.logger, "Replaced 0.0.0.0 with localhost (127.0.0.1)");
            }
        }

        let node_metadata = self.collect_local_service_capabilities().await?;
        let node_info = NodeInfo {
            node_public_key: self.node_public_key.clone(),
            network_ids: self.network_ids.clone(),
            addresses: vec![address],
            node_metadata,
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

        log_debug!(self.logger, "Discovered local network interface IP: {ip}");
        Ok(ip)
    }

    /// Shutdown the network components
    async fn shutdown_network(&self) -> Result<()> {
        // Early return if networking is disabled
        if !self.supports_networking {
            log_debug!(
                self.logger,
                "Network shutdown skipped - networking is disabled"
            );
            return Ok(());
        }

        log_info!(self.logger, "Shutting down network discovery providers");

        // Discovery: collect providers first to avoid holding lock during await
        let providers_to_shutdown = {
            let guard = self.network_discovery_providers.read().await;
            guard.as_ref().cloned()
        };
        if let Some(discovery) = providers_to_shutdown {
            for provider in discovery {
                provider.shutdown().await?;
            }
        }

        log_info!(self.logger, "Shutting down transport");

        // Transport: clone handle first to avoid holding lock during await
        let transport_to_stop = {
            let guard = self.network_transport.read().await;
            guard.as_ref().cloned()
        };
        if let Some(transport) = transport_to_stop {
            transport.stop().await?;
        }

        Ok(())
    }
}

/// Start networking components

#[async_trait]
impl NodeDelegate for Node {
    async fn request<P>(&self, path: &str, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        // Delegate directly to our (now generic) inherent implementation.
        self.request(path, payload).await
    }

    async fn publish(&self, topic: &str, data: Option<ArcValue>) -> Result<()> {
        // Create default options
        let options = PublishOptions {
            broadcast: true,
            guaranteed_delivery: false,
            retain_for: None,
            target: None,
        };

        self.publish_with_options(topic, data, options).await
    }

    async fn subscribe(
        &self,
        topic: &str, // This is the service-relative path, e.g., "math_service/numbers"
        callback: EventHandler, // Changed to use the type alias
        options: Option<EventRegistrationOptions>, // None-ish when default
    ) -> Result<String> {
        // The `topic` parameter is the service-relative path (e.g., "service_name/event_name").
        // This will be combined with `self.network_id` to form the full TopicPath for registry storage.
        let topic_path = TopicPath::new(topic, &self.network_id)
            .map_err(|e| anyhow!(
                "Invalid topic string for subscribe_with_options: {e}. Topic: '{topic}', Network ID: '{network_id}'", 
                network_id=self.network_id
            ))?;

        let node_started = self.running.load(Ordering::SeqCst);

        log_debug!(
            self.logger,
            "[subscribe] Node: subscribe called for topic_path '{}' - node started: {}",
            topic_path.as_str(),
            node_started
        );

        let subscription_id = self
            .service_registry
            .register_local_event_subscription(
                &topic_path,
                callback,
                &options.clone().unwrap_or_default(),
            )
            .await?;

        // Deliver past event if requested
        if let Some(lookback) = options.and_then(|o| o.include_past) {
            let now = std::time::Instant::now();
            let cutoff = now - lookback;

            // Build matched topics: prefer index (supports normalized keys), fallback to direct exact key
            let matched: Vec<String> = if topic_path.is_pattern() {
                let idx = self.retained_index.read().await;
                idx.find_wildcard_matches(&topic_path)
                    .into_iter()
                    .map(|m| m.content)
                    .collect()
            } else {
                let idx = self.retained_index.read().await;
                let exact = idx
                    .find_matches(&topic_path)
                    .into_iter()
                    .map(|m| m.content)
                    .collect::<Vec<String>>();
                if exact.is_empty() {
                    vec![topic_path.as_str().to_string()]
                } else {
                    exact
                }
            };

            log_debug!(
                self.logger,
                "[subscribe] matched_keys={} first={}",
                matched.len(),
                matched.first().cloned().unwrap_or_default()
            );

            // Find the newest retained event among matched topics within cutoff
            let mut newest: Option<(std::time::Instant, Option<ArcValue>, String)> = None;
            for key in matched {
                if let Some(entry) = self.retained_events.get(&key) {
                    log_debug!(
                        self.logger,
                        "[subscribe] considering key={} retained_count={} cutoff={:?}",
                        key,
                        entry.len(),
                        lookback
                    );
                    if let Some((ts, data)) = entry.iter().rev().find(|(ts, _)| *ts >= cutoff) {
                        let is_newer = match &newest {
                            None => true,
                            Some((nts, _, _)) => ts > nts,
                        };
                        if is_newer {
                            newest = Some((*ts, data.clone(), key.clone()));
                        }
                    }
                }
            }

            if let Some((_ts, data, _key)) = newest.clone() {
                log_debug!(
                    self.logger,
                    "[subscribe] delivering retained event to new subscriber"
                );
                let event_context = Arc::new(EventContext::new(
                    &topic_path,
                    Arc::new(self.clone()),
                    true,
                    self.logger.clone(),
                ));
                // Invoke only the newly registered subscription by id
                let cb = self
                    .service_registry
                    .get_local_event_subscribers(&topic_path)
                    .await;
                for (sid, handler, _) in cb {
                    if sid == subscription_id {
                        let _ = handler(event_context.clone(), data.clone()).await;
                    }
                }
            } else {
                log_debug!(
                    self.logger,
                    "[subscribe] no retained event found to deliver"
                );
            }
        }

        if node_started && !is_internal_service(topic_path.as_str()) {
            log_debug!(
                self.logger,
                "[subscribe] node started, notifying node change"
            );
            self.notify_node_change().await?;
        }

        Ok(subscription_id)
    }

    async fn unsubscribe(&self, subscription_id: &str) -> Result<()> {
        let node_started = self.running.load(Ordering::SeqCst);
        log_debug!(
            self.logger,
            "[unsubscribe] Unsubscribing from with ID: {subscription_id} - node started: {node_started}"
        );
        // Directly forward to service registry's method
        let registry = self.service_registry.clone();
        let topic_path = match registry.unsubscribe_local(subscription_id).await {
            Ok(topic_path) => {
                log_debug!(
                    self.logger,
                    "[unsubscribe] Successfully unsubscribed locally from  with id {subscription_id} and topic path {topic_path}"
                );
                topic_path
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "[unsubscribe] Failed to unsubscribe locally from  with id {subscription_id}: {e}"
                );
                return Err(anyhow!("Failed to unsubscribe locally: {e}"));
            }
        };
        //if already started and if not internal service... need to increment  -> registry_version
        if node_started && !is_internal_service(topic_path.as_str()) {
            log_debug!(
                self.logger,
                "[unsubscribe] node started, notifying node change"
            );
            self.notify_node_change().await?;
        }
        Ok(())
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
    async fn on(
        &self,
        topic: &str,
        options: Option<crate::services::OnOptions>,
    ) -> Result<Option<ArcValue>> {
        let full_topic = if topic.contains(':') {
            topic.to_string()
        } else {
            format!("{}:{}", self.network_id, topic)
        };

        let node = self.clone();
        let handle = tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<ArcValue>>(1);
            use crate::services as services_mod;
            let on_opts = options.clone().unwrap_or(services_mod::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            });
            let opts = services_mod::EventRegistrationOptions {
                include_past: on_opts.include_past,
            };
            let subscription_id = node
                .subscribe(
                    &full_topic,
                    Arc::new(move |_ctx, data| {
                        let tx = tx.clone();
                        Box::pin(async move {
                            let _ = tx.send(data).await;
                            Ok(())
                        })
                    }),
                    Some(opts),
                )
                .await?;

            let result = match tokio::time::timeout(on_opts.timeout, rx.recv()).await {
                Ok(Some(event_data)) => Ok(event_data),
                Ok(None) => Err(anyhow!(
                    "Channel closed while waiting for event on topic: {full_topic}"
                )),
                Err(_) => Err(anyhow!("Timeout waiting for event on topic: {full_topic}")),
            };

            let _ = node.unsubscribe(&subscription_id).await;
            result
        });

        handle.await.map_err(|e| anyhow!(e))?
    }
}

// Tests for include_past are located in runar-node-tests

#[async_trait]
impl KeysDelegate for Node {
    async fn ensure_symmetric_key(&self, key_name: &str) -> Result<ArcValue> {
        let mut keys_manager = self.keys_manager_mut.lock().await;
        let key = keys_manager.ensure_symmetric_key(key_name)?;
        Ok(ArcValue::new_bytes(key))
    }
}

#[async_trait]
impl RegistryDelegate for Node {
    /// Get service state
    async fn get_local_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.service_registry
            .get_local_service_state(service_path)
            .await
    }

    async fn get_remote_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.service_registry
            .get_remote_service_state(service_path)
            .await
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
    ) -> Result<HashMap<String, ServiceMetadata>> {
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

    async fn register_remote_event_handler(
        &self,
        topic_path: &TopicPath,
        handler: RemoteEventHandler,
    ) -> Result<String> {
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
        self.service_registry
            .validate_pause_transition(service_path)
            .await
    }

    async fn validate_resume_transition(&self, service_path: &TopicPath) -> Result<()> {
        // Delegate to the service registry
        self.service_registry
            .validate_resume_transition(service_path)
            .await
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
            // peer_directory: self.peer_directory.clone(),
            // peer_connect_mutexes: self.peer_connect_mutexes.clone(),
            remote_node_info: self.remote_node_info.clone(),
            discovery_seen_times: self.discovery_seen_times.clone(),
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
            service_tasks: self.service_tasks.clone(),
            local_node_info: self.local_node_info.clone(),
            retained_events: self.retained_events.clone(),
            retained_index: self.retained_index.clone(),
        }
    }
}
