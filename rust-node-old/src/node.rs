use anyhow::{anyhow, Result};
use log::info;
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid;
use uuid::Uuid;


use crate::db::SqliteDatabase;
use crate::p2p::service::P2PRemoteServiceDelegate;
use crate::p2p::transport::{TransportConfig, P2PTransport};
use crate::services::abstract_service::{ServiceState, AbstractService};
use crate::routing::TopicPath;
use crate::services::{
    NodeRequestHandler, RequestContext, ServiceRequest, ServiceResponse,
    SubscriptionOptions, ResponseStatus,
};
use crate::services::service_registry::ServiceRegistry;
use crate::services::node_info::NodeInfoService;
use runar_common::utils::logging::{Component, debug_log, debug_log_with_data, info_log, error_log, warn_log};
use runar_common::types::ValueType;
use crate::services::RequestOptions;

/// Configuration for a Node
/// Encapsulates all configuration options for a node in one place
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Network ID for the node
    pub network_id: String,
    /// Node ID for logging and identification
    pub node_id: Option<String>,
    /// Path to the node's storage directory
    pub node_path: String,
    /// Path to the node's database file
    pub db_path: String,
    /// P2P transport configuration
    pub p2p_config: Option<TransportConfig>,
    /// Node state directory (defaults to node_path)
    pub state_path: Option<String>,
    /// Test network IDs to use for testing purposes
    pub test_network_ids: Option<Vec<String>>,
    /// Bootstrap nodes for the node
    pub bootstrap_nodes: Option<Vec<String>>,
    /// Listen address for the node
    pub listen_addr: Option<String>,
}

impl NodeConfig {
    /// Create a new NodeConfig with minimal required parameters
    pub fn new(network_id: &str, node_path: &str, db_path: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            node_path: node_path.to_string(),
            db_path: db_path.to_string(),
            node_id: None, // Default to None
            p2p_config: None,
            state_path: None,
            test_network_ids: None,
            bootstrap_nodes: None,
            listen_addr: None,
        }
    }

    /// Generate a random node ID if one is not provided
    fn get_or_generate_node_id(&self) -> String {
        self.node_id.clone().unwrap_or_else(|| {
            if cfg!(test) {
                "TEST_NODE".to_string()
            } else {
                format!("node-{}", Uuid::new_v4())
            }
        })
    }

    /// Create a new NodeConfig with a specific node ID (for testing)
    pub fn new_with_node_id(network_id: &str, node_path: &str, node_id: &str) -> Self {
        let db_path = format!("{}/node.db", node_path);
        NodeConfig {
            network_id: network_id.to_string(),
            node_id: Some(node_id.to_string()),
            node_path: node_path.to_string(),
            db_path,
            p2p_config: None,
            state_path: None,
            test_network_ids: None,
            bootstrap_nodes: None,
            listen_addr: None,
        }
    }
}

/// Node represents a Runar node that can host services and communicate with other nodes
pub struct Node {
    /// Configuration for the node
    pub config: NodeConfig,

    /// Service registry for managing services
    pub service_registry: Arc<ServiceRegistry>,

    /// Database instance
    pub db: Arc<SqliteDatabase>,

    /// Network ID for this node
    pub network_id: String,

    /// Path to the node's data directory
    pub node_path: String,

    /// Path to the node's database
    pub db_path: String,

    /// Path to the node's state directory
    pub state_path: String,

    /// The P2P delegate for remote service calls and transport management
    p2p_delegate: Arc<P2PRemoteServiceDelegate>,

    /// Track initialization state
    pub initialized: bool,

    /// Service map for tracking registered services
    services: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,

    /// Service state
    state: Arc<RwLock<ServiceState>>,
}

/// NodeRequestHandlerImpl - Implements NodeRequestHandler by wrapping a reference to the Node
pub struct NodeRequestHandlerImpl {
    /// Reference to the service registry
    service_registry: Arc<ServiceRegistry>,
    /// Thread-local storage for current context
    #[allow(unused)]
    current_context: Arc<tokio::sync::RwLock<Option<RequestContext>>>,
}

impl NodeRequestHandlerImpl {
    /// Create a new NodeRequestHandlerImpl
    pub fn new(service_registry: Arc<ServiceRegistry>) -> Self {
        Self { 
            service_registry,
            current_context: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Set the current context for this request handler
    pub async fn set_current_context(&self, context: RequestContext) {
        let mut ctx = self.current_context.write().await;
        *ctx = Some(context);
    }

    /// Clear the current context
    pub async fn clear_current_context(&self) {
        let mut ctx = self.current_context.write().await;
        *ctx = None;
    }

    //TODO this method should receive a topicPath instead of service name and operation. 
    //the topicPath object shoudl ahve methods pot access erviuce bname and action or event name easilyt
    async fn request_impl(&self, service_name: String, operation: String, params: Option<ValueType>) -> Result<ServiceResponse> {
        let _ = debug_log(
            Component::Node,
            &format!(
                "NodeRequestHandlerImpl::request - Service: {}, Operation: {}",
                service_name, operation
            ),
        );
        
        // Get a reference to the service with fallback to error
        let service = match self.service_registry.get_service(&service_name).await {
            Some(service) => service,
            None => {
                return Ok(ServiceResponse::error(format!("Service not found: {}", service_name)));
            }
        };
        
        // Create a simple topic path for the request (without using network_id)
        //wont be neede when this func receives a topicPath instance as param
        let action_path = TopicPath::new_action("", &service_name, &operation); // Network ID not needed here
        
        // Create the request
        let request = ServiceRequest {
            path: service_name.clone(),
            action: operation.clone(),
            data: params,
            //request id should be generated by the node here.
            request_id: None,
            // Create RequestContext with proper parameters
            context: Arc::new(RequestContext::new(
                //this method should receive a topicPath instance and that shuold be passed over ehre.
                format!("{}/{}", service_name, operation),
                //TODO data shouold be the params here not an EMPTY map
                ValueType::Map(HashMap::new()),
                Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()))
            )),
            metadata: None,
            topic_path: Some(action_path),
        };
        
        // Handle the request
        service.handle_request(request).await
    }
}

#[async_trait::async_trait]
impl NodeRequestHandler for NodeRequestHandlerImpl {
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse> {
        // Extract service name and operation from the path
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid path format: {}", path));
        }

        let service_name = parts[0].to_string();
        let operation = parts[1].to_string();

        // Create empty params if None is provided
        let params = Some(params).unwrap_or(ValueType::Null);

        // Call the utility function
        self.request_impl(service_name, operation, Some(params)).await
    }

    async fn request_with_options(&self, path: String, params: ValueType, options: RequestOptions) -> Result<ServiceResponse> {
        // Extract service name and operation from the path
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid path format: {}", path));
        }

        let service_name = parts[0].to_string();
        let operation = parts[1].to_string();

        // Create empty params if None is provided
        let params = Some(params).unwrap_or(ValueType::Null);

        // Check if we should use a timeout
        if let Some(timeout_ms) = options.timeout_ms {
            // Use tokio's timeout function to wrap the request
            match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                self.request_impl(service_name, operation, Some(params))
            ).await {
                Ok(result) => result,
                Err(_) => Ok(ServiceResponse::error("Request timed out")),
            }
        } else {
            // No timeout, just forward the request
            self.request_impl(service_name, operation, Some(params)).await
        }
    }

    async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        // Parse the topic and data, and publish the event
        // We do this by making a request to the service registry


        //TODO the publish shoult not be done in the registry..
        //the registru should just do the search and find all the subscribers for a given topic.
        //then the node is responsioble to publish to them and also hadnle all the other details that current are iside the regist
        self.service_registry.publish(topic, data).await
    }

    async fn subscribe(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
    ) -> Result<String> {
        // Use default subscription options
        self.subscribe_with_options(topic, callback, SubscriptionOptions::default()).await
    }
    
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
        options: SubscriptionOptions,
    ) -> Result<String> {
        // Debug logging
        println!("[DEBUG] NodeRequestHandlerImpl::subscribe_with_options called with topic: '{}'", topic);
        
        // Pass the full topic directly to the service registry
        // The registry will parse it correctly using TopicPath
        println!("[DEBUG] Calling registry.subscribe_with_options with full topic: '{}'", topic);
        self.service_registry.subscribe_with_options(topic, callback, options).await
    }

    async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()> {
        // Debug logging
        println!("[DEBUG] NodeRequestHandlerImpl::unsubscribe called with topic: '{}'", topic);
        
        // Pass the full topic directly to the service registry
        // The registry will parse it correctly using TopicPath
        println!("[DEBUG] Calling registry.unsubscribe with full topic: '{}'", topic);
        self.service_registry.unsubscribe(topic, subscription_id).await
    }

    fn list_services(&self) -> Vec<String> {
        // Spawn a blocking task to fetch the services synchronously
        let registry = self.service_registry.clone();
        match tokio::task::block_in_place(move || {
            match tokio::runtime::Handle::current().block_on(async {
                registry.list_services()
            }) {
                services => services
            }
        }) {
            services => services,
        }
    }
    
    fn current_context(&self) -> Option<RequestContext> {
        // Try to get the current context from the RwLock
        // We can't use async/await here because the trait method is not async
        // Instead, we'll use a blocking approach that should be used with caution
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            let ctx = self.current_context.read().await;
            ctx.clone()
        })
    }
}

// Explicitly implement Send and Sync for NodeRequestHandlerImpl
// This is needed because the trait object requires these bounds
unsafe impl Send for NodeRequestHandlerImpl {}
unsafe impl Sync for NodeRequestHandlerImpl {}

impl Node {
    /// Create a new node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Create the database
        let db = Arc::new(SqliteDatabase::new(&config.db_path).await?);

        // Create the service registry with the database
        let service_registry =
            Arc::new(ServiceRegistry::new_with_db(&config.network_id, db.clone()));

        // Get state path, defaulting to node_path if not set
        let state_path = config
            .state_path
            .as_ref()
            .map(String::clone)
            .unwrap_or_else(|| config.node_path.clone());

        // Create P2P delegate
        let p2p_delegate =
            P2PRemoteServiceDelegate::new(None, &config.network_id, db.clone()).await?;

        Ok(Self {
            service_registry,
            db,
            network_id: config.network_id.clone(),
            node_path: config.node_path.clone(),
            db_path: config.db_path.clone(),
            state_path,
            config,
            p2p_delegate: Arc::new(p2p_delegate),
            initialized: false,
            services: Arc::new(RwLock::new(HashMap::new())),
            state: Arc::new(RwLock::new(ServiceState::Created)),
        })
    }

    /// Initialize the node
    pub async fn init(&mut self) -> Result<()> {
        info_log(Component::Node, "Initializing node").await;

        // Set state to initializing
        *self.state.write().await = ServiceState::Initialized;

        // We can't set the node handler directly since we don't have mutable access to service_registry
        // instead, we'll create the node handler and use it for all our requests
        let _node_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));

        // Create and open the node database
        // (This is already done in the constructor, so just check for success)
        if !Path::new(&self.db_path).exists() {
            return Err(anyhow!("Database file not found: {}", self.db_path));
        }

        // Initialize services
        self.init_services().await?;

        // Initialize P2P
        self.init_p2p(None).await?;

        // Start anonymous service cleanup (every 30 minutes)
        Node::start_anonymous_service_cleanup(
            Arc::new(self.config.clone()),
            self.service_registry.clone(),
            Duration::from_secs(1800),
        )?;

        // Run initializers
        crate::init::run_initializers().await?;
        
        // When linkme is not available, use runtime registrations
        #[cfg(not(feature = "distributed_slice"))]
        {
            self.service_registry.init_runtime_registrations().await?;
        }

        // Set state to running
        *self.state.write().await = ServiceState::Running;
        self.initialized = true;

        info_log(Component::Node, "Node initialized").await;

        Ok(())
    }

    /// Initialize the P2P subsystem
    pub async fn init_p2p(&mut self, fixed_id_ref: Option<&str>) -> Result<()> {
        info_log(Component::Node, "Initializing P2P functionality").await;

        // Create transport config
        let transport_config = TransportConfig {
            network_id: self.config.network_id.clone(),
            state_path: self.state_path.clone(),
            bootstrap_nodes: self.config.bootstrap_nodes.clone(),
            listen_addr: self.config.listen_addr.clone(),
        };

        // Create and initialize P2P transport
        let p2p_transport = P2PTransport::new(transport_config, fixed_id_ref).await?;
        let p2p_transport = Arc::new(p2p_transport);

        // Update the delegate's transport
        let mut delegate = (*self.p2p_delegate).clone();
        delegate = delegate
            .with_transport(p2p_transport.clone(), Some(&self.config.network_id))
            .await?;
        self.p2p_delegate = Arc::new(delegate);

        // Start the transport to begin listening
        p2p_transport.start().await?;

        // If bootstrap nodes are configured, connect to them automatically
        if let Some(bootstrap_nodes) = &self.config.bootstrap_nodes {
            for bootstrap_addr in bootstrap_nodes {
                let _ = debug_log(
                    Component::Node,
                    &format!("Connecting to bootstrap node: {}", bootstrap_addr),
                );

                // Connect to the bootstrap node
                let connect_result = p2p_transport.connect(bootstrap_addr).await;
                match connect_result {
                    Ok(_) => {
                        let _ = info_log(
                            Component::Node,
                            &format!(
                                "Successfully connected to bootstrap node: {}",
                                bootstrap_addr
                            ),
                        );
                    }
                    Err(e) => {
                        let _ = warn_log(
                            Component::Node,
                            &format!(
                                "Failed to connect to bootstrap node {}: {}",
                                bootstrap_addr, e
                            ),
                        );
                    }
                }
            }
        }

        info_log(Component::Node, "P2P functionality initialized").await;
        Ok(())
    }

    /// Initialize built-in services
    pub async fn init_services(&mut self) -> Result<()> {
        info_log(Component::Node, "Initializing services").await;

        // Initialize the node info service
        let node_info_service =
            NodeInfoService::new(&self.config.network_id, Arc::new(self.config.clone()));
        self.add_service(node_info_service).await?;

        // Initialize the registry info service
        let registry_info_service = crate::services::registry_info::RegistryInfoService::new(
            &self.config.network_id,
            self.service_registry.clone(),
        );
        self.add_service(registry_info_service).await?;

        Ok(())
    }

    /// Add a service to the node
    pub async fn add_service<S>(&mut self, mut service: S) -> Result<()>
    where
        S: AbstractService + 'static,
    {
        // Create a node handler for request context
        let node_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));

        // Create a request context for initialization
        let request_context = Arc::new(RequestContext::new_with_option(
            service.name().to_string(),
            None,
            node_handler,
        ));

        // Initialize and start the service
        info!("Initializing service: {}", service.name());
        service.init(&request_context).await?;

        //TODO: service start shuold only happen after node starts is complete.; 
        //so if a service is added before node starts,. which is possible, we need to handle this scenarion.
        //they shuold be registered, but not started until the node starts.
        info!("Starting service: {}", service.name());
        service.start().await?;

        // Register with the service registry
        self.service_registry
            .register_service(Arc::new(service))
            .await?;

        Ok(())
    }

    //TODO rwemove this and any code that uses iyt.. we dont need this.  this has lead to isses in the past.. so remove ity
    /// Call a service with the given path, operation, and parameters
    /// This method is mainly for backward compatibility
    pub async fn call<P: Into<String>, O: Into<String>, V: Into<ValueType>>(
        &self,
        path: P,
        operation: O,
        params: V,
    ) -> Result<ServiceResponse> {
        // Combine path and operation into the new format
        let path_str = path.into();
        let op_str = operation.into();
        let full_path = format!("{}/{}", path_str, op_str);

        // Forward to the new request method
        self.request(full_path, params).await
    }

    /// Make a request to a service
    pub async fn request<P: Into<String>, D: Into<ValueType>>(
        &self,
        path: P,
        data: D,
    ) -> Result<ServiceResponse> {
        let path = path.into();
        let data = data.into();
        self.process_request(path, data).await
    }
    
    /// Helper method that does the actual request processing
    async fn process_request(&self, path_str: String, data_value: ValueType) -> Result<ServiceResponse> {
        // Parse the path using TopicPath
        // Format can be "[network_id:]serviceName/action"
        let topic_path = match TopicPath::parse(&path_str, &self.config.network_id) {
            Ok(tp) => tp,
            Err(_) => {
                // check if is a simplified path (aka local path)
                let parts: Vec<&str> = path_str.split('/').collect();
                if parts.len() < 2 {
                    return Err(anyhow!(
                        "Invalid path format, expected 'serviceName/action' or 'network:serviceName/action'"
                    ));
                }
                
                // Use current network_id with the parsed service path and action
                 TopicPath::new_action(&self.network_id, parts[0], parts[1])
            }
        };
        
        let service_name = topic_path.service_path.clone();
        let action = topic_path.action_or_event.clone();
        
        // Create a request context for the request
        let request_context = Arc::new(RequestContext::new_with_option(
            format!("node_request_{}", uuid::Uuid::new_v4()),
            None,
            Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone())),
        ));
        
        // Handle ValueTypes properly without unnecessary wrapping
        // We don't need to wrap ValueType variants in a map
        let processed_data = data_value;
        
        let request = ServiceRequest {
            path: service_name.clone(),
            action: action.clone(),
            data: Some(processed_data),
            //TODO: we need request_id, should not be None here
            request_id: None,
            context: request_context,
            metadata: None,
            topic_path: Some(topic_path.clone()),
        };
        
        // Find the target service
        // Use the TopicPath directly instead of extracting service_name
        if let Some(_service) = self.service_registry.get_service_by_topic_path(&topic_path).await {
            // Call the service
            _service.handle_request(request).await
        } else {
            // Service not found
            Ok(ServiceResponse::error(format!("Service '{}' not found", service_name)))
        }
    }
 
    /// Make a node request with any parameters
    pub async fn node_request(&self, params: ValueType) -> Result<ServiceResponse> {
        // Create a request context for the request
        let request_context = Arc::new(RequestContext::new_with_option(
            format!("node_request_{}", uuid::Uuid::new_v4()),
            None,
            Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone())),
        ));
        
        // Create an action path for the node info request
        let action_path = TopicPath::new_action(&self.config.network_id, "node", "info");
        let request = ServiceRequest {
            path: "node".to_string(),
            action: "info".to_string(),
            data: Some(params),
            request_id: None,
            context: request_context,
            metadata: None,
            topic_path: Some(action_path),
        };
        
        // Find the target service
        if let Some(service) = self.services.read().await.get("node_info").cloned() {
            // Call the service
            service.handle_request(request).await
        } else {
            // Service not found
            Ok(ServiceResponse::error("Node info service not found".to_string()))
        }
    }

    /// Publish an event on a topic
    pub async fn publish<T: Into<String>, V: Into<ValueType>>(
        &self,
        topic: T,
        data: V,
    ) -> Result<()> {
        let topic_str = topic.into();
        let data_value = data.into();

        // Parse topic to validate it, but we don't need to use the result
        // Adding underscore prefix to indicate it's intentionally unused
        let _topic_path = crate::routing::path_utils::parse_topic(&topic_str, &self.config.network_id)?;
        
        // Create a node handler reference for the request context with the correct network ID
        let node_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));

        // Delegate to the node handler's publish method
        node_handler.publish(topic_str, data_value).await
    }

    /// Subscribe to events on a topic
    pub async fn subscribe<T: Into<String>, F>(&self, topic: T, callback: F) -> Result<String>
    where
        F: Fn(ValueType) -> Result<()> + Send + Sync + 'static,
    {
        let topic_str = topic.into();
        let callback_box = Box::new(callback);

        // Use utility function to parse topic into TopicPath
        let topic_path = crate::routing::path_utils::parse_topic(&topic_str, &self.config.network_id)?;
        
        // Create a node handler reference for the request context with the correct network ID
        let node_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));

        // Create a request context
        let request_context = Arc::new(RequestContext::new_with_option(
            format!("{}/{}", topic_path.service_path, topic_path.action_or_event),
            None,
            node_handler.clone(),
        ));

        // Clone necessary data for background tasks
        let service_registry = self.service_registry.clone();
        let network_id = self.config.network_id.clone();
        let topic_str_clone = topic_str.clone();

        // Spawn a task to handle the async initialization and registration of the anonymous service
        tokio::spawn(async move {
            // Create an anonymous service to handle this subscription
            // This ensures all subscribers are tied to a service to maintain architectural consistency
            let mut anonymous_service =
                crate::services::AnonymousSubscriberService::new(&network_id, &topic_str_clone);

            // Initialize and start the service
            if let Err(e) = anonymous_service.init(&request_context).await {
                error_log(
                    Component::Node,
                    &format!("Error initializing anonymous service: {:?}", e)
                ).await;
                return;
            }

            if let Err(e) = anonymous_service.start().await {
                error_log(
                    Component::Node,
                    &format!("Error starting anonymous service: {:?}", e)
                ).await;
                return;
            }

            // Register the service with the registry
            let service_arc = Arc::new(anonymous_service);
            if let Err(e) = service_registry.register_service(service_arc.clone()).await {
                error_log(
                    Component::Node,
                    &format!("Error registering anonymous service: {:?}", e)
                ).await;
            }
        });

        // Create a wrapper that converts the synchronous callback to an async one
        // We need to use Arc to make the callback shareable and implement Fn
        let callback_arc = Arc::new(callback_box);
        let wrapper = Box::new(move |value: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            // Use a clone of the Arc instead of moving the callback_box
            let cb = callback_arc.clone();
            Box::pin(async move {
                (*cb)(value)
            })
        });

        // Register the subscription with a temporary service name
        // The background task will update with the actual service name once it's ready
        let subscription_id = format!("temp_{}", uuid::Uuid::new_v4().to_string());
        let anonymous_service_name = format!("anonymous_subscriber_{}", subscription_id);

        // Register the subscription with the anonymous service name using the provided options
        // This is now synchronous
        self.service_registry.subscribe(anonymous_service_name, wrapper).await
    }
    
    /// Subscribe to events on a topic with options
    pub async fn subscribe_with_options<T: Into<String>, F>(
        &self,
        topic: T,
        callback: F,
        options: SubscriptionOptions,
    ) -> Result<String>
    where
        F: Fn(ValueType) -> Result<()> + Send + Sync + 'static,
    {
        let topic_str = topic.into();
        let callback_box = Box::new(callback);

        // Use utility function to parse topic into TopicPath
        let topic_path = crate::routing::path_utils::parse_topic(&topic_str, &self.config.network_id)?;
        
        // Create a node handler reference for the request context with the correct network ID
        let node_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));

        // Create a request context
        let request_context = Arc::new(RequestContext::new_with_option(
            format!("{}/{}", topic_path.service_path, topic_path.action_or_event),
            None,
            node_handler.clone(),
        ));

        // Clone necessary data for background tasks
        let service_registry = self.service_registry.clone();
        let network_id = self.config.network_id.clone();
        let topic_str_clone = topic_str.clone();

        // Spawn a task to handle the async initialization and registration of the anonymous service
        tokio::spawn(async move {
            // Create an anonymous service to handle this subscription
            // This ensures all subscribers are tied to a service to maintain architectural consistency
            let mut anonymous_service =
                crate::services::AnonymousSubscriberService::new(&network_id, &topic_str_clone);

            // Initialize and start the service
            if let Err(e) = anonymous_service.init(&request_context).await {
                error_log(
                    Component::Node,
                    &format!("Error initializing anonymous service: {:?}", e)
                ).await;
                return;
            }

            if let Err(e) = anonymous_service.start().await {
                error_log(
                    Component::Node,
                    &format!("Error starting anonymous service: {:?}", e)
                ).await;
                return;
            }

            // Register the service with the registry
            let service_arc = Arc::new(anonymous_service);
            if let Err(e) = service_registry.register_service(service_arc.clone()).await {
                error_log(
                    Component::Node,
                    &format!("Error registering anonymous service: {:?}", e)
                ).await;
            }
        });

        // Create a wrapper that converts the synchronous callback to an async one
        // We need to use Arc to make the callback shareable and implement Fn
        let callback_arc = Arc::new(callback_box);
        let wrapper = Box::new(move |value: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            // Use a clone of the Arc instead of moving the callback_box
            let cb = callback_arc.clone();
            Box::pin(async move {
                (*cb)(value)
            })
        });

        // Register the subscription with a temporary service name
        // The background task will update with the actual service name once it's ready
        let subscription_id = format!("temp_{}", uuid::Uuid::new_v4().to_string());
        let anonymous_service_name = format!("anonymous_subscriber_{}", subscription_id);

        // Register the subscription with the anonymous service name using the provided options
        // This is now synchronous
        self.service_registry.subscribe_with_options(anonymous_service_name, wrapper, options).await
    }

    /// Subscribe to an event once (unsubscribes after first event)
    pub async fn once<T: Into<String>, F>(&self, topic: T, callback: F) -> Result<String>
    where
        F: Fn(ValueType) -> Result<()> + Send + Sync + 'static,
    {
        // Create subscription options
        let options = SubscriptionOptions::new(RequestContext::default()).once();

        // Subscribe with the one-time options
        self.subscribe_with_options(topic, callback, options).await
    }

    /// Unsubscribe from a topic
    pub async fn unsubscribe<T: Into<String>>(
        &self,
        topic: T,
        subscription_id: Option<&str>,
    ) -> Result<()>
where {
        let topic_str = topic.into();

        // Use the service registry's unsubscribe method directly
        self.service_registry.unsubscribe(topic_str, subscription_id).await
    }

    /// Get the service registry
    pub fn service_registry(&self) -> Arc<ServiceRegistry> {
        log::warn!("[{}][{}] Warning: Using service_registry() which returns a new empty clone", 
            self.config.get_or_generate_node_id(), 
            Component::Node.as_str());
        Arc::new(ServiceRegistry::new(&self.network_id))
    }

    /// Get the service registry as an Arc
    pub fn service_registry_arc(&self) -> Arc<ServiceRegistry> {
        log::debug!("[{}][{}] Using service_registry_arc() which returns the actual registry", 
            self.config.get_or_generate_node_id(), 
            Component::Node.as_str());
        self.service_registry.clone()
    }

    /// Get the database connection
    pub fn db(&self) -> Arc<SqliteDatabase> {
        self.db.clone()
    }

    /// Get the network ID
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Get the node path
    pub fn node_path(&self) -> &str {
        &self.node_path
    }

    /// Get the database path
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Stop all registered services
    pub async fn stop_services(&self) -> Result<()> {
        let services = self.services.read().await.clone();
        
        for service_name in services.keys() {
            // Use request-based API with empty map
            self.request(&format!("{}/stop", service_name), ValueType::Map(HashMap::new())).await?;
        }
        
        Ok(())
    }

    /// Start all registered services
    pub async fn start_services(&self) -> Result<()> {
        let services = self.services.read().await.clone();
        
        for service_name in services.keys() {
            // Use request-based API with empty map
            self.request(&format!("{}/start", service_name), ValueType::Map(HashMap::new())).await?;
        }
        
        Ok(())
    }

    /// Stop the node and all its services
    pub async fn stop(&self) -> Result<()> {
        // Stop all services first
        self.stop_services().await?;

        // Stop P2P delegate - clone and use deref
        let p2p_delegate = (*self.p2p_delegate).clone();
        p2p_delegate.stop().await?;

        Ok(())
    }

    /// Start the node and all its services
    pub async fn start(&self) -> Result<()> {
        if !self.initialized {
            return Err(anyhow!("Node must be initialized before starting. Call init() first."));
        }

        // Start all services
        self.start_services().await?;

        // Start P2P delegate - clone and use deref
        let mut p2p_delegate = (*self.p2p_delegate).clone();
        p2p_delegate.start().await?;

        log::info!("[{}][{}] Node started: {}", 
            Component::Node.as_str(),
            self.network_id, 
            self.config.get_or_generate_node_id());
        
        Ok(())
    }

    /// Run periodic cleanup of anonymous services
    pub fn start_anonymous_service_cleanup(
        config: Arc<NodeConfig>,
        registry: Arc<ServiceRegistry>,
        interval: Duration,
    ) -> Result<()> {
        // Spawn a background task to perform periodic cleanup
        tokio::spawn(async move {
            let network_id = config.network_id.clone();

            // Create a node request handler for the cleanup task
            let node_handler = Arc::new(NodeRequestHandlerImpl::new(registry.clone()));

            loop {
                // Sleep for the specified interval
                tokio::time::sleep(interval).await;

                // Get all services
                let services = registry.get_all_services().await;
                let mut removed_count = 0;

                // Loop through all anonymous subscriber services
                for service in services {
                    // Check if this is an anonymous subscriber service
                    if service.name().starts_with("anonymous_subscriber_") {
                        // Create a request context
                        let _request_context = Arc::new(RequestContext::new_with_option(
                            format!("{}/get_info", service.name()),
                            None,
                            node_handler.clone(),
                        ));

                        // Create a get_info request to check the service status
                        let service_path = service.path().to_string();
                        let action_path = TopicPath::new_action(&network_id, &service_path, "get_info");
                        let request = ServiceRequest {
                            request_id: Some(Uuid::new_v4().to_string()),
                            path: service_path,
                            action: "get_info".to_string(),
                            data: None,
                            context: _request_context,
                            metadata: None,
                            topic_path: Some(action_path),
                        };

                        // Process the request
                        match service.handle_request(request).await {
                            Ok(response) => {
                                if response.status == ResponseStatus::Success {
                                    // Extract information from the response
                                    if let Some(data) = response.data {
                                        // Check if this is an anonymous subscriber service that can be cleaned up
                                        let is_expired = if let ValueType::Map(data_map) = &data {
                                            if let Some(ValueType::Bool(expired)) = data_map.get("is_expired") {
                                                *expired
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        };

                                        let subscription_count = if let ValueType::Map(data_map) = &data {
                                            if let Some(ValueType::Number(count)) = data_map.get("subscription_count") {
                                                *count as i64
                                            } else {
                                                1
                                            }
                                        } else {
                                            1
                                        };

                                        if is_expired && subscription_count == 0 {
                                            // Get the service name
                                            let name = service.name().to_string();

                                            // Stop the service
                                            // Note: We can't call stop() directly because it requires &mut self
                                            // Instead, we'll create a request to stop the service
                                            // Create action path for the stop request
                                            let action_path = TopicPath::new_action(&network_id, &name, "stop");
                                            let request = ServiceRequest {
                                                path: name.clone(),
                                                action: "stop".to_string(),
                                                data: None,
                                                request_id: Some(uuid::Uuid::new_v4().to_string()),
                                                context: Arc::new(RequestContext::new_with_option(
                                                    format!("{}/stop", name),
                                                    None,
                                                    Arc::new(NodeRequestHandlerImpl::new(registry.clone())),
                                                )),
                                                metadata: None,
                                                topic_path: Some(action_path),
                                            };
                                            
                                            if let Err(e) = service.handle_request(request).await {
                                                log::error!("[{}][{}] Failed to stop service {}: {}", 
                                                    Component::Node.as_str(),
                                                    network_id,
                                                    name, 
                                                    e);
                                                continue;
                                            }

                                            // Log the cleanup
                                            let _ = info_log(
                                                Component::Node,
                                                &format!(
                                                    "Cleaned up expired anonymous service: {}",
                                                    name
                                                ),
                                            ).await;

                                            removed_count += 1;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Log the error but continue processing other services
                                let _ = error_log(
                                    Component::Node,
                                    &format!("Error checking anonymous service status: {}", e),
                                ).await;
                            }
                        }
                    }
                }

                if removed_count > 0 {
                    let _ = info_log(
                        Component::Node,
                        &format!("Cleaned up {} expired anonymous services", removed_count),
                    ).await;
                }
            }
        });

        Ok(())
    }

    /// Wait for a service to become available
    pub async fn wait_for_service(&self, service_name: &str, timeout_ms: Option<u64>) -> Result<bool> {
        let timeout_duration = Duration::from_millis(timeout_ms.unwrap_or(10000));
        let start_time = Instant::now();

        while start_time.elapsed() < timeout_duration {
            // Check if service exists in registry
            let services = self.request("registry/list", ValueType::Json(json!({}))).await?;
            
            if let Some(ValueType::Array(services)) = services.data {
                for service in services {
                    if let ValueType::String(name) = service {
                        if name == service_name {
                            return Ok(true);
                        }
                    }
                }
            }

            // Wait a bit before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(false)
    }

    /// Get a mutable reference to a service by name
    async fn get_service_mut(&self, name: &str) -> Result<Box<dyn AbstractService>> {
        let _service = self.service_registry.get_service(name).await
            .ok_or_else(|| anyhow!("Service '{}' not found", name))?;
        
        // Instead of creating a dummy service, we should properly handle mutability
        // using interior mutability patterns or by redesigning the API
        Err(anyhow!("Mutable access to services is not supported in this way. Consider using interior mutability or redesigning the API."))
    }

    pub async fn request_with_options<P: Into<String>, D: Into<ValueType>>(
        &self,
        path: P,
        data: D,
        options: RequestOptions,
    ) -> Result<ServiceResponse> {
        let path_str = path.into();
        let data_value = data.into();
        
        // Create a request handler
        let request_handler = Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone()));
        
        // Call request_with_options on the handler
        request_handler.request_with_options(path_str, data_value, options).await
    }

    #[cfg(test)]
    pub fn get_registry_for_test(&self) -> Arc<ServiceRegistry> {
        self.service_registry_arc().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> NodeConfig {
        NodeConfig {
            network_id: "test".to_string(),
            node_id: None,
            node_path: "/tmp/test".to_string(),
            db_path: "/tmp/test/node.db".to_string(),
            p2p_config: None,
            state_path: None,
            test_network_ids: None,
            bootstrap_nodes: None,
            listen_addr: None,
        }
    }
}
