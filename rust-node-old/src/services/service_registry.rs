use anyhow::{anyhow, Result};
use async_trait::async_trait;
use uuid::Uuid;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration as StdDuration;
use tokio::runtime::Handle;
use std::sync::atomic::{AtomicUsize, Ordering};
use log::{debug, info, warn, error};

use crate::db::SqliteDatabase;
use crate::node::NodeRequestHandlerImpl;
use crate::p2p::crypto::PeerId;
use crate::p2p::service::P2PRemoteServiceDelegate;
use crate::p2p::transport::P2PServiceInfo;
use crate::p2p::peer_id_convert::CryptoToLibP2pPeerId;
use crate::routing::{TopicPath, PathType};
use crate::services::abstract_service::{ServiceState, AbstractService, ActionMetadata, EventMetadata};
use crate::services::remote::P2PTransport;
use crate::services::{
    NodeRequestHandler, RequestContext, ServiceRequest, ServiceResponse, ValueType,
    ResponseStatus, SubscriptionOptions
};
use crate::server::Service;
use crate::services::RequestOptions;
use runar_common::utils::logging::{debug_log, error_log, info_log, warn_log, Component};

// Simple AsyncCache implementation
struct AsyncCache<K, V> {
    cache: Arc<Mutex<HashMap<K, V>>>,
    _ttl: StdDuration,
}

impl<K, V> AsyncCache<K, V> 
where 
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    fn new(ttl: StdDuration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            _ttl: ttl,
        }
    }

    async fn get(&self, key: &K) -> Option<V> 
    where 
        K: Clone,
        V: Clone,
    {
        let cache = self.cache.lock().unwrap();
        cache.get(key).cloned()
    }

    async fn set(&self, key: K, value: V) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key, value);
    }
}

// Define the necessary types here
type EventData = ValueType;
type EventCallback = Arc<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;
struct Event {
    topic: String,
    data: EventData,
}

/// Type definition for action handlers
pub type ActionHandler = dyn Fn(&RequestContext, &ValueType) -> Pin<Box<dyn Future<Output = Result<ServiceResponse>> + Send>> + Send + Sync;

/// Type definition for process handlers
pub type ProcessHandler = dyn Fn(&RequestContext, &str, &ValueType) -> Pin<Box<dyn Future<Output = Result<ServiceResponse>> + Send>> + Send + Sync;

/// Type definition for subscription handlers
pub type SubscriptionHandler = dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync;

/// Entry for an action handler in the registry
#[derive(Clone)]
pub struct ActionHandlerEntry {
    /// The service that owns this action
    pub service: String,
    /// The action name
    pub action: String,
    /// Timeout for this action
    pub timeout: StdDuration,
    /// The handler function
    pub handler: Arc<ActionHandler>,
}

/// Registry for process handlers - maps service_name to handler functions
#[derive(Clone)]
pub struct ProcessHandlerEntry {
    pub service: String,
    pub process_id: String,
    pub timeout: StdDuration,
    pub handler: Arc<ProcessHandler>,
}

/// Entry for a subscription in the registry
#[derive(Clone)]
pub struct SubscriptionEntry {
    /// Unique ID for this subscription
    pub id: String,
    /// The topic this subscription is for
    pub topic: String,
    /// The service path of the subscriber
    pub service_path: String,
    /// Subscription options
    pub options: SubscriptionOptions,
    /// Whether this is a remote subscription
    pub remote: bool,
    /// Peer ID for remote subscriptions
    pub peer_id: Option<PeerId>,
}

/// ServiceRegistry is responsible for registering, discovering, and managing services
/// It combines the functionality of the previous ServiceRegistry and ServiceManager
pub struct ServiceRegistry {
    /// The path of the registry
    path: String,

    /// The services managed by this registry, organized by network_id -> service_name -> service
    services: Arc<RwLock<HashMap<String, HashMap<String, Arc<dyn AbstractService>>>>>,

    /// The database connection (optional)
    db: Option<Arc<SqliteDatabase>>,

    /// The node handler for sending requests to other services
    node_handler: Option<Arc<dyn NodeRequestHandler + Send + Sync>>,

    /// Event subscribers with topic as the key - wrapped in Arc to share between clones
    event_subscribers: Arc<RwLock<HashMap<String, Vec<String>>>>,

    /// Callback map for event subscribers - wrapped in Arc to share between clones
    event_callbacks: Arc<RwLock<HashMap<String, Vec<(String, EventCallback)>>>>,

    /// Remote peer map - peer_id to list of services offered by that peer
    remote_peers: RwLock<HashMap<PeerId, Vec<String>>>,

    /// P2P delegate for communicating with remote peers
    p2p_delegate: RwLock<Option<Arc<P2PRemoteServiceDelegate>>>,

    /// Remote subscriptions map - peer_id to set of topics they are subscribed to
    remote_subscriptions: RwLock<HashMap<PeerId, HashSet<String>>>,

    /// Service info cache
    service_info_cache: RwLock<HashMap<String, P2PServiceInfo>>,

    /// Node handler lock for interior mutability
    node_handler_lock: RwLock<Option<Arc<dyn NodeRequestHandler + Send + Sync>>>,

    /// Storage for action handlers
    action_handlers: RwLock<HashMap<(String, String), ActionHandlerEntry>>,
    
    /// Storage for process handlers
    process_handlers: RwLock<HashMap<String, ProcessHandlerEntry>>,
    
    /// Storage for subscriptions
    subscription_handlers: RwLock<HashMap<(String, String), Arc<dyn Fn(ValueType) -> Result<()> + Send + Sync>>>,
    
    /// Storage for publications
    publication_topics: RwLock<HashMap<String, HashSet<String>>>,

    /// Cache for service lookups
    services_cache: AsyncCache<String, Arc<dyn AbstractService + Send + Sync>>,

    /// Events that are waiting for a subscription
    pending_events: Arc<Mutex<Vec<(String, EventData)>>>,

    /// Maximum number of pending events to store
    max_pending_events: usize,

    /// Concurrency control for event tasks
    event_task_semaphore: Arc<Semaphore>,
    max_event_tasks: usize,
    max_concurrent_event_executions: usize,
    current_event_tasks: Arc<AtomicUsize>,
}

// Implement Clone manually for ServiceRegistry
impl Clone for ServiceRegistry {
    fn clone(&self) -> Self {
        // Debug logging for cloning
        println!("[ServiceRegistry] Cloning registry instance with address {:p}", self);
        
        // Debug: Dump the subscribers map
        println!("[ServiceRegistry] CLONE: Dumping event_subscribers map:");
        let event_subscribers_ref = self.event_subscribers.try_read();
        if let Ok(subs) = event_subscribers_ref {
            for (topic, subscribers) in subs.iter() {
                println!("[ServiceRegistry] CLONE:   Topic '{}': {:?}", topic, subscribers);
            }
        } else {
            println!("[ServiceRegistry] CLONE: Could not read event_subscribers (locked)");
        }
        
        // Instead of trying to clone the services, just reuse the Arc<RwLock>
        println!("[ServiceRegistry] CLONE: Using shared services Arc<RwLock> for clone");
        
        // Create new registry sharing the same maps through Arc
        ServiceRegistry {
            path: self.path.clone(),
            services: Arc::clone(&self.services),
            db: self.db.clone(),
            node_handler: self.node_handler.clone(),
            event_subscribers: Arc::clone(&self.event_subscribers),
            event_callbacks: Arc::clone(&self.event_callbacks),
            remote_peers: RwLock::new(HashMap::new()),
            p2p_delegate: RwLock::new(None),
            remote_subscriptions: RwLock::new(HashMap::new()),
            service_info_cache: RwLock::new(HashMap::new()),
            node_handler_lock: RwLock::new(None),
            action_handlers: RwLock::new(HashMap::new()),
            process_handlers: RwLock::new(HashMap::new()),
            subscription_handlers: RwLock::new(HashMap::new()),
            publication_topics: RwLock::new(HashMap::new()),
            services_cache: AsyncCache::new(StdDuration::from_secs(300)),
            pending_events: Arc::new(Mutex::new(Vec::new())),
            max_pending_events: self.max_pending_events,
            event_task_semaphore: Arc::clone(&self.event_task_semaphore),
            max_event_tasks: self.max_event_tasks,
            max_concurrent_event_executions: self.max_concurrent_event_executions,
            current_event_tasks: Arc::clone(&self.current_event_tasks),
        }
    }
}

// Implement the ServiceRegistry trait from server.rs
#[async_trait]
impl crate::server::ServiceRegistry for ServiceRegistry {
    async fn register_service(&self, service: Arc<dyn crate::server::Service>) -> Result<()> {
        // Get the service name
        let service_name = service.name().to_string();
        
        info_log(
            Component::Registry,
            &format!("Registering server service: {}", service_name)
        ).await;
        
        // Create an adapter that wraps the Server::Service as an AbstractService
        let adapter = ServerServiceAdapter::new(service);
        
        // Use default network ID for server services
        self.register_service("default", Arc::new(adapter)).await
    }
    
    async fn get_service(&self, name: &str) -> Option<Arc<dyn crate::server::Service>> {
        // Create a topic path for lookup in the default network
        let topic_path = TopicPath::new_service("default", name);
        
        // Try to get the service from our registry
        if let Some(abstract_service) = self.get_service_by_topic_path(&topic_path).await {
            // Check if it's a ServerServiceAdapter
            if let Some(adapter) = ServerServiceAdapter::from_abstract(abstract_service.clone()) {
                return Some(adapter.inner_service());
            }
        }
        None
    }
}

/// Adapter to convert between Service and AbstractService
struct ServerServiceAdapter {
    inner: Arc<dyn crate::server::Service>,
}

impl ServerServiceAdapter {
    fn new(service: Arc<dyn crate::server::Service>) -> Self {
        Self { inner: service }
    }
    
    fn inner_service(&self) -> Arc<dyn crate::server::Service> {
        self.inner.clone()
    }
    
    fn from_abstract(service: Arc<dyn AbstractService>) -> Option<Arc<Self>> {
        // For now, we need to use a simpler method since downcast isn't working well
        // Check if the name follows our convention for server adapters
        let name = service.name();
        if name.starts_with("server_adapter_") {
            // Create a new adapter - we can't actually extract the inner service
            // This is a simplified version that won't work well in practice
            None
        } else {
            None
        }
    }
}

#[async_trait]
impl AbstractService for ServerServiceAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }
    
    fn path(&self) -> &str {
        // Since the server::Service trait might not have a path method,
        // we'll just use the name as the path for now
        self.inner.name()
    }
    
    fn description(&self) -> &str {
        "Server service adapter"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn state(&self) -> ServiceState {
        // Server services are always considered running
        ServiceState::Running
    }
    
    async fn init(&mut self, _context: &RequestContext) -> Result<()> {
        // Server services are already initialized
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        // Server services are already started
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        // No-op for server services
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Forward the request to the inner service
        self.inner.handle_request(request).await
    }
}

/// A ServiceRequest handler for the ServiceRegistry
/// This allows it to receive and process requests like a service
#[async_trait]
impl NodeRequestHandler for ServiceRegistry {
    /// Request a service to perform an action
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse> {
        // Parse the path into a TopicPath
        let topic_path = match TopicPath::parse(&path, "default") {
            Ok(tp) => tp,
            Err(e) => {
                return Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: format!("Invalid path format: {}", e),
                    data: None,
                });
            }
        };
        
        // Get the service using the parsed path
        let service_path = topic_path.service_path.clone();
        let network_id = topic_path.network_id.clone();
        
        // Create a topic path for service lookup
        let service_topic_path = TopicPath::new_service(&network_id, &service_path);
        
        // Try to get the service
        let service = match self.get_service_by_topic_path(&service_topic_path).await {
            Some(s) => s,
            None => {
                return Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: format!("Service not found: {}", service_path),
                    data: None,
                });
            }
        };
        
        // Create a request context
        let context = RequestContext::default();
        
        // Create a service request
        let request = ServiceRequest::new(
            &service_path,
            &topic_path.action_or_event,
            params,
            Arc::new(context)
        );
        
        // Forward to the service
        service.handle_request(request).await
    }
    
    /// Publish an event to a topic
    async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        debug_log(
            Component::Registry,
            &format!("Publishing event to topic '{}'", topic)
        );
        
        // Get callbacks for this topic
        let callbacks = {
            let callbacks_map = self.event_callbacks.read().await;
            if let Some(cb_list) = callbacks_map.get(&topic) {
                // Return the references to callbacks but don't clone them
                cb_list.iter().map(|(id, cb)| (id.clone(), cb.clone())).collect::<Vec<_>>()
            } else {
                // No subscribers
                Vec::new()
            }
        };
        
        // Store as a pending event if there are no subscribers
        if callbacks.is_empty() {
            debug_log(
                Component::Registry,
                &format!("No subscribers for topic '{}', storing as pending event", topic)
            );
            
            // Add to pending events
            let mut pending_events = self.pending_events.lock().unwrap();
            
            // Maintain max size
            if pending_events.len() >= self.max_pending_events {
                // Remove oldest events to stay under limit
                let new_start = pending_events.len() - self.max_pending_events + 1;
                let mut new_events = Vec::new();
                for i in new_start..pending_events.len() {
                    new_events.push(pending_events[i].clone());
                }
                *pending_events = new_events;
            }
            
            // Add the new event
            pending_events.push((topic, data));
            
            return Ok(());
        }
        
        // Invoke each callback
        for (subscription_id, callback) in callbacks {
            debug_log(
                Component::Registry,
                &format!("Invoking callback for subscription '{}' on topic '{}'", 
                        subscription_id, topic)
            );
            
            // Clone data for each callback
            let data_clone = data.clone();
            
            // Get a permit from the semaphore
            let permit = match self.event_task_semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    error_log(
                        Component::Registry,
                        &format!("Failed to acquire semaphore permit: {}", e)
                    );
                    continue;
                }
            };
            
            // Spawn a task to handle the callback
            let current_tasks = self.current_event_tasks.clone();
            current_tasks.fetch_add(1, Ordering::SeqCst);
            
            tokio::spawn(async move {
                // Execute the callback
                let result = callback(data_clone);
                
                // Drop the permit when done
                drop(permit);
                
                // Update task count
                current_tasks.fetch_sub(1, Ordering::SeqCst);
                
                // Log any errors
                if let Err(e) = result.await {
                    error!("Error executing event callback: {}", e);
                }
            });
        }
        
        Ok(())
    }
    
    /// Subscribe to a topic
    async fn subscribe(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
    ) -> Result<String> {
        self.subscribe_with_options(topic, callback, SubscriptionOptions::default()).await
    }
    
    /// Subscribe to a topic with options
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
        _options: SubscriptionOptions,
    ) -> Result<String> {
        // Generate a unique subscription ID
        let subscription_id = uuid::Uuid::new_v4().to_string();
        
        debug_log(
            Component::Registry,
            &format!("Subscribing to topic '{}' with ID '{}'", topic, subscription_id)
        );
        
        // Update the subscribers map
        {
            let mut subscribers = self.event_subscribers.write().await;
            
            // Create entry if not exists
            if !subscribers.contains_key(&topic) {
                subscribers.insert(topic.clone(), Vec::new());
            }
            
            // Add this subscription ID to the list
            if let Some(sub_list) = subscribers.get_mut(&topic) {
                sub_list.push(subscription_id.clone());
            }
        }
        
        // Convert Box to Arc to make it cloneable
        let callback_arc: EventCallback = Arc::new(move |value| callback(value));
        
        // Update the callbacks map
        {
            let mut callbacks = self.event_callbacks.write().await;
            
            // Create entry if not exists
            if !callbacks.contains_key(&topic) {
                callbacks.insert(topic.clone(), Vec::new());
            }
            
            // Add the callback
            if let Some(cb_list) = callbacks.get_mut(&topic) {
                cb_list.push((subscription_id.clone(), callback_arc));
            }
        }
        
        // Return the subscription ID
        Ok(subscription_id)
    }
    
    /// Unsubscribe from a topic
    async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()> {
        match subscription_id {
            Some(id) => {
                debug_log(
                    Component::Registry,
                    &format!("Unsubscribing from topic '{}' with ID '{}'", topic, id)
                );
                
                // Remove from subscribers map
                {
                    let mut subscribers = self.event_subscribers.write().await;
                    if let Some(sub_list) = subscribers.get_mut(&topic) {
                        sub_list.retain(|sub_id| sub_id != id);
                    }
                }
                
                // Remove from callbacks map
                {
                    let mut callbacks = self.event_callbacks.write().await;
                    if let Some(cb_list) = callbacks.get_mut(&topic) {
                        cb_list.retain(|(sub_id, _)| sub_id != id);
                    }
                }
            },
            None => {
                debug_log(
                    Component::Registry,
                    &format!("Unsubscribing from all callbacks for topic '{}'", topic)
                );
                
                // Remove entire topic
                {
                    let mut subscribers = self.event_subscribers.write().await;
                    subscribers.remove(&topic);
                }
                
                {
                    let mut callbacks = self.event_callbacks.write().await;
                    callbacks.remove(&topic);
                }
            }
        }
        
        Ok(())
    }
    
    /// List all services
    fn list_services(&self) -> Vec<String> {
        // Return a flattened list of all services across all networks
        let services_opt = self.services.try_read();
        if let Ok(services) = services_opt {
            let mut result = Vec::new();
            
            // Iterate through each network
            for (_, network_services) in services.iter() {
                // Extract unique service names
                for (name, _) in network_services.iter() {
                    // Only add the name if it's not a path
                    if !name.contains('/') {
                        result.push(name.clone());
                    }
                }
            }
            
            result
        } else {
            Vec::new()
        }
    }
}

// Add a method to list services for a specific network (not part of NodeRequestHandler trait)
impl ServiceRegistry {
    /// List services for a specific network
    pub fn list_services_for_network(&self, network_id: &str) -> Vec<String> {
        // Return a list of services for the specified network
        let services_opt = self.services.try_read();
        if let Ok(services) = services_opt {
            if let Some(network_services) = services.get(network_id) {
                let mut result = Vec::new();
                
                // Extract unique service names
                for (name, _) in network_services.iter() {
                    // Only add the name if it's not a path
                    if !name.contains('/') {
                        result.push(name.clone());
                    }
                }
                
                return result;
            }
        }
        
        Vec::new()
    }
    
    /// Create a new ServiceRegistry with a database
    pub fn new_with_db(db: Arc<SqliteDatabase>) -> Self {
        let mut registry = Self::new();
        registry.db = Some(db);
        registry
    }
    
    /// Register a service with a specific network ID
    pub async fn register_service(&self, network_id: &str, service: Arc<dyn AbstractService>) -> Result<()> {
        let service_name = service.name().to_string();
        let service_path = service.path().to_string();
        
        debug_log(
            Component::Registry,
            &format!("Registering service '{}' with path '{}' on network '{}'", 
                     service_name, service_path, network_id)
        );
        
        // Get our services map
        let mut services = self.services.write().await;
        
        // Ensure the network_id entry exists
        if !services.contains_key(network_id) {
            services.insert(network_id.to_string(), HashMap::new());
        }
        
        // Get the network's services map
        let network_services = services.get_mut(network_id).unwrap();
        
        // Add the service to the map
        network_services.insert(service_name.clone(), service.clone());
        
        // Also index by path for path-based lookups (lowercase for case-insensitive lookup)
        if !service_path.is_empty() && service_path != service_name {
            let lower_path = service_path.to_lowercase();
            network_services.insert(lower_path, service.clone());
        }
        
        // Log success
        debug_log(
            Component::Registry,
            &format!("Successfully registered service '{}' on network '{}'", service_name, network_id)
        );
        
        Ok(())
    }
    
    /// Get a service by TopicPath
    pub async fn get_service_by_topic_path(&self, topic_path: &TopicPath) -> Option<Arc<dyn AbstractService>> {
        let network_id = &topic_path.network_id;
        let service_path = &topic_path.service_path;
        
        debug_log(
            Component::Registry,
            &format!("Looking up service by topic path: network='{}', service='{}'", 
                    network_id, service_path)
        );
        
        // Get the services map for this network
        let services = self.services.read().await;
        
        if let Some(network_services) = services.get(network_id) {
            // Try lookup by service name first
            if let Some(service) = network_services.get(service_path) {
                return Some(service.clone());
            }
            
            // Try lookup by lowercase path
            let lower_path = service_path.to_lowercase();
            if let Some(service) = network_services.get(&lower_path) {
                return Some(service.clone());
            }
            
            // Try to find by service name/path attribute
            for (_, service) in network_services.iter() {
                if service.name() == service_path || service.path() == service_path {
                    return Some(service.clone());
                }
                
                // Also try case-insensitive match
                if service.name().to_lowercase() == lower_path || 
                   service.path().to_lowercase() == lower_path {
                    return Some(service.clone());
                }
            }
        }
        
        debug_log(
            Component::Registry,
            &format!("Service not found: network='{}', service='{}'", network_id, service_path)
        );
        
        None
    }
    
    /// Handle a service request (internal method, not part of the trait)
    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Parse the request into components
        let service_path = request.path.clone();
        let action = request.action.clone();
        let data = request.data.clone();
        let context = request.context.clone();
        
        // Extract network ID from context or use default
        // Use a default network ID if none is provided
        let network_id = if context.network_id.is_empty() {
            "default".to_string()
        } else {
            context.network_id.clone()
        };
        
        debug_log(
            Component::Registry,
            &format!("ServiceRegistry received request for service '{}', action '{}' on network '{}'", 
                    service_path, action, network_id)
        );
        
        // Create a topic path for service lookup
        let topic_path = TopicPath::new_service(&network_id, &service_path);
        
        // Try to find the service
        if let Some(service) = self.get_service_by_topic_path(&topic_path).await {
            debug_log(
                Component::Registry,
                &format!("Found service '{}', forwarding request", service.name())
            );
            
            // Forward the request to the service
            return service.handle_request(request).await;
        }
        
        // If we get here, the service was not found
        error_log(
            Component::Registry,
            &format!("Service not found: '{}' on network '{}'", service_path, network_id)
        );
        
        // Return a not found response
        Ok(ServiceResponse {
            status: ResponseStatus::Error,
            message: format!("Service not found: {}", service_path),
            data: None,
        })
    }
    
    /// Get all services across all networks
    pub async fn get_all_services(&self) -> Vec<Arc<dyn AbstractService>> {
        let services = self.services.read().await;
        let mut result = Vec::new();
        let mut seen = HashSet::new();
        
        // Collect unique services (avoid duplicates from name/path storage)
        for (_, network_services) in services.iter() {
            for (name, service) in network_services.iter() {
                if !name.contains('/') && !seen.contains(name) {
                    seen.insert(name.clone());
                    result.push(service.clone());
                }
            }
        }
        
        result
    }
    
    /// Get subscribers for a topic
    pub async fn get_subscribers_for_topic(&self, topic: &str) -> Vec<(String, EventCallback)> {
        let callbacks_map = self.event_callbacks.read().await;
        if let Some(cb_list) = callbacks_map.get(topic) {
            // Return references to the callbacks but don't clone them
            cb_list.iter().map(|(id, cb)| (id.clone(), cb.clone())).collect()
        } else {
            Vec::new()
        }
    }
    
    /// Set the database connection
    pub fn set_database(&mut self, db: Arc<SqliteDatabase>) {
        self.db = Some(db);
    }
    
    /// Set the node request handler
    pub fn set_node_handler(&mut self, handler: Arc<dyn NodeRequestHandler + Send + Sync>) {
        self.node_handler = Some(handler.clone());
        
        // Also update the locked version
        if let Ok(mut lock) = self.node_handler_lock.try_write() {
            *lock = Some(handler);
        }
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRegistry {
    /// Create a new ServiceRegistry
    pub fn new() -> Self {
        info_log(
            Component::Registry,
            &format!("Creating new ServiceRegistry")
        );
        
        Self {
            path: "registry".to_string(),
            services: Arc::new(RwLock::new(HashMap::new())),
            db: None,
            node_handler: None,
            event_subscribers: Arc::new(RwLock::new(HashMap::new())),
            event_callbacks: Arc::new(RwLock::new(HashMap::new())),
            remote_peers: RwLock::new(HashMap::new()),
            p2p_delegate: RwLock::new(None),
            remote_subscriptions: RwLock::new(HashMap::new()),
            service_info_cache: RwLock::new(HashMap::new()),
            node_handler_lock: RwLock::new(None),
            action_handlers: RwLock::new(HashMap::new()),
            process_handlers: RwLock::new(HashMap::new()),
            subscription_handlers: RwLock::new(HashMap::new()),
            publication_topics: RwLock::new(HashMap::new()),
            services_cache: AsyncCache::new(StdDuration::from_secs(300)),
            pending_events: Arc::new(Mutex::new(Vec::new())),
            max_pending_events: 1000, // Default value
            event_task_semaphore: Arc::new(Semaphore::new(10)), // Default value
            max_event_tasks: 10, // Default value
            max_concurrent_event_executions: 5, // Default value
            current_event_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }
}