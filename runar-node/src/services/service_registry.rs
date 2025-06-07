// Service Registry Module
//
// INTENTION:
// This module provides action handler and event subscription management capabilities for the node.
// It acts as a central registry for action handlers and event subscriptions, enabling the node to
// find the correct subscribers and actions handlers. THE Registry does not CALL ANY CALLBACKS/Handler directly
//.. this is NODEs functions.
//
// ARCHITECTURAL PRINCIPLES:
// 1. Handler Registration - Manages registration of action handlers
// 2. Event Subscription Registration - Manages registration of event handlers
// 3. Network Isolation - Respects network boundaries for handlers and subscriptions
// 4. Path Consistency - ALL Registry APIs use TopicPath objects for proper validation
//    and consistent path handling, NEVER raw strings
// 5. Separate Storage - Local and remote handlers are stored separately for clear responsibility
//
// IMPORTANT NOTE:
// The Registry should focus solely on managing action handlers and subscriptions.
// It should NOT handle service discovery or lifecycle - that's the responsibility of the Node.
// Request routing and handling is also the Node's responsibility.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::routing::{PathTrie, TopicPath};
use crate::services::abstract_service::{AbstractService, ServiceState};
use crate::services::{ActionHandler, EventContext, RemoteService};
use runar_common::logging::Logger;
use runar_common::types::schemas::{ActionMetadata, EventMetadata, ServiceMetadata};
use runar_common::types::ArcValueType;

/// Type definition for event callbacks
///
/// INTENTION: Define a type that can handle event notifications asynchronously.
/// The callback takes an event context and payload and returns a future that
/// resolves once the event has been processed.
pub type EventCallback = Arc<
    dyn Fn(
            Arc<EventContext>,
            Option<ArcValueType>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Type definition for event handler
///
/// INTENTION: Provide a sharable type similar to ActionHandler that can be referenced
/// by multiple subscribers and cloned as needed. This fixes lifetime issues by using Arc.
pub type EventHandler = Arc<
    dyn Fn(
            Arc<EventContext>,
            Option<ArcValueType>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Import Future trait for use in type definition
use std::future::Future;

/// Future returned by service operations
pub type ServiceFuture = Pin<Box<dyn Future<Output = Result<ArcValueType>> + Send>>;

/// Type for event subscription callbacks
pub type EventSubscriber = Arc<
    dyn Fn(
            Arc<EventContext>,
            Option<ArcValueType>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Type for action registration function
pub type ActionRegistrar = Arc<
    dyn Fn(
            &str,
            &str,
            ActionHandler,
            Option<ActionMetadata>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Enum to distinguish between local and remote items
pub enum LocationType {
    Local,
    Remote,
}

#[derive(Clone)]
pub struct ServiceEntry {
    /// The service instance
    pub service: Arc<dyn AbstractService>,
    /// service topic path
    pub service_topic: TopicPath,
    //service state
    pub service_state: ServiceState,
    /// Timestamp when the service was registered (in seconds since UNIX epoch)
    pub registration_time: u64,
    /// Timestamp when the service was last started (in seconds since UNIX epoch)
    /// This is None if the service has never been started
    pub last_start_time: Option<u64>,
}

impl std::fmt::Debug for ServiceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceEntry")
            .field("name", &self.service.name())
            .field("path", &self.service.path())
            .field("version", &self.service.version())
            .field("description", &self.service.description())
            .field("state", &self.service_state)
            .field("topic", &self.service_topic)
            .field("registration_time", &self.registration_time)
            .field("last_start_time", &self.last_start_time)
            .finish()
    }
}

// Type alias for the value stored in local_action_handlers PathTrie
pub type LocalActionEntryValue = (ActionHandler, TopicPath, Option<ActionMetadata>);

// Type alias for the Vec stored in local_event_subscriptions PathTrie
pub type LocalEventSubscribersVec = Vec<(String, EventCallback, Option<EventMetadata>)>;

// Type alias for the Vec stored in remote_event_subscriptions PathTrie
pub type RemoteEventSubscribersVec = Vec<(String, EventCallback)>;

/// Service registry for managing services and their handlers
///
/// INTENTION: Provide a centralized registry for action handlers and event subscriptions.
/// This ensures consistent handling of service operations and enables service routing.
///
/// ARCHITECTURAL PRINCIPLE:
/// Service discovery and routing should be centralized for consistency and
/// to ensure proper service isolation.
pub struct ServiceRegistry {
    /// Local action handlers organized by path (using PathTrie instead of HashMap)
    /// Store both the handler and the original registration topic path for parameter extraction
    local_action_handlers: Arc<RwLock<PathTrie<LocalActionEntryValue>>>,

    //reverse index where we store the events that a service listens to
    local_events_by_service: Arc<RwLock<PathTrie<Vec<EventMetadata>>>>,

    /// Remote action handlers organized by path (using PathTrie instead of HashMap)
    remote_action_handlers: Arc<RwLock<PathTrie<Vec<ActionHandler>>>>,

    /// Local event subscriptions (using PathTrie instead of WildcardSubscriptionRegistry)
    local_event_subscriptions: Arc<RwLock<PathTrie<LocalEventSubscribersVec>>>,

    /// Remote event subscriptions (using PathTrie instead of WildcardSubscriptionRegistry)
    remote_event_subscriptions: Arc<RwLock<PathTrie<RemoteEventSubscribersVec>>>,

    /// Map subscription IDs back to TopicPath for efficient unsubscription
    /// (Single HashMap for both local and remote subscriptions)
    subscription_id_to_topic_path: Arc<RwLock<HashMap<String, TopicPath>>>,

    /// Map subscription IDs back to the service TopicPath for efficient unsubscription
    subscription_id_to_service_topic_path: Arc<RwLock<HashMap<String, TopicPath>>>,

    /// Local services registry (using PathTrie instead of HashMap)
    local_services: Arc<RwLock<PathTrie<Arc<ServiceEntry>>>>,

    local_services_list: Arc<RwLock<HashMap<TopicPath, Arc<ServiceEntry>>>>,

    /// Remote services registry (using PathTrie instead of HashMap)
    remote_services: Arc<RwLock<PathTrie<Arc<RemoteService>>>>,

    /// Service lifecycle states - moved from Node
    service_states_by_service_path: Arc<RwLock<HashMap<String, ServiceState>>>,

    /// Logger instance
    logger: Arc<Logger>,
}

impl Clone for ServiceRegistry {
    fn clone(&self) -> Self {
        ServiceRegistry {
            local_action_handlers: self.local_action_handlers.clone(),
            local_events_by_service: self.local_events_by_service.clone(),
            remote_action_handlers: self.remote_action_handlers.clone(),
            local_event_subscriptions: self.local_event_subscriptions.clone(),
            remote_event_subscriptions: self.remote_event_subscriptions.clone(),
            subscription_id_to_topic_path: self.subscription_id_to_topic_path.clone(),
            subscription_id_to_service_topic_path: self
                .subscription_id_to_service_topic_path
                .clone(),
            local_services: self.local_services.clone(),
            local_services_list: self.local_services_list.clone(),
            remote_services: self.remote_services.clone(),
            service_states_by_service_path: self.service_states_by_service_path.clone(),
            logger: self.logger.clone(),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new_with_default_logger()
    }
}

impl ServiceRegistry {
    /// Create a new registry with a provided logger
    ///
    /// INTENTION: Initialize a new registry with a logger provided by the parent
    /// component (typically the Node). This ensures proper logger hierarchy.
    pub fn new(logger: Arc<Logger>) -> Self {
        Self {
            local_action_handlers: Arc::new(RwLock::new(PathTrie::new())),
            local_events_by_service: Arc::new(RwLock::new(PathTrie::new())),
            remote_action_handlers: Arc::new(RwLock::new(PathTrie::new())),
            local_event_subscriptions: Arc::new(RwLock::new(PathTrie::new())),
            remote_event_subscriptions: Arc::new(RwLock::new(PathTrie::new())),
            subscription_id_to_topic_path: Arc::new(RwLock::new(HashMap::new())),
            subscription_id_to_service_topic_path: Arc::new(RwLock::new(HashMap::new())),
            local_services: Arc::new(RwLock::new(PathTrie::new())),
            local_services_list: Arc::new(RwLock::new(HashMap::new())),
            remote_services: Arc::new(RwLock::new(PathTrie::new())),
            service_states_by_service_path: Arc::new(RwLock::new(HashMap::new())),
            logger,
        }
    }

    /// Create a new registry with a default root logger
    ///
    /// INTENTION: Create a registry with a default logger when no parent logger
    /// is available. This is primarily used for testing or standalone usage.
    pub fn new_with_default_logger() -> Self {
        Self::new(Arc::new(Logger::new_root(
            runar_common::Component::Registry,
            "global",
        )))
    }

    /// Register a local service
    ///
    /// INTENTION: Register a local service implementation for use by the node.
    pub async fn register_local_service(&self, service: Arc<ServiceEntry>) -> Result<()> {
        let service_entry = service.clone();
        let service_topic = service_entry.service_topic.clone();
        self.logger
            .info(format!("Registering local service: {service_topic}"));

        // Store the service in the local services registry
        self.local_services
            .write()
            .await
            .set_value(service_topic.clone(), service);

        self.update_service_state(&service_topic, service_entry.service_state)
            .await?;

        self.local_services_list
            .write()
            .await
            .insert(service_topic, service_entry.clone());

        Ok(())
    }

    pub async fn remove_remote_service(&self, service_topic: &TopicPath) -> Result<()> {
        //get the service.. so we can call .stop() on it
        let services = self.remote_services.read().await.find(service_topic);

        if services.is_empty() {
            return Err(anyhow!("Service not found for topic: {}", service_topic));
        }

        let registry_delegate = Arc::new(self.clone());
        for service in services {
            let context =
                super::RemoteLifecycleContext::new(&service.service_topic, self.logger.clone())
                    .with_registry_delegate(registry_delegate.clone());

            // Initialize the service - this triggers handler registration via the context
            if let Err(e) = service.stop(context).await {
                self.logger.error(format!(
                    "Failed to stop remote service '{}' error: {}",
                    service.path(),
                    e
                ));
            }
        }

        //this function will do the oposite of the register_remote_service function
        self.remote_services
            .write()
            .await
            .remove_values(service_topic);

        Ok(())
    }

    /// Register a remote service
    ///
    /// INTENTION: Register a service that exists on a remote node, making it available for local requests.
    pub async fn register_remote_service(&self, service: Arc<RemoteService>) -> Result<()> {
        let service_topic = service.service_topic.clone();
        let service_path = service.path().to_string();
        let peer_id = service.peer_id().clone();

        self.logger.info(format!(
            "Registering remote service: {service_path} from peer: {peer_id}"
        ));

        // Add to remote services using PathTrie
        {
            let mut services = self.remote_services.write().await;
            let matches = services.find_matches(&service_topic);

            if matches.is_empty() {
                // No existing services for this topic
                services.set_value(service_topic, service);
            } else {
                //return an error.. just one service shuold exist for a given topic
                return Err(anyhow!(
                    "Service already exists for topic: {}",
                    service_topic
                ));
            }
        }

        Ok(())
    }

    /// Register a local action handler
    ///
    /// INTENTION: Register a handler for a specific action path that will be executed locally.
    pub async fn register_local_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
        metadata: Option<ActionMetadata>,
    ) -> Result<()> {
        self.logger.debug(format!(
            "Registering local action handler for: {topic_path}"
        ));

        // Store in the new local action handlers trie with the original topic path for parameter extraction
        self.local_action_handlers
            .write()
            .await
            .set_value(topic_path.clone(), (handler, topic_path.clone(), metadata));

        Ok(())
    }

    pub async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()> {
        self.logger
            .debug(format!("Removing remote action handler for: {topic_path}"));

        // Remove from remote action handlers trie
        self.remote_action_handlers
            .write()
            .await
            .remove_values(topic_path);

        Ok(())
    }

    /// Register a remote action handler
    ///
    /// INTENTION: Register a handler for a specific action path that exists on a remote node.
    pub async fn register_remote_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
    ) -> Result<()> {
        self.logger.debug(format!(
            "Registering remote action handler for: {}",
            topic_path.as_str()
        ));

        // Store the handler in remote_action_handlers using PathTrie
        {
            let mut handlers_trie = self.remote_action_handlers.write().await;
            let matches = handlers_trie.find_matches(topic_path);

            if matches.is_empty() {
                // No handlers yet for this path
                handlers_trie.set_value(topic_path.clone(), vec![handler.clone()]);
            } else {
                // Get existing handlers and add the new one
                let mut existing_handlers = matches[0].content.clone();
                existing_handlers.push(handler.clone());

                // Update the handlers in the trie
                handlers_trie.set_value(topic_path.clone(), existing_handlers);
            }
        }

        Ok(())
    }

    /// Get a local action handler only
    ///
    /// INTENTION: Retrieve a handler for a specific action path that will be executed locally.
    /// Now returns both the handler and the original registration topic path for parameter extraction.
    pub async fn get_local_action_handler(
        &self,
        topic_path: &TopicPath,
    ) -> Option<(ActionHandler, TopicPath)> {
        let handlers_trie = self.local_action_handlers.read().await;
        let matches = handlers_trie.find_matches(topic_path);

        if !matches.is_empty() {
            let (handler, topic_path, _metadata) = matches[0].content.clone();
            Some((handler, topic_path))
        } else {
            None
        }
    }

    /// Get all remote action handlers for a path (for load balancing)
    ///
    /// INTENTION: Retrieve all handlers for a specific action path that exist on remote nodes.
    /// Get all remote action handlers for a path (for load balancing)
    ///
    /// INTENTION: Retrieve all handlers for a specific action path that exist on remote nodes.
    /// Returns a flattened vector of all matching handlers across all matching topic patterns.
    pub async fn get_remote_action_handlers(&self, topic_path: &TopicPath) -> Vec<ActionHandler> {
        let handlers_trie = self.remote_action_handlers.read().await;
        let matches = handlers_trie.find_matches(topic_path);

        // Flatten all matches into a single vector of handlers
        matches
            .into_iter()
            .flat_map(|mat| mat.content.clone())
            .collect()
    }

    /// Get an action handler for a specific topic path
    ///
    /// INTENTION: Look up the appropriate action handler for a given topic path
    /// supporting both local and remote handlers.
    pub async fn get_action_handler(&self, topic_path: &TopicPath) -> Option<ActionHandler> {
        // First try local handlers
        if let Some((handler, _)) = self.get_local_action_handler(topic_path).await {
            return Some(handler);
        }

        // Then check remote handlers
        let remote_handlers = self.get_remote_action_handlers(topic_path).await;
        if !remote_handlers.is_empty() {
            // For backward compatibility, just return the first one
            // The Node will apply proper load balancing when using get_remote_action_handlers directly
            return Some(remote_handlers[0].clone());
        }

        None
    }

    /// Stable API - DO NOT CHANGE UNLES ASKED EXPLICITLY!
    /// Register local event subscription
    ///
    /// INTENTION: Register a callback to be invoked when events are published locally.
    pub async fn register_local_event_subscription(
        &self,
        topic_path: &TopicPath,
        callback: EventCallback,
        metadata: Option<EventMetadata>,
    ) -> Result<String> {
        let subscription_id = Uuid::new_v4().to_string();

        // Store in local event subscriptions using PathTrie
        {
            let mut subscriptions = self.local_event_subscriptions.write().await;
            let matches = subscriptions.find_matches(topic_path);

            if matches.is_empty() {
                // No existing subscriptions for this topic
                subscriptions.set_value(
                    topic_path.clone(),
                    vec![(subscription_id.clone(), callback.clone(), metadata.clone())],
                );
            } else {
                // Add to existing subscriptions
                let mut updated_subscriptions = matches[0].content.clone();
                updated_subscriptions.push((
                    subscription_id.clone(),
                    callback.clone(),
                    metadata.clone(),
                ));

                // First remove the old handlers, then add the updated ones
                subscriptions.remove_handler(topic_path, |_| true);
                subscriptions.set_value(topic_path.clone(), updated_subscriptions);
            }
        }

        // Store the mapping from ID to TopicPath in the combined HashMap
        {
            let mut id_map = self.subscription_id_to_topic_path.write().await;
            id_map.insert(subscription_id.clone(), topic_path.clone());
        }

        let service_topic =
            TopicPath::new(&topic_path.service_path(), &topic_path.network_id()).unwrap();

        // store metadata in local_events_by_service
        if let Some(metadata) = metadata {
            let mut events = self.local_events_by_service.write().await;
            let matches = events.find_matches(&service_topic);

            if matches.is_empty() {
                // No existing events for this service
                //add a vec with one item -> topic_path indexed by the source_service_path
                events.set_value(service_topic.clone(), vec![metadata]);
            } else {
                // Add to existing events
                let mut updated_events = matches[0].content.clone();
                updated_events.push(metadata);

                // First remove the old handlers, then add the updated ones
                events.remove_handler(&service_topic, |_| true);
                events.set_value(service_topic.clone(), updated_events);
            }
        }

        //store in subscription_id_to_service_topic_path
        {
            let mut id_map = self.subscription_id_to_service_topic_path.write().await;
            id_map.insert(subscription_id.clone(), service_topic.clone());
        }

        Ok(subscription_id)
    }

    /// Register remote event subscription
    ///
    /// INTENTION: Register a callback to be invoked when events are published from remote nodes.
    pub async fn register_remote_event_subscription(
        &self,
        topic_path: &TopicPath,
        callback: EventCallback,
    ) -> Result<String> {
        let subscription_id = Uuid::new_v4().to_string();

        // Store in remote event subscriptions using PathTrie
        {
            let mut subscriptions = self.remote_event_subscriptions.write().await;
            let matches = subscriptions.find_matches(topic_path);

            if matches.is_empty() {
                // No existing subscriptions for this topic
                subscriptions.set_value(
                    topic_path.clone(),
                    vec![(subscription_id.clone(), callback.clone())],
                );
            } else {
                // Add to existing subscriptions
                let mut updated_subscriptions = matches[0].content.clone();
                updated_subscriptions.push((subscription_id.clone(), callback.clone()));

                // First remove the old handlers, then add the updated ones
                subscriptions.remove_handler(topic_path, |_| true);
                subscriptions.set_value(topic_path.clone(), updated_subscriptions);
            }
        }

        // Store the mapping from ID to TopicPath in the combined HashMap
        {
            let mut id_map = self.subscription_id_to_topic_path.write().await;
            id_map.insert(subscription_id.clone(), topic_path.clone());
        }

        Ok(subscription_id)
    }

    /// Get local event subscribers
    ///
    /// INTENTION: Find all local subscribers for a specific event topic.
    pub async fn get_local_event_subscribers(
        &self,
        topic_path: &TopicPath,
    ) -> Vec<(String, EventCallback)> {
        let subscriptions = self.local_event_subscriptions.read().await;
        let matches = subscriptions.find_matches(topic_path);

        let mut result = Vec::new();
        for match_item in matches {
            // Each item in content is a (String, EventCallback, Option<EventMetadata>) tuple
            for (subscription_id, callback, _metadata) in match_item.content.clone() {
                result.push((subscription_id, callback));
            }
        }
        result
    }

    /// Get remote event subscribers
    ///
    /// INTENTION: Find all remote subscribers for a specific event topic.
    pub async fn get_remote_event_subscribers(
        &self,
        topic_path: &TopicPath,
    ) -> Vec<(String, EventCallback)> {
        let subscriptions = self.remote_event_subscriptions.read().await;
        let matches = subscriptions.find_matches(topic_path);

        // Flatten all matches into a single vector
        let mut result = Vec::new();
        for match_item in matches {
            // Each item in content is already a (String, EventCallback) tuple
            for (subscription_id, callback) in match_item.content.clone() {
                result.push((subscription_id, callback));
            }
        }
        result
    }

    //FIX: this mnethods should reveive a topiPAth instead of a string for service_path
    /// Update service state
    ///
    /// INTENTION: Track the lifecycle state of a service.
    pub async fn update_service_state(
        &self,
        service_topic: &TopicPath,
        state: ServiceState,
    ) -> Result<()> {
        self.logger.debug(format!(
            "Updating service state for {}: {:?}",
            service_topic.clone(),
            state
        ));
        let mut states = self.service_states_by_service_path.write().await;
        states.insert(service_topic.as_str().to_string(), state);
        Ok(())
    }

    pub async fn get_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        let map = self.service_states_by_service_path.read().await;
        map.get(service_path.as_str()).copied()
    }

    /// Get metadata for all events under a specific service path
    ///
    /// INTENTION: Retrieve metadata for all events registered under a service path.
    /// This is useful for service discovery and introspection.
    pub async fn get_events_metadata(&self, search_path: &TopicPath) -> Vec<EventMetadata> {
        // Search in the events trie local_event_handlers
        let events = self.local_events_by_service.read().await;
        let matches = events.find_matches(search_path);

        // Collect all events that match the service path
        let mut result = Vec::new();

        for match_item in matches {
            // Extract the topic path from the match
            let event_topic_list = &match_item.content;

            //iterate event_topic_list
            for event_metadata in event_topic_list {
                result.push(event_metadata.clone());
            }
        }

        result
    }

    /// Get metadata for all actions under a specific service path
    ///
    /// INTENTION: Retrieve metadata for all actions registered under a service path.
    /// This is useful for service discovery and introspection.
    pub async fn get_actions_metadata(&self, search_path: &TopicPath) -> Vec<ActionMetadata> {
        // Search in the actions trie local_action_handlers
        let actions = self.local_action_handlers.read().await;
        let matches = actions.find_matches(search_path);

        // Collect all actions that match the service path
        let mut result = Vec::new();

        for match_item in matches {
            // Extract the topic path from the match
            let (_, _, metadata) = &match_item.content;
            if let Some(metadata) = metadata {
                result.push(metadata.clone());
            }
        }

        result
    }

    /// Get all local services
    ///
    /// INTENTION: Provide access to all registered local services, allowing the
    /// Node to directly interact with them for lifecycle operations like initialization,
    /// starting, and stopping. This preserves the Node's responsibility for service
    /// lifecycle management while keeping the Registry focused on registration.
    pub async fn get_local_services(&self) -> HashMap<TopicPath, Arc<ServiceEntry>> {
        self.local_services_list.read().await.clone()
    }

    pub async fn unsubscribe_local(&self, subscription_id: &str) -> Result<()> {
        self.logger.debug(format!(
            "Attempting to unsubscribe local subscription ID: {subscription_id}"
        ));

        // Find the TopicPath associated with the subscription ID
        let topic_path_option = {
            let id_map = self.subscription_id_to_topic_path.read().await;
            id_map.get(subscription_id).cloned()
        };

        if let Some(topic_path) = topic_path_option {
            self.logger.debug(format!(
                "Found topic path '{}' for subscription ID: {}",
                topic_path.as_str(),
                subscription_id
            ));
            let mut subscriptions = self.local_event_subscriptions.write().await;

            // Find current subscriptions for this topic
            let matches = subscriptions.find_matches(&topic_path);

            if !matches.is_empty() {
                // Get the first match (should be the only one for exact path)
                let mut updated_subscriptions = Vec::new();

                // Create a new list without the subscription we want to remove
                for (id, callback, metadata) in matches[0].content.clone() {
                    if id != subscription_id {
                        updated_subscriptions.push((id, callback, metadata));
                    }
                }

                // Remove the old list and add the updated one
                let removed = subscriptions.remove_handler(&topic_path, |_| true);

                if !updated_subscriptions.is_empty() {
                    // If we still have subscriptions for this topic, add them back
                    subscriptions.set_value(topic_path.clone(), updated_subscriptions);
                }

                if removed {
                    // Also remove from the ID map
                    {
                        let mut id_to_topic_path_map =
                            self.subscription_id_to_topic_path.write().await;
                        id_to_topic_path_map.remove(subscription_id);
                    }
                    self.logger.debug(format!(
                        "Successfully unsubscribed from topic: {} with ID: {}",
                        topic_path.as_str(),
                        subscription_id
                    ));
                } else {
                    // This case might happen if the subscription was already removed concurrently
                    let msg = format!("Subscription handler not found for topic path {} and ID {}, although ID was mapped. Potential race condition?", topic_path.as_str(), subscription_id);
                    self.logger.warn(msg.clone());
                    return Err(anyhow!(msg));
                }

                //remove from service topic path map
                let service_topic_path = self.subscription_id_to_service_topic_path.read().await;
                let service_topic_path = service_topic_path.get(subscription_id).cloned();

                if let Some(service_topic_path) = service_topic_path {
                    self.logger.debug(format!(
                        "Unsubscribing from service topic : {} at service path: {}",
                        topic_path.as_str(),
                        service_topic_path.as_str()
                    ));
                    let mut events = self.local_events_by_service.write().await;
                    let events_by_service = events.find_matches(&service_topic_path);
                    if !events_by_service.is_empty() {
                        for match_item in events_by_service {
                            let mut updated_list = Vec::new();
                            let items = match_item.content.clone();
                            for event_metadata in items {
                                if event_metadata.path == topic_path.as_str() {
                                    continue;
                                }
                                updated_list.push(event_metadata);
                            }
                            events.remove_handler(&service_topic_path, |_| true);
                            if !updated_list.is_empty() {
                                events.set_value(service_topic_path.clone(), updated_list);
                            }
                        }
                    }
                }
                Ok(())
            } else {
                // No subscriptions found for this topic
                let msg = format!(
                    "No subscriptions found for topic path {} and ID {}",
                    topic_path.as_str(),
                    subscription_id
                );
                self.logger.warn(msg.clone());
                Err(anyhow!(msg))
            }
        } else {
            let msg = format!(
                "No topic path found mapping to subscription ID: {subscription_id}. Cannot unsubscribe."
            );
            self.logger.warn(msg.clone());
            Err(anyhow!(msg))
        }
    }

    /// Unsubscribe from a remote event subscription using only the subscription ID.
    ///
    /// INTENTION: Remove a specific subscription by ID from the remote event subscriptions,
    /// providing a simpler API that doesn't require the original topic.
    pub async fn unsubscribe_remote(&self, subscription_id: &str) -> Result<()> {
        self.logger.debug(format!(
            "Attempting to unsubscribe remote subscription ID: {subscription_id}"
        ));

        // Find the TopicPath associated with the subscription ID
        let topic_path_option = {
            let id_map = self.subscription_id_to_topic_path.read().await;
            id_map.get(subscription_id).cloned()
        };

        if let Some(topic_path) = topic_path_option {
            self.logger.debug(format!(
                "Found topic path '{}' for subscription ID: {}",
                topic_path.as_str(),
                subscription_id
            ));
            let mut subscriptions = self.remote_event_subscriptions.write().await;

            // Find current subscriptions for this topic
            let matches = subscriptions.find_matches(&topic_path);

            if !matches.is_empty() {
                // Get the first match (should be the only one for exact path)
                let mut updated_subscriptions = Vec::new();

                // Create a new list without the subscription we want to remove
                for (id, callback) in matches[0].content.clone() {
                    if id != subscription_id {
                        updated_subscriptions.push((id, callback));
                    }
                }

                // Remove the old list and add the updated one
                let removed = subscriptions.remove_handler(&topic_path, |_| true);

                if !updated_subscriptions.is_empty() {
                    // If we still have subscriptions for this topic, add them back
                    subscriptions.set_value(topic_path.clone(), updated_subscriptions);
                }

                if removed {
                    // Also remove from the ID map
                    {
                        let mut id_map = self.subscription_id_to_topic_path.write().await;
                        id_map.remove(subscription_id);
                    }
                    self.logger.debug(format!(
                        "Successfully unsubscribed from remote topic: {} with ID: {}",
                        topic_path.as_str(),
                        subscription_id
                    ));
                    Ok(())
                } else {
                    // This case might happen if the subscription was already removed concurrently
                    let msg = format!("Subscription handler not found for remote topic path {} and ID {}, although ID was mapped. Potential race condition?", topic_path.as_str(), subscription_id);
                    self.logger.warn(msg.clone());
                    Err(anyhow!(msg))
                }
            } else {
                // No subscriptions found for this topic
                let msg = format!(
                    "No subscriptions found for remote topic path {} and ID {}",
                    topic_path.as_str(),
                    subscription_id
                );
                self.logger.warn(msg.clone());
                Err(anyhow!(msg))
            }
        } else {
            let msg = format!(
                "No topic path found mapping to remote subscription ID: {subscription_id}. Cannot unsubscribe."
            );
            self.logger.warn(msg.clone());
            Err(anyhow!(msg))
        }
    }

    /// Get metadata for all services with an option to filter internal services
    ///
    /// INTENTION: Retrieve metadata for all registered services with the option
    /// to exclude internal services (those with paths starting with $)
    pub async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> HashMap<String, ServiceMetadata> {
        let mut result = HashMap::new();
        let local_services = self.get_local_services().await;

        // Iterate through all services
        for (_, service_entry) in local_services {
            let service = &service_entry.service;
            let path_str = service.path().to_string();

            // Skip internal services if not included
            if !include_internal_services && path_str.starts_with("$") {
                continue;
            }

            let search_path = format!("{}/*", &path_str);
            // Use the network_id from the service_entry's topic_path, which was set by the Node during add_service
            let network_id_string = service_entry.service_topic.network_id().to_string();
            let service_topic_path =
                TopicPath::new(search_path.as_str(), &network_id_string).unwrap();

            // Get actions metadata for this service - create a wildcard path
            let actions = self.get_actions_metadata(&service_topic_path).await;

            // Get events metadata for this service - create a wildcard path
            let events = self.get_events_metadata(&service_topic_path).await;

            // Create metadata using individual getter methods from the service
            result.insert(
                path_str,
                ServiceMetadata {
                    // Use the network_id from the service_entry's topic_path
                    network_id: service_entry.service_topic.network_id().to_string(),
                    service_path: service.path().to_string(),
                    name: service.name().to_string(),
                    version: service.version().to_string(),
                    description: service.description().to_string(),
                    actions,
                    events,
                    registration_time: service_entry.registration_time,
                    last_start_time: service_entry.last_start_time,
                },
            );
        }

        result
    }
}

#[async_trait::async_trait]
impl crate::services::RegistryDelegate for ServiceRegistry {
    async fn get_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.service_states_by_service_path
            .read()
            .await
            .get(service_path.as_str())
            .cloned()
    }

    // This method is now implemented as a public method above
    async fn get_actions_metadata(&self, service_topic_path: &TopicPath) -> Vec<ActionMetadata> {
        // Delegate to the public implementation
        self.get_actions_metadata(service_topic_path).await
    }

    /// Get metadata for a specific service
    ///
    /// INTENTION: Retrieve comprehensive metadata for a service, including its actions and events.
    /// This is useful for service discovery and introspection.
    async fn get_service_metadata(&self, topic_path: &TopicPath) -> Option<ServiceMetadata> {
        // Find service in the local services trie
        let services = self.local_services.read().await;
        let matches = services.find_matches(topic_path);

        if !matches.is_empty() {
            let service_entry = &matches[0].content;
            let service = service_entry.service.clone();
            let search_path = format!("{}/*", &service.path());
            let network_id_string = topic_path.network_id();
            let service_topic_path =
                TopicPath::new(search_path.as_str(), &network_id_string).unwrap();

            // Get actions metadata for this service - create a wildcard path
            let actions = self.get_actions_metadata(&service_topic_path).await;

            // Get events metadata for this service - create a wildcard path
            let events = self.get_events_metadata(&service_topic_path).await;

            // Create metadata using individual getter methods
            return Some(ServiceMetadata {
                network_id: network_id_string,
                service_path: service.path().to_string(),
                name: service.name().to_string(),
                version: service.version().to_string(),
                description: service.description().to_string(),
                actions,
                events,
                registration_time: service_entry.registration_time,
                last_start_time: service_entry.last_start_time,
            });
        }

        None
    }

    /// Get metadata for all registered services with an option to filter internal services
    async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> HashMap<String, ServiceMetadata> {
        self.get_all_service_metadata(include_internal_services)
            .await
    }

    /// Register a remote action handler
    async fn register_remote_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
    ) -> Result<()> {
        // This is just a proxy to the instance method
        self.register_remote_action_handler(topic_path, handler)
            .await
    }

    async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()> {
        self.remove_remote_action_handler(topic_path).await
    }
}
