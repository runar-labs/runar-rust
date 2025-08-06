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
use crate::services::{ActionHandler, EventContext, EventRegistrationOptions, RemoteService};
use runar_common::logging::Logger;
use runar_schemas::{ActionMetadata, ServiceMetadata, SubscriptionMetadata};
use runar_serializer::ArcValue;

 

/// Type definition for event handler
///
/// INTENTION: Provide a sharable type similar to ActionHandler that can be referenced
/// by multiple subscribers and cloned as needed. This fixes lifetime issues by using Arc.
pub type EventHandler = Arc<
    dyn Fn(Arc<EventContext>, Option<ArcValue>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

pub type RemoteEventHandler = Arc<
    dyn Fn(Option<ArcValue>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Import Future trait for use in type definition
use std::future::Future;

/// Future returned by service operations
pub type ServiceFuture = Pin<Box<dyn Future<Output = Result<ArcValue>> + Send>>;

/// Type for event subscription callbacks
pub type EventSubscriber = Arc<
    dyn Fn(Arc<EventContext>, Option<ArcValue>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
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
pub type LocalEventSubscribersVec = Vec<(String, EventHandler, SubscriptionMetadata)>;

// Type alias for the Vec stored in remote_event_subscriptions PathTrie
pub type RemoteEventSubscribersVec = Vec<(String, RemoteEventHandler, SubscriptionMetadata)>;

pub const INTERNAL_SERVICES: [&str; 2] = ["$registry", "$keys"];

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

    /// Local service lifecycle states
    local_service_states: Arc<RwLock<HashMap<String, ServiceState>>>,
    
    /// Remote service lifecycle states
    remote_service_states: Arc<RwLock<HashMap<String, ServiceState>>>,

    /// Logger instance
    logger: Arc<Logger>,
}

impl Clone for ServiceRegistry {
    fn clone(&self) -> Self {
        ServiceRegistry {
            local_action_handlers: self.local_action_handlers.clone(),
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
            local_service_states: self.local_service_states.clone(),
            remote_service_states: self.remote_service_states.clone(),
            logger: self.logger.clone(),
        }
    }
}

// impl Default for ServiceRegistry {
//     fn default() -> Self {
//         Self::new_with_default_logger()
//     }
// }

impl ServiceRegistry {
    /// Create a new registry with a provided logger
    ///
    /// INTENTION: Initialize a new registry with a logger provided by the parent
    /// component (typically the Node). This ensures proper logger hierarchy.
    pub fn new(logger: Arc<Logger>) -> Self {
        Self {
            local_action_handlers: Arc::new(RwLock::new(PathTrie::new())),
            remote_action_handlers: Arc::new(RwLock::new(PathTrie::new())),
            local_event_subscriptions: Arc::new(RwLock::new(PathTrie::new())),
            remote_event_subscriptions: Arc::new(RwLock::new(PathTrie::new())),
            subscription_id_to_topic_path: Arc::new(RwLock::new(HashMap::new())),
            subscription_id_to_service_topic_path: Arc::new(RwLock::new(HashMap::new())),
            local_services: Arc::new(RwLock::new(PathTrie::new())),
            local_services_list: Arc::new(RwLock::new(HashMap::new())),
            remote_services: Arc::new(RwLock::new(PathTrie::new())),
            local_service_states: Arc::new(RwLock::new(HashMap::new())),
            remote_service_states: Arc::new(RwLock::new(HashMap::new())),
            logger,
        }
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
        //TODO understand why we have this duplciation of local_services and local_services_list
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

        // Remove the services from the registry
        self.remote_services
            .write()
            .await
            .remove_values(service_topic);

        // Remove the service state
        self.remove_remote_service_state(service_topic).await?;

        Ok(())
    }

    /// Register a remote service
    ///
    /// INTENTION: Register a service that exists on a remote node, making it available for local requests.
    pub async fn register_remote_service(&self, service: Arc<RemoteService>) -> Result<()> {
        let service_topic = service.service_topic.clone();
        let service_path = service.path().to_string();
        let peer_node_id = service.peer_node_id().clone();

        self.logger.info(format!(
            "Registering remote service: {service_path} from peer: {peer_node_id}"
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
        callback: EventHandler,
        _options: EventRegistrationOptions,
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
                    vec![(subscription_id.clone(), callback.clone(), SubscriptionMetadata{
                        path: topic_path.as_str().to_string(),
                    })],
                );
            } else {
                // Add to existing subscriptions
                let mut updated_subscriptions = matches[0].content.clone();
                updated_subscriptions.push((
                    subscription_id.clone(),
                    callback.clone(),
                    SubscriptionMetadata{
                        path: topic_path.as_str().to_string(),
                    },
                ));

                // Replace the existing content with the updated list
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
        callback: RemoteEventHandler,
        _options: EventRegistrationOptions,
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
                    vec![(subscription_id.clone(), callback.clone(), SubscriptionMetadata{
                        path: topic_path.as_str().to_string(),
                    })],
                );
            } else {
                // Add to existing subscriptions
                let mut updated_subscriptions = matches[0].content.clone();
                updated_subscriptions.push((subscription_id.clone(), callback.clone(), SubscriptionMetadata{
                    path: topic_path.as_str().to_string(),
                }));

                // Replace the existing content with the updated list
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


    pub async fn remove_remote_event_subscription(&self, topic_path: &TopicPath) -> Result<()> {
        let mut subscriptions = self.remote_event_subscriptions.write().await;
        let matches = subscriptions.find_matches(topic_path);
        
        for match_item in matches {
            for (subscription_id, _, _) in &match_item.content {
                // Remove from subscription ID mappings
                {
                    let mut id_map = self.subscription_id_to_topic_path.write().await;
                    id_map.remove(subscription_id);
                }
                {
                    let mut service_id_map = self.subscription_id_to_service_topic_path.write().await;
                    service_id_map.remove(subscription_id);
                }
            }
        }
        
        // Remove from the trie
        subscriptions.remove_values(topic_path);
        Ok(())
    }

    /// Get local event subscribers
    ///
    /// INTENTION: Find all local subscribers for a specific event topic.
    pub async fn get_local_event_subscribers(
        &self,
        topic_path: &TopicPath,
    ) -> Vec<(String, EventHandler, SubscriptionMetadata)> {
        let subscriptions = self.local_event_subscriptions.read().await;
        let matches = subscriptions.find_matches(topic_path);

        let mut result = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        
        for match_item in matches {
            // Each item in content is a (String, EventHandler, SubscriptionMetadata) tuple
            for (subscription_id, callback, metadata) in match_item.content.clone() {
                // Deduplicate by subscription ID to prevent the same subscription from appearing multiple times
                if seen_ids.insert(subscription_id.clone()) {
                    result.push((subscription_id, callback, metadata));
                }
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
    ) -> Vec<(String, RemoteEventHandler, SubscriptionMetadata)> {
        let subscriptions = self.remote_event_subscriptions.read().await;
        let matches = subscriptions.find_matches(topic_path);

        // Flatten all matches into a single vector
        let mut result = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        
        for match_item in matches {
            // Each item in content is already a (String, EventHandler, SubscriptionMetadata) tuple
            for (subscription_id, callback, metadata) in match_item.content.clone() {
                // Deduplicate by subscription ID to prevent the same subscription from appearing multiple times
                if seen_ids.insert(subscription_id.clone()) {
                    result.push((subscription_id, callback, metadata));
                }
            }
        }
        result
    }

    //FIX: this mnethods should reveive a topiPAth instead of a string for service_path
    /// Update local service state
    ///
    /// INTENTION: Track the lifecycle state of a local service.
    pub async fn update_local_service_state(
        &self,
        service_topic: &TopicPath,
        state: ServiceState,
    ) -> Result<()> {
        self.logger.debug(format!(
            "Updating local service state for {}: {:?}",
            service_topic.clone(),
            state
        ));
        let mut states = self.local_service_states.write().await;
        states.insert(service_topic.as_str().to_string(), state);
        Ok(())
    }

    /// Update remote service state
    ///
    /// INTENTION: Track the lifecycle state of a remote service.
    pub async fn update_remote_service_state(
        &self,
        service_topic: &TopicPath,
        state: ServiceState,
    ) -> Result<()> {
        self.logger.debug(format!(
            "Updating remote service state for {}: {:?}",
            service_topic.clone(),
            state
        ));
        let mut states = self.remote_service_states.write().await;
        states.insert(service_topic.as_str().to_string(), state);
        Ok(())
    }

    pub async fn remove_remote_service_state(
        &self,
        service_topic: &TopicPath, 
    ) -> Result<()> {
        let mut states = self.remote_service_states.write().await;
        states.remove(service_topic.as_str());
        Ok(())
    }

    /// Get local service state
    pub async fn get_local_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        let map = self.local_service_states.read().await;
        map.get(service_path.as_str()).copied()
    }

    /// Get remote service state
    pub async fn get_remote_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        let map = self.remote_service_states.read().await;
        map.get(service_path.as_str()).copied()
    }
 
    /// Get metadata for all events under a specific service path
    ///
    /// INTENTION: Retrieve metadata for all events registered under a service path.
    /// This is useful for service discovery and introspection.
    pub async fn get_subscriptions_metadata(&self, search_path: &TopicPath) -> Vec<SubscriptionMetadata> {
        // Search in the events trie local_event_handlers
        let events = self.local_event_subscriptions.read().await;
        let matches = events.find_matches(search_path);

        // Collect all events that match the service path
        let mut result = Vec::new();

        for match_item in matches {
            // Extract the topic path from the match
            let event_topic_list = &match_item.content;

            //iterate event_topic_list
            for (_, _    , metadata) in event_topic_list {
                //TODO when EventRegistrationOptions is defined.. we need to pass that info here in the metadata to be sent to a remote node
                result.push(metadata.clone());
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
                for (id, callback, options) in matches[0].content.clone() {
                    if id != subscription_id {
                        updated_subscriptions.push((id, callback, options));
                    }
                }

                // Replace the existing content with the updated list
                if !updated_subscriptions.is_empty() {
                    subscriptions.set_value(topic_path.clone(), updated_subscriptions);
                } else {
                    // If no subscriptions remain, remove the topic entirely
                    subscriptions.remove_values(&topic_path);
                }

                // Remove from the ID map
                {
                    let mut id_to_topic_path_map =
                        self.subscription_id_to_topic_path.write().await;
                    id_to_topic_path_map.remove(subscription_id);
                }

                // Remove from service topic path map
                {
                    let mut service_topic_map = self.subscription_id_to_service_topic_path.write().await;
                    service_topic_map.remove(subscription_id);
                }

                self.logger.debug(format!(
                    "Successfully unsubscribed from topic: {} with ID: {}",
                    topic_path.as_str(),
                    subscription_id
                ));
                Ok(())
            } else {
                let msg = format!(
                    "No subscriptions found for topic path {topic_path} and ID {subscription_id}",
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
                for (id, callback, options) in matches[0].content.clone() {
                    if id != subscription_id {
                        updated_subscriptions.push((id, callback, options));
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
                    let msg = format!("Subscription handler not found for remote topic path {topic_path} and ID {subscription_id}, although ID was mapped. Potential race condition?");
                    self.logger.warn(msg.clone());
                    Err(anyhow!(msg))
                }
            } else {
                let msg = format!(
                    "No subscriptions found for remote topic path {topic_path} and ID {subscription_id}",
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

    async fn get_service_metadata(&self, topic_path: &TopicPath) -> Option<ServiceMetadata> {
        // Find service in the local services trie
        let services = self.local_services.read().await;
        let matches = services.find_matches(topic_path);

        if !matches.is_empty() {
            let service_entry = &matches[0].content;
            let service = service_entry.service.clone();
            let search_path = format!("{service_path}/*", service_path = service.path());
            let network_id_string = topic_path.network_id();
            let service_topic_path =
                TopicPath::new(search_path.as_str(), &network_id_string).unwrap();

            // Get actions metadata for this service - create a wildcard path
            let actions = self.get_actions_metadata(&service_topic_path).await;
 
            // Create metadata using individual getter methods
            return Some(ServiceMetadata {
                network_id: network_id_string,
                service_path: service.path().to_string(),
                name: service.name().to_string(),
                version: service.version().to_string(),
                description: service.description().to_string(),
                actions,
                registration_time: service_entry.registration_time,
                last_start_time: service_entry.last_start_time,
            });
        }

        None
    }

    pub async fn get_all_subscriptions(&self, include_internal_services: bool) -> Result<Vec<SubscriptionMetadata>> {
        let subscriptions = self.local_event_subscriptions.read().await;
        let all_values = subscriptions.get_all_values();
        
        let mut result = Vec::new();
        
        for subscription_vec in all_values {
            for (_, _, metadata) in subscription_vec {
                // Filter out internal services if not included
                if !include_internal_services && metadata.path.starts_with('$') {
                    continue;
                }
                result.push(metadata);
            }
        }
        
        Ok(result)
    }

    /// Get metadata for all services with an option to filter internal services
    ///
    /// INTENTION: Retrieve metadata for all registered services with the option
    /// to exclude internal services (those with paths starting with $)
    pub async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> Result<HashMap<String, ServiceMetadata>> {
        let mut result = HashMap::new();
        let local_services = self.get_local_services().await;

        // Iterate through all services
        for (_, service_entry) in local_services {
            let service = &service_entry.service;
            let path_str = service.path();

            // Skip internal services if not included
            if !include_internal_services && INTERNAL_SERVICES.contains(&path_str) {
                continue;
            }

            let search_path = format!("{path_str}/*");
            let search_topic = TopicPath::new(&search_path, &service_entry.service_topic.network_id().to_string())
                .map_err(|e| anyhow!("Failed to create topic path: {e}"))?;
            let service_metadata = self.get_service_metadata(&search_topic).await
                .ok_or_else(|| anyhow!("Service metadata not found for topic: {}", search_topic))?;
            
             
            // Create metadata using individual getter methods from the service
            result.insert(
                path_str.to_string(),
                service_metadata,
            );
        }

        Ok(result)
    }
}

#[async_trait::async_trait]
impl crate::services::RegistryDelegate for ServiceRegistry {
    async fn get_local_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.get_local_service_state(service_path).await
    }

    async fn get_remote_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.get_remote_service_state(service_path).await
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
        self.get_service_metadata(topic_path).await
    }

    /// Get metadata for all registered services with an option to filter internal services
    async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> Result<HashMap<String, ServiceMetadata>> {
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

    async fn register_remote_event_handler(&self, topic_path: &TopicPath, handler: RemoteEventHandler) -> Result<String> {
        self.register_remote_event_subscription(topic_path, handler, EventRegistrationOptions::default()).await
    }

    async fn remove_remote_event_handler(&self, topic_path: &TopicPath) -> Result<()> {
        self.remove_remote_event_subscription(topic_path).await
    }

    async fn update_local_service_state_if_valid(
        &self,
        service_path: &TopicPath,
        new_state: ServiceState,
        current_state: ServiceState,
    ) -> Result<()> {
        // Validate the state transition
        match (current_state, new_state) {
            (ServiceState::Running, ServiceState::Paused) => {
                // Valid transition: Running -> Paused
                self.update_local_service_state(service_path, new_state).await
            }
            (ServiceState::Paused, ServiceState::Running) => {
                // Valid transition: Paused -> Running
                self.update_local_service_state(service_path, new_state).await
            }
            _ => {
                // Invalid transition
                Err(anyhow!(
                    "Invalid state transition from {:?} to {:?}",
                    current_state,
                    new_state
                ))
            }
        }
    }

    async fn validate_pause_transition(&self, service_path: &TopicPath) -> Result<()> {
        let current_state = self.get_local_service_state(service_path).await;
        match current_state {
            Some(ServiceState::Running) => {
                // Valid state for pausing
                Ok(())
            }
            Some(state) => {
                // Invalid state for pausing
                Err(anyhow!(
                    "Cannot pause service in {:?} state. Service must be in Running state.",
                    state
                ))
            }
            None => {
                // Service not found
                Err(anyhow!("Service not found: {}", service_path.as_str()))
            }
        }
    }

    async fn validate_resume_transition(&self, service_path: &TopicPath) -> Result<()> {
        let current_state = self.get_local_service_state(service_path).await;
        match current_state {
            Some(ServiceState::Paused) => {
                // Valid state for resuming
                Ok(())
            }
            Some(state) => {
                // Invalid state for resuming
                Err(anyhow!(
                    "Cannot resume service in {:?} state. Service must be in Paused state.",
                    state
                ))
            }
            None => {
                // Service not found
                Err(anyhow!("Service not found: {}", service_path.as_str()))
            }
        }
    }
}
