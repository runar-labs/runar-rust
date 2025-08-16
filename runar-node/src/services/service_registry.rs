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
use dashmap::DashMap;
use runar_macros_common::{log_debug, log_error, log_info, log_warn};
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

pub type RemoteEventHandler =
    Arc<dyn Fn(Option<ArcValue>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

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

/// Unified subscriber type for event subscriptions – distinguishes local vs remote handlers
#[derive(Clone)]
pub enum SubscriberKind {
    Local(EventHandler),
    Remote(RemoteEventHandler),
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

/// Tuple stored in the unified `event_subscriptions` trie
pub type SubscriptionEntry = (String, SubscriberKind, SubscriptionMetadata);

// Wrapper stored at each trie leaf
pub type SubscriptionVec = Vec<SubscriptionEntry>;

const INTERNAL_SERVICES: [&str; 2] = ["$registry", "$keys"];

pub fn is_internal_service(service_path: &str) -> bool {
    // Check if it starts with an internal service directly (exact match or followed by /)
    for &internal in &INTERNAL_SERVICES {
        if service_path == internal || service_path.starts_with(&format!("{}/", internal)) {
            return true;
        }
    }

    // Check if it has the pattern <network_id>:<internal_service>/...
    if let Some(colon_pos) = service_path.find(':') {
        let after_colon = &service_path[colon_pos + 1..];
        for &internal in &INTERNAL_SERVICES {
            if after_colon == internal || after_colon.starts_with(&format!("{}/", internal)) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_internal_service() {
        // Test direct internal service paths
        assert!(is_internal_service("$registry"));
        assert!(is_internal_service("$registry/services/list"));
        assert!(is_internal_service("$registry/peer/node123/discovered"));
        assert!(is_internal_service("$keys"));
        assert!(is_internal_service("$keys/ensure_symmetric_key"));
        assert!(is_internal_service("$keys/generate_keypair"));

        // Test network-prefixed internal service paths
        assert!(is_internal_service("31cpl9tk8gbtreprejof9orghts:$registry"));
        assert!(is_internal_service(
            "31cpl9tk8gbtreprejof9orghts:$registry/peer/node123/discovered"
        ));
        assert!(is_internal_service("abc123:$keys/ensure_symmetric_key"));
        assert!(is_internal_service(
            "network-456:$registry/services/math1/state/running"
        ));

        // Test non-internal service paths
        assert!(!is_internal_service("math1"));
        assert!(!is_internal_service("math1/add"));
        assert!(!is_internal_service("echo-service/echo"));
        assert!(!is_internal_service("user-service/profile"));

        // Test edge cases - internal service names appearing elsewhere in the path
        assert!(!is_internal_service("my_service/$registry"));
        assert!(!is_internal_service("service/$keys/backup"));
        assert!(!is_internal_service("app/math1/$registry/helper"));
        assert!(!is_internal_service("external/$keys/manager"));

        // Test network-prefixed non-internal services
        assert!(!is_internal_service(
            "31cpl9tk8gbtreprejof9orghts:math1/add"
        ));
        assert!(!is_internal_service("abc123:echo-service/echo"));
        assert!(!is_internal_service("network-456:user-service/profile"));

        // Test edge cases with special characters
        assert!(!is_internal_service("$registry_helper")); // Doesn't start with exact internal service
        assert!(!is_internal_service("$keys_backup")); // Doesn't start with exact internal service
        assert!(!is_internal_service(
            "31cpl9tk8gbtreprejof9orghts:$registry_helper"
        )); // Network prefix but not internal
        assert!(!is_internal_service("abc123:$keys_backup")); // Network prefix but not internal

        // Test empty and single character cases
        assert!(!is_internal_service(""));
        assert!(!is_internal_service("$"));
        assert!(!is_internal_service("a"));
        assert!(!is_internal_service(":"));

        // Test malformed network prefixes
        assert!(!is_internal_service(":math1/add")); // Colon at start
        assert!(!is_internal_service("network::math1/add")); // Double colon
        assert!(!is_internal_service("network:math1/add:")); // Colon at end
    }

    #[test]
    fn test_is_internal_service_with_complex_paths() {
        // Test deeply nested internal service paths
        assert!(is_internal_service(
            "$registry/services/math1/state/running"
        ));
        assert!(is_internal_service(
            "$registry/peer/node123/services/math1/state/running"
        ));
        assert!(is_internal_service("$keys/ensure_symmetric_key/result"));
        assert!(is_internal_service("$keys/generate_keypair/private/public"));

        // Test network-prefixed deeply nested paths
        assert!(is_internal_service(
            "31cpl9tk8gbtreprejof9orghts:$registry/services/math1/state/running"
        ));
        assert!(is_internal_service(
            "abc123:$registry/peer/node123/services/math1/state/running"
        ));
        assert!(is_internal_service(
            "network-456:$keys/ensure_symmetric_key/result"
        ));
        assert!(is_internal_service(
            "test-789:$keys/generate_keypair/private/public"
        ));

        // Test mixed internal and non-internal in same path (should still be internal)
        assert!(is_internal_service("$registry/services/math1/actions/add"));
        assert!(is_internal_service(
            "$keys/ensure_symmetric_key/for_service/math1"
        ));
        assert!(is_internal_service(
            "31cpl9tk8gbtreprejof9orghts:$registry/peer/node123/services/math1/actions/add"
        ));
        assert!(is_internal_service(
            "abc123:$keys/ensure_symmetric_key/for_service/math1"
        ));
    }
}

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

    /// Unified event subscriptions – stores both local and remote subscribers in a single trie
    event_subscriptions: Arc<RwLock<PathTrie<SubscriptionVec>>>,

    /// Map subscription IDs back to TopicPath for efficient unsubscription
    /// (Single DashMap for both local and remote subscriptions)
    subscription_id_to_topic_path: Arc<DashMap<String, TopicPath>>,

    /// Map subscription IDs back to the service TopicPath for efficient unsubscription
    subscription_id_to_service_topic_path: Arc<DashMap<String, TopicPath>>,

    /// Local services registry (using PathTrie instead of HashMap)
    local_services: Arc<RwLock<PathTrie<Arc<ServiceEntry>>>>,

    local_services_list: Arc<DashMap<TopicPath, Arc<ServiceEntry>>>,

    /// Remote services registry (using PathTrie instead of HashMap)
    remote_services: Arc<RwLock<PathTrie<Arc<RemoteService>>>>,

    /// Local service lifecycle states
    local_service_states: Arc<DashMap<String, ServiceState>>,

    /// Remote service lifecycle states
    remote_service_states: Arc<DashMap<String, ServiceState>>,

    /// Mapping of peer node IDs to subscription IDs registered on their behalf
    remote_peer_subscriptions: Arc<DashMap<String, DashMap<String, String>>>,

    /// Logger instance
    logger: Arc<Logger>,
}

impl Clone for ServiceRegistry {
    fn clone(&self) -> Self {
        ServiceRegistry {
            local_action_handlers: self.local_action_handlers.clone(),
            remote_action_handlers: self.remote_action_handlers.clone(),
            event_subscriptions: self.event_subscriptions.clone(),

            subscription_id_to_topic_path: self.subscription_id_to_topic_path.clone(),
            subscription_id_to_service_topic_path: self
                .subscription_id_to_service_topic_path
                .clone(),
            local_services: self.local_services.clone(),
            local_services_list: self.local_services_list.clone(),
            remote_services: self.remote_services.clone(),
            local_service_states: self.local_service_states.clone(),
            remote_service_states: self.remote_service_states.clone(),
            remote_peer_subscriptions: self.remote_peer_subscriptions.clone(),
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
            event_subscriptions: Arc::new(RwLock::new(PathTrie::new())),
            subscription_id_to_topic_path: Arc::new(DashMap::new()),
            subscription_id_to_service_topic_path: Arc::new(DashMap::new()),
            local_services: Arc::new(RwLock::new(PathTrie::new())),
            local_services_list: Arc::new(DashMap::new()),
            remote_services: Arc::new(RwLock::new(PathTrie::new())),
            local_service_states: Arc::new(DashMap::new()),
            remote_service_states: Arc::new(DashMap::new()),
            remote_peer_subscriptions: Arc::new(DashMap::new()),
            logger,
        }
    }

    /// Register a local service
    ///
    /// INTENTION: Register a local service implementation for use by the node.
    pub async fn register_local_service(&self, service: Arc<ServiceEntry>) -> Result<()> {
        let service_entry = service.clone();
        let service_topic = service_entry.service_topic.clone();
        log_info!(self.logger, "Registering local service: {service_topic}");

        // Store the service in the local services registry
        self.local_services
            .write()
            .await
            .set_value(service_topic.clone(), service);
        //TODO understand why we have this duplciation of local_services and local_services_list
        self.local_services_list
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
                log_error!(
                    self.logger,
                    "Failed to stop remote service '{}' error: {}",
                    service.path(),
                    e
                );
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
    pub async fn register_remote_service(&self, service: Arc<RemoteService>) -> bool {
        let service_topic = service.service_topic.clone();
        let service_path = service.path().to_string();
        let peer_node_id = service.peer_node_id().clone();

        log_info!(
            self.logger,
            "Registering remote service: {service_path} from peer: {peer_node_id}"
        );

        // Add to remote services using PathTrie
        {
            let mut services = self.remote_services.write().await;
            let matches = services.find_matches(&service_topic);

            if matches.is_empty() {
                // No existing services for this topic
                services.set_value(service_topic, service);
            } else {
                log_warn!(
                    self.logger,
                    "Service already exists for topic: {service_topic}"
                );
                return false;
            }
        }

        true
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
        log_debug!(
            self.logger,
            "Registering local action handler for: {topic_path}"
        );

        // Store in the new local action handlers trie with the original topic path for parameter extraction
        self.local_action_handlers
            .write()
            .await
            .set_value(topic_path.clone(), (handler, topic_path.clone(), metadata));

        Ok(())
    }

    pub async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()> {
        log_debug!(
            self.logger,
            "Removing remote action handler for: {topic_path}"
        );

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
        log_debug!(
            self.logger,
            "Registering remote action handler for: {}",
            topic_path.as_str()
        );

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
        _options: &EventRegistrationOptions,
    ) -> Result<String> {
        let subscription_id = Uuid::new_v4().to_string();

        // Insert into unified event_subscriptions trie
        {
            let mut trie = self.event_subscriptions.write().await;
            let mut list = trie
                .find_matches(topic_path)
                .first()
                .map(|m| m.content.clone())
                .unwrap_or_default();
            list.push((
                subscription_id.clone(),
                SubscriberKind::Local(callback),
                SubscriptionMetadata {
                    path: topic_path.as_str().to_string(),
                },
            ));
            trie.set_value(topic_path.clone(), list);
        }

        // Map subscription ID to topic path - use Arc::clone for shared data
        self.subscription_id_to_topic_path
            .insert(subscription_id.clone(), topic_path.clone());

        let service_topic =
            TopicPath::new(&topic_path.service_path(), &topic_path.network_id()).unwrap();
        self.subscription_id_to_service_topic_path
            .insert(subscription_id.clone(), service_topic);
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

        {
            let mut trie = self.event_subscriptions.write().await;
            let mut list = trie
                .find_matches(topic_path)
                .first()
                .map(|m| m.content.clone())
                .unwrap_or_default();
            list.push((
                subscription_id.clone(),
                SubscriberKind::Remote(callback),
                SubscriptionMetadata {
                    path: topic_path.as_str().to_string(),
                },
            ));
            trie.set_value(topic_path.clone(), list);
        }

        // Map subscription ID to topic path - use Arc::clone for shared data
        self.subscription_id_to_topic_path
            .insert(subscription_id.clone(), topic_path.clone());

        Ok(subscription_id)
    }

    pub async fn remove_remote_event_subscription(&self, topic_path: &TopicPath) -> Result<()> {
        let mut trie = self.event_subscriptions.write().await;
        let matches = trie.find_matches(topic_path);

        let mut ids_to_remove = Vec::new();
        for m in &matches {
            for (id, kind, _) in &m.content {
                if matches!(kind, SubscriberKind::Remote(_)) {
                    ids_to_remove.push(id.clone());
                }
            }
        }

        if ids_to_remove.is_empty() {
            return Ok(());
        }

        // Rebuild vectors without the remote entries we want to remove
        for m in matches {
            let remaining: Vec<(String, SubscriberKind, SubscriptionMetadata)> = m
                .content
                .into_iter()
                .filter(|(id, kind, _)| {
                    !(ids_to_remove.contains(id) && matches!(kind, SubscriberKind::Remote(_)))
                })
                .collect();
            if remaining.is_empty() {
                trie.remove_values(topic_path);
            } else {
                trie.set_value(topic_path.clone(), remaining);
            }
        }

        // Clean up maps
        for id in ids_to_remove {
            self.subscription_id_to_topic_path.remove(&id);
            self.subscription_id_to_service_topic_path.remove(&id);
        }
        Ok(())
    }

    /// Get local event subscribers
    ///
    /// INTENTION: Find all local subscribers for a specific event topic.
    pub async fn get_local_event_subscribers(
        &self,
        topic_path: &TopicPath,
    ) -> Vec<(String, EventHandler, SubscriptionMetadata)> {
        let trie = self.event_subscriptions.read().await;
        let matches = trie.find_matches(topic_path);

        let estimated: usize = matches.iter().map(|m| m.content.len()).sum();
        let mut result = Vec::with_capacity(estimated);
        let mut seen_ids = std::collections::HashSet::new();

        for m in matches {
            for (id, kind, meta) in m.content.clone() {
                if seen_ids.contains(&id) {
                    continue;
                }
                if let SubscriberKind::Local(handler) = kind {
                    seen_ids.insert(id.clone());
                    result.push((id, handler, meta));
                }
            }
        }

        result
    }

    /// Get remote event subscribers
    pub async fn get_remote_event_subscribers(
        &self,
        topic_path: &TopicPath,
    ) -> Vec<(String, RemoteEventHandler, SubscriptionMetadata)> {
        let trie = self.event_subscriptions.read().await;
        let matches = trie.find_matches(topic_path);

        let estimated: usize = matches.iter().map(|m| m.content.len()).sum();
        let mut result = Vec::with_capacity(estimated);
        let mut seen_ids = std::collections::HashSet::new();
        for m in matches {
            for (id, kind, meta) in m.content.clone() {
                if seen_ids.contains(&id) {
                    continue;
                }
                if let SubscriberKind::Remote(handler) = kind {
                    seen_ids.insert(id.clone());
                    result.push((id, handler, meta));
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
        log_debug!(
            self.logger,
            "Updating local service state for {}: {:?}",
            service_topic,
            state
        );
        self.local_service_states
            .insert(service_topic.as_str().to_string(), state);
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
        log_debug!(
            self.logger,
            "Updating remote service state for {}: {:?}",
            service_topic,
            state
        );
        self.remote_service_states
            .insert(service_topic.as_str().to_string(), state);
        Ok(())
    }

    pub async fn remove_remote_service_state(&self, service_topic: &TopicPath) -> Result<()> {
        self.remote_service_states.remove(service_topic.as_str());
        Ok(())
    }

    /// Get local service state
    pub async fn get_local_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.local_service_states
            .get(service_path.as_str())
            .map(|entry| *entry.value())
    }

    /// Get remote service state
    pub async fn get_remote_service_state(&self, service_path: &TopicPath) -> Option<ServiceState> {
        self.remote_service_states
            .get(service_path.as_str())
            .map(|entry| *entry.value())
    }

    /// Get metadata for all events under a specific service path
    ///
    /// INTENTION: Retrieve metadata for all events registered under a service path.
    /// This is useful for service discovery and introspection.
    pub async fn get_subscriptions_metadata(
        &self,
        search_path: &TopicPath,
    ) -> Vec<SubscriptionMetadata> {
        // Search unified subscriptions and filter local ones
        let events = self.event_subscriptions.read().await;
        let matches = events.find_matches(search_path);

        // Collect all events that match the service path
        let estimated: usize = matches.iter().map(|m| m.content.len()).sum();
        let mut result = Vec::with_capacity(estimated);

        for match_item in matches {
            // Extract the topic path from the match
            let event_topic_list = &match_item.content;

            //iterate event_topic_list
            for (_, _, metadata) in event_topic_list {
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
        let mut result = Vec::with_capacity(matches.len());

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
        // Convert DashMap to HashMap using DashMap iter pattern
        let mut result = HashMap::with_capacity(self.local_services_list.len());
        for entry in self.local_services_list.iter() {
            result.insert(entry.key().clone(), entry.value().clone());
        }
        result
    }

    /// Get a reference to local services without cloning
    pub async fn get_local_services_ref(&self) -> &DashMap<TopicPath, Arc<ServiceEntry>> {
        &self.local_services_list
    }

    pub async fn unsubscribe_local(&self, subscription_id: &str) -> Result<TopicPath> {
        log_debug!(
            self.logger,
            "Attempting to unsubscribe local subscription ID: {subscription_id}"
        );

        // Find the TopicPath associated with the subscription ID
        let topic_path_option = self
            .subscription_id_to_topic_path
            .get(subscription_id)
            .map(|entry| entry.value().clone());

        if let Some(topic_path) = topic_path_option {
            log_debug!(
                self.logger,
                "Found topic path '{}' for subscription ID: {}",
                topic_path.as_str(),
                subscription_id
            );
            let mut trie = self.event_subscriptions.write().await;
            let matches = trie.find_matches(&topic_path);

            if !matches.is_empty() {
                // Build new entry vectors without the subscription to remove
                for m in matches {
                    let filtered: Vec<_> = m
                        .content
                        .into_iter()
                        .filter(|(id, kind, _)| {
                            // keep every entry except the one with matching id & Local kind
                            !(id == subscription_id && matches!(kind, SubscriberKind::Local(_)))
                        })
                        .collect();
                    if filtered.is_empty() {
                        trie.remove_values(&topic_path);
                    } else {
                        trie.set_value(topic_path.clone(), filtered);
                    }
                }

                // Remove from the ID map
                self.subscription_id_to_topic_path.remove(subscription_id);

                // Remove from service topic path map
                self.subscription_id_to_service_topic_path
                    .remove(subscription_id);

                log_debug!(
                    self.logger,
                    "Successfully unsubscribed from topic: {} with ID: {}",
                    topic_path.as_str(),
                    subscription_id
                );
                Ok(topic_path)
            } else {
                let msg = format!(
                    "No subscriptions found for topic path {topic_path} and ID {subscription_id}",
                );
                log_warn!(self.logger, "{}", msg);
                Err(anyhow!(msg))
            }
        } else {
            let msg = format!(
                "No topic path found mapping to subscription ID: {subscription_id}. Cannot unsubscribe."
            );
            log_warn!(self.logger, "{}", msg);
            Err(anyhow!(msg))
        }
    }

    /// Unsubscribe from a remote event subscription using only the subscription ID.
    ///
    /// INTENTION: Remove a specific subscription by ID from the remote event subscriptions,
    /// providing a simpler API that doesn't require the original topic.
    /// Upsert a mapping peer -> path -> subscription_id
    pub async fn upsert_remote_peer_subscription(
        &self,
        peer_id: &str,
        path: &TopicPath,
        sub_id: String,
    ) {
        let peer_subscriptions = self
            .remote_peer_subscriptions
            .entry(peer_id.to_string())
            .or_default();
        peer_subscriptions.insert(path.as_str().to_string(), sub_id);
    }

    /// Optimized version that takes ownership of peer_id to avoid cloning
    pub async fn upsert_remote_peer_subscription_owned(
        &self,
        peer_id: String,
        path: &TopicPath,
        sub_id: String,
    ) {
        let peer_subscriptions = self.remote_peer_subscriptions.entry(peer_id).or_default();
        peer_subscriptions.insert(path.as_str().to_string(), sub_id);
    }

    /// Remove a single subscription mapping and return its id (if any)
    pub async fn remove_remote_peer_subscription(
        &self,
        peer_id: &str,
        path: &TopicPath,
    ) -> Option<String> {
        self.remote_peer_subscriptions
            .get(peer_id)
            .and_then(|peer_entry| {
                peer_entry
                    .value()
                    .remove(path.as_str())
                    .map(|(_, sub_id)| sub_id)
            })
    }

    /// Return all (path, sub_id) pairs for a peer and clear them (used on peer disconnect)
    pub async fn drain_remote_peer_subscriptions(&self, peer_id: &str) -> Vec<String> {
        self.remote_peer_subscriptions
            .remove(peer_id)
            .map(|(_, peer_subscriptions)| {
                peer_subscriptions
                    .into_iter()
                    .map(|entry| entry.1)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return current set of paths for a peer
    pub async fn remote_subscription_paths(
        &self,
        peer_id: &str,
    ) -> std::collections::HashSet<String> {
        self.remote_peer_subscriptions
            .get(peer_id)
            .map(|peer_entry| {
                peer_entry
                    .value()
                    .iter()
                    .map(|path_entry| path_entry.key().clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn unsubscribe_remote(&self, subscription_id: &str) -> Result<()> {
        log_debug!(
            self.logger,
            "Attempting to unsubscribe remote subscription ID: {subscription_id}"
        );

        // Find the TopicPath associated with the subscription ID
        let topic_path_option = self
            .subscription_id_to_topic_path
            .get(subscription_id)
            .map(|entry| entry.value().clone());

        if let Some(topic_path) = topic_path_option {
            log_debug!(
                self.logger,
                "Found topic path '{}' for subscription ID: {}",
                topic_path.as_str(),
                subscription_id
            );
            let mut trie = self.event_subscriptions.write().await;
            let matches = trie.find_matches(&topic_path);

            if !matches.is_empty() {
                let mut removed_flag = false;
                for m in matches {
                    let filtered: Vec<_> = m
                        .content
                        .into_iter()
                        .filter(|(id, kind, _)| {
                            // keep entries except the matching Remote one
                            !(id == subscription_id && matches!(kind, SubscriberKind::Remote(_)))
                        })
                        .collect();
                    if filtered.is_empty() {
                        trie.remove_values(&topic_path);
                    } else {
                        trie.set_value(topic_path.clone(), filtered);
                    }
                    removed_flag = true;
                }
                if removed_flag {
                    self.subscription_id_to_topic_path.remove(subscription_id);
                    log_debug!(
                        self.logger,
                        "Successfully unsubscribed from remote topic: {} with ID: {}",
                        topic_path.as_str(),
                        subscription_id
                    );
                    Ok(())
                } else {
                    let msg = format!(
                        "Subscription handler not found for remote topic path {topic_path} and ID {subscription_id}, although ID was mapped. Potential race condition?"
                    );
                    log_warn!(self.logger, "{}", msg);
                    Err(anyhow!(msg))
                }
            } else {
                let msg = format!(
                    "No subscriptions found for remote topic path {topic_path} and ID {subscription_id}",
                );
                log_warn!(self.logger, "{}", msg);
                Err(anyhow!(msg))
            }
        } else {
            let msg = format!(
                "No topic path found mapping to remote subscription ID: {subscription_id}. Cannot unsubscribe."
            );
            log_warn!(self.logger, "{}", msg);
            Err(anyhow!(msg))
        }
    }

    async fn get_service_metadata(&self, topic_path: &TopicPath) -> Option<ServiceMetadata> {
        // Find service in the local services trie
        let services = self.local_services.read().await;
        let matches = services.find_matches(topic_path);

        if !matches.is_empty() {
            let service_entry = &matches[0].content;
            let service = &service_entry.service; // Use reference instead of cloning
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

    pub async fn get_all_subscriptions(
        &self,
        include_internal_services: bool,
    ) -> Result<Vec<SubscriptionMetadata>> {
        let subscriptions = self.event_subscriptions.read().await;
        let all_values = subscriptions.get_all_values();

        let mut result = Vec::new();

        for subscription_vec in all_values {
            for (_, _, metadata) in subscription_vec {
                // Filter out internal services if not included
                if !include_internal_services {
                    // metadata.path is a full topic path including network id prefix
                    let tp = TopicPath::from_full_path(&metadata.path).map_err(|e| {
                        anyhow!("Invalid subscription topic path {}: {e}", metadata.path)
                    })?;
                    let service_path = tp.service_path();
                    if is_internal_service(&service_path.as_str()) {
                        continue;
                    }
                }
                result.push(metadata);
            }
        }

        Ok(result)
    }

    /// Optimized version that pre-allocates the result vector
    pub async fn get_all_subscriptions_optimized(
        &self,
        include_internal_services: bool,
    ) -> Result<Vec<SubscriptionMetadata>> {
        let subscriptions = self.event_subscriptions.read().await;
        let all_values = subscriptions.get_all_values();

        // Pre-allocate with estimated capacity to reduce reallocations
        let estimated_capacity = all_values.iter().map(|vec| vec.len()).sum();
        let mut result = Vec::with_capacity(estimated_capacity);

        for subscription_vec in all_values {
            for (_, _, metadata) in subscription_vec {
                // Filter out internal services if not included
                if !include_internal_services {
                    // metadata.path is a full topic path including network id prefix
                    let tp = TopicPath::from_full_path(&metadata.path).map_err(|e| {
                        anyhow!("Invalid subscription topic path {}: {e}", metadata.path)
                    })?;
                    let service_path = tp.service_path();
                    if is_internal_service(&service_path.as_str()) {
                        continue;
                    }
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
        let mut result = HashMap::with_capacity(self.local_services_list.len());
        let local_services = self.get_local_services().await;

        // Iterate through all services
        for (_, service_entry) in local_services {
            let service = &service_entry.service;
            let path_str = service.path();

            // Skip internal services if not included
            if !include_internal_services && is_internal_service(&path_str) {
                continue;
            }

            let search_path = format!("{path_str}/*");
            let search_topic = TopicPath::new(
                &search_path,
                &service_entry.service_topic.network_id().to_string(),
            )
            .map_err(|e| anyhow!("Failed to create topic path: {e}"))?;
            let service_metadata = self
                .get_service_metadata(&search_topic)
                .await
                .ok_or_else(|| anyhow!("Service metadata not found for topic: {}", search_topic))?;

            // Create metadata using individual getter methods from the service
            result.insert(path_str.to_string(), service_metadata);
        }

        Ok(result)
    }

    /// Optimized version that uses references to avoid cloning
    pub async fn get_all_service_metadata_ref(
        &self,
        include_internal_services: bool,
    ) -> Result<HashMap<String, ServiceMetadata>> {
        let mut result = HashMap::new();

        // Iterate through all services using DashMap iter pattern
        for entry in self.local_services_list.iter() {
            let service_entry = entry.value();
            let service = &service_entry.service;
            let path_str = service.path();

            // Skip internal services if not included
            if !include_internal_services && is_internal_service(&path_str) {
                continue;
            }

            let search_path = format!("{path_str}/*");
            let search_topic = TopicPath::new(
                &search_path,
                &service_entry.service_topic.network_id().to_string(),
            )
            .map_err(|e| anyhow!("Failed to create topic path: {e}"))?;
            let service_metadata = self
                .get_service_metadata(&search_topic)
                .await
                .ok_or_else(|| anyhow!("Service metadata not found for topic: {}", search_topic))?;

            // Create metadata using individual getter methods from the service
            result.insert(path_str.to_string(), service_metadata);
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

    async fn register_remote_event_handler(
        &self,
        topic_path: &TopicPath,
        handler: RemoteEventHandler,
    ) -> Result<String> {
        self.register_remote_event_subscription(
            topic_path,
            handler,
            EventRegistrationOptions::default(),
        )
        .await
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
                self.update_local_service_state(service_path, new_state)
                    .await
            }
            (ServiceState::Paused, ServiceState::Running) => {
                // Valid transition: Paused -> Running
                self.update_local_service_state(service_path, new_state)
                    .await
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
