use anyhow::Result;
use async_trait::async_trait;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;
use std::collections::HashMap;

use crate::services::abstract_service::{AbstractService, ActionMetadata, EventMetadata, ServiceState};
use crate::services::{ServiceRequest, ServiceResponse, ValueType};
use runar_common::utils::logging::{info_log, Component};

/// Default time-to-live for anonymous services (2 hours)
pub const DEFAULT_ANONYMOUS_SERVICE_TTL: Duration = Duration::from_secs(7200);

/// Metrics for anonymous subscriber services
#[derive(Debug, Clone, Default)]
pub struct AnonymousServiceMetrics {
    /// Total number of events received
    pub events_received: usize,
    /// Last event received timestamp
    pub last_event_received: Option<SystemTime>,
    /// Total number of successful events
    pub successful_events: usize,
    /// Total number of failed events
    pub failed_events: usize,
    /// Total processing time for all events (microseconds)
    pub total_processing_time_us: u64,
    /// Longest processing time for a single event (microseconds)
    pub max_processing_time_us: u64,
}

/// An anonymous service that exists solely to support direct node.subscribe() calls
/// This allows us to maintain the service-based architecture even for subscriptions
/// that are created directly through the Node API rather than a specific service.
pub struct AnonymousSubscriberService {
    /// Unique name for this anonymous service
    name: String,

    /// Path for the service
    path: String,

    /// Service state
    state: Mutex<ServiceState>,

    /// Network ID
    _network_id: String,

    /// Original subscription topic
    subscription_topic: String,

    /// Last activity timestamp
    last_activity: Mutex<Instant>,

    /// Time-to-live for this service
    ttl: Duration,

    /// Active subscription count
    subscription_count: Mutex<usize>,

    /// Service metrics
    metrics: Mutex<AnonymousServiceMetrics>,

    /// Creation time of the service
    _creation_time: SystemTime,
}

impl AnonymousSubscriberService {
    /// Create a new anonymous subscriber service with a unique name
    pub fn new(network_id: &str, subscription_topic: &str) -> Self {
        // Generate a unique ID for this anonymous service
        let unique_id = Uuid::new_v4();
        let name = format!("anonymous_subscriber_{}", unique_id);

        let service = AnonymousSubscriberService {
            name,
            // Use the network ID in the path
            path: format!("{}/anonymous/{}", network_id, unique_id),
            state: Mutex::new(ServiceState::Created),
            _network_id: network_id.to_string(),
            subscription_topic: subscription_topic.to_string(),
            last_activity: Mutex::new(Instant::now()),
            ttl: DEFAULT_ANONYMOUS_SERVICE_TTL,
            subscription_count: Mutex::new(1), // Start with 1 subscription
            metrics: Mutex::new(AnonymousServiceMetrics::default()),
            _creation_time: SystemTime::now(),
        };

        log::debug!("[{}] Created anonymous subscriber service {} for topic '{}'",
            Component::Service.as_str(),
            service.name, 
            subscription_topic
        );

        service
    }

    /// Create a new anonymous subscriber service with a custom TTL
    pub fn new_with_ttl(network_id: &str, subscription_topic: &str, ttl: Duration) -> Self {
        let mut service = Self::new(network_id, subscription_topic);
        service.ttl = ttl;
        service
    }

    /// Get the original subscription topic
    pub fn subscription_topic(&self) -> &str {
        &self.subscription_topic
    }

    /// Update the last activity timestamp
    pub fn update_last_activity(&self) {
        let mut last_activity = self.last_activity.lock().unwrap();
        *last_activity = Instant::now();
    }

    /// Check if this service is expired based on its last activity and TTL
    pub fn is_expired(&self) -> bool {
        let last_activity = self.last_activity.lock().unwrap();
        last_activity.elapsed() > self.ttl
    }

    /// Get the time since last activity
    pub fn time_since_last_activity(&self) -> Duration {
        let last_activity = self.last_activity.lock().unwrap();
        last_activity.elapsed()
    }

    /// Increment subscription count
    pub fn increment_subscription_count(&self) {
        let mut count = self.subscription_count.lock().unwrap();
        *count += 1;
        // Update last activity when adding a subscription
        self.update_last_activity();
    }

    /// Decrement subscription count
    pub fn decrement_subscription_count(&self) -> usize {
        let mut count = self.subscription_count.lock().unwrap();
        if *count > 0 {
            *count -= 1;
        }
        // Update last activity when removing a subscription
        self.update_last_activity();
        *count
    }

    /// Get the current subscription count
    pub fn subscription_count(&self) -> usize {
        let count = self.subscription_count.lock().unwrap();
        *count
    }

    /// Update metrics for an event received
    pub fn record_event_received(&self, is_success: bool, processing_time_us: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.events_received += 1;
        metrics.last_event_received = Some(SystemTime::now());

        if is_success {
            metrics.successful_events += 1;
        } else {
            metrics.failed_events += 1;
        }

        metrics.total_processing_time_us += processing_time_us;
        if processing_time_us > metrics.max_processing_time_us {
            metrics.max_processing_time_us = processing_time_us;
        }
    }

    /// Get the current metrics
    pub fn get_metrics(&self) -> AnonymousServiceMetrics {
        let metrics = self.metrics.lock().unwrap();
        metrics.clone()
    }
}

#[async_trait]
impl AbstractService for AnonymousSubscriberService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn state(&self) -> ServiceState {
        ServiceState::Running
    }
    
    fn version(&self) -> &str {
        "1.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "subscribe".to_string() },
            ActionMetadata { name: "unsubscribe".to_string() },
            ActionMetadata { name: "publish".to_string() },
            ActionMetadata { name: "get_metrics".to_string() },
            ActionMetadata { name: "handle_event".to_string() },
        ]
    }
    
    fn events(&self) -> Vec<EventMetadata> {
        vec![
            EventMetadata { name: "message_received".to_string() },
            EventMetadata { name: "subscription_expired".to_string() },
        ]
    }

    async fn init(&mut self, _context: &crate::services::RequestContext) -> Result<()> {
        *self.state.lock().unwrap() = ServiceState::Initialized;
        self.update_last_activity();
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        *self.state.lock().unwrap() = ServiceState::Running;
        self.update_last_activity();
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        *self.state.lock().unwrap() = ServiceState::Stopped;
        self.update_last_activity();
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Anonymous subscriber service for handling pub/sub events"
    }

    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let operation = &request.action;
        
        match operation.as_str() {
            "subscribe" => {
                // Handle subscription request
                self.update_last_activity();
                self.increment_subscription_count();
                
                Ok(ServiceResponse::success(
                    format!("Subscribed to topic {}", self.subscription_topic()),
                    Some(ValueType::String(self.subscription_topic().to_string())),
                ))
            }
            "unsubscribe" => {
                // Handle unsubscription request
                self.update_last_activity();
                let count = self.decrement_subscription_count();
                
                Ok(ServiceResponse::success(
                    format!("Unsubscribed from topic {}, remaining subscribers: {}", 
                            self.subscription_topic(), count),
                    Some(ValueType::Number(count as f64)),
                ))
            }
            "handle_event" => {
                // Handle incoming events for subscriptions
                self.update_last_activity();
                
                // Log that we received an event
                log::debug!(
                    "[{}] Anonymous subscriber {} received event on topic '{}'", 
                    Component::Service.as_str(),
                    self.name, 
                    self.subscription_topic
                );
                
                // Start timing the processing
                let start_time = Instant::now();
                
                // In the actual implementation, this would be handled by the callback
                // that's stored in the service registry. The registry will invoke the
                // callback directly when publishing events.
                
                // Record metrics for this event
                let processing_time_us = start_time.elapsed().as_micros() as u64;
                self.record_event_received(true, processing_time_us);
                
                Ok(ServiceResponse::success::<ValueType>(
                    "Event processed successfully".to_string(),
                    None,
                ))
            }
            "publish" => {
                // Handle publish request
                if let Some(data) = &request.data {
                    if let ValueType::Map(param_map) = data {
                        if let Some(message) = param_map.get("message") {
                            self.update_last_activity();
                            
                            // In a real implementation, this would publish the message
                            // to the subscription topic
                            
                            Ok(ServiceResponse::success(
                                format!("Message published to topic {}", self.subscription_topic()),
                                Some(message.clone()),
                            ))
                        } else {
                            Ok(ServiceResponse::error("Missing 'message' parameter"))
                        }
                    } else {
                        Ok(ServiceResponse::error("Invalid parameters format"))
                    }
                } else {
                    Ok(ServiceResponse::error("Missing parameters"))
                }
            }
            "get_metrics" => {
                // Return service metrics
                self.update_last_activity();
                let metrics = self.get_metrics();
                
                let mut metrics_map = HashMap::new();
                metrics_map.insert("events_received".to_string(), ValueType::Number(metrics.events_received as f64));
                metrics_map.insert("successful_events".to_string(), ValueType::Number(metrics.successful_events as f64));
                metrics_map.insert("failed_events".to_string(), ValueType::Number(metrics.failed_events as f64));
                metrics_map.insert("total_processing_time_us".to_string(), ValueType::Number(metrics.total_processing_time_us as f64));
                metrics_map.insert("max_processing_time_us".to_string(), ValueType::Number(metrics.max_processing_time_us as f64));
                
                if let Some(last_event) = metrics.last_event_received {
                    if let Ok(duration) = last_event.duration_since(SystemTime::UNIX_EPOCH) {
                        metrics_map.insert("last_event_received".to_string(), 
                                          ValueType::Number(duration.as_secs() as f64));
                    }
                }
                
                Ok(ServiceResponse::success(
                    "Service metrics".to_string(),
                    Some(ValueType::Map(metrics_map)),
                ))
            }
            _ => {
                Ok(ServiceResponse::error(format!("Unknown operation: {}", operation)))
            }
        }
    }
}
