use anyhow::Result;
use async_trait::async_trait;
use runar_node::services::abstract_service::{AbstractService, ServiceState, ActionMetadata};
use runar_node::services::ResponseStatus;
use runar_node::{RequestContext, ServiceRequest, ServiceResponse, ValueType};
use runar_node::logging::{debug_log, info_log, Component};
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashMap;

/// A base station service that monitors ship events
pub struct BaseStationService {
    name: String,
    path: String,
    state: ServiceState,
    pub events: Arc<Mutex<Vec<ValueType>>>, // Store all received events
}

impl Clone for BaseStationService {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            state: self.state,
            events: Arc::clone(&self.events),
        }
    }
}

impl BaseStationService {
    /// Create a new base station service
    pub fn new(name: &str) -> Self {
        println!("[BaseStationService] Creating new instance with name={}", name);
        Self {
            name: name.to_string(),
            path: "base".to_string(),
            state: ServiceState::Created,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Handle get_events action: returns all collected events
    async fn handle_get_events(&self, _request: ServiceRequest) -> Result<ServiceResponse> {
        println!("[BaseStationService] handle_request: {} / get_events", self.path);
        
        // Get all stored events
        let events = self.events.lock().unwrap().clone();
        println!("Total events received: {}", events.len());
        
        // Create response data with counts by type
        let mut landed_count = 0;
        let mut took_off_count = 0;
        
        // Debug each event in detail
        println!("\n[DEBUG] Examining each event for status:");
        for (i, event) in events.iter().enumerate() {
            println!("[DEBUG] Event {}: {:?}", i+1, event);
            
            // Only expect Map type events for consistent internal handling
            if let ValueType::Map(map) = event {
                // Handle Map type (internal HashMap)
                if let Some(status_value) = map.get("status") {
                    println!("[DEBUG]   - Status value from Map: {:?}", status_value);
                    if let ValueType::String(status) = status_value {
                        println!("[DEBUG]   - Status string: '{}'", status);
                        if status == "landed" {
                            println!("[DEBUG]   - COUNTED as LANDED");
                            landed_count += 1;
                        } else if status == "airborne" {
                            println!("[DEBUG]   - COUNTED as AIRBORNE");
                            took_off_count += 1;
                        } else {
                            println!("[DEBUG]   - UNKNOWN status value");
                        }
                    } else {
                        println!("[DEBUG]   - Status is not a string value");
                    }
                } else {
                    println!("[DEBUG]   - No 'status' field found in Map event");
                }
            } else {
                println!("[DEBUG]   - Event is not a Map type: {:?}", event);
            }
        }
        
        println!("\n[DEBUG] TOTALS: landed={}, took_off={}", landed_count, took_off_count);
        
        // Build response with counts and full events
        let mut data = HashMap::new();
        data.insert("total_events".to_string(), ValueType::Number(events.len() as f64));
        data.insert("landed_count".to_string(), ValueType::Number(landed_count as f64));
        data.insert("took_off_count".to_string(), ValueType::Number(took_off_count as f64));
        data.insert("events".to_string(), ValueType::Array(events));
        
        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: "Event data retrieved".to_string(),
            data: Some(ValueType::Map(data)),
        })
    }
    
    /// Helper method to directly process an event without going through the handle_event flow
    fn directly_process_event(&self, payload: ValueType) -> Result<()> {
        println!("[BaseStationService] Directly processing event: {:?}", payload);
        
        // Store the event
        let mut events = self.events.lock().unwrap();
        events.push(payload.clone());
        
        println!("[BaseStationService] Event stored directly. Total count: {}", events.len());
        Ok(())
    }
    
    /// Set up subscriptions to various ship events
    async fn setup_subscriptions(&self, ctx: &RequestContext) -> Result<()> {
        println!("[BaseStationService] Subscribing to ship events directly");
                
        // Create direct subscription to exact topic paths the ship service publishes to
        let self_clone_landed = self.clone();
        let self_clone_takeoff = self.clone();
        
        // Subscribe to ship landing events
        println!("[BaseStationService] Subscribing to 'ship/landed'");
        let _ = ctx.subscribe("ship/landed", move |payload| {
            let service = self_clone_landed.clone();
            Box::pin(async move {
                println!("[BaseStationService] Received landed event: {:?}", payload);
                
                // Store the event
                {
                    let mut events = service.events.lock().unwrap();
                    events.push(payload.clone());
                    println!("[BaseStationService] Stored landed event. Total count: {}", events.len());
                } // MutexGuard dropped here
                
                info_log(Component::Service,
                       &format!("[BaseStationService] Received landed event")).await;
                Ok(())
            })
        }).await;
        
        println!("[BaseStationService] Successfully subscribed to 'ship/landed'");
        
        // Subscribe to ship takeoff events
        println!("[BaseStationService] Subscribing to 'ship/tookOff'");
        let _ = ctx.subscribe("ship/tookOff", move |payload| {
            let service = self_clone_takeoff.clone();
            Box::pin(async move {
                println!("[BaseStationService] Received takeOff event: {:?}", payload);
                
                // Store the event
                {
                    let mut events = service.events.lock().unwrap();
                    events.push(payload.clone());
                    println!("[BaseStationService] Stored takeOff event. Total count: {}", events.len());
                } // MutexGuard dropped here
                
                info_log(Component::Service,
                       &format!("[BaseStationService] Received tookOff event")).await;
                Ok(())
            })
        }).await;
        
        println!("[BaseStationService] Successfully subscribed to 'ship/tookOff'");
        
        Ok(())
    }
}

#[async_trait]
impl AbstractService for BaseStationService {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn path(&self) -> &str {
        &self.path
    }
    
    fn state(&self) -> ServiceState {
        self.state
    }
    
    fn description(&self) -> &str {
        "Base Station Service for monitoring ship activities"
    }
    
    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn init(&mut self, context: &RequestContext) -> Result<()> {
        println!("[BaseStationService] init called");
        self.state = ServiceState::Initialized;
        
        // Set up subscriptions to various ship events
        match self.setup_subscriptions(context).await {
            Ok(_) => info_log(Component::Service, 
                  "[BaseStationService] Successfully subscribed to ship events").await,
            Err(e) => info_log(Component::Service, 
                  &format!("[BaseStationService] Error subscribing to events: {}", e)).await,
        }
        
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        println!("[BaseStationService] start called");
        self.state = ServiceState::Running;
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        println!("[BaseStationService] stop called");
        self.state = ServiceState::Stopped;
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        println!("[BaseStationService] handle_request: {} / {}", self.path, request.action);
        
        match request.action.as_str() {
            "get_events" => self.handle_get_events(request).await,
            _ => {
                println!("[BaseStationService] Unknown action: {}", request.action);
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: format!("Unknown action: {}", request.action),
                    data: None,
                })
            }
        }
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata {
                name: "get_events".to_string(),
            }
        ]
    }
}

impl BaseStationService {
    pub async fn handle_event(&self, event_data: ValueType, topic: &str) -> Result<()> {
        info_log(Component::Service,
                &format!("[BaseStationService] Received event on topic '{}' with data: {:?}", 
                        topic, event_data)).await;
        
        // Store the event regardless of type for our event collection
        info_log(Component::Service,
                &format!("[BaseStationService] Current event count before adding: {}", 
                        self.events.lock().unwrap().len())).await;
        
        // Store the event
        let mut events = self.events.lock().unwrap();
        events.push(event_data.clone());
        
        info_log(Component::Service,
                &format!("[BaseStationService] Total events after update: {}", 
                        events.len())).await;
        
        Ok(())
    }
} 