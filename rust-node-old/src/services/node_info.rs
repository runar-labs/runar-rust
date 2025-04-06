use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use log::{debug, info};

use crate::node::NodeConfig;
use crate::services::abstract_service::{AbstractService, ServiceState, ActionMetadata, EventMetadata};
use crate::services::{ServiceRequest, ServiceResponse, ValueType};

/// Node Info Service - provides information about the node
pub struct NodeInfoService {
    /// The path at which the service is available
    path: String,

    /// Current state of the service
    state: Mutex<ServiceState>,

    /// Node uptime tracker
    start_time: Instant,

    /// Node configuration
    config: Arc<NodeConfig>,
}

impl NodeInfoService {
    /// Create a new Node Info Service
    pub fn new(network_id: &str, config: Arc<NodeConfig>) -> Self {
        Self {
            path: format!("{}/node_info", network_id),
            state: Mutex::new(ServiceState::Created),
            start_time: Instant::now(),
            config,
        }
    }

    /// Get basic node information
    fn get_node_info(&self) -> ValueType {
        let mut info = std::collections::HashMap::new();
        info.insert("name".to_string(), ValueType::String(self.config.node_id.clone().unwrap_or_else(|| "unnamed_node".to_string())));
        info.insert("path".to_string(), ValueType::String(self.path.clone()));
        info.insert("state".to_string(), ValueType::String(self.state().to_string()));
        info.insert("uptime".to_string(), ValueType::Number(self.start_time.elapsed().as_secs() as f64));
        ValueType::Map(info)
    }
    
    /// Handle the info operation
    async fn handle_info(&self, request: &ServiceRequest) -> Result<ServiceResponse> {
        debug!("Getting node info for: {}", request.path);
        
        let info = self.get_node_info();
        
        info!("Node info retrieved successfully");
            
        Ok(ServiceResponse::success(
            "Node information retrieved successfully".to_string(),
            Some(info)
        ))
    }
    
    /// Handle the stats operation
    async fn handle_stats(&self, request: &ServiceRequest) -> Result<ServiceResponse> {
        debug!("Getting node stats for: {}", request.path);
        
        let uptime = self.start_time.elapsed().as_secs();
        
        // Get node stats
        let stats = json!({
            "uptime": uptime,
            "memory_usage": 0, // Placeholder
            "cpu_usage": 0,    // Placeholder
            "disk_usage": 0,   // Placeholder
            "network": {
                "peers": 0,
                "inbound": 0,
                "outbound": 0,
            }
        });

        info!("Node stats retrieved successfully");
            
        Ok(ServiceResponse::success(
            "Node stats retrieved successfully".to_string(),
            Some(crate::services::ValueType::from_json(stats))
        ))
    }
    
    /// Handle the config operation
    async fn handle_config(&self, request: &ServiceRequest) -> Result<ServiceResponse> {
        debug!("Getting node config for: {}", request.path);
        
        // Get node configuration
        let config_json = json!({
            "network_id": &self.config.network_id,
            "node_path": &self.config.node_path,
            "db_path": &self.config.db_path,
            "state_path": self.config.state_path.as_ref().unwrap_or(&self.config.node_path),
            "has_p2p_config": self.config.p2p_config.is_some(),
            "version": env!("CARGO_PKG_VERSION"),
        });

        info!("Node configuration retrieved successfully");
            
        Ok(ServiceResponse::success(
            "Node configuration retrieved successfully".to_string(),
            Some(crate::services::ValueType::from_json(config_json))
        ))
    }
}

#[async_trait]
impl AbstractService for NodeInfoService {
    fn name(&self) -> &str {
        "node_info"
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn state(&self) -> ServiceState {
        *self.state.lock().unwrap()
    }

    fn description(&self) -> &str {
        "Node information service"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "get_info".to_string() },
            ActionMetadata { name: "get_status".to_string() },
            ActionMetadata { name: "get_metrics".to_string() },
            ActionMetadata { name: "get_peer_info".to_string() },
        ]
    }

    fn events(&self) -> Vec<EventMetadata> {
        vec![
            EventMetadata { name: "status_changed".to_string() },
        ]
    }

    async fn init(&mut self, context: &crate::services::RequestContext) -> Result<()> {
        info!("Initializing NodeInfoService: {:?}", context);
        self.start_time = Instant::now();
        *self.state.lock().unwrap() = ServiceState::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting NodeInfoService");
        *self.state.lock().unwrap() = ServiceState::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping NodeInfoService");
        *self.state.lock().unwrap() = ServiceState::Stopped;
        Ok(())
    }

    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("NodeInfoService handling request: {}", request.action);
        
        match request.action.as_str() {
            "info" => self.handle_info(&request).await,
            "stats" => self.handle_stats(&request).await,
            "config" => self.handle_config(&request).await,
            _ => {
                let _error_info = json!({
                    "error": format!("Unknown operation: {}", request.action),
                });
                Ok(ServiceResponse::error(
                    format!("Unknown operation: {}", request.action)
                ))
            }
        }
    }
}
