use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
use crate::services::{AbstractService, ServiceRequest, ServiceResponse};

pub struct ServiceManager {
    services: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_service(&self, service: Arc<dyn AbstractService>) -> Result<()> {
        let mut services = self.services.write().await;
        services.insert(service.path().to_string(), service);
        Ok(())
    }

    pub async fn get_service(&self, path: &str) -> Option<Arc<dyn AbstractService>> {
        let services = self.services.read().await;
        services.get(path).cloned()
    }

    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let service = self.get_service(&request.path).await
            .ok_or_else(|| anyhow!("Service not found: {}", request.path))?;

        service.handle_request(request).await
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
} 