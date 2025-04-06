use crate::services::{ServiceRequest, ServiceResponse};
use anyhow::Result;
use std::sync::Arc;
use async_trait::async_trait;

#[async_trait]
pub trait ServiceRegistry: Send + Sync {
    async fn register_service(&self, service: Arc<dyn Service>) -> Result<()>;
    async fn get_service(&self, name: &str) -> Option<Arc<dyn Service>>;
}

#[async_trait]
pub trait Service: Send + Sync {
    fn name(&self) -> &str;
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse>;
} 