use runar_macros::{action, service, service_impl};
use runar_node::{
    anyhow::{self, Result},
    async_trait::async_trait,
    Node,
};
use runar_gateway::GatwayService;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// Define a simple user service
#[derive(Clone)]
#[service(name = "user_service", path="user_service")]
pub struct UserService {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
}

#[service_impl]
impl UserService {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
}

#[async_trait]
impl UserService {
    #[action]
    pub async fn get_users(&self) -> Result<Vec<User>> {
        let users = self.users.read().await;
        Ok(users.values().cloned().collect())
    }
    
    #[action]
    pub async fn get_user(&self, id: Uuid) -> Result<User> {
        let users = self.users.read().await;
        users
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("User not found"))
    }
    
    #[action]
    pub async fn create_user(&self, req: CreateUserRequest) -> Result<User> {
        let user = User {
            id: Uuid::new_v4(),
            username: req.username,
            email: req.email,
        };
        
        let mut users = self.users.write().await;
        users.insert(user.id, user.clone());
        
        Ok(user)
    }
}

// Define an API gateway service
#[service(name = "api_gateway", path="api")]
pub struct ApiGateway;

#[service_impl]
impl ApiGateway {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ApiGateway {
    #[action]
    async fn get_users(&self) -> Result<Vec<User>> {
        // This would typically make a request to the user service
        // For now, return empty list
        Ok(vec![])
    }
    
    #[action]
    async fn create_user(&self, req: CreateUserRequest) -> Result<User> {
        // This would typically make a request to the user service
        // For now, create a mock user
        Ok(User {
            id: Uuid::new_v4(),
            username: req.username,
            email: req.email,
        })
    }
    
    #[action]
    async fn get_user(&self, id: Uuid) -> Result<User> {
        // This would typically make a request to the user service
        // For now, return a mock user
        Ok(User {
            id,
            username: "mock_user".to_string(),
            email: "mock@example.com".to_string(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting Gateway Example");
    
    // Create a node
    let mut node = runar_node::Node::new(runar_node::NodeConfig::default()).await?;
    
    // Create and register services
    let user_service = UserService::new();
    let api_gateway = ApiGateway::new();
    
    node.add_service(user_service).await?;
    node.add_service(api_gateway).await?;
    
    // Create and register the HTTP gateway
    let http_gateway = GatwayService::new("HTTP Gateway", "gateway");
    node.add_service(http_gateway).await?;
    
    // Start the node
    node.start().await?;
    
    println!("✅ Gateway example started successfully!");
    println!("🌐 HTTP gateway should be available at http://localhost:3000");
    println!("📡 Services registered:");
    println!("   - user_service");
    println!("   - api_gateway");
    println!("   - HTTP gateway");
    
    // Keep the node running
    tokio::signal::ctrl_c().await?;
    println!("🛑 Shutting down...");
    
    Ok(())
} 