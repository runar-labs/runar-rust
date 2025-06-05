use runar_macros::{action, gateway, init, main, middleware, route, service};
use runar_node::{
    anyhow::{self, Result},
    async_trait::async_trait,
    node::NodeConfig,
    Node,
};
use runar_gateway::{
    Gateway, GatewayConfig, Next, hyper::{Request, Response, Body}
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// Define a simple user service
#[service(name = "user_service")]
pub struct UserService {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
}

#[init]
impl UserService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        })
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

// Define an auth middleware
#[middleware]
pub struct AuthMiddleware;

impl AuthMiddleware {
    pub fn new() -> Self {
        Self {}
    }
    
    #[action]
    async fn handle_request(&self, req: &Request<hyper::Body>, next: Next<'_>) -> Result<Response<hyper::Body>> {
        // In a real app, we would validate a token here
        let token = req.headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
            
        if token.is_none() {
            // For this example, we'll only check if the header exists
            // In a real app, we would validate the token
            return Err(anyhow::anyhow!("Unauthorized"));
        }
        
        // Continue processing
        next.run(req).await
    }
}

// Define the API gateway
#[service]
#[gateway(
    host = "0.0.0.0",
    port = 8080,
    services = [UserService],
    middleware = [AuthMiddleware::new()]
)]
pub struct ApiGateway;

#[init]
impl ApiGateway {
    pub async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl ApiGateway {
    // Public endpoints
    #[route(GET, "/api/users")]
    async fn get_users(&self) -> Result<Vec<User>> {
        self.context.request("user_service", "get_users", {}).await
    }
    
    #[route(POST, "/api/users")]
    async fn create_user(&self, req: CreateUserRequest) -> Result<User> {
        self.context.request("user_service", "create_user", { req }).await
    }
    
    #[route(GET, "/api/users/:id")]
    async fn get_user(&self, id: Uuid) -> Result<User> {
        self.context.request("user_service", "get_user", { id }).await
    }
    
    // Protected endpoints
    #[route(GET, "/api/profile", middleware = [AuthMiddleware])]
    async fn get_profile(&self, #[from_context] user_id: Uuid) -> Result<User> {
        self.context.request("user_service", "get_user", { id: user_id }).await
    }
}

// Main application entry point
#[main]
async fn main() -> Result<()> {
    // Create and initialize node
    let mut node = Node::new(NodeConfig {
        node_id: "api_node".to_string(),
        data_dir: "./data".to_string(),
        db_path: "./data/db".to_string(),
        p2p_config: None, // Configure if P2P is needed
    }).await?;
    
    // Initialize services
    let user_service = UserService::new().await?;
    let api_gateway = ApiGateway::new().await?;
    
    // Register services with the node using the proper add_service method
    node.add_service(user_service).await?;
    node.add_service(api_gateway).await?;
    
    // Start the node which will manage all services
    node.start().await?;
    
    // Wait for the node to complete (typically runs until interrupted)
    node.wait_for_shutdown().await?;
    
    Ok(())
} 