use anyhow::{anyhow, Result};
use async_trait::async_trait;
use runar_node::services::abstract_service::{AbstractService, ServiceState, ActionMetadata};
use runar_node::services::ResponseStatus;
use runar_node::{RequestContext, ServiceRequest, ServiceResponse, ValueType, vmap};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Authentication service that demonstrates service-to-service communication
/// This implementation uses the Node API directly without macros
pub struct AuthService {
    name: String,
    path: String,
    users: Arc<RwLock<HashMap<String, ValueType>>>,
    tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl Clone for AuthService {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            users: self.users.clone(),
            tokens: self.tokens.clone(),
        }
    }
}

impl AuthService {
    /// Create a new AuthService
    pub fn new(name: &str) -> Self {
        // Create a HashMap for users
        let mut users = HashMap::new();
        
        // Add test users using vmap! macro
        users.insert(
            "admin".to_string(),
            vmap!("username" => "admin", "password" => "password123", "role" => "admin")
        );
        
        users.insert(
            "user".to_string(),
            vmap!("username" => "user", "password" => "user123", "role" => "user")
        );
        
        // Add testuser account for service-to-service communication tests
        users.insert(
            "testuser".to_string(),
            vmap!("username" => "testuser", "password" => "password123", "role" => "user")
        );
        
        Self {
            name: name.to_string(),
            path: format!("/auth/{}", name),
            users: Arc::new(RwLock::new(users)),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Login a user with username and password
    pub async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ServiceResponse> {
        // Simulate user lookup
        let user_value = {
            let users = self.users.read().unwrap();
            // Copy the user value to avoid holding the lock across an await point
            users.get(username).cloned()
        };
        
        if let Some(user_value) = user_value {
            // Check password based on the user data format
            let password_matches = match &user_value {
                // Handle when users are stored as Map (from vmap! macro)
                ValueType::Map(user_map) => {
                    if let Some(ValueType::String(stored_password)) = user_map.get("password") {
                        stored_password == password
                    } else {
                        false
                    }
                },
                // Handle when users are stored as Json
                ValueType::Json(user_data) => {
                    if let Some(stored_password) = user_data.get("password").and_then(|v| v.as_str()) {
                        stored_password == password
                    } else {
                        false
                    }
                },
                // Any other format - not supported
                _ => false
            };
            
            if password_matches {
                // Generate token
                let token = Uuid::new_v4().to_string();
                
                // Store token
                let mut tokens = self.tokens.write().unwrap();
                tokens.insert(token.clone(), username.to_string());
                
                // Return success with token
                return Ok(ServiceResponse {
                    status: ResponseStatus::Success,
                    message: "Login successful".to_string(),
                    data: Some(vmap! {
                        "token" => token
                    }),
                });
            }
        }
        
        // Return error for invalid credentials
        Ok(ServiceResponse {
            status: ResponseStatus::Error,
            message: "Invalid username or password".to_string(),
            data: None,
        })
    }

    /// Logout a user by invalidating their token
    pub async fn logout(&self, token: &str) -> Result<ServiceResponse> {
        // Remove token from storage
        let mut tokens = self.tokens.write().unwrap();
        let removed = tokens.remove(token).is_some();
        
        if removed {
            Ok(ServiceResponse {
                status: ResponseStatus::Success,
                message: "Logout successful".to_string(),
                data: None,
            })
        } else {
            Ok(ServiceResponse {
                status: ResponseStatus::Error,
                message: "Invalid token".to_string(),
                data: None,
            })
        }
    }

    /// Validate a token and return the associated username
    pub async fn validate_token(&self, token: &str) -> Result<ServiceResponse> {
        // Look up token
        let tokens = self.tokens.read().unwrap();
        if let Some(username) = tokens.get(token) {
            // Token is valid
            return Ok(ServiceResponse {
                status: ResponseStatus::Success,
                message: "Token is valid".to_string(),
                data: Some(vmap! {
                    "username" => username.clone()
                }),
            });
        }
        
        // Token not found
        Ok(ServiceResponse {
            status: ResponseStatus::Error,
            message: "Invalid or expired token".to_string(),
            data: None,
        })
    }
}

#[async_trait]
impl AbstractService for AuthService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn state(&self) -> ServiceState {
        ServiceState::Running
    }

    fn description(&self) -> &str {
        "Authentication service for testing"
    }

    fn version(&self) -> &str {
        "1.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "login".to_string() },
            ActionMetadata { name: "validateToken".to_string() },
            ActionMetadata { name: "logout".to_string() }
        ]
    }

    async fn init(&mut self, _context: &RequestContext) -> Result<()> {
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Check if action is empty and extract it from path if needed
        let action = if request.action.is_empty() && request.path.contains("/") {
            request.path.split("/").last().unwrap_or("").to_string()
        } else {
            request.action.clone()
        };

        match action.as_str() {
            "login" => {
                if let Some(data) = &request.data {
                    // Extract username and password
                    let username = match data {
                        ValueType::Map(map) => {
                            if let Some(ValueType::String(username)) = map.get("username") {
                                username.clone()
                            } else {
                                String::new()
                            }
                        },
                        ValueType::Json(json) => {
                            json.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        },
                        _ => String::new()
                    };
                    
                    let password = match data {
                        ValueType::Map(map) => {
                            if let Some(ValueType::String(password)) = map.get("password") {
                                password.clone()
                            } else {
                                String::new()
                            }
                        },
                        ValueType::Json(json) => {
                            json.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        },
                        _ => String::new()
                    };
                    
                    if username.is_empty() || password.is_empty() {
                        return Ok(ServiceResponse {
                            status: ResponseStatus::Error,
                            message: "Missing username or password".to_string(),
                            data: None,
                        });
                    }
                    
                    return self.login(&username, &password).await;
                }
                
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: "Missing parameters".to_string(),
                    data: None,
                })
            },
            "logout" => {
                if let Some(data) = &request.data {
                    // Extract token
                    let token = match data {
                        ValueType::Map(map) => {
                            if let Some(ValueType::String(token)) = map.get("token") {
                                token.clone()
                            } else {
                                String::new()
                            }
                        },
                        ValueType::Json(json) => {
                            json.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        },
                        ValueType::String(token_str) => token_str.clone(),
                        _ => String::new()
                    };
                    
                    if token.is_empty() {
                        return Ok(ServiceResponse {
                            status: ResponseStatus::Error,
                            message: "Missing token".to_string(),
                            data: None,
                        });
                    }
                    
                    return self.logout(&token).await;
                }
                
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: "Missing parameters".to_string(),
                    data: None,
                })
            },
            "validateToken" => {
                if let Some(data) = &request.data {
                    // Extract token
                    let token = match data {
                        ValueType::Map(map) => {
                            if let Some(ValueType::String(token)) = map.get("token") {
                                token.clone()
                            } else {
                                String::new()
                            }
                        },
                        ValueType::Json(json) => {
                            json.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        },
                        ValueType::String(token_str) => token_str.clone(),
                        _ => String::new()
                    };
                    
                    if token.is_empty() {
                        return Ok(ServiceResponse {
                            status: ResponseStatus::Error,
                            message: "Missing token".to_string(),
                            data: None,
                        });
                    }
                    
                    return self.validate_token(&token).await;
                }
                
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: "Missing parameters".to_string(),
                    data: None,
                })
            },
            _ => {
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: format!("Unknown action: {}", action),
                    data: None,
                })
            }
        }
    }
}
