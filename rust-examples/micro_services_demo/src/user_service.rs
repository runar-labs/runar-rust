use anyhow::{anyhow, Result};
use runar_common::types::ArcValue;
use runar_macros::{action, service};
use runar_node::services::RequestContext;

use crate::models::User;

// Define the User service
#[derive(Clone)]
pub struct UserService;

#[service(
    name = "User Service",
    path = "users",
    description = "Manages user accounts",
    version = "0.1.0"
)]
impl UserService {
    pub fn new() -> Self {
        Self
    }

    #[action(name = "create_user")]
    pub async fn create_user(
        &self,
        username: String,
        email: String,
        _ctx: &RequestContext,
    ) -> Result<ArcValue> {
        // Placeholder implementation
        println!("UserService: Called create_user with username: {username}, email: {email}");
        Ok(ArcValue::from_struct(User {
            id: "user_123".to_string(), // Dummy ID
            username,
            email,
        }))
    }
}
