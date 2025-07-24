use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::User;

// Define the User service
#[service(
    name = "User Service",
    path = "users",
    description = "Manages user accounts",
    version = "0.1.0"
)]
pub struct UserService;

#[service_impl]
impl UserService {
    #[action]
    pub async fn create_user(
        &self,
        username: String,
        email: String,
        password_hash: String,
        _ctx: &RequestContext,
    ) -> Result<User> {
        // Placeholder implementation
        println!("UserService: Called create_user with username: {username}, email: {email}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(User {
            id: format!("user_{now}"), // Generate ID based on timestamp
            username,
            email,
            password_hash,
            created_at: now,
        })
    }
}
