use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::User;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {}", e))
}

// Define the User service
#[service(
    name = "User Service",
    path = "users",
    description = "Manages user accounts",
    version = "0.1.0"
)]
pub struct UserService;

#[service]
impl UserService {
    #[action]
    pub async fn create_user(
        &self,
        username: String,
        email: String,
        password_hash: String,
        ctx: &RequestContext,
    ) -> Result<User> {
        // Placeholder implementation
        ctx.info(format!(
            "Called create_user with username: {username}, email: {email}"
        ));

        let now = get_current_timestamp()?;

        Ok(User {
            id: format!("user_{now}"), // Generate ID based on timestamp
            username,
            email,
            password_hash,
            created_at: now,
        })
    }
}
