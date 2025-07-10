use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;

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
    #[action(name = "create_user")]
    pub async fn create_user(
        &self,
        username: String,
        email: String,
        _ctx: &RequestContext,
    ) -> Result<User> {
        // Placeholder implementation
        println!("UserService: Called create_user with username: {username}, email: {email}");
        Ok(User {
            id: "user_123".to_string(), // Dummy ID
            username,
            email,
        })
    }
}
