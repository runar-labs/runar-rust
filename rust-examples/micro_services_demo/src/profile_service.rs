use anyhow::{anyhow, Result};
use runar_common::types::ArcValue;
use runar_macros::{action, service};
use runar_node::services::RequestContext;

use crate::models::Profile;

// Define the Profile service
#[derive(Clone)]
pub struct ProfileService;

#[service(
    name = "Profile Service",
    path = "profiles",
    description = "Manages user profiles",
    version = "0.1.0"
)]
impl ProfileService {
    pub fn new() -> Self {
        Self
    }

    #[action(name = "get_profile")]
    pub async fn get_profile(&self, user_id: String, _ctx: &RequestContext) -> Result<ArcValue> {
        // Placeholder implementation
        println!("ProfileService: Called get_profile for user_id: {user_id}");
        Ok(ArcValue::from_struct(Profile {
            id: "profile_456".to_string(), // Dummy ID
            user_id,
            full_name: "Placeholder User".to_string(),
            bio: Some("This is a test bio".to_string()),
        }))
    }
}
