use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Profile;

// Define the Profile service
#[service(
    name = "Profile Service",
    path = "profiles",
    description = "Manages user profiles",
    version = "0.1.0"
)]
pub struct ProfileService;

#[service_impl]
impl ProfileService {
    #[action]
    pub async fn create_profile(
        &self,
        user_id: String,
        full_name: String,
        bio: String,
        private_notes: String,
        _ctx: &RequestContext,
    ) -> Result<Profile> {
        // Placeholder implementation
        println!("ProfileService: Called create_profile for user_id: {user_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Profile {
            id: format!("profile_{user_id}"),
            user_id,
            full_name,
            bio,
            private_notes,
            last_updated: now,
        })
    }

    #[action]
    pub async fn get_profile(&self, user_id: String, _ctx: &RequestContext) -> Result<Profile> {
        // Placeholder implementation
        println!("ProfileService: Called get_profile for user_id: {user_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Profile {
            id: format!("profile_{user_id}"),
            user_id,
            full_name: "John Doe".to_string(),
            bio: "Software developer".to_string(),
            private_notes: "Secret notes".to_string(),
            last_updated: now,
        })
    }

    #[action]
    pub async fn update_profile(
        &self,
        user_id: String,
        full_name: String,
        bio: String,
        _ctx: &RequestContext,
    ) -> Result<Profile> {
        // Placeholder implementation
        println!("ProfileService: Called update_profile for user_id: {user_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Profile {
            id: format!("profile_{user_id}"),
            user_id,
            full_name,
            bio,
            private_notes: "Secret notes".to_string(),
            last_updated: now,
        })
    }
}
