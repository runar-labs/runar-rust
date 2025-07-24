use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Profile;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {}", e))
}

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
        ctx: &RequestContext,
    ) -> Result<Profile> {
        // Placeholder implementation
        ctx.info(format!("Called create_profile for user_id: {user_id}"));

        let now = get_current_timestamp()?;

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
    pub async fn get_profile(&self, user_id: String, ctx: &RequestContext) -> Result<Profile> {
        // Placeholder implementation
        ctx.info(format!("Called get_profile for user_id: {user_id}"));

        let now = get_current_timestamp()?;

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
        ctx: &RequestContext,
    ) -> Result<Profile> {
        // Placeholder implementation
        ctx.info(format!("Called update_profile for user_id: {user_id}"));

        let now = get_current_timestamp()?;

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
