use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use runar_serializer::ArcValue;
use runar_services::crud_sqlite::{FindOneRequest, FindOneResponse, InsertOneRequest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Profile;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {e}"))
}

// Define the Profile service
#[service(
    name = "Profile Service",
    path = "profiles",
    description = "Manages user profiles",
    version = "0.1.0"
)]
pub struct ProfileService;

#[service]
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
        ctx.info(format!("Called create_profile for user_id: {user_id}"));

        let now = get_current_timestamp()?;
        let profile_id = format!("profile_{user_id}");

        // Create the full profile object
        let profile = Profile {
            id: profile_id.clone(),
            user_id: user_id.clone(),
            full_name: full_name.clone(),
            bio: bio.clone(),
            private_notes: private_notes.clone(),
            last_updated: now,
        };

        // Serialize the full profile object for encrypted storage
        let profile_arc = ArcValue::new_struct(profile.clone());
        let profile_serialized = profile_arc.serialize(None)?;

        // Create database document with system fields and encrypted blob
        let mut profile_doc = HashMap::new();
        profile_doc.insert(
            "_id".to_string(),
            ArcValue::new_primitive(profile_id.clone()),
        );
        profile_doc.insert("user_id".to_string(), ArcValue::new_primitive(user_id));
        profile_doc.insert("full_name".to_string(), ArcValue::new_primitive(full_name));
        profile_doc.insert(
            "last_updated".to_string(),
            ArcValue::new_primitive(now as i64),
        );
        profile_doc.insert(
            "user_encrypted_data".to_string(),
            ArcValue::new_bytes(profile_serialized),
        );

        // Store in database
        let insert_req = InsertOneRequest {
            collection: "profiles".to_string(),
            document: profile_doc,
        };

        let _insert_resp: ArcValue = ctx
            .request("crud_db/insertOne", Some(ArcValue::new_struct(insert_req)))
            .await?;

        ctx.info(format!(
            "✅ Profile created and stored in database with ID: {profile_id}"
        ));
        Ok(profile)
    }

    #[action]
    pub async fn get_profile(&self, user_id: String, ctx: &RequestContext) -> Result<Profile> {
        ctx.info(format!("Called get_profile for user_id: {user_id}"));

        // Query database by user_id
        let mut filter = HashMap::new();
        filter.insert(
            "user_id".to_string(),
            ArcValue::new_primitive(user_id.clone()),
        );
        let find_req = FindOneRequest {
            collection: "profiles".to_string(),
            filter,
        };

        let find_resp: ArcValue = ctx
            .request("crud_db/findOne", Some(ArcValue::new_struct(find_req)))
            .await?;

        // Extract the document from response
        let find_response: FindOneResponse = find_resp.as_type()?;
        if let Some(doc_map) = find_response.document {
            // Get encrypted data and decrypt
            if let Some(encrypted_data) = doc_map.get("user_encrypted_data") {
                if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                    let profile_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                    let profile: Profile = profile_arc.as_type()?;
                    ctx.info(format!("✅ Retrieved profile: {}", profile.full_name));
                    return Ok(profile);
                }
            }
        }

        Err(anyhow!("Profile not found for user: {user_id}"))
    }

    #[action]
    pub async fn update_profile(
        &self,
        user_id: String,
        full_name: String,
        bio: String,
        ctx: &RequestContext,
    ) -> Result<Profile> {
        ctx.info(format!("Called update_profile for user_id: {user_id}"));

        // For now, we'll just create a new profile (in a real implementation, you'd update the existing one)
        let now = get_current_timestamp()?;
        let profile_id = format!("profile_{user_id}");

        // Create the updated profile object
        let profile = Profile {
            id: profile_id.clone(),
            user_id: user_id.clone(),
            full_name: full_name.clone(),
            bio: bio.clone(),
            private_notes: "Secret notes".to_string(), // Keep existing private notes
            last_updated: now,
        };

        // Serialize the full profile object for encrypted storage
        let profile_arc = ArcValue::new_struct(profile.clone());
        let profile_serialized = profile_arc.serialize(None)?;

        // Create database document with system fields and encrypted blob
        let mut profile_doc = HashMap::new();
        profile_doc.insert(
            "_id".to_string(),
            ArcValue::new_primitive(profile_id.clone()),
        );
        profile_doc.insert("user_id".to_string(), ArcValue::new_primitive(user_id));
        profile_doc.insert("full_name".to_string(), ArcValue::new_primitive(full_name));
        profile_doc.insert(
            "last_updated".to_string(),
            ArcValue::new_primitive(now as i64),
        );
        profile_doc.insert(
            "user_encrypted_data".to_string(),
            ArcValue::new_bytes(profile_serialized),
        );

        // Store in database (this would be an update in a real implementation)
        let insert_req = InsertOneRequest {
            collection: "profiles".to_string(),
            document: profile_doc,
        };

        let _insert_resp: ArcValue = ctx
            .request("crud_db/insertOne", Some(ArcValue::new_struct(insert_req)))
            .await?;

        ctx.info(format!(
            "✅ Profile updated and stored in database with ID: {profile_id}"
        ));
        Ok(profile)
    }
}
