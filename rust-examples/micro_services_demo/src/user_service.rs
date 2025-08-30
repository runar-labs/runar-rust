use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use runar_serializer::ArcValue;
use runar_services::crud_sqlite::{FindOneRequest, FindOneResponse, InsertOneRequest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::User;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {e}"))
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
        ctx.info(format!(
            "Called create_user with username: {username}, email: {email}"
        ));

        let now = get_current_timestamp()?;
        let user_id = format!("user_{now}");

        // Create the full user object
        let user = User {
            id: user_id.clone(),
            username: username.clone(),
            email: email.clone(),
            password_hash: password_hash.clone(),
            created_at: now,
        };

        // Serialize the full user object for encrypted storage
        let user_arc = ArcValue::new_struct(user.clone());
        let user_serialized = user_arc.serialize(None)?;

        // Create database document with system fields and encrypted blob
        let mut user_doc = HashMap::new();
        user_doc.insert("_id".to_string(), ArcValue::new_primitive(user_id.clone()));
        user_doc.insert("username".to_string(), ArcValue::new_primitive(username));
        user_doc.insert("email".to_string(), ArcValue::new_primitive(email));
        user_doc.insert(
            "created_at".to_string(),
            ArcValue::new_primitive(now as i64),
        );
        user_doc.insert(
            "user_encrypted_data".to_string(),
            ArcValue::new_bytes(user_serialized),
        );

        // Store in database
        let insert_req = InsertOneRequest {
            collection: "users".to_string(),
            document: user_doc,
        };

        let _insert_resp: ArcValue = ctx
            .request(
                "crud_db/insertOne",
                Some(ArcValue::new_struct(insert_req)),
                None,
            )
            .await?;

        ctx.info(format!(
            "✅ User created and stored in database with ID: {user_id}"
        ));
        Ok(user)
    }

    #[action]
    pub async fn get_user(&self, user_id: String, ctx: &RequestContext) -> Result<User> {
        ctx.info(format!("Called get_user for user_id: {user_id}"));

        // Query database
        let mut filter = HashMap::new();
        filter.insert("_id".to_string(), ArcValue::new_primitive(user_id.clone()));
        let find_req = FindOneRequest {
            collection: "users".to_string(),
            filter,
        };

        let find_resp: ArcValue = ctx
            .request(
                "crud_db/findOne",
                Some(ArcValue::new_struct(find_req)),
                None,
            )
            .await?;

        // Extract the document from response
        let find_response: FindOneResponse = find_resp.as_type()?;
        if let Some(doc_map) = find_response.document {
            // Get encrypted data and decrypt
            if let Some(encrypted_data) = doc_map.get("user_encrypted_data") {
                if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                    let user_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                    let user: User = user_arc.as_type()?;
                    ctx.info(format!("✅ Retrieved user: {}", user.username));
                    return Ok(user);
                }
            }
        }

        Err(anyhow!("User not found: {user_id}"))
    }
}
