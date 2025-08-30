use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use runar_serializer::ArcValue;
use runar_services::crud_sqlite::{FindOneRequest, FindOneResponse, InsertOneRequest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Account;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {e}"))
}

// Define the Account service
#[service(
    name = "Account Service",
    path = "accounts",
    description = "Manages user accounts",
    version = "0.1.0"
)]
pub struct AccountService;

#[service]
impl AccountService {
    #[action]
    pub async fn create_account(
        &self,
        name: String,
        balance_cents: u64,
        account_type: String,
        ctx: &RequestContext,
    ) -> Result<Account> {
        ctx.info(format!(
            "Called create_account with name: {name}, balance: ${:.2}",
            balance_cents as f64 / 100.0
        ));

        let now = get_current_timestamp()?;
        let account_id = format!("account_{now}");

        // Create the full account object
        let account = Account {
            id: account_id.clone(),
            name: name.clone(),
            balance_cents,
            account_type: account_type.clone(),
            created_at: now,
        };

        // Serialize the full account object for encrypted storage
        let account_arc = ArcValue::new_struct(account.clone());
        let account_serialized = account_arc.serialize(None)?;

        // Create database document with system fields and encrypted blob
        let mut account_doc = HashMap::new();
        account_doc.insert(
            "_id".to_string(),
            ArcValue::new_primitive(account_id.clone()),
        );
        account_doc.insert("name".to_string(), ArcValue::new_primitive(name));
        account_doc.insert(
            "account_type".to_string(),
            ArcValue::new_primitive(account_type),
        );
        account_doc.insert(
            "created_at".to_string(),
            ArcValue::new_primitive(now as i64),
        );
        account_doc.insert(
            "user_encrypted_data".to_string(),
            ArcValue::new_bytes(account_serialized),
        );

        // Store in database
        let insert_req = InsertOneRequest {
            collection: "accounts".to_string(),
            document: account_doc,
        };

        let _insert_resp: ArcValue = ctx
            .request(
                "crud_db/insertOne",
                Some(ArcValue::new_struct(insert_req)),
                None,
            )
            .await?;

        ctx.info(format!(
            "✅ Account created and stored in database with ID: {account_id}"
        ));
        Ok(account)
    }

    #[action]
    pub async fn get_account(&self, account_id: String, ctx: &RequestContext) -> Result<Account> {
        ctx.info(format!("Called get_account for account_id: {account_id}"));

        // Query database
        let mut filter = HashMap::new();
        filter.insert(
            "_id".to_string(),
            ArcValue::new_primitive(account_id.clone()),
        );
        let find_req = FindOneRequest {
            collection: "accounts".to_string(),
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
                    let account_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                    let account: Account = account_arc.as_type()?;
                    ctx.info(format!("✅ Retrieved account: {}", account.name));
                    return Ok(account);
                }
            }
        }

        Err(anyhow!("Account not found: {account_id}"))
    }
}
