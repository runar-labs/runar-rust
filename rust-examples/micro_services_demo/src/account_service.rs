use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Account;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {}", e))
}

// Define the Account service
#[service(
    name = "Account Service",
    path = "accounts",
    description = "Manages user financial accounts",
    version = "0.1.0"
)]
pub struct AccountService;

#[service_impl]
impl AccountService {
    #[action]
    pub async fn create_account(
        &self,
        name: String,
        balance_cents: u64,
        account_type: String,
        ctx: &RequestContext,
    ) -> Result<Account> {
        // Placeholder implementation
        ctx.info(format!("Called create_account with name: {name}"));

        let now = get_current_timestamp()?;

        Ok(Account {
            id: format!("account_{now}"),
            name,
            balance_cents,
            account_type,
            created_at: now,
        })
    }

    #[action]
    pub async fn get_account_balance(
        &self,
        account_id: String,
        ctx: &RequestContext,
    ) -> Result<u64> {
        // Placeholder implementation
        ctx.info(format!(
            "Called get_account_balance for account_id: {account_id}"
        ));
        Ok(1234500) // Return balance in cents (12345.00)
    }

    #[action]
    pub async fn get_account(&self, account_id: String, ctx: &RequestContext) -> Result<Account> {
        // Placeholder implementation
        ctx.info(format!("Called get_account for account_id: {account_id}"));

        let now = get_current_timestamp()?;

        Ok(Account {
            id: account_id,
            name: "Main Account".to_string(),
            balance_cents: 1234500, // 12345.00 in cents
            account_type: "checking".to_string(),
            created_at: now,
        })
    }
}
