use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Account;

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
    #[action(name = "get_account_balance")]
    pub async fn get_account_balance(
        &self,
        account_id: String,
        _ctx: &RequestContext,
    ) -> Result<u64> {
        // Changed from f64 to u64
        // Placeholder implementation
        println!("AccountService: Called get_account_balance for account_id: {account_id}");
        Ok(1234500) // Return balance in cents (12345.00)
    }

    #[action(name = "create_account")]
    pub async fn create_account(
        &self,
        user_id: String,
        name: String,
        account_type: String,
        _ctx: &RequestContext,
    ) -> Result<Account> {
        // Placeholder implementation
        println!("AccountService: Called create_account for user_id: {user_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Account {
            id: format!("account_{}", now),
            name,
            balance_cents: 0, // Changed from 0.0
            account_type,
            created_at: now,
        })
    }

    #[action(name = "get_account")]
    pub async fn get_account(&self, account_id: String, _ctx: &RequestContext) -> Result<Account> {
        // Placeholder implementation
        println!("AccountService: Called get_account for account_id: {account_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Account {
            id: account_id,
            name: "Main Account".to_string(),
            balance_cents: 1234500, // Changed from 12345.0 (12345.00 in cents)
            account_type: "checking".to_string(),
            created_at: now,
        })
    }
}
