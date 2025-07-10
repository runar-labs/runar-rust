use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;

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
    ) -> Result<f64> {
        // Placeholder implementation
        println!("AccountService: Called get_account_balance for account_id: {account_id}");
        Ok(1234.56f64) // Dummy balance
    }

    // Example of another action, e.g., to create an account
    #[action(name = "create_account")]
    pub async fn create_account(
        &self,
        name: String,
        initial_balance: f64,
        _ctx: &RequestContext,
    ) -> Result<Account> {
        println!(
            "AccountService: Creating account with name: {name} and balance: {initial_balance}"
        );
        Ok(Account {
            id: "acc_789".to_string(), // Dummy ID
            name,
            balance: initial_balance,
        })
    }
}
