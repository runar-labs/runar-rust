use runar_serializer::Encrypt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default, Encrypt)]
pub struct User {
    pub id: String,

    #[runar(user, system, search)]
    pub username: String,

    #[runar(user, system, search)]
    pub email: String,

    #[runar(user)]
    pub password_hash: String,

    #[runar(user, system, search)]
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default, Encrypt)]
pub struct Profile {
    pub id: String,

    #[runar(user, system, search)]
    pub user_id: String,

    #[runar(user, system, search)]
    pub full_name: String,

    #[runar(user, system, search)]
    pub bio: String, // Changed from Option<String> to String

    #[runar(user)]
    pub private_notes: String,

    #[runar(user, system, search)]
    pub last_updated: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default, Encrypt)]
pub struct Account {
    pub id: String,

    #[runar(user, system, search)]
    pub name: String,

    #[runar(user)]
    pub balance_cents: u64, // Changed from f64 to u64 (balance in cents)

    #[runar(user, system, search)]
    pub account_type: String,

    #[runar(user, system, search)]
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default, Encrypt)]
pub struct Order {
    pub id: String,

    #[runar(user, system, search)]
    pub user_id: String,

    #[runar(user, system, search)]
    pub product_id: String,

    #[runar(user, system, search)]
    pub quantity: u32,

    #[runar(user)]
    pub total_price_cents: u64, // Changed from f64 to u64 (price in cents)

    #[runar(user, system, search)]
    pub status: String,

    #[runar(user, system, search)]
    pub created_at: u64,
}
