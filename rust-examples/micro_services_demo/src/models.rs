use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, prost::Message)]
#[prost(message)]
pub struct User {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub username: String,
    #[prost(string, tag = "3")]
    pub email: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, prost::Message)]
#[prost(message)]
pub struct Profile {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(string, tag = "3")]
    pub full_name: String,
    #[prost(string, optional, tag = "4")]
    pub bio: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, prost::Message)]
#[prost(message)]
pub struct Account {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(double, tag = "3")]
    pub balance: f64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, prost::Message)]
#[prost(message)]
pub struct Order {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(string, tag = "3")]
    pub product_id: String,
    #[prost(uint32, tag = "4")]
    pub quantity: u32,
    #[prost(double, tag = "5")]
    pub total_price: f64,
}
