use anyhow::{anyhow, Result};
use runar_common::types::ArcValue;
use runar_macros::{action, service, service_meta};
use runar_node::services::RequestContext;

use crate::models::Order;

// Define the Order service
#[derive(Clone)]
#[service_meta(
    name = "Order Service",
    path = "orders",
    description = "Manages customer orders",
    version = "0.1.0"
)]
pub struct OrderService;

#[service]
impl OrderService {
    pub fn new() -> Self {
        Self
    }

    #[action(name = "create_order")]
    pub async fn create_order(
        &self,
        user_id: String,
        product_id: String,
        quantity: u32,
        _ctx: &RequestContext,
    ) -> Result<ArcValue> {
        // Placeholder implementation
        let _total_price = quantity as f64 * 10.0; // Dummy price calculation
        println!("OrderService: Called create_order for user_id: {user_id}, product_id: {product_id}, quantity: {quantity}");
        Ok(ArcValue::from_struct(Order {
            id: "order_789".to_string(), // Dummy ID
            user_id,
            product_id,
            quantity,
            total_price: quantity as f64 * 10.0, // Dummy price calculation
        }))
    }
}
