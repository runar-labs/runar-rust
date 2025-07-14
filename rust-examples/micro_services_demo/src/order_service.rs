use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Order;

// Define the Order service
#[service(
    name = "Order Service",
    path = "orders",
    description = "Manages customer orders",
    version = "0.1.0"
)]
pub struct OrderService;

#[service_impl]
impl OrderService {
    #[action(name = "create_order")]
    pub async fn create_order(
        &self,
        user_id: String,
        product_id: String,
        quantity: u32,
        unit_price_cents: u64, // Changed from f64 to u64
        _ctx: &RequestContext,
    ) -> Result<Order> {
        // Placeholder implementation
        let total_price_cents = quantity as u64 * unit_price_cents; // Changed from f64 calculation
        println!("OrderService: Called create_order for user_id: {user_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Order {
            id: format!("order_{}", now),
            user_id,
            product_id,
            quantity,
            total_price_cents, // Changed from total_price
            status: "pending".to_string(),
            created_at: now,
        })
    }

    #[action(name = "get_order")]
    pub async fn get_order(&self, order_id: String, _ctx: &RequestContext) -> Result<Order> {
        // Placeholder implementation
        println!("OrderService: Called get_order for order_id: {order_id}");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Order {
            id: order_id,
            user_id: "user123".to_string(),
            product_id: "prod456".to_string(),
            quantity: 2,
            total_price_cents: 2998, // Changed from 29.98 (2998 cents)
            status: "completed".to_string(),
            created_at: now,
        })
    }
}
