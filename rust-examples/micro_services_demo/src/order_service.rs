use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Order;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {}", e))
}

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
    #[action]
    pub async fn create_order(
        &self,
        user_id: String,
        product_id: String,
        quantity: u32,
        total_price_cents: u64,
        status: String,
        ctx: &RequestContext,
    ) -> Result<Order> {
        // Placeholder implementation
        ctx.info(format!("Called create_order for user_id: {user_id}"));

        let now = get_current_timestamp()?;

        Ok(Order {
            id: format!("order_{now}"),
            user_id,
            product_id,
            quantity,
            total_price_cents,
            status,
            created_at: now,
        })
    }

    #[action]
    pub async fn get_order(&self, order_id: String, ctx: &RequestContext) -> Result<Order> {
        // Placeholder implementation
        ctx.info(format!("Called get_order for order_id: {order_id}"));

        let now = get_current_timestamp()?;

        Ok(Order {
            id: order_id,
            user_id: "user123".to_string(),
            product_id: "prod456".to_string(),
            quantity: 2,
            total_price_cents: 2998, // 29.98 in cents
            status: "completed".to_string(),
            created_at: now,
        })
    }
}
