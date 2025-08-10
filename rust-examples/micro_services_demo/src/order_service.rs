use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use runar_serializer::ArcValue;
use runar_services::crud_sqlite::{FindOneRequest, FindOneResponse, InsertOneRequest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Order;

// Helper function to safely get current timestamp
fn get_current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow!("System clock error: {e}"))
}

// Define the Order service
#[service(
    name = "Order Service",
    path = "orders",
    description = "Manages user orders",
    version = "0.1.0"
)]
pub struct OrderService;

#[service]
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
        ctx.info(format!(
            "Called create_order for user_id: {user_id}, product_id: {product_id}, quantity: {quantity}, total: ${:.2}",
            total_price_cents as f64 / 100.0
        ));

        let now = get_current_timestamp()?;
        let order_id = format!("order_{now}");

        // Create the full order object
        let order = Order {
            id: order_id.clone(),
            user_id: user_id.clone(),
            product_id: product_id.clone(),
            quantity,
            total_price_cents: total_price_cents as f64,
            status: status.clone(),
            created_at: now,
        };

        // Serialize the full order object for encrypted storage
        let order_arc = ArcValue::new_struct(order.clone());
        let order_serialized = order_arc.serialize(None)?;

        // Create database document with system fields and encrypted blob
        let mut order_doc = HashMap::new();
        order_doc.insert("_id".to_string(), ArcValue::new_primitive(order_id.clone()));
        order_doc.insert("user_id".to_string(), ArcValue::new_primitive(user_id));
        order_doc.insert(
            "product_id".to_string(),
            ArcValue::new_primitive(product_id),
        );
        order_doc.insert(
            "quantity".to_string(),
            ArcValue::new_primitive(quantity as i64),
        );
        order_doc.insert("status".to_string(), ArcValue::new_primitive(status));
        order_doc.insert(
            "created_at".to_string(),
            ArcValue::new_primitive(now as i64),
        );
        order_doc.insert(
            "user_encrypted_data".to_string(),
            ArcValue::new_bytes(order_serialized),
        );

        // Store in database
        let insert_req = InsertOneRequest {
            collection: "orders".to_string(),
            document: order_doc,
        };

        let _insert_resp: ArcValue = ctx
            .request("crud_db/insertOne", Some(ArcValue::new_struct(insert_req)))
            .await?;

        ctx.info(format!(
            "✅ Order created and stored in database with ID: {order_id}"
        ));
        Ok(order)
    }

    #[action]
    pub async fn get_order(&self, order_id: String, ctx: &RequestContext) -> Result<Order> {
        ctx.info(format!("Called get_order for order_id: {order_id}"));

        // Query database
        let mut filter = HashMap::new();
        filter.insert("_id".to_string(), ArcValue::new_primitive(order_id.clone()));
        let find_req = FindOneRequest {
            collection: "orders".to_string(),
            filter,
        };

        let find_resp: ArcValue = ctx
            .request("crud_db/findOne", Some(ArcValue::new_struct(find_req)))
            .await?;

        // Extract the document from response
        let find_response: FindOneResponse = find_resp.as_type()?;
        if let Some(doc_map) = find_response.document {
            // Get encrypted data and decrypt
            if let Some(encrypted_data) = doc_map.get("user_encrypted_data") {
                if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                    let order_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                    let order: Order = order_arc.as_type()?;
                    ctx.info(format!("✅ Retrieved order: {}", order.id));
                    return Ok(order);
                }
            }
        }

        Err(anyhow!("Order not found: {order_id}"))
    }
}
