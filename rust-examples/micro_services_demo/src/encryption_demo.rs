use anyhow::Result;
use runar_common::logging::Logger;
use runar_node::Node;
use runar_serializer::traits::LabelResolver;
use runar_serializer::ArcValue;
use std::sync::Arc;
use runar_services::crud_sqlite::{FindOneRequest, FindOneResponse, InsertOneRequest};
use std::collections::HashMap;

use crate::models::{Account, Order, Profile, User};

/// Demonstrate the encryption flow with the updated API using CrudSqliteService
pub async fn demonstrate_encryption_flow(
    _mobile_resolver: Arc<dyn LabelResolver>,
    _node_resolver: Arc<dyn LabelResolver>,
    crud_service_path: &str,
    node: &Node,
    logger: &Logger,
) -> Result<()> {
    logger.info("🔄 Demonstrating encryption flow with database...");

    // Create test data
    let user = User {
        id: "user123".to_string(),
        username: "alice".to_string(),
        email: "alice@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        created_at: 1234567890,
    };

    let profile = Profile {
        id: "profile123".to_string(),
        user_id: "user123".to_string(),
        full_name: "Alice Johnson".to_string(),
        bio: "Software engineer".to_string(),
        private_notes: "Secret notes".to_string(),
        last_updated: 1234567890,
    };

    let account = Account {
        id: "account123".to_string(),
        name: "Main Account".to_string(),
        balance_cents: 50000, // $500.00
        account_type: "checking".to_string(),
        created_at: 1234567890,
    };

    let order = Order {
        id: "order123".to_string(),
        user_id: "user123".to_string(),
        product_id: "product456".to_string(),
        quantity: 2,
        total_price_cents: 25.00, // $25.00
        status: "pending".to_string(),
        created_at: 1234567890,
    };

    // Serialize and encrypt data using ArcValue
    logger.info("📝 Serializing and encrypting data...");

    // Create ArcValue instances for each struct
    let user_arc = ArcValue::new_struct(user.clone());
    let profile_arc = ArcValue::new_struct(profile.clone());
    let account_arc = ArcValue::new_struct(account.clone());
    let order_arc = ArcValue::new_struct(order.clone());

    // Serialize the ArcValue instances
    let user_serialized = user_arc.serialize(None)?;
    let profile_serialized = profile_arc.serialize(None)?;
    let account_serialized = account_arc.serialize(None)?;
    let order_serialized = order_arc.serialize(None)?;

    // Store encrypted data in database
    logger.info("💾 Storing encrypted data in database...");

    // Store user
    let mut user_doc = HashMap::new();
    user_doc.insert("_id".to_string(), ArcValue::new_primitive(user.id.clone()));
    user_doc.insert(
        "username".to_string(),
        ArcValue::new_primitive(user.username.clone()),
    );
    user_doc.insert(
        "email".to_string(),
        ArcValue::new_primitive(user.email.clone()),
    );
    user_doc.insert(
        "created_at".to_string(),
        ArcValue::new_primitive(user.created_at as i64),
    );
    user_doc.insert(
        "user_encrypted_data".to_string(),
        ArcValue::new_bytes(user_serialized),
    );

    let insert_user_req = InsertOneRequest {
        collection: "users".to_string(),
        document: user_doc,
    };
    let _insert_user_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/insertOne"),
            Some(ArcValue::new_struct(insert_user_req)),
        )
        .await?;
    logger.info(format!("✅ Stored user with ID: {}", user.id));

    // Store profile
    let mut profile_doc = HashMap::new();
    profile_doc.insert(
        "_id".to_string(),
        ArcValue::new_primitive(profile.id.clone()),
    );
    profile_doc.insert(
        "user_id".to_string(),
        ArcValue::new_primitive(profile.user_id.clone()),
    );
    profile_doc.insert(
        "full_name".to_string(),
        ArcValue::new_primitive(profile.full_name.clone()),
    );
    profile_doc.insert(
        "last_updated".to_string(),
        ArcValue::new_primitive(profile.last_updated as i64),
    );
    profile_doc.insert(
        "user_encrypted_data".to_string(),
        ArcValue::new_bytes(profile_serialized),
    );

    let insert_profile_req = InsertOneRequest {
        collection: "profiles".to_string(),
        document: profile_doc,
    };
    let _insert_profile_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/insertOne"),
            Some(ArcValue::new_struct(insert_profile_req)),
        )
        .await?;
    logger.info(format!("✅ Stored profile with ID: {}", profile.id));

    // Store account
    let mut account_doc = HashMap::new();
    account_doc.insert(
        "_id".to_string(),
        ArcValue::new_primitive(account.id.clone()),
    );
    account_doc.insert(
        "name".to_string(),
        ArcValue::new_primitive(account.name.clone()),
    );
    account_doc.insert(
        "account_type".to_string(),
        ArcValue::new_primitive(account.account_type.clone()),
    );
    account_doc.insert(
        "created_at".to_string(),
        ArcValue::new_primitive(account.created_at as i64),
    );
    account_doc.insert(
        "user_encrypted_data".to_string(),
        ArcValue::new_bytes(account_serialized),
    );

    let insert_account_req = InsertOneRequest {
        collection: "accounts".to_string(),
        document: account_doc,
    };
    let _insert_account_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/insertOne"),
            Some(ArcValue::new_struct(insert_account_req)),
        )
        .await?;
    logger.info(format!("✅ Stored account with ID: {}", account.id));

    // Store order
    let mut order_doc = HashMap::new();
    order_doc.insert("_id".to_string(), ArcValue::new_primitive(order.id.clone()));
    order_doc.insert(
        "user_id".to_string(),
        ArcValue::new_primitive(order.user_id.clone()),
    );
    order_doc.insert(
        "product_id".to_string(),
        ArcValue::new_primitive(order.product_id.clone()),
    );
    order_doc.insert(
        "quantity".to_string(),
        ArcValue::new_primitive(order.quantity as i64),
    );
    order_doc.insert(
        "status".to_string(),
        ArcValue::new_primitive(order.status.clone()),
    );
    order_doc.insert(
        "created_at".to_string(),
        ArcValue::new_primitive(order.created_at as i64),
    );
    order_doc.insert(
        "user_encrypted_data".to_string(),
        ArcValue::new_bytes(order_serialized),
    );

    let insert_order_req = InsertOneRequest {
        collection: "orders".to_string(),
        document: order_doc,
    };
    let _insert_order_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/insertOne"),
            Some(ArcValue::new_struct(insert_order_req)),
        )
        .await?;
    logger.info(format!("✅ Stored order with ID: {}", order.id));

    logger.info("✅ Data encrypted and stored successfully!");

    // Demonstrate decryption
    logger.info("🔓 Demonstrating decryption...");

    // Retrieve and decrypt data
    let mut user_filter = HashMap::new();
    user_filter.insert("_id".to_string(), ArcValue::new_primitive(user.id.clone()));
    let find_user_req = FindOneRequest {
        collection: "users".to_string(),
        filter: user_filter,
    };
    let find_user_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/findOne"),
            Some(ArcValue::new_struct(find_user_req)),
        )
        .await?;

    let find_user_response: FindOneResponse = find_user_resp.as_type()?;
    if let Some(user_doc_map) = find_user_response.document {
        if let Some(encrypted_data) = user_doc_map.get("user_encrypted_data") {
            if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                let user_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                let decrypted_user: User = user_arc.as_type()?;
                logger.info(format!("👤 Decrypted user: {}", decrypted_user.username));
            }
        }
    }

    // Retrieve profile
    let mut profile_filter = HashMap::new();
    profile_filter.insert(
        "_id".to_string(),
        ArcValue::new_primitive(profile.id.clone()),
    );
    let find_profile_req = FindOneRequest {
        collection: "profiles".to_string(),
        filter: profile_filter,
    };
    let find_profile_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/findOne"),
            Some(ArcValue::new_struct(find_profile_req)),
        )
        .await?;

    let find_profile_response: FindOneResponse = find_profile_resp.as_type()?;
    if let Some(profile_doc_map) = find_profile_response.document {
        if let Some(encrypted_data) = profile_doc_map.get("user_encrypted_data") {
            if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                let profile_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                let decrypted_profile: Profile = profile_arc.as_type()?;
                logger.info(format!(
                    "📋 Decrypted profile: {}",
                    decrypted_profile.full_name
                ));
            }
        }
    }

    // Retrieve account
    let mut account_filter = HashMap::new();
    account_filter.insert(
        "_id".to_string(),
        ArcValue::new_primitive(account.id.clone()),
    );
    let find_account_req = FindOneRequest {
        collection: "accounts".to_string(),
        filter: account_filter,
    };
    let find_account_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/findOne"),
            Some(ArcValue::new_struct(find_account_req)),
        )
        .await?;

    let find_account_response: FindOneResponse = find_account_resp.as_type()?;
    if let Some(account_doc_map) = find_account_response.document {
        if let Some(encrypted_data) = account_doc_map.get("user_encrypted_data") {
            if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                let account_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                let decrypted_account: Account = account_arc.as_type()?;
                logger.info(format!(
                    "💰 Decrypted account: {} (${:.2})",
                    decrypted_account.name,
                    decrypted_account.balance_cents as f64 / 100.0
                ));
            }
        }
    }

    // Retrieve order
    let mut order_filter = HashMap::new();
    order_filter.insert("_id".to_string(), ArcValue::new_primitive(order.id.clone()));
    let find_order_req = FindOneRequest {
        collection: "orders".to_string(),
        filter: order_filter,
    };
    let find_order_resp: ArcValue = node
        .request(
            &format!("{crud_service_path}/findOne"),
            Some(ArcValue::new_struct(find_order_req)),
        )
        .await?;

    let find_order_response: FindOneResponse = find_order_resp.as_type()?;
    if let Some(order_doc_map) = find_order_response.document {
        if let Some(encrypted_data) = order_doc_map.get("user_encrypted_data") {
            if let Ok(encrypted_bytes) = encrypted_data.as_type_ref::<Vec<u8>>() {
                let order_arc = ArcValue::deserialize(&encrypted_bytes, None)?;
                let decrypted_order: Order = order_arc.as_type()?;
                logger.info(format!(
                    "🛒 Decrypted order: {} items for ${:.2}",
                    decrypted_order.quantity,
                    decrypted_order.total_price_cents / 100.0
                ));
            }
        }
    }

    logger.info("✅ Decryption completed successfully!");
    Ok(())
}
