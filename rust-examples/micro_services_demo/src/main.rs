use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_macros_common::params;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;

use runar_serializer::ArcValue;
use runar_test_utils::create_test_environment;
use std::sync::Arc;

// Declare modules
mod account_service;
mod db_services;
mod encryption_demo;
mod models;
mod order_service;
mod profile_service;
mod user_service;

// Import services and models
use models::{Account, Order, Profile, User};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::System, "microservices-demo"));

    logger.info("🚀 Starting Runar Encryption Demo with Database");
    logger.info("================================================");

    // Setup encryption infrastructure using mobile simulator
    let (simulator, config) = create_test_environment()?;
    let (mobile_resolver, node_resolver) = simulator.create_label_resolvers()?;

    simulator.print_summary();
    logger.info("✅ Encryption infrastructure ready");

    // Create and run the microservices demo
    logger.info("🏗️  Setting up microservices with database...");

    // Use the config from the simulator
    let config = config.with_logging_config(logging_config);
    let mut node = Node::new(config).await?;

    // Setup database services
    let (sqlite_service, crud_service) = db_services::setup_database_services();
    node.add_service(sqlite_service).await?;
    node.add_service(crud_service).await?;

    // Create and register business services
    let user_service = user_service::UserService::default();
    let profile_service = profile_service::ProfileService::default();
    let account_service = account_service::AccountService::default();
    let order_service = order_service::OrderService::default();

    node.add_service(user_service).await?;
    node.add_service(profile_service).await?;
    node.add_service(account_service).await?;
    node.add_service(order_service).await?;

    // Start the node
    node.start().await?;
    logger.info("✅ Node started successfully");

    // Demonstrate encryption flow with database
    encryption_demo::demonstrate_encryption_flow(
        &mobile_resolver,
        &node_resolver,
        "crud_db",
        &node,
        &logger,
    )
    .await?;

    // Run some test operations
    logger.info("🧪 Running test operations...");

    // Test user creation
    let user_arc: ArcValue = node
        .request(
            "users/create_user",
            Some(params! {
                "username" => "testuser".to_string(),
                "email" => "test@example.com".to_string(),
                "password_hash" => "hashed_password".to_string()
            }),
        )
        .await?;
    let created_user: User = user_arc.as_type()?;
    logger.info(format!("✅ Created user: {}", created_user.username));

    // Test profile creation
    let profile_arc: ArcValue = node
        .request(
            "profiles/create_profile",
            Some(params! {
                "user_id" => created_user.id.clone(),
                "full_name" => "Test User".to_string(),
                "bio" => "Test bio".to_string(),
                "private_notes" => "Private notes".to_string()
            }),
        )
        .await?;
    let created_profile: Profile = profile_arc.as_type()?;
    logger.info(format!("✅ Created profile: {}", created_profile.full_name));

    // Test account creation
    let account_arc: ArcValue = node
        .request(
            "accounts/create_account",
            Some(params! {
                "name" => "Test Account".to_string(),
                "balance_cents" => 10000u64, // $100.00 in cents
                "account_type" => "checking".to_string()
            }),
        )
        .await?;
    let created_account: Account = account_arc.as_type()?;
    logger.info(format!(
        "✅ Created account: {} (${:.2})",
        created_account.name,
        created_account.balance_cents as f64 / 100.0
    ));

    // Test order creation
    let order_arc: ArcValue = node
        .request(
            "orders/create_order",
            Some(params! {
                "user_id" => created_user.id.clone(),
                "product_id" => "product123".to_string(),
                "quantity" => 1u32,
                "total_price_cents" => 1500u64, // $15.00 in cents
                "status" => "pending".to_string()
            }),
        )
        .await?;
    let created_order: Order = order_arc.as_type()?;
    logger.info(format!(
        "✅ Created order: {} items for ${:.2}",
        created_order.quantity,
        created_order.total_price_cents / 100.0
    ));

    node.stop().await?;

    logger.info("🎉 Microservices demo completed successfully!");
    logger.info("All operations completed with encryption support and database persistence.");

    Ok(())
}
