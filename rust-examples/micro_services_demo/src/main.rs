use anyhow::Result;
use runar_common::types::ArcValue;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::network::network_config::NetworkConfig;
use runar_node::network::transport::quic_transport::QuicTransportOptions; // Added for QuicTransportOptions
                                                                          // TransportOptions was unused, removed.
use runar_node::{Node, NodeConfig};
use std::collections::HashMap;
// Arc was unused, removed.
use std::time::Duration;
use tokio::time;

// Declare modules
mod account_service;
mod models;
mod order_service;
mod profile_service;
mod user_service;

// Import services and models
use account_service::AccountService;
use models::{Order, Profile, User};
use order_service::OrderService;
use profile_service::ProfileService;
use user_service::UserService;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting micro-services demo application...");

    // Configure and create a Node
    let logging_config = LoggingConfig {
        default_level: LogLevel::Debug,
        component_levels: HashMap::new(), // Initialize explicitly
    };

    // Configure NetworkConfig using its constructor and builder methods
    let quic_options = QuicTransportOptions::new().with_test_certificates();
    let mut network_config = NetworkConfig::new();
    network_config.quic_options = Some(quic_options);
    // Override default transport options if necessary (NetworkConfig::new() sets defaults)
    // The bind_address is handled by TransportOptions::default() called within NetworkConfig::new()
    network_config.transport_options.timeout = Some(Duration::from_secs(30));

    let node_config = NodeConfig {
        node_id: "micro_services_demo_node".to_string(),
        default_network_id: "default_network".to_string(),
        network_ids: vec!["default_network".to_string()],
        network_config: Some(network_config),
        logging_config: Some(logging_config),
        request_timeout_ms: 30000, // Default or example value
    };

    let mut node = Node::new(node_config).await?;
    println!("Node created successfully.");

    // Instantiate services
    let user_service = UserService::new();
    let profile_service = ProfileService::new();
    let account_service = AccountService::new();
    let order_service = OrderService::new();

    println!("Services instantiated.");

    // Register services with the Node
    // The service macro should handle path registration based on the `path` attribute.
    node.add_service(user_service).await?;
    node.add_service(profile_service).await?;
    node.add_service(account_service).await?;
    node.add_service(order_service).await?;
    println!("Services registered with the Node.");

    // --- Example Service Calls ---
    println!("\n--- Making example service calls ---");

    // 1. Call UserService: create_user
    let mut user_params = HashMap::new();
    user_params.insert(
        "username".to_string(),
        ArcValue::new_primitive("test_user".to_string()),
    );
    user_params.insert(
        "email".to_string(),
        ArcValue::new_primitive("test@example.com".to_string()),
    );
    let created_user: Option<User> = node
        .request("users/create_user", Some(ArcValue::new_map(user_params)))
        .await?;
    if let Some(user) = created_user {
        println!("UserService response: Created User: {:?}", user);

        // 2. Call ProfileService: get_profile (using the created user's ID)
        let mut profile_params = HashMap::new();
        profile_params.insert(
            "user_id".to_string(),
            ArcValue::new_primitive(user.id.clone()),
        );
        let user_profile: Option<Profile> = node
            .request(
                "profiles/get_profile",
                Some(ArcValue::new_map(profile_params)),
            )
            .await?;
        if let Some(profile) = user_profile {
            println!("ProfileService response: Got Profile: {:?}", profile);
        }

        // 3. Call AccountService: get_account_balance
        let mut account_params = HashMap::new();
        // Assuming a dummy account_id for now, as create_account might return the Account struct
        account_params.insert(
            "account_id".to_string(),
            ArcValue::new_primitive("acc_123".to_string()),
        );
        let balance: Option<f64> = node
            .request(
                "accounts/get_account_balance",
                Some(ArcValue::new_map(account_params)),
            )
            .await?;
        if let Some(bal) = balance {
            println!("AccountService response: Account Balance: {}", bal);
        }

        // 4. Call OrderService: create_order
        let mut order_params = HashMap::new();
        order_params.insert(
            "user_id".to_string(),
            ArcValue::new_primitive(user.id.clone()),
        );
        order_params.insert(
            "product_id".to_string(),
            ArcValue::new_primitive("prod_789".to_string()),
        );
        order_params.insert("quantity".to_string(), ArcValue::new_primitive(2u32));
        let new_order: Option<Order> = node
            .request("orders/create_order", Some(ArcValue::new_map(order_params)))
            .await?;
        if let Some(order) = new_order {
            println!("OrderService response: Created Order: {:?}", order);
        }
    } else {
        println!("UserService: Failed to create user.");
    }

    println!("\nMicro-services demo application finished example calls.");
    // Node will run until explicitly stopped or program exits.
    // For a demo, we might just let it run for a bit or add a ctrl-c handler.
    // For now, it will exit after calls.

    println!("--- ALL DONE --- Will exit in 5 seconds. ---");
    time::sleep(Duration::from_secs(5)).await;
    println!("--- EXITING NOW ---");

    Ok(())
}
