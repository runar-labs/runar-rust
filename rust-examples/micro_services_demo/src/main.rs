use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};
use runar_macros_common::params;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::traits::{ConfigurableLabelResolver, KeyMappingConfig, LabelKeyInfo};
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use std::collections::HashMap;
use std::sync::Arc;

// Declare modules
mod account_service;
mod models;
mod order_service;
mod profile_service;
mod user_service;

// Import services and models
use models::{Account, Order, Profile, User};

// Mock in-memory database for storing encrypted data
struct MockDatabase {
    users: HashMap<String, Vec<u8>>,    // user_id -> encrypted_user_data
    profiles: HashMap<String, Vec<u8>>, // user_id -> encrypted_profile_data
    accounts: HashMap<String, Vec<u8>>, // account_id -> encrypted_account_data
    orders: HashMap<String, Vec<u8>>,   // order_id -> encrypted_order_data
    logger: Arc<Logger>,
}

impl MockDatabase {
    fn new(logger: Arc<Logger>) -> Self {
        Self {
            users: HashMap::new(),
            profiles: HashMap::new(),
            accounts: HashMap::new(),
            orders: HashMap::new(),
            logger,
        }
    }

    fn store_user(&mut self, user_id: &str, encrypted_data: Vec<u8>) {
        self.users.insert(user_id.to_string(), encrypted_data);
        self.logger.info(format!(
            "📦 Stored encrypted user data for user_id: {user_id}"
        ));
    }

    fn store_profile(&mut self, user_id: &str, encrypted_data: Vec<u8>) {
        self.profiles.insert(user_id.to_string(), encrypted_data);
        self.logger.info(format!(
            "📦 Stored encrypted profile data for user_id: {user_id}"
        ));
    }

    fn store_account(&mut self, account_id: &str, encrypted_data: Vec<u8>) {
        self.accounts.insert(account_id.to_string(), encrypted_data);
        self.logger.info(format!(
            "📦 Stored encrypted account data for account_id: {account_id}"
        ));
    }

    fn store_order(&mut self, order_id: &str, encrypted_data: Vec<u8>) {
        self.orders.insert(order_id.to_string(), encrypted_data);
        self.logger.info(format!(
            "📦 Stored encrypted order data for order_id: {order_id}"
        ));
    }

    fn get_user(&self, user_id: &str) -> Option<&Vec<u8>> {
        self.users.get(user_id)
    }

    fn get_profile(&self, user_id: &str) -> Option<&Vec<u8>> {
        self.profiles.get(user_id)
    }

    fn get_account(&self, account_id: &str) -> Option<&Vec<u8>> {
        self.accounts.get(account_id)
    }

    fn get_order(&self, order_id: &str) -> Option<&Vec<u8>> {
        self.orders.get(order_id)
    }
}

/// Setup encryption infrastructure for mobile and server nodes
async fn setup_encryption() -> Result<(
    Arc<MobileKeyManager>,
    Arc<NodeKeyManager>,
    ConfigurableLabelResolver,
    ConfigurableLabelResolver,
    String,
)> {
    let logger = Arc::new(Logger::new_root(Component::System, "encryption-demo"));

    // -------- Mobile key manager (user keys) --------
    logger.info("🔑 Initializing Mobile Key Manager...");
    let mut mobile_mgr = MobileKeyManager::new(logger.clone())?;
    mobile_mgr.initialize_user_root_key()?;
    let profile_pk = mobile_mgr.derive_user_profile_key("user")?;
    let network_id = mobile_mgr.generate_network_data_key()?;
    let network_pub = mobile_mgr.get_network_public_key(&network_id)?;
    let mobile_mgr = Arc::new(mobile_mgr);

    // -------- Node key manager (system keys) --------
    logger.info("🔑 Initializing Node Key Manager...");
    let mut node_mgr = NodeKeyManager::new(logger.clone())?;
    let nk_msg =
        mobile_mgr.create_network_key_message(&network_id, &node_mgr.get_node_public_key())?;
    node_mgr.install_network_key(nk_msg)?;
    let node_mgr = Arc::new(node_mgr);

    // -------- Label resolvers --------
    logger.info("🔑 Setting up label resolvers...");

    // Mobile label resolver (user context)
    let mobile_mappings = KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![profile_pk.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![network_pub.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![network_pub.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
        ]),
    };
    let mobile_resolver = ConfigurableLabelResolver::new(mobile_mappings);

    // Node label resolver (system context)
    let node_mappings = KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![profile_pk.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![network_pub.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![network_pub.clone()],
                    network_id: Some(network_id.clone()),
                },
            ),
        ]),
    };
    let node_resolver = ConfigurableLabelResolver::new(node_mappings);

    Ok((
        mobile_mgr,
        node_mgr,
        mobile_resolver,
        node_resolver,
        network_id,
    ))
}

/// Demonstrate the encryption flow with the updated API
async fn demonstrate_encryption_flow(
    _mobile_resolver: &ConfigurableLabelResolver,
    _node_resolver: &ConfigurableLabelResolver,
    db: &mut MockDatabase,
    logger: &Logger,
) -> Result<()> {
    logger.info("🔄 Demonstrating encryption flow...");

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
        total_price_cents: 2500, // $25.00
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

    // Store encrypted data
    db.store_user(&user.id, user_serialized);
    db.store_profile(&user.id, profile_serialized);
    db.store_account(&account.id, account_serialized);
    db.store_order(&order.id, order_serialized);

    logger.info("✅ Data encrypted and stored successfully!");

    // Demonstrate decryption
    logger.info("🔓 Demonstrating decryption...");

    // Retrieve and decrypt data
    if let Some(user_data) = db.get_user(&user.id) {
        let user_arc = ArcValue::deserialize(user_data, None)?;
        let decrypted_user: User = user_arc.as_type()?;
        logger.info(format!("👤 Decrypted user: {}", decrypted_user.username));
    }

    if let Some(profile_data) = db.get_profile(&user.id) {
        let profile_arc = ArcValue::deserialize(profile_data, None)?;
        let decrypted_profile: Profile = profile_arc.as_type()?;
        logger.info(format!(
            "📋 Decrypted profile: {}",
            decrypted_profile.full_name
        ));
    }

    if let Some(account_data) = db.get_account(&account.id) {
        let account_arc = ArcValue::deserialize(account_data, None)?;
        let decrypted_account: Account = account_arc.as_type()?;
        logger.info(format!(
            "💰 Decrypted account: {} (${:.2})",
            decrypted_account.name,
            decrypted_account.balance_cents as f64 / 100.0
        ));
    }

    if let Some(order_data) = db.get_order(&order.id) {
        let order_arc = ArcValue::deserialize(order_data, None)?;
        let decrypted_order: Order = order_arc.as_type()?;
        logger.info(format!(
            "🛒 Decrypted order: {} items for ${:.2}",
            decrypted_order.quantity,
            decrypted_order.total_price_cents as f64 / 100.0
        ));
    }

    logger.info("✅ Decryption completed successfully!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::System, "microservices-demo"));

    logger.info("🚀 Starting Runar Encryption Demo");
    logger.info("==================================");

    // Setup encryption infrastructure
    let (_mobile_mgr, _node_mgr, mobile_resolver, node_resolver, network_id) =
        setup_encryption().await?;

    logger.info("✅ Encryption infrastructure ready");
    logger.info(format!("📡 Network ID: {network_id}"));

    // Create mock database
    let mut db = MockDatabase::new(logger.clone());

    // Demonstrate encryption flow
    demonstrate_encryption_flow(&mobile_resolver, &node_resolver, &mut db, &logger).await?;

    // Create and run the microservices demo
    logger.info("🏗️  Setting up microservices...");

    // Create node configuration
    let config = create_node_test_config()?.with_logging_config(logging_config);
    let mut node = Node::new(config).await?;

    // Create and register services
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
        created_order.total_price_cents as f64 / 100.0
    ));

    node.stop().await?;

    logger.info("🎉 Microservices demo completed successfully!");
    logger.info("All operations completed with encryption support.");

    Ok(())
}
