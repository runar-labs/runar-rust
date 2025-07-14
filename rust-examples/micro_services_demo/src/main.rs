use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::traits::{
    ConfigurableLabelResolver, KeyMappingConfig, KeyScope, LabelKeyInfo,
};
use runar_serializer::{ArcValue, SerializerRegistry, ValueCategory};
use runar_test_utils::create_node_test_config;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

// Declare modules
mod account_service;
mod models;
mod order_service;
mod profile_service;
mod user_service;

// Import services and models
use models::{Account, Order, Profile, User};

// Mock in-memory database for storing encrypted data
#[derive(Default)]
struct MockDatabase {
    users: HashMap<String, Vec<u8>>,    // user_id -> encrypted_user_data
    profiles: HashMap<String, Vec<u8>>, // user_id -> encrypted_profile_data
    accounts: HashMap<String, Vec<u8>>, // account_id -> encrypted_account_data
    orders: HashMap<String, Vec<u8>>,   // order_id -> encrypted_order_data
}

impl MockDatabase {
    fn store_user(&mut self, user_id: &str, encrypted_data: Vec<u8>) {
        self.users.insert(user_id.to_string(), encrypted_data);
        println!("📦 Stored encrypted user data for user_id: {user_id}");
    }

    fn store_profile(&mut self, user_id: &str, encrypted_data: Vec<u8>) {
        self.profiles.insert(user_id.to_string(), encrypted_data);
        println!("📦 Stored encrypted profile data for user_id: {user_id}");
    }

    fn store_account(&mut self, account_id: &str, encrypted_data: Vec<u8>) {
        self.accounts.insert(account_id.to_string(), encrypted_data);
        println!("📦 Stored encrypted account data for account_id: {account_id}");
    }

    fn store_order(&mut self, order_id: &str, encrypted_data: Vec<u8>) {
        self.orders.insert(order_id.to_string(), encrypted_data);
        println!("📦 Stored encrypted order data for order_id: {order_id}");
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
    SerializerRegistry,
    SerializerRegistry,
    String,
)> {
    let logger = Arc::new(Logger::new_root(Component::System, "encryption-demo"));

    // -------- Mobile key manager (user keys) --------
    println!("🔑 Initializing Mobile Key Manager...");
    let mut mobile_mgr = MobileKeyManager::new(logger.clone())?;
    mobile_mgr.initialize_user_root_key()?;
    let profile_pk = mobile_mgr.derive_user_profile_key("user")?;
    let network_id = mobile_mgr.generate_network_data_key()?;
    let network_pub = mobile_mgr.get_network_public_key(&network_id)?;
    let mobile_mgr = Arc::new(mobile_mgr);

    // -------- Node key manager (system keys) --------
    println!("🔑 Initializing Node Key Manager...");
    let mut node_mgr = NodeKeyManager::new(logger.clone())?;
    let nk_msg =
        mobile_mgr.create_network_key_message(&network_id, &node_mgr.get_node_public_key())?;
    node_mgr.install_network_key(nk_msg)?;
    let node_mgr = Arc::new(node_mgr);

    // -------- Label resolvers --------
    let mobile_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".into(),
                LabelKeyInfo {
                    public_key: profile_pk.clone(),
                    scope: KeyScope::Profile,
                },
            ),
            (
                "system".into(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
            (
                "search".into(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
        ]),
    }));

    let node_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "system".into(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
            (
                "search".into(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
        ]),
    }));

    // -------- Serializer registries --------
    println!("📝 Setting up Serializer Registries...");
    let mut mobile_registry = SerializerRegistry::with_keystore(
        logger.clone(),
        mobile_mgr.clone(),
        mobile_resolver.clone(),
    );
    mobile_registry.register_encryptable::<User>()?;
    mobile_registry.register_encryptable::<Profile>()?;
    mobile_registry.register_encryptable::<Account>()?;
    mobile_registry.register_encryptable::<Order>()?;

    let mut node_registry =
        SerializerRegistry::with_keystore(logger, node_mgr.clone(), node_resolver.clone());
    node_registry.register_encryptable::<User>()?;
    node_registry.register_encryptable::<Profile>()?;
    node_registry.register_encryptable::<Account>()?;
    node_registry.register_encryptable::<Order>()?;

    Ok((
        mobile_mgr,
        node_mgr,
        mobile_registry,
        node_registry,
        network_id,
    ))
}

/// Demonstrate data flow from mobile to server and back
async fn demonstrate_encryption_flow(
    mobile_registry: &SerializerRegistry,
    node_registry: &SerializerRegistry,
    db: &mut MockDatabase,
) -> Result<()> {
    println!("\n🚀 Starting Encryption Flow Demonstration");
    println!("{}", "=".repeat(60));

    // -------- 1. Create data on mobile (user side) --------
    println!("\n📱 MOBILE SIDE: Creating user data...");

    let user = User {
        id: "user_123".to_string(),
        username: "alice_smith".to_string(),
        email: "alice@example.com".to_string(),
        password_hash: "hashed_password_123".to_string(),
        created_at: 1234567890,
    };

    let profile = Profile {
        id: "profile_456".to_string(),
        user_id: "user_123".to_string(),
        full_name: "Alice Smith".to_string(),
        bio: "Software engineer and coffee enthusiast".to_string(), // Fixed: removed Some()
        private_notes: "VIP customer - special discount eligible".to_string(),
        last_updated: 1234567890,
    };

    let account = Account {
        id: "acc_789".to_string(),
        name: "Main Checking".to_string(),
        balance_cents: 543210, // Fixed: changed from 5432.10 to cents
        account_type: "checking".to_string(),
        created_at: 1234567890,
    };

    let order = Order {
        id: "order_101".to_string(),
        user_id: "user_123".to_string(),
        product_id: "prod_xyz".to_string(),
        quantity: 2,
        total_price_cents: 9998, // Fixed: changed from 99.98 to cents
        status: "pending".to_string(),
        created_at: 1234567890,
    };

    // -------- 2. Encrypt and serialize on mobile --------
    println!("\n🔐 MOBILE SIDE: Encrypting and serializing data...");

    let user_serialized = mobile_registry.serialize_value(&ArcValue::from_struct(user.clone()))?;
    let profile_serialized =
        mobile_registry.serialize_value(&ArcValue::from_struct(profile.clone()))?;
    let account_serialized =
        mobile_registry.serialize_value(&ArcValue::from_struct(account.clone()))?;
    let order_serialized =
        mobile_registry.serialize_value(&ArcValue::from_struct(order.clone()))?;

    println!("✅ Data encrypted and serialized on mobile");

    // -------- 3. Send to server (simulate network transfer) --------
    println!("\n🌐 NETWORK: Sending encrypted data to server...");

    // Store encrypted data in mock database (convert Arc<[u8]> to Vec<u8>)
    db.store_user(&user.id, user_serialized.to_vec());
    db.store_profile(&user.id, profile_serialized.to_vec());
    db.store_account(&account.id, account_serialized.to_vec());
    db.store_order(&order.id, order_serialized.to_vec());

    // -------- 4. Server side processing --------
    println!("\n🖥️  SERVER SIDE: Processing encrypted data...");

    // Server can only access system-shared fields
    let mut server_user = node_registry.deserialize_value(user_serialized.clone())?;
    let server_user_data = server_user.as_struct_ref::<User>()?;

    println!("📊 SERVER can see User data:");
    println!("   - ID: {}", server_user_data.id);
    println!("   - Username: {}", server_user_data.username);
    println!("   - Email: {}", server_user_data.email);
    println!("   - Created at: {}", server_user_data.created_at);
    println!(
        "   - Password hash: '{}' (user-only field)",
        server_user_data.password_hash
    );

    let mut server_profile = node_registry.deserialize_value(profile_serialized.clone())?;
    let server_profile_data = server_profile.as_struct_ref::<Profile>()?;

    println!("📊 SERVER can see Profile data:");
    println!("   - ID: {}", server_profile_data.id);
    println!("   - User ID: {}", server_profile_data.user_id);
    println!("   - Full name: {}", server_profile_data.full_name);
    println!("   - Bio: {}", server_profile_data.bio);
    println!("   - Last updated: {}", server_profile_data.last_updated);
    println!(
        "   - Private notes: '{}' (user-only field)",
        server_profile_data.private_notes
    );

    let mut server_account = node_registry.deserialize_value(account_serialized.clone())?;
    let server_account_data = server_account.as_struct_ref::<Account>()?;

    println!("📊 SERVER can see Account data:");
    println!("   - ID: {}", server_account_data.id);
    println!("   - Name: {}", server_account_data.name);
    println!("   - Account type: {}", server_account_data.account_type);
    println!("   - Created at: {}", server_account_data.created_at);
    println!(
        "   - Balance: ${:.2} (user-only field)",
        server_account_data.balance_cents as f64 / 100.0
    );

    let mut server_order = node_registry.deserialize_value(order_serialized.clone())?;
    let server_order_data = server_order.as_struct_ref::<Order>()?;

    println!("📊 SERVER can see Order data:");
    println!("   - ID: {}", server_order_data.id);
    println!("   - User ID: {}", server_order_data.user_id);
    println!("   - Product ID: {}", server_order_data.product_id);
    println!("   - Quantity: {}", server_order_data.quantity);
    println!("   - Status: {}", server_order_data.status);
    println!("   - Created at: {}", server_order_data.created_at);
    println!(
        "   - Total price: ${:.2} (user-only field)",
        server_order_data.total_price_cents as f64 / 100.0
    );

    // -------- 5. Retrieve data back to mobile --------
    println!("\n📱 MOBILE SIDE: Retrieving data from server...");

    // Simulate retrieving from database (convert Vec<u8> to Arc<[u8]>)
    if let Some(encrypted_user) = db.get_user(&user.id) {
        let mut mobile_user =
            mobile_registry.deserialize_value(Arc::from(encrypted_user.as_slice()))?;
        let mobile_user_data = mobile_user.as_struct_ref::<User>()?;

        println!("📊 MOBILE can see full User data:");
        println!("   - ID: {}", mobile_user_data.id);
        println!("   - Username: {}", mobile_user_data.username);
        println!("   - Email: {}", mobile_user_data.email);
        println!("   - Password hash: {}", mobile_user_data.password_hash);
        println!("   - Created at: {}", mobile_user_data.created_at);
    }

    if let Some(encrypted_profile) = db.get_profile(&user.id) {
        let mut mobile_profile =
            mobile_registry.deserialize_value(Arc::from(encrypted_profile.as_slice()))?;
        let mobile_profile_data = mobile_profile.as_struct_ref::<Profile>()?;

        println!("📊 MOBILE can see full Profile data:");
        println!("   - ID: {}", mobile_profile_data.id);
        println!("   - User ID: {}", mobile_profile_data.user_id);
        println!("   - Full name: {}", mobile_profile_data.full_name);
        println!("   - Bio: {}", mobile_profile_data.bio);
        println!("   - Private notes: {}", mobile_profile_data.private_notes);
        println!("   - Last updated: {}", mobile_profile_data.last_updated);
    }

    if let Some(encrypted_account) = db.get_account(&account.id) {
        let mut mobile_account =
            mobile_registry.deserialize_value(Arc::from(encrypted_account.as_slice()))?;
        let mobile_account_data = mobile_account.as_struct_ref::<Account>()?;

        println!("📊 MOBILE can see full Account data:");
        println!("   - ID: {}", mobile_account_data.id);
        println!("   - Name: {}", mobile_account_data.name);
        println!(
            "   - Balance: ${:.2}",
            mobile_account_data.balance_cents as f64 / 100.0
        );
        println!("   - Account type: {}", mobile_account_data.account_type);
        println!("   - Created at: {}", mobile_account_data.created_at);
    }

    if let Some(encrypted_order) = db.get_order(&order.id) {
        let mut mobile_order =
            mobile_registry.deserialize_value(Arc::from(encrypted_order.as_slice()))?;
        let mobile_order_data = mobile_order.as_struct_ref::<Order>()?;

        println!("📊 MOBILE can see full Order data:");
        println!("   - ID: {}", mobile_order_data.id);
        println!("   - User ID: {}", mobile_order_data.user_id);
        println!("   - Product ID: {}", mobile_order_data.product_id);
        println!("   - Quantity: {}", mobile_order_data.quantity);
        println!(
            "   - Total price: ${:.2}",
            mobile_order_data.total_price_cents as f64 / 100.0
        );
        println!("   - Status: {}", mobile_order_data.status);
        println!("   - Created at: {}", mobile_order_data.created_at);
    }

    println!("\n✅ Encryption flow demonstration completed!");
    println!("{}", "=".repeat(60));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting Encrypted Micro-Services Demo");
    println!("{}", "=".repeat(60));

    // Setup encryption infrastructure
    let (_mobile_mgr, _node_mgr, mobile_registry, node_registry, _network_id) =
        setup_encryption().await?;
    println!("✅ Encryption infrastructure ready");

    // Initialize mock database
    let mut db = MockDatabase::default();
    println!("✅ Mock database initialized");

    // Demonstrate encryption flow
    demonstrate_encryption_flow(&mobile_registry, &node_registry, &mut db).await?;

    println!("\n🎉 Demo completed successfully!");
    println!("Key takeaways:");
    println!("  • User-only fields (password_hash, private_notes, balance, total_price) are encrypted and not accessible to the server");
    println!("  • System-shared fields (username, email, full_name, bio, etc.) are accessible to both mobile and server");
    println!("  • Data flows securely from mobile → server → mobile with proper access control");
    println!("  • Server can store and process encrypted data without compromising user privacy");

    Ok(())
}
