use runar_serializer::traits::{
    create_context_label_resolver, LabelKeyword, LabelResolverConfig, LabelValue,
};

/// Example demonstrating the new label resolver system
fn main() -> anyhow::Result<()> {
    println!("=== Label Resolver Example ===\n");

    // 1. Create system label configuration
    let system_config = LabelResolverConfig {
        label_mappings: std::collections::HashMap::from([
            // System label - specific network key, no user keys
            ("system".to_string(), LabelValue {
                network_public_key: Some(vec![1, 2, 3, 4]), // System network key
                user_key_spec: None,
            }),

            // Admin label - specific network key, no user keys
            ("admin".to_string(), LabelValue {
                network_public_key: Some(vec![5, 6, 7, 8]), // Admin network key
                user_key_spec: None,
            }),

            // Current user label - explicit network key, current user keys
            ("current_user".to_string(), LabelValue {
                network_public_key: Some(vec![9, 10, 11, 12]), // Default network key
                user_key_spec: Some(LabelKeyword::CurrentUser),
            }),

            // User-only label - no network key, only current user keys
            ("my_private_data".to_string(), LabelValue {
                network_public_key: None, // User-only encryption
                user_key_spec: Some(LabelKeyword::CurrentUser),
            }),

            // Mixed label - specific network + current user
            ("user_data".to_string(), LabelValue {
                network_public_key: Some(vec![13, 14, 15, 16]),
                user_key_spec: Some(LabelKeyword::CurrentUser),
            }),
        ]),
    };

    // 2. Validate the configuration
    println!("Validating system label configuration...");
    runar_serializer::traits::ConfigurableLabelResolver::validate_label_config(&system_config)?;
    println!("✅ Configuration is valid\n");

    // 3. Create resolver without user context (system context)
    println!("Creating resolver for system context (no user)...");
    let system_resolver = create_context_label_resolver(&system_config, None)?;
    
    println!("Available labels: {:?}", system_resolver.available_labels());
    
    // Test system label resolution
    let system_info = system_resolver.resolve_label_info("system")?.unwrap();
    println!("System label: network_key={:?}, profile_keys={:?}", 
        system_info.network_public_key, system_info.profile_public_keys);
    
    let admin_info = system_resolver.resolve_label_info("admin")?.unwrap();
    println!("Admin label: network_key={:?}, profile_keys={:?}", 
        admin_info.network_public_key, admin_info.profile_public_keys);
    
    let current_user_info = system_resolver.resolve_label_info("current_user")?.unwrap();
    println!("Current user label: network_key={:?}, profile_keys={:?}", 
        current_user_info.network_public_key, current_user_info.profile_public_keys);
    println!();

    // 4. Create resolver with user context
    println!("Creating resolver for user context...");
    let user_profile_keys = vec![vec![100, 101, 102], vec![103, 104, 105]];
    let user_resolver = create_context_label_resolver(&system_config, Some(&user_profile_keys))?;
    
    println!("Available labels: {:?}", user_resolver.available_labels());
    
    // Test user-specific label resolution
    let current_user_info = user_resolver.resolve_label_info("current_user")?.unwrap();
    println!("Current user label: network_key={:?}, profile_keys={:?}", 
        current_user_info.network_public_key, current_user_info.profile_public_keys);
    
    let private_data_info = user_resolver.resolve_label_info("my_private_data")?.unwrap();
    println!("Private data label: network_key={:?}, profile_keys={:?}", 
        private_data_info.network_public_key, private_data_info.profile_public_keys);
    
    let user_data_info = user_resolver.resolve_label_info("user_data")?.unwrap();
    println!("User data label: network_key={:?}, profile_keys={:?}", 
        user_data_info.network_public_key, user_data_info.profile_public_keys);
    println!();

    // 5. Demonstrate how this would be used in SerializationContext
    println!("=== SerializationContext Usage Example ===");
    
    // For a system request (no user context)
    let system_context = runar_serializer::traits::SerializationContext {
        keystore: Arc::new(ExampleKeyStore), // Placeholder
        resolver: system_resolver,
        network_public_key: vec![1, 2, 3, 4], // Resolved from topic path
        profile_public_keys: vec![], // No user keys
    };
    println!("System context created with {} labels", system_context.resolver.available_labels().len());
    
    // For a user request
    let user_context = runar_serializer::traits::SerializationContext {
        keystore: Arc::new(ExampleKeyStore), // Placeholder
        resolver: user_resolver,
        network_public_key: vec![9, 10, 11, 12], // Resolved from topic path
        profile_public_keys: user_profile_keys.clone(), // User's profile keys
    };
    println!("User context created with {} labels", user_context.resolver.available_labels().len());

    println!("\n✅ Label resolver example completed successfully!");
    Ok(())
}

// Placeholder keystore for the example
struct ExampleKeyStore;

impl runar_serializer::traits::EnvelopeCrypto for ExampleKeyStore {
    fn encrypt_with_envelope(
        &self,
        _data: &[u8],
        _network_public_key: Option<&[u8]>,
        _profile_public_keys: Vec<Vec<u8>>,
    ) -> anyhow::Result<runar_keys::mobile::EnvelopeEncryptedData> {
        unimplemented!("This is just an example")
    }

    fn decrypt_envelope_data(
        &self,
        _env: &runar_keys::mobile::EnvelopeEncryptedData,
    ) -> anyhow::Result<Vec<u8>> {
        unimplemented!("This is just an example")
    }
}
