use runar_serializer::traits::{
    create_context_label_resolver, LabelKeyword, LabelResolverConfig, LabelValue,
};

#[test]
fn test_label_resolver_config_creation() {
    // Create a simple label resolver config
    let config = LabelResolverConfig {
        label_mappings: std::collections::HashMap::from([
            (
                "system".to_string(),
                LabelValue {
                    network_public_key: Some(vec![1, 2, 3, 4]),
                    user_key_spec: None,
                },
            ),
            (
                "current_user".to_string(),
                LabelValue {
                    network_public_key: Some(vec![5, 6, 7, 8]),
                    user_key_spec: Some(LabelKeyword::CurrentUser),
                },
            ),
        ]),
    };

    // Test validation
    assert!(
        runar_serializer::traits::ConfigurableLabelResolver::validate_label_config(&config).is_ok()
    );

    // Test resolver creation without user context (empty profile keys)
    let empty_profile_keys = vec![];
    let resolver = create_context_label_resolver(&config, &empty_profile_keys).unwrap();
    assert!(resolver.can_resolve("system"));
    assert!(resolver.can_resolve("current_user"));

    // Test resolver creation with user context
    let user_keys = vec![vec![10, 11, 12], vec![13, 14, 15]];
    let resolver_with_user = create_context_label_resolver(&config, &user_keys).unwrap();

    // Verify current_user label gets user keys
    let current_user_info = resolver_with_user
        .resolve_label_info("current_user")
        .unwrap()
        .unwrap();
    assert_eq!(current_user_info.profile_public_keys, user_keys);
}

#[test]
fn test_label_resolver_config_validation() {
    // Test empty config (should fail)
    let empty_config = LabelResolverConfig {
        label_mappings: std::collections::HashMap::new(),
    };
    assert!(
        runar_serializer::traits::ConfigurableLabelResolver::validate_label_config(&empty_config)
            .is_err()
    );

    // Test invalid label with neither network key nor user spec (should fail)
    let invalid_config = LabelResolverConfig {
        label_mappings: std::collections::HashMap::from([(
            "invalid".to_string(),
            LabelValue {
                network_public_key: None,
                user_key_spec: None,
            },
        )]),
    };
    assert!(
        runar_serializer::traits::ConfigurableLabelResolver::validate_label_config(&invalid_config)
            .is_err()
    );

    // Test valid user-only label
    let valid_user_only_config = LabelResolverConfig {
        label_mappings: std::collections::HashMap::from([(
            "user_only".to_string(),
            LabelValue {
                network_public_key: None,
                user_key_spec: Some(LabelKeyword::CurrentUser),
            },
        )]),
    };
    assert!(
        runar_serializer::traits::ConfigurableLabelResolver::validate_label_config(
            &valid_user_only_config
        )
        .is_ok()
    );
}
