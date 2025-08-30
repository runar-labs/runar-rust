use runar_common::routing::TopicPath;

/// INTENTION: Test comprehensive scenarios for wildcard pattern matching in TopicPath
#[cfg(test)]
mod topic_path_wildcard_tests {
    use super::*;

    #[test]
    fn test_is_pattern() {
        // Test without wildcards
        let path1 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        assert!(!path1.is_pattern());

        // Test with single-segment wildcard
        let pattern1 = TopicPath::new("main:services/*/login", "default").expect("Valid pattern");
        assert!(pattern1.is_pattern());

        // Test with multi-segment wildcard
        let pattern2 = TopicPath::new("main:services/>", "default").expect("Valid pattern");
        assert!(pattern2.is_pattern());
        assert!(pattern2.has_multi_wildcard());
    }

    #[test]
    fn test_single_wildcard_matching() {
        // Create pattern with single-segment wildcard
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");

        // Test successful matches
        let path1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        let non_match2 =
            TopicPath::new("main:services/auth/state/active", "default").expect("Valid path");
        let non_match3 = TopicPath::new("main:events/user/created", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different last segment
        assert!(!pattern.matches(&non_match2)); // Too many segments
        assert!(!pattern.matches(&non_match3)); // Different service path
    }

    #[test]
    fn test_multi_wildcard_matching() {
        // Create pattern with multi-segment wildcard
        let pattern = TopicPath::new("main:services/>", "default").expect("Valid pattern");

        // Test successful matches (should match any path that starts with "services")
        let path1 = TopicPath::new("main:services/auth", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        let path3 =
            TopicPath::new("main:services/math/add/numbers", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));
        assert!(pattern.matches(&path3));

        // Test non-matches
        let non_match1 = TopicPath::new("main:events/user/created", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different service path
    }

    #[test]
    fn test_multi_wildcard_position() {
        // Multi-wildcard must be the last segment
        let invalid_pattern = TopicPath::new("main:services/>/state", "default");
        assert!(invalid_pattern.is_err());

        // But can be in the middle of a pattern as long as it's the last segment
        let valid_pattern = TopicPath::new("main:services/>", "default").expect("Valid pattern");
        assert!(valid_pattern.is_pattern());
        assert!(valid_pattern.has_multi_wildcard());
    }

    #[test]
    fn test_complex_patterns() {
        // Pattern with both types of wildcards
        let pattern = TopicPath::new("main:services/*/events/>", "default").expect("Valid pattern");

        // Test successful matches
        let path1 =
            TopicPath::new("main:services/auth/events/user/login", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/math/events/calculation/completed", "default")
            .expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let non_match2 =
            TopicPath::new("main:services/auth/logs/error", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different segment after service
        assert!(!pattern.matches(&non_match2)); // "logs" instead of "events"
    }

    #[test]
    fn test_wildcard_at_beginning() {
        // Pattern with wildcard at beginning
        let pattern = TopicPath::new("main:*/state", "default").expect("Valid pattern");

        // Test successful matches (should match any service with "state" action)
        let path1 = TopicPath::new("main:auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("main:math/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:auth/login", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different action
    }

    #[test]
    fn test_network_isolation() {
        // Patterns should only match within the same network
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
        let path1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("other:services/auth/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1)); // Same network
        assert!(!pattern.matches(&path2)); // Different network
    }

    #[test]
    fn test_efficient_template_pattern_lookup() {
        use runar_common::routing::TopicPath;
        use std::collections::HashMap;

        // Create a HashMap to store handlers by path pattern
        let mut handlers = HashMap::new();
        let network_id = "main";

        // Store handlers with template patterns
        let template1 = TopicPath::new("services/{service_path}/actions/{action}", network_id)
            .expect("Valid template path");
        let template2 =
            TopicPath::new("services/*/state", network_id).expect("Valid wildcard path");

        handlers.insert(template1.to_string(), "TEMPLATE_HANDLER_1");
        handlers.insert(template2.to_string(), "WILDCARD_HANDLER");

        // Create a concrete path to look up
        let concrete_path =
            TopicPath::new("services/math/actions/add", network_id).expect("Valid concrete path");

        // Generate possible template patterns from the concrete path
        // This is the key insight - we can pre-compute all possible template patterns
        // that might match our concrete path, then look them up directly
        let possible_templates = generate_possible_templates(&concrete_path);

        // Look up each possible template pattern
        for template in possible_templates {
            if let Some(handler) = handlers.get(&template) {
                println!("Found handler for template: {template}");
                println!("Handler: {handler}");
                // Found a matching handler, use it
                return;
            }
        }

        // No matching template found
        panic!("No matching template found for {concrete_path}");
    }

    /// Generate all possible template patterns that could match a concrete path
    fn generate_possible_templates(path: &TopicPath) -> Vec<String> {
        // For this example, we'll manually create the patterns we know should match
        // In a real implementation, we would generate these systematically

        let concrete_path = path.to_string();
        let mut templates = Vec::new();

        // Add the concrete path itself (for exact matching)
        templates.push(concrete_path.clone());

        // Extract segments (network_id:path/to/resource)
        if let Some(path_part) = concrete_path.split(':').nth(1) {
            let segments: Vec<&str> = path_part.split('/').collect();

            // Create specific template patterns based on the segments
            if segments.len() >= 4 && segments[0] == "services" && segments[2] == "actions" {
                // Create services/{service_path}/actions/{action} pattern
                let network_id = concrete_path.split(':').next().unwrap_or("main");
                let template = format!("{network_id}:services/{{service_path}}/actions/{{action}}");
                templates.push(template);
            }

            if segments.len() >= 3 && segments[0] == "services" {
                // Create services/*/state pattern (wildcard)
                let network_id = concrete_path.split(':').next().unwrap_or("main");
                let template = format!("{network_id}:services/*/state");
                templates.push(template);
            }
        }

        templates
    }

    #[test]
    fn test_efficient_wildcard_pattern_lookup() {
        use runar_common::routing::TopicPath;
        use std::collections::HashMap;

        // Create a HashMap to store handlers by path pattern
        let mut handlers = HashMap::new();
        let network_id = "main";

        // Store handlers with wildcard patterns
        let wildcard1 =
            TopicPath::new("services/*/events", network_id).expect("Valid wildcard path");
        let wildcard2 =
            TopicPath::new("services/>", network_id).expect("Valid multi-wildcard path");

        handlers.insert(wildcard1.to_string(), "SINGLE_WILDCARD_HANDLER");
        handlers.insert(wildcard2.to_string(), "MULTI_WILDCARD_HANDLER");

        // Create a concrete path to look up
        let concrete_path =
            TopicPath::new("services/math/events", network_id).expect("Valid concrete path");

        // Generate possible wildcard patterns from the concrete path
        let possible_patterns = generate_wildcard_patterns(&concrete_path);

        // Look up each possible pattern
        let mut found_handler = false;
        for pattern in possible_patterns {
            if let Some(handler) = handlers.get(&pattern) {
                println!("Found handler for wildcard pattern: {pattern}");
                println!("Handler: {handler}");
                found_handler = true;
                break;
            }
        }

        assert!(
            found_handler,
            "No matching wildcard handler found for {concrete_path}",
        );
    }

    /// Generate possible wildcard patterns that could match a concrete path
    fn generate_wildcard_patterns(path: &TopicPath) -> Vec<String> {
        let concrete_path = path.to_string();
        let mut patterns = Vec::new();

        // Add the concrete path itself
        patterns.push(concrete_path.clone());

        // Extract segments (network_id:path/to/resource)
        if let Some(network_prefix) = concrete_path.split(':').next() {
            if let Some(path_part) = concrete_path.split(':').nth(1) {
                let segments: Vec<&str> = path_part.split('/').collect();

                // Generate wildcards based on structure
                if segments.len() >= 3 && segments[0] == "services" {
                    // Replace the middle segment with a * wildcard
                    let wildcard_middle =
                        format!("{}:services/*/{}", network_prefix, segments[2..].join("/"));
                    patterns.push(wildcard_middle);

                    // Add a multi-segment wildcard pattern
                    patterns.push(format!("{network_prefix}:services/>"));
                }
            }
        }

        patterns
    }
}
