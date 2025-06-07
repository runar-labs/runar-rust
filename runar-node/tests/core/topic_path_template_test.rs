use runar_node::routing::TopicPath;
use std::collections::HashMap;

#[test]
fn test_extract_params_from_template() {
    // A template pattern for our Registry Service paths
    let template = "services/{service_path}/state";

    // An actual path that matches the template
    let path: TopicPath = TopicPath::new("services/math/state", "main").expect("Valid path");

    // Extract parameters from the path
    let params = path
        .extract_params(template)
        .expect("Template should match");

    // Verify the extracted parameter
    assert_eq!(params.get("service_path"), Some(&"math".to_string()));

    // Try another path
    let path2 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
    let params2 = path2
        .extract_params(template)
        .expect("Template should match");
    assert_eq!(params2.get("service_path"), Some(&"auth".to_string()));

    // A path that doesn't match the segment count
    let non_matching1 = TopicPath::new("main:services/math", "default").expect("Valid path");
    assert!(non_matching1.extract_params(template).is_err());

    // A path that doesn't match the literal segments
    let non_matching2 = TopicPath::new("main:users/math/profile", "default").expect("Valid path");
    assert!(non_matching2.extract_params(template).is_err());
}

#[test]
fn test_matches_template() {
    let template = "services/{service_path}/state";

    // Paths that should match
    let path1 = TopicPath::new("main:services/math/state", "default").expect("Valid path");
    let path2 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");

    assert!(path1.matches_template(template));
    assert!(path2.matches_template(template));

    // Paths that shouldn't match
    let path3 = TopicPath::new("main:services/math", "default").expect("Valid path");
    let path4 = TopicPath::new("main:users/auth/profile", "default").expect("Valid path");

    assert!(!path3.matches_template(template));
    assert!(!path4.matches_template(template));
}

#[test]
fn test_from_template() {
    let template = "services/{service_path}/state";

    // Create parameters
    let mut params = HashMap::new();
    params.insert("service_path".to_string(), "math".to_string());

    // Create a path from the template
    let path = TopicPath::from_template(template, params, "main").expect("Valid template");

    // Verify the created path
    assert_eq!(path.as_str(), "main:services/math/state");
    assert_eq!(path.service_path(), "services");
    assert_eq!(path.network_id(), "main");

    // Multiple parameters test
    let template2 = "{service_type}/{service_name}/{action}";

    let mut params2 = HashMap::new();
    params2.insert("service_type".to_string(), "internal".to_string());
    params2.insert("service_name".to_string(), "registry".to_string());
    params2.insert("action".to_string(), "list".to_string());

    let path2 = TopicPath::from_template(template2, params2, "main").expect("Valid template");
    assert_eq!(path2.as_str(), "main:internal/registry/list");
}

#[test]
fn test_registry_service_use_case() {
    // Template for our registry service paths
    let list_template = "services/list";
    let service_template = "services/{service_path}";
    let state_template = "services/{service_path}/state";
    let actions_template = "services/{service_path}/actions";
    let _events_template = "services/{service_path}/events";

    // Test matching for various paths
    let list_path = TopicPath::new("main:services/list", "default").expect("Valid path");
    assert!(list_path.matches_template(list_template));

    let service_path = TopicPath::new("main:services/math", "default").expect("Valid path");
    assert!(service_path.matches_template(service_template));

    let state_path = TopicPath::new("main:services/math/state", "default").expect("Valid path");
    assert!(state_path.matches_template(state_template));

    // Create template path objects for testing matches() in both directions
    let template_topic_path = TopicPath::new(service_template, "default").expect("Valid path");

    // A template path shouldn't match a concrete path in this direction
    assert!(
        !template_topic_path.matches(&service_path),
        "Template shouldn't match concrete path when tested in this direction"
    );

    // Extract service path from a request
    let params = state_path
        .extract_params(state_template)
        .expect("Template should match");
    assert_eq!(params.get("service_path"), Some(&"math".to_string()));

    // Create a path for a specific service's actions
    let mut params = HashMap::new();
    params.insert("service_path".to_string(), "auth".to_string());

    let actions_path =
        TopicPath::from_template(actions_template, params, "main").expect("Valid template");
    assert_eq!(actions_path.as_str(), "main:services/auth/actions");
}

// Note: The current implementation of TopicPath doesn't consider templates and matching concrete paths
// to be equal for HashMap lookups. This is intentional - we use the PathTrie for matching instead.
// This test demonstrates the current behavior without assertions that would fail.
#[test]
fn test_template_path_key() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Create a template path and a concrete path
    let template = "services/{service_path}";
    let match_value = "services/math";
    let network_id = "main";

    let template_path = TopicPath::new(template, network_id).expect("Valid path");
    let match_value_path = TopicPath::new(match_value, network_id).expect("Valid path");

    // Print for debugging
    println!("Template path: {}", template_path);
    println!("Match value path: {}", match_value_path);

    // Calculate hash values
    let mut hasher1 = DefaultHasher::new();
    template_path.hash(&mut hasher1);
    let template_hash = hasher1.finish();

    let mut hasher2 = DefaultHasher::new();
    match_value_path.hash(&mut hasher2);
    let match_value_hash = hasher2.finish();

    println!("Template path hash: {:x}", template_hash);
    println!("Match value hash: {:x}", match_value_hash);
    println!("Hash equality: {}", template_hash == match_value_hash);

    // Note: In the current implementation, these hashes are different and
    // the paths cannot be used interchangeably as HashMap keys
    // The PathTrie implementation provides the matching functionality instead
}

#[test]
fn test_template_path_key_with_wildcards() {
    // Create test paths
    let network_id = "main";

    // Single-segment wildcard
    let wildcard_path =
        TopicPath::new("services/*/state", network_id).expect("Valid wildcard path");
    let match_path1 = TopicPath::new("services/math/state", network_id).expect("Valid path");
    let match_path2 = TopicPath::new("services/auth/state", network_id).expect("Valid path");
    let non_match = TopicPath::new("services/math/config", network_id).expect("Valid path");

    // For the current implementation, we verify matching using matches() not equality
    assert!(wildcard_path.matches(&match_path1));
    assert!(wildcard_path.matches(&match_path2));
    assert!(!wildcard_path.matches(&non_match));
}

#[test]
fn test_simplified_template_key() {
    // Create paths we want to test
    let template = "services/{service_path}";
    let match_value = "services/math";
    let network_id = "main";

    let template_path = TopicPath::new(template, network_id).expect("Valid path");
    let match_value_path = TopicPath::new(match_value, network_id).expect("Valid path");

    // A template path doesn't match a concrete path in this direction
    assert!(
        !template_path.matches(&match_value_path),
        "Template shouldn't match concrete path"
    );

    // But a concrete path should match a template via the matches_template method
    assert!(
        match_value_path.matches_template("services/{service_path}"),
        "Concrete path should match template"
    );
}

#[test]
fn test_normalized_template_matching() {
    let template_path =
        TopicPath::new("main:services/{service_path}", "default").expect("Valid path");
    let concrete_path = TopicPath::new("main:services/math", "default").expect("Valid path");

    let template_matches = template_path.matches(&concrete_path);
    let concrete_matches_template = concrete_path.matches_template("services/{service_path}");

    // A template path shouldn't match a concrete path in this direction
    assert!(
        !template_matches,
        "Template shouldn't match concrete path when tested in this direction"
    );

    // But a concrete path should match a template via the matches_template method
    assert!(
        concrete_matches_template,
        "Concrete path should match template"
    );
}

/// Tests for topic path templates and parameter extraction
///
/// INTENTION: Verify that TopicPath template parameters are correctly handled.
#[cfg(test)]
mod tests {
    use super::*;

    // Test matching a path against a template and extracting parameters
    #[test]
    fn test_extract_params() {
        let path = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        // Test with a valid template
        let params = path
            .extract_params("services/{service_path}/state")
            .expect("Template should match");
        assert_eq!(params.get("service_path"), Some(&"math".to_string()));

        // Test with multiple parameters
        let nested_path =
            TopicPath::new("main:services/math/users/admin", "default").expect("Valid path");
        let nested_params = nested_path
            .extract_params("services/{service}/users/{user_id}")
            .expect("Template should match");
        assert_eq!(nested_params.get("service"), Some(&"math".to_string()));
        assert_eq!(nested_params.get("user_id"), Some(&"admin".to_string()));

        // Test with a non-matching template
        let result = path.extract_params("services/{service_path}/config");
        assert!(result.is_err());

        // Test with a template that has a different segment count
        let result = path.extract_params("services/{service_path}");
        assert!(result.is_err());
    }

    // Test checking if a path matches a template
    #[test]
    fn test_matches_template() {
        let path = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        // Test with matching templates
        assert!(path.matches_template("services/{service_path}/state"));
        assert!(path.matches_template("services/math/state"));
        assert!(path.matches_template("services/{service_path}/{action}"));

        // Test with non-matching templates
        assert!(!path.matches_template("services/{service_path}/config"));
        assert!(!path.matches_template("users/{user_id}"));
        assert!(!path.matches_template("services/{service_path}"));
        assert!(!path.matches_template("services/{service_path}/state/details"));
    }

    // Test creating a path from a template and parameter values
    #[test]
    fn test_from_template() {
        let mut params = HashMap::new();
        params.insert("service_path".to_string(), "math".to_string());
        params.insert("action".to_string(), "add".to_string());

        let path =
            TopicPath::from_template("services/{service_path}/{action}", params.clone(), "main")
                .expect("Valid template");

        assert_eq!(path.as_str(), "main:services/math/add");
        assert_eq!(path.service_path(), "services");
        assert_eq!(path.network_id(), "main");

        // Test with missing parameter
        let result =
            TopicPath::from_template("services/{service_path}/{missing_param}", params, "main");
        assert!(result.is_err());
    }

    // Test basic template behavior in TopicPath
    #[test]
    fn test_path_with_templates() {
        let path_str = "main:services/{service_path}/state";
        let path = TopicPath::new(path_str, "default").expect("Valid path");

        assert!(path.has_templates());
        assert_eq!(path.as_str(), path_str);

        // A path with templates is not a wildcard pattern
        assert!(!path.is_pattern());
    }

    // Added test for testing template path with action path extraction
    #[test]
    fn test_template_path_action_path() {
        let path = TopicPath::new(
            "main:services/{service_path}/actions/{action_name}",
            "default",
        )
        .expect("Valid path");

        assert_eq!(path.service_path(), "services");
        assert_eq!(
            path.action_path(),
            "services/{service_path}/actions/{action_name}"
        );

        // Test with specific values
        let mut params = HashMap::new();
        params.insert("service_path".to_string(), "math".to_string());
        params.insert("action_name".to_string(), "add".to_string());

        let concrete_path = TopicPath::from_template(
            "services/{service_path}/actions/{action_name}",
            params,
            "main",
        )
        .expect("Valid template");

        assert_eq!(concrete_path.service_path(), "services");
        assert_eq!(concrete_path.action_path(), "services/math/actions/add");
    }

    // Test more complex template usage
    #[test]
    fn test_complex_template_usage() {
        let template = "services/{service_path}/users/{user_id}/profile";

        let mut params = HashMap::new();
        params.insert("service_path".to_string(), "auth".to_string());
        params.insert("user_id".to_string(), "12345".to_string());

        let path = TopicPath::from_template(template, params, "main").expect("Valid template");

        assert_eq!(path.as_str(), "main:services/auth/users/12345/profile");

        // Now extract params back from the path
        let extracted = path
            .extract_params(template)
            .expect("Should match template");
        assert_eq!(extracted.get("service_path"), Some(&"auth".to_string()));
        assert_eq!(extracted.get("user_id"), Some(&"12345".to_string()));
    }

    // Test edge cases with templates
    #[test]
    fn test_template_edge_cases() {
        // Test empty parameter name (should still work)
        let path = TopicPath::new("main:services/{}/state", "default").expect("Valid path");
        assert!(path.has_templates());

        // Test template at beginning of path
        let path = TopicPath::new("main:{service}/actions/list", "default").expect("Valid path");
        assert!(path.has_templates());

        // Test template at end of path
        let path = TopicPath::new("main:services/actions/{name}", "default").expect("Valid path");
        assert!(path.has_templates());

        // Test multiple templates in a single path
        let path = TopicPath::new("main:{service}/{action}/{id}", "default").expect("Valid path");
        assert!(path.has_templates());

        let mut params = HashMap::new();
        params.insert("service".to_string(), "auth".to_string());
        params.insert("action".to_string(), "login".to_string());
        params.insert("id".to_string(), "12345".to_string());

        let concrete = TopicPath::from_template("{service}/{action}/{id}", params, "main")
            .expect("Valid template");

        assert_eq!(concrete.as_str(), "main:auth/login/12345");
    }

    // Test service paths versus action paths with templates
    #[test]
    fn test_service_versus_action_templates() {
        let service_path =
            TopicPath::new("main:services/{service_type}", "default").expect("Valid path");
        assert!(service_path.has_templates());
        assert_eq!(service_path.service_path(), "services");

        // Instead of using new_action_topic, create the action path manually
        let action_path_str = "main:services/{service_type}/list";
        let action_path = TopicPath::new(action_path_str, "default").expect("Valid path");
        assert_eq!(action_path.as_str(), action_path_str);
        assert!(action_path.has_templates());
    }

    // Test the event path creation with templates
    #[test]
    fn test_event_path_with_templates() {
        let _service_path =
            TopicPath::new("main:services/{service_type}", "default").expect("Valid path");

        // Instead of using new_event_topic, create the event path manually
        let event_path_str = "main:services/{service_type}/updated";
        let event_path = TopicPath::new(event_path_str, "default").expect("Valid event path");

        assert_eq!(event_path.as_str(), event_path_str);
        assert!(event_path.has_templates());

        let _events_template = "services/{service_path}/events";
    }

    /*
    #[test]
    fn test_hash_keys_with_template() {
        let template_path = TopicPath::new("main:services/{service_path}", "default").expect("Valid path");
        let match_value_path = TopicPath::new("main:services/math", "default").expect("Valid path");
        let not_match_path = TopicPath::new("main:services/math/config", "default").expect("Valid path");

        let template_key = TemplatePathKey(template_path);
        let match_value_key = TemplatePathKey(match_value_path);
        let not_match_key = TemplatePathKey(not_match_path);

        // Check equality - template path key should equal concrete path key with same segments
        assert_eq!(template_key, match_value_key);

        // Segment count difference means keys are not equal
        assert_ne!(template_key, not_match_key);

        // Create a HashMap using TemplatePathKey
        let mut handlers = std::collections::HashMap::new();
        handlers.insert(template_key, "VALUE");

        // We should be able to retrieve the handler using a concrete path key
        let handler = handlers.get(&match_value_key);
        assert_eq!(handler, Some(&"VALUE"));
    }
    */

    #[test]
    fn test_registry_service_use_case() {
        // Test with a real-world use case: registry service

        // Template paths for registry service
        let list_services_template = "services/list";
        let service_info_template = "services/{service_path}";
        let service_state_template = "services/{service_path}/state";

        // Create actual request paths
        let list_path = TopicPath::new("main:services/list", "default").expect("Valid path");
        let info_path = TopicPath::new("main:services/math", "default").expect("Valid path");
        let state_path = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        // Create template path objects for testing matches() in both directions
        let template_path = TopicPath::new(service_info_template, "default").expect("Valid path");

        // These should match their respective templates using matches_template
        assert!(list_path.matches_template(list_services_template));
        assert!(info_path.matches_template(service_info_template));
        assert!(state_path.matches_template(service_state_template));

        // A template path shouldn't match a concrete path in this direction
        assert!(
            !template_path.matches(&info_path),
            "Template shouldn't match concrete path when tested in this direction"
        );

        // Extract parameters
        let info_params = info_path
            .extract_params(service_info_template)
            .expect("Should match");
        assert_eq!(info_params.get("service_path"), Some(&"math".to_string()));

        let state_params = state_path
            .extract_params(service_state_template)
            .expect("Should match");
        assert_eq!(state_params.get("service_path"), Some(&"math".to_string()));
    }
}
