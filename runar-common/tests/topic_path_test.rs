use runar_common::routing::TopicPath;

/// Comprehensive test suite for TopicPath
///
/// INTENTION: Verify that TopicPath correctly handles path parsing, manipulation,
/// and validation according to documented requirements. Covers all methods and edge cases.
#[cfg(test)]
mod topic_path_tests {
    use super::*;

    /// Test TopicPath::new() constructor with various valid inputs
    #[test]
    fn test_new_valid_paths() {
        // Test with network_id prefix
        let path = TopicPath::new("main:auth/login", "default").expect("Valid path");
        assert_eq!(path.network_id(), "main");
        assert_eq!(path.service_path(), "auth");
        let segments = path.get_segments();
        assert_eq!(segments.last().unwrap(), "login");
        assert_eq!(path.as_str(), "main:auth/login");
        assert_eq!(path.action_path(), "auth/login");

        // Test without network_id (uses default)
        let path = TopicPath::new("auth/login", "default").expect("Valid path");
        assert_eq!(path.network_id(), "default");
        assert_eq!(path.service_path(), "auth");
        let segments = path.get_segments();
        assert_eq!(segments.last().unwrap(), "login");
        assert_eq!(path.as_str(), "default:auth/login");
        assert_eq!(path.action_path(), "auth/login");

        // Test with just service name
        let path = TopicPath::new("auth", "default").expect("Valid path");
        assert_eq!(path.network_id(), "default");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.as_str(), "default:auth");
        assert_eq!(path.action_path(), "");

        // Test with multiple path segments
        let path = TopicPath::new("main:auth/users/details", "default").expect("Valid path");
        assert_eq!(path.network_id(), "main");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.as_str(), "main:auth/users/details");
        assert_eq!(path.action_path(), "auth/users/details");
    }

    /// Test TopicPath::new() constructor with invalid inputs
    #[test]
    fn test_new_invalid_paths() {
        // Empty path
        assert!(TopicPath::new("", "default").is_err());

        // Multiple colons
        assert!(TopicPath::new("main:auth:login", "default").is_err());

        // Empty network ID
        assert!(TopicPath::new(":auth/login", "default").is_err());
    }

    /// Test TopicPath::new_service() constructor
    #[test]
    fn test_new_service() {
        let path = TopicPath::new_service("main", "auth");
        assert_eq!(path.network_id(), "main");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.as_str(), "main:auth");
        assert_eq!(path.action_path(), "");
        // Service-only paths don't have an action/event segment
        assert_eq!(path.get_segments().len(), 1);
    }

    /// Test TopicPath::child() for creating child paths
    #[test]
    fn test_child() {
        // Create a base path and add a child
        let base = TopicPath::new("main:auth", "default").expect("Valid path");
        let child = base.child("login").expect("Valid child path");

        assert_eq!(child.as_str(), "main:auth/login");
        assert_eq!(child.network_id(), "main");
        assert_eq!(child.service_path(), "auth");
        assert_eq!(child.action_path(), "auth/login");

        // Add another child
        let nested_child = child.child("advanced").expect("Valid nested child");
        assert_eq!(nested_child.as_str(), "main:auth/login/advanced");

        // Test invalid child (with slash)
        assert!(base.child("invalid/segment").is_err());
    }

    /// Test TopicPath::parent() for creating parent paths
    #[test]
    fn test_parent() {
        // Create a nested path
        let path = TopicPath::new("main:auth/users/details", "default").expect("Valid path");

        // Get parent (one level up)
        let parent = path.parent().expect("Valid parent");
        assert_eq!(parent.as_str(), "main:auth/users");
        // The service_path should remain the same as the original path (just the service name)
        assert_eq!(parent.service_path(), "auth");

        // Get grandparent (two levels up)
        let grandparent = parent.parent().expect("Valid grandparent");
        assert_eq!(grandparent.as_str(), "main:auth");

        // Cannot get parent of root path
        assert!(grandparent.parent().is_err());

        // Cannot get parent of service-only path
        let service_only = TopicPath::new("main:service", "default").expect("Valid path");
        assert!(service_only.parent().is_err());
    }

    /// Test TopicPath::starts_with() for path prefix matching
    #[test]
    fn test_starts_with() {
        let path = TopicPath::new("main:auth/users/list", "default").expect("Valid path");

        // Test with matching prefixes
        let prefix1 = TopicPath::new("main:auth", "default").expect("Valid path");
        let prefix2 = TopicPath::new("main:auth/users", "default").expect("Valid path");

        assert!(path.starts_with(&prefix1));
        assert!(path.starts_with(&prefix2));

        // Test with non-matching prefixes
        let different_network = TopicPath::new("other:auth/users", "default").expect("Valid path");
        let different_service = TopicPath::new("main:payments", "default").expect("Valid path");

        assert!(!path.starts_with(&different_network));
        assert!(!path.starts_with(&different_service));
    }

    /// Test TopicPath::get_segments() for path segment extraction
    #[test]
    fn test_get_segments() {
        // Simple path
        let path1 = TopicPath::new("main:auth/login", "default").expect("Valid path");
        let segments1 = path1.get_segments();
        assert_eq!(segments1, vec!["auth", "login"]);

        // Complex path with multiple segments
        let path2 = TopicPath::new("main:auth/users/profile/edit", "default").expect("Valid path");
        let segments2 = path2.get_segments();
        assert_eq!(segments2, vec!["auth", "users", "profile", "edit"]);

        // Path with service name only
        let path3 = TopicPath::new("main:auth", "default").expect("Valid path");
        let segments3 = path3.get_segments();
        assert_eq!(segments3, vec!["auth"]);
    }

    /// Test TopicPath::test_default() helper for tests
    #[test]
    fn test_default_helper() {
        let path = TopicPath::test_default("auth/login");
        assert_eq!(path.network_id(), "default");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.action_path(), "auth/login");
        assert_eq!(path.as_str(), "default:auth/login");
    }

    /// Test consistency between methods
    #[test]
    fn test_method_consistency() {
        let path = TopicPath::new("main:service/action", "default").expect("Valid path");

        // The service_path should return just the service name (first segment)
        assert_eq!(path.service_path(), "service");

        // The segments should include all parts
        let segments = path.get_segments();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], "service");
        assert_eq!(segments[1], "action");

        // The action_path should include everything after the network ID
        assert_eq!(path.action_path(), "service/action");
    }

    /// Test with unusual but valid paths
    #[test]
    fn test_unusual_paths() {
        // Network ID with special characters
        let path1 = TopicPath::new("test-network_01:service", "default").expect("Valid path");
        assert_eq!(path1.network_id(), "test-network_01");
        assert_eq!(path1.service_path(), "service");

        // Service path with special characters
        let path2 = TopicPath::new("main:my-service_01", "default").expect("Valid path");
        assert_eq!(path2.service_path(), "my-service_01");

        // Long paths with many segments
        let path3 = TopicPath::new("main:service/a/b/c/d/e/f", "default").expect("Valid path");
        let segments3 = path3.get_segments();
        assert_eq!(segments3.len(), 7);
        assert_eq!(path3.action_path(), "service/a/b/c/d/e/f");
    }

    /// Test service paths with embedded slashes
    #[test]
    fn test_service_paths_with_slashes() {
        // Test with internal service path using $ prefix
        let path =
            TopicPath::new("test_network:$registry/services/list", "default").expect("Valid path");

        // The service_path should be "$registry" - first segment only
        assert_eq!(path.service_path(), "$registry");

        // Verify the action_path includes the complete path after network ID
        assert_eq!(path.action_path(), "$registry/services/list");

        // Test parameters extraction with path templates
        let template = "services/{service_path}/state";
        let path = TopicPath::new("test_network:$registry/services/math/state", "default")
            .expect("Valid path");

        let params = path.extract_params(template);

        // This will fail because segment counts don't match:
        // - Path segments: ["$registry", "services", "math", "state"]
        // - Template segments: ["services", "{service_path}", "state"]
        assert!(params.is_err());
    }

    /// Test with internal registry service path using $ prefix
    #[test]
    fn test_registry_service_paths() {
        // Create a service with $ prefix path
        let service_path = "$registry";

        // Register action with path "services/list"
        let action_path = "services/list";

        // The full action path that should be constructed when handling requests
        let expected_full_path = "test_network:$registry/services/list";

        // Simulate how paths should be handled
        let path = TopicPath::new(
            &format!("test_network:{service_path}/{action_path}"),
            "default",
        )
        .expect("Valid path");

        assert_eq!(path.as_str(), expected_full_path);

        // Test with template pattern for service state
        let template = "services/{service_path}/state";

        // Get a service state path that matches the template
        let service_state_path =
            TopicPath::new("test_network:services/math/state", "default").expect("Valid path");

        // Extract parameters from the path
        let params = service_state_path
            .extract_params(template)
            .expect("Template should match");
        assert_eq!(params.get("service_path"), Some(&"math".to_string()));
    }

    #[test]
    fn test_new_action_topic() {
        // Create a service path
        let service_path = TopicPath::new("main:auth", "default").expect("Valid path");

        // Create an action path
        let action_path = service_path
            .new_action_topic("login")
            .expect("Valid action path");

        // Verify the path components
        assert_eq!(action_path.network_id(), "main");
        assert_eq!(action_path.service_path(), "auth");
        assert_eq!(action_path.action_path(), "auth/login");
    }

    #[test]
    fn test_new_event_topic() {
        // Create a service path
        let service_path = TopicPath::new("main:auth", "default").expect("Valid path");

        // Create an event path
        let event_path = service_path
            .new_event_topic("user_logged_in")
            .expect("Valid event path");

        // Verify the path components
        assert_eq!(event_path.network_id(), "main");
        assert_eq!(event_path.service_path(), "auth");
        // Check the full path instead of the last segment
        assert_eq!(event_path.action_path(), "auth/user_logged_in");
    }

    #[test]
    fn test_nested_action_path() {
        // Create a nested service path
        let service_path = TopicPath::new("main:serviceX", "default").expect("Valid path");

        let action_result = service_path.new_action_topic("verify_token");
        //shuold not be an error. sould be a valid action path
        assert!(action_result.is_ok());

        let action_path = action_result.unwrap();
        assert_eq!(action_path.network_id(), "main");
        assert_eq!(action_path.service_path(), "serviceX");
        assert_eq!(action_path.action_path(), "serviceX/verify_token");
    }

    #[test]
    fn test_nested_invalid_action_path() {
        // Create a nested service with action  already
        let service_path = TopicPath::new("main:services/auth", "default").expect("Valid path");

        // Creating an action path from a topic path with action already is not allowed
        let action_result = service_path.new_action_topic("verify_token");

        // Verify the error - this is the expected behavior because we don't support nested service paths
        assert!(
            action_result.is_err(),
            "Should not allow creating action topics on nested service paths"
        );
        assert!(action_result
            .unwrap_err()
            .contains("cannot create an action path on top of another action path"));
    }

    #[test]
    fn test_default_network_id() {
        // Create a service path with default network ID
        let service_path = TopicPath::new("auth", "test-network").expect("Valid path");

        // Create an action path
        let action_path = service_path
            .new_action_topic("login")
            .expect("Valid action path");

        // Verify the network ID was preserved
        assert_eq!(action_path.network_id(), "test-network");
        assert_eq!(action_path.service_path(), "auth");
        assert_eq!(action_path.action_path(), "auth/login");
    }

    #[test]
    fn test_invalid_action_name() {
        // Create a service path
        let service_path = TopicPath::new("main:auth", "default").expect("Valid path");

        // Try to create an action path with an invalid name (containing a colon)
        let action_result = service_path.new_action_topic("invalid:name");

        // Verify the result is an error
        assert!(action_result.is_err());
    }

    // Test basic path parsing
    #[test]
    fn test_basic_parse() {
        // Parse a path with network ID and action
        let path = TopicPath::new("default:auth/login", "fallback").expect("Valid path");
        assert_eq!(path.network_id(), "default");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.action_path(), "auth/login");
        assert_eq!(path.as_str(), "default:auth/login");

        // Parse a path with just service path and default network ID
        let path = TopicPath::new("auth/login", "default").expect("Valid path");
        assert_eq!(path.network_id(), "default");
        assert_eq!(path.service_path(), "auth");
        assert_eq!(path.action_path(), "auth/login");
    }

    // Test with various path formats
    #[test]
    fn test_various_formats() {
        // Format 1: Full path with network ID and action
        let path1 = TopicPath::new("network:auth/login", "default").expect("Valid path");
        assert_eq!(path1.network_id(), "network");
        assert_eq!(path1.service_path(), "auth");
        assert_eq!(path1.action_path(), "auth/login");

        // Format 2: Network and service only
        let path2 = TopicPath::new("network:auth", "default").expect("Valid path");
        assert_eq!(path2.network_id(), "network");
        assert_eq!(path2.service_path(), "auth");
        assert_eq!(path2.action_path(), "");

        // Format 3: Service and action without network (uses default)
        let path3 = TopicPath::new("auth/login", "default").expect("Valid path");
        assert_eq!(path3.network_id(), "default");
        assert_eq!(path3.service_path(), "auth");
        assert_eq!(path3.action_path(), "auth/login");
    }
}
