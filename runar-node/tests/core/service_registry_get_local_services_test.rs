// Tests for the ServiceRegistry's get_local_services method
//
// INTENTION: This test validates that the ServiceRegistry properly retrieves
// all registered local services without using a dummy path.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_common::logging::{Component, Logger};
use runar_node::routing::TopicPath;
use runar_node::services::abstract_service::ServiceState;
use runar_node::services::service_registry::{ServiceEntry, ServiceRegistry};

use crate::fixtures::math_service::MathService;

/// Test that verifies the get_local_services method correctly retrieves all registered services
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple services in different networks
/// - Retrieve all registered services using get_local_services without a dummy path
#[tokio::test]
async fn test_get_local_services() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a service registry
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Create services in different networks
        let service1 = Arc::new(MathService::new("service1", "service1"));
        let topic_path1 = TopicPath::new("service1", "service1").unwrap();
        let service2 = Arc::new(MathService::new("service2", "network1"));
        let topic_path2 = TopicPath::new("service2", "network1").unwrap();
        let service3 = Arc::new(MathService::new("service3", "network2"));
        let topic_path3 = TopicPath::new("service3", "network2").unwrap();

        // Create ServiceEntry objects
        let service_entry1 = Arc::new(ServiceEntry {
            service: service1.clone(),
            service_topic: topic_path1.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1000,
            last_start_time: None,
        });

        let service_entry2 = Arc::new(ServiceEntry {
            service: service2.clone(),
            service_topic: topic_path2.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1001,
            last_start_time: None,
        });

        let service_entry3 = Arc::new(ServiceEntry {
            service: service3.clone(),
            service_topic: topic_path3.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1002,
            last_start_time: None,
        });

        // Register the services
        registry
            .register_local_service(service_entry1.clone())
            .await
            .unwrap();
        registry
            .register_local_service(service_entry2.clone())
            .await
            .unwrap();
        registry
            .register_local_service(service_entry3.clone())
            .await
            .unwrap();

        // Get all local services
        let services = registry.get_local_services().await;

        // Verify that all services are retrieved
        assert_eq!(
            services.len(),
            3,
            "Expected all three services to be retrieved"
        );

        // Verify that each service is correctly retrieved
        assert!(
            services.contains_key(&topic_path1.clone()),
            "Service 1 should be in the result"
        );
        assert!(
            services.contains_key(&topic_path2.clone()),
            "Service 2 should be in the result"
        );
        assert!(
            services.contains_key(&topic_path3.clone()),
            "Service 3 should be in the result"
        );

        // Verify that the service entries match
        assert_eq!(
            services[&topic_path1.clone()].service.path().to_string(),
            service_entry1.service.path().to_string(),
            "Service 1 entry should match"
        );

        assert_eq!(
            services[&topic_path2.clone()].service.path().to_string(),
            service_entry2.service.path().to_string(),
            "Service 2 entry should match"
        );

        assert_eq!(
            services[&topic_path3.clone()].service.path().to_string(),
            service_entry3.service.path().to_string(),
            "Service 3 entry should match"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}
