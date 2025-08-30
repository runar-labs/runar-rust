use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_common::routing::TopicPath;
use runar_node::services::service_registry::ServiceRegistry;
use std::sync::Arc;

#[tokio::test]
async fn test_diff_remote_subscriptions() -> Result<()> {
    let logger = Arc::new(Logger::new_root(Component::Custom("Test")));
    let registry = ServiceRegistry::new(logger);

    let peer = "peer1";
    let path_a = TopicPath::new("service1/eventA", "net").unwrap();
    let path_b = TopicPath::new("service1/eventB", "net").unwrap();
    let path_c = TopicPath::new("service1/eventC", "net").unwrap();

    // insert two fake subscription ids for peer
    registry
        .upsert_remote_peer_subscription(peer, &path_a, "sub_a".into())
        .await;
    registry
        .upsert_remote_peer_subscription(peer, &path_b, "sub_b".into())
        .await;

    let old_paths = registry.remote_subscription_paths(peer).await;
    assert!(old_paths.contains(path_a.as_str()));
    assert!(old_paths.contains(path_b.as_str()));

    // simulate node.update_peer_capabilities adding C, removing A
    registry
        .remove_remote_peer_subscription(peer, &path_a)
        .await;
    registry
        .upsert_remote_peer_subscription(peer, &path_c, "sub_c".into())
        .await;

    let new_paths = registry.remote_subscription_paths(peer).await;
    assert!(!new_paths.contains(path_a.as_str()));
    assert!(new_paths.contains(path_b.as_str()));
    assert!(new_paths.contains(path_c.as_str()));
    Ok(())
}
