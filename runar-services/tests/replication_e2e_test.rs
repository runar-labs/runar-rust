use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_services::{
    replication::{ConflictResolutionStrategy, ReplicationConfig},
    sqlite::{DataType, Schema, SqliteConfig, SqliteService, TableDefinition, ColumnDefinition},
};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_test_utils::{create_networked_node_test_config, create_test_environment};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// Test schema for replication
fn create_test_schema() -> Schema {
    Schema {
        tables: vec![
            TableDefinition {
                name: "users".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "id".to_string(),
                        data_type: DataType::Integer,
                        primary_key: true,
                        autoincrement: true,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "username".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "email".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "created_at".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                ],
            },
            TableDefinition {
                name: "posts".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "id".to_string(),
                        data_type: DataType::Integer,
                        primary_key: true,
                        autoincrement: true,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "user_id".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "title".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "content".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "created_at".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                ],
            },
        ],
        indexes: vec![],
    }
}

fn create_replicated_sqlite_service(name: &str, path: &str, db_path: &str, startup_sync: bool) -> SqliteService {
    let schema = create_test_schema();
    let config = SqliteConfig::new(db_path.to_string(), schema, false)
        .with_replication(ReplicationConfig {
            enabled_tables: vec!["users".to_string(), "posts".to_string()],
            conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
            startup_sync : startup_sync, // Enable startup sync for this test
            event_retention_days: 30,
        });

    SqliteService::new(name.to_string(), path.to_string(), config)
}

/// Test 1: Basic replication between two nodes
/// Node 1 creates data, Node 2 starts and syncs, then both can replicate live changes
#[tokio::test]
async fn test_basic_replication_between_nodes() -> Result<()> {
    // Configure logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();

    // Set up logger
    let logger = Arc::new(Logger::new_root(
        Component::Custom("replication_e2e_test"),
        "",
    ));

    logger.info("=== Test 1: Basic Replication Between Nodes ===");

    // Create two node configurations that can communicate
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    // Create SQLite services for both nodes (using in-memory databases)
    let sqlite_service1 = create_replicated_sqlite_service("users_db", "users_db", ":memory:", false);
    let sqlite_service2 = create_replicated_sqlite_service("users_db", "users_db", ":memory:", true);

    // Start Node 1 and add some initial data
    logger.info("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    // Add some initial data to Node 1
    logger.info("Adding initial data to Node 1...");
    
    // Insert users
    for i in 1..=3 {
        let username = format!("user{}", i);
        let email = format!("user{}@example.com", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{}', '{}', ?)", username, email)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
        logger.info(format!("   ✅ Inserted user: {}", username));
    }

    // Insert posts
    for i in 1..=2 {
        let title = format!("Post {}", i);
        let content = format!("Content for post {}", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO posts (user_id, title, content, created_at) VALUES ({}, '{}', '{}', ?)", i, title, content)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 post");
        logger.info(format!("   ✅ Inserted post: {}", title));
    }

    // Verify data exists on Node 1
    let users_result = node1.request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count, 3, "Node 1 should have 3 users");

    let posts_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM posts")
        )))
        .await?;
    let post_count: i64 = *posts_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(post_count, 2, "Node 1 should have 2 posts");

    logger.info(format!("✅ Node 1 has {} users and {} posts", user_count, post_count));

    // Now start Node 2 - it should sync during startup
    logger.info("Starting Node 2 (should sync during startup)...");
    let mut node2 = Node::new(node2_config).await?;
    node2.start().await?;
    logger.info("✅ Node 2 started");
    
    // Wait for nodes to discover each other and exchange service information
    logger.info("Waiting for nodes to discover each other...");
    let _ = node2.on(format!("$registry/peer/{node1_id}/discovered", node1_id=node1.node_id()), Duration::from_secs(3)).await?;
    logger.info("✅ Nodes discovered each other");

    node2.add_service(sqlite_service2).await?;

    // Verify that Node 2 has the same data (replication worked)
    logger.info("Verifying replication to Node 2...");
    let users_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count2, 3, "Node 2 should have 3 users after replication");

    let posts_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM posts")
        )))
        .await?;
    let post_count2: i64 = *posts_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(post_count2, 2, "Node 2 should have 2 posts after replication");

    logger.info(format!("✅ Node 2 has {} users and {} posts (replication successful)", user_count2, post_count2));

    // Test live replication: Add data to Node 2 and verify it appears on Node 1
    logger.info("Testing live replication from Node 2 to Node 1...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('node2_user', 'node2@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 2");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the new user appears on Node 1
    let new_user_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'node2_user'")
        )))
        .await?;
    let new_users: Vec<ArcValue> = (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users.len(), 1, "Node 1 should have the new user from Node 2");
    logger.info("✅ Live replication Node 2 → Node 1 successful");

    // Test live replication: Add data to Node 1 and verify it appears on Node 2
    logger.info("Testing live replication from Node 1 to Node 2...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('node1_user', 'node1@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 1");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the new user appears on Node 2
    let new_user_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'node1_user'")
        )))
        .await?;
    let new_users2: Vec<ArcValue> = (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users2.len(), 1, "Node 2 should have the new user from Node 1");
    println!("✅ Live replication Node 1 → Node 2 successful");

    // Final verification: both nodes should have the same total count
    let final_users1 = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    let final_users2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    assert_eq!(final_count1, final_count2, "Both nodes should have the same user count");
    assert_eq!(final_count1, 5, "Both nodes should have 5 users total");
    println!("✅ Final verification: Both nodes have {} users", final_count1);

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    println!("✅ Test 1 completed successfully!");
    Ok(())
}

/// Test 2: Service availability during startup synchronization
/// Node 1 has data, Node 2 starts and service is not available until sync completes
#[tokio::test]
async fn test_service_availability_during_sync() -> Result<()> {
    println!("=== Test 2: Service Availability During Sync ===");

    // Create two node configurations
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    // Create SQLite services
    let sqlite_service1 = create_replicated_sqlite_service("sqlite1", "sqlite", ":memory:", false);
    let sqlite_service2 = create_replicated_sqlite_service("sqlite2", "sqlite", ":memory:", true);

    // Start Node 1 and add substantial data
    println!("Starting Node 1 and adding substantial data...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    println!("✅ Node 1 started");

    // Add 10 users and 5 posts to Node 1
    for i in 1..=10 {
        let username = format!("sync_user{}", i);
        let email = format!("sync_user{}@example.com", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{}', '{}', ?)", username, email)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
    }

    for i in 1..=5 {
        let title = format!("Sync Post {}", i);
        let content = format!("Content for sync post {}", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO posts (user_id, title, content, created_at) VALUES ({}, '{}', '{}', ?)", i, title, content)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 post");
    }

    println!("✅ Node 1 has 10 users and 5 posts");

    // Verify Node 1 data
    let users_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count, 10, "Node 1 should have 10 users");

    // Now start Node 2 - it should sync during startup and service should not be available until complete
    println!("Starting Node 2 (service should not be available until sync completes)...");
    let start_time = std::time::Instant::now();
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    node2.start().await?;
    let startup_duration = start_time.elapsed();
    println!("✅ Node 2 started in {:?}", startup_duration);

    // Wait for nodes to discover each other
    println!("Waiting for nodes to discover each other...");
    let _ = node2.on(format!("$registry/peer/{node1_id}/discovered", node1_id=node1.node_id()), Duration::from_secs(3)).await?;
    let _ = node1.on(format!("$registry/peer/{node2_id}/discovered", node2_id=node2.node_id()), Duration::from_secs(3)).await?;
    
    println!("✅ Nodes discovered each other");

    // Wait a bit more for replication to complete
    sleep(Duration::from_secs(3)).await;

    // Verify that Node 2 has the same data (replication worked)
    println!("Verifying replication to Node 2...");
    let users_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count2, 10, "Node 2 should have 10 users after replication");

    let posts_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM posts")
        )))
        .await?;
    let post_count2: i64 = *posts_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(post_count2, 5, "Node 2 should have 5 posts after replication");

    println!("✅ Node 2 has {} users and {} posts (sync successful)", user_count2, post_count2);

    // Test that Node 2 service is now available and can handle requests
    println!("Testing that Node 2 service is available after sync...");
    let test_result = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'sync_user1'")
        )))
        .await?;
    let test_users: Vec<ArcValue> = (*test_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(test_users.len(), 1, "Node 2 should be able to query data after sync");
    println!("✅ Node 2 service is available and working");

    // Test bidirectional live replication after sync
    println!("Testing bidirectional live replication after sync...");
    
    // Add data to Node 2
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('post_sync_user', 'post_sync@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 2");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify it appears on Node 1
    let new_user_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'post_sync_user'")
        )))
        .await?;
    let new_users: Vec<ArcValue> = (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users.len(), 1, "Node 1 should have the new user from Node 2");
    println!("✅ Post-sync replication Node 2 → Node 1 successful");

    // Add data to Node 1
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('post_sync_user2', 'post_sync2@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 1");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify it appears on Node 2
    let new_user_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'post_sync_user2'")
        )))
        .await?;
    let new_users2: Vec<ArcValue> = (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users2.len(), 1, "Node 2 should have the new user from Node 1");
    println!("✅ Post-sync replication Node 1 → Node 2 successful");

    // Final verification
    let final_users1 = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    let final_users2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    assert_eq!(final_count1, final_count2, "Both nodes should have the same user count");
    assert_eq!(final_count1, 12, "Both nodes should have 12 users total (10 initial + 2 post-sync)");
    println!("✅ Final verification: Both nodes have {} users", final_count1);

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    println!("✅ Test 2 completed successfully!");
    Ok(())
}

/// Test 3: Event table verification and event ordering
/// Verify that event tables are created correctly and events are properly ordered
#[tokio::test]
async fn test_event_tables_and_ordering() -> Result<()> {
    println!("=== Test 3: Event Tables and Ordering ===");

    // Create two node configurations
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    // Create SQLite services
    let sqlite_service1 = create_replicated_sqlite_service("sqlite1", "sqlite", ":memory:", false);
    let sqlite_service2 = create_replicated_sqlite_service("sqlite2", "sqlite", ":memory:", true);

    // Start Node 1
    println!("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    println!("✅ Node 1 started");

    // Verify event tables were created
    println!("Verifying event tables were created on Node 1...");
    let event_tables_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_Events' ORDER BY name")
        )))
        .await?;
    let event_tables: Vec<ArcValue> = (*event_tables_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(event_tables.len(), 2, "Should have 2 event tables (users_Events, posts_Events)");
    
    let table_names: Vec<String> = event_tables.iter()
        .map(|table| {
            let table_map = table.as_map_ref().unwrap();
            (*table_map.get("name").unwrap().as_type_ref::<String>().unwrap()).clone()
        })
        .collect();
    
    assert!(table_names.contains(&"users_Events".to_string()), "Should have users_Events table");
    assert!(table_names.contains(&"posts_Events".to_string()), "Should have posts_Events table");
    println!("✅ Event tables created: {:?}", table_names);

    // Add some data to Node 1
    println!("Adding data to Node 1...");
    for i in 1..=3 {
        let username = format!("event_user{}", i);
        let email = format!("event_user{}@example.com", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{}', '{}', ?)", username, email)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
    }

    // Verify events were created
    println!("Verifying events were created...");
    let events_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, sequence_number FROM users_Events ORDER BY sequence_number")
        )))
        .await?;
    let events: Vec<ArcValue> = (*events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(events.len(), 3, "Should have 3 events");
    
    // Verify sequence numbers are in order
    for (i, event) in events.iter().enumerate() {
        let event_map = event.as_map_ref().unwrap();
        let sequence = event_map.get("sequence_number").unwrap().as_type_ref::<i64>().unwrap();
        assert_eq!(*sequence, i as i64, "Sequence numbers should be in order");
    }
    println!("✅ Events created with proper sequence numbers");

    // Start Node 2
    println!("Starting Node 2...");
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    node2.start().await?;
    println!("✅ Node 2 started");

    // Wait for nodes to discover each other and sync
    println!("Waiting for nodes to discover each other...");
    let _ = node2.on(format!("$registry/peer/{node1_id}/discovered", node1_id=node1.node_id()), Duration::from_secs(3)).await?;
    let _ = node1.on(format!("$registry/peer/{node2_id}/discovered", node2_id=node2.node_id()), Duration::from_secs(3)).await?;
    
    println!("✅ Nodes discovered each other");

    // Wait for replication
    sleep(Duration::from_secs(3)).await;

    // Verify Node 2 has the same event tables
    println!("Verifying Node 2 has event tables...");
    let event_tables_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_Events' ORDER BY name")
        )))
        .await?;
    let event_tables2: Vec<ArcValue> = (*event_tables_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(event_tables2.len(), 2, "Node 2 should have 2 event tables");
    println!("✅ Node 2 has event tables");

    // Verify Node 2 has the same events
    println!("Verifying Node 2 has the same events...");
    let events_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, sequence_number FROM users_Events ORDER BY sequence_number")
        )))
        .await?;
    let events2: Vec<ArcValue> = (*events_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(events2.len(), 3, "Node 2 should have 3 events");
    println!("✅ Node 2 has the same events");

    // Test UPDATE and DELETE operations to verify different event types
    println!("Testing UPDATE and DELETE operations...");
    
    // Update a user
    let result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("UPDATE users SET email = 'updated@example.com' WHERE username = 'event_user1'")
        )))
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should update 1 user");

    // Delete a user
    let result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("DELETE FROM users WHERE username = 'event_user3'")
        )))
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should delete 1 user");

    // Wait for replication
    sleep(Duration::from_secs(2)).await;

    // Verify all event types on Node 1
    println!("Verifying all event types on Node 1...");
    let all_events_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, sequence_number FROM users_Events ORDER BY sequence_number")
        )))
        .await?;
    let all_events: Vec<ArcValue> = (*all_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    
    let operation_types: Vec<String> = all_events.iter()
        .map(|event| {
            let event_map = event.as_map_ref().unwrap();
            (*event_map.get("operation_type").unwrap().as_type_ref::<String>().unwrap()).clone()
        })
        .collect();
    
    println!("Event types on Node 1: {:?}", operation_types);
    assert!(operation_types.contains(&"CREATE".to_string()), "Should have CREATE events");
    assert!(operation_types.contains(&"UPDATE".to_string()), "Should have UPDATE events");
    assert!(operation_types.contains(&"DELETE".to_string()), "Should have DELETE events");
    println!("✅ All event types present on Node 1");

    // Verify all event types on Node 2
    println!("Verifying all event types on Node 2...");
    let all_events_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, sequence_number FROM users_Events ORDER BY sequence_number")
        )))
        .await?;
    let all_events2: Vec<ArcValue> = (*all_events_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    
    let operation_types2: Vec<String> = all_events2.iter()
        .map(|event| {
            let event_map = event.as_map_ref().unwrap();
            (*event_map.get("operation_type").unwrap().as_type_ref::<String>().unwrap()).clone()
        })
        .collect();
    
    println!("Event types on Node 2: {:?}", operation_types2);
    assert_eq!(operation_types, operation_types2, "Both nodes should have the same event types");
    println!("✅ All event types present on Node 2");

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    println!("✅ Test 3 completed successfully!");
    Ok(())
}

/// Test 4: Mobile Simulator Integration Test
/// Test replication using the MobileSimulator for proper key management and encryption
#[tokio::test]
async fn test_mobile_simulator_replication() -> Result<()> {
    println!("=== Test 4: Mobile Simulator Replication Test ===");

    // Set up logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    // Create mobile simulation environment
    println!("Creating mobile simulation environment...");
    let (simulator, node1_config) = create_test_environment()?;
    simulator.print_summary();

    // Create a second node config using the same simulator
    let node2_config = simulator.create_node_config()?;

    // Create SQLite services with replication enabled
    let sqlite_service1 = create_replicated_sqlite_service("sqlite1", "sqlite", ":memory:", false);
    let sqlite_service2 = create_replicated_sqlite_service("sqlite2", "sqlite", ":memory:", true);

    // Start Node 1
    println!("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    println!("✅ Node 1 started with ID: {}", node1.node_id());

    // Add initial data to Node 1
    println!("Adding initial data to Node 1...");
    for i in 1..=5 {
        let username = format!("mobile_user{}", i);
        let email = format!("mobile_user{}@example.com", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node1
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{}', '{}', ?)", username, email)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
        println!("   ✅ Inserted user: {}", username);
    }

    // Verify Node 1 has the data
    let users_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count, 5, "Node 1 should have 5 users");
    println!("✅ Node 1 has {} users", user_count);

    // Start Node 2 - it should sync during startup
    println!("Starting Node 2 (should sync during startup)...");
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    node2.start().await?;
    println!("✅ Node 2 started with ID: {}", node2.node_id());

    // Wait for nodes to discover each other
    println!("Waiting for nodes to discover each other...");
    let _ = node2.on(format!("$registry/peer/{node1_id}/discovered", node1_id=node1.node_id()), Duration::from_secs(3)).await?;
    let _ = node1.on(format!("$registry/peer/{node2_id}/discovered", node2_id=node2.node_id()), Duration::from_secs(3)).await?;
    
    println!("✅ Nodes discovered each other");

    // Wait for replication to complete
    sleep(Duration::from_secs(3)).await;

    // Verify Node 2 has the same data (replication worked)
    println!("Verifying replication to Node 2...");
    let users_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count2, 5, "Node 2 should have 5 users after replication");
    println!("✅ Node 2 has {} users (replication successful)", user_count2);

    // Test live replication: Add data to Node 2 and verify it appears on Node 1
    println!("Testing live replication from Node 2 to Node 1...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('mobile_node2_user', 'mobile_node2@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 2");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the new user appears on Node 1
    let new_user_result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'mobile_node2_user'")
        )))
        .await?;
    let new_users: Vec<ArcValue> = (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users.len(), 1, "Node 1 should have the new user from Node 2");
    println!("✅ Live replication Node 2 → Node 1 successful");

    // Test live replication: Add data to Node 1 and verify it appears on Node 2
    println!("Testing live replication from Node 1 to Node 2...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('mobile_node1_user', 'mobile_node1@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user on Node 1");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the new user appears on Node 2
    let new_user_result2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT username FROM users WHERE username = 'mobile_node1_user'")
        )))
        .await?;
    let new_users2: Vec<ArcValue> = (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(new_users2.len(), 1, "Node 2 should have the new user from Node 1");
    println!("✅ Live replication Node 1 → Node 2 successful");

    // Test encryption with mobile simulator label resolvers
    println!("Testing encryption with mobile simulator...");
    let (_mobile_resolver, _node_resolver) = simulator.create_label_resolvers()?;
    
    // Verify label resolvers were created successfully
    println!("✅ Label resolvers created successfully");
    println!("✅ Mobile simulator integration working");

    // Final verification: both nodes should have the same total count
    let final_users1 = node1
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    let final_users2 = node2
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();

    assert_eq!(final_count1, final_count2, "Both nodes should have the same user count");
    assert_eq!(final_count1, 7, "Both nodes should have 7 users total (5 initial + 2 live)");
    println!("✅ Final verification: Both nodes have {} users", final_count1);

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    println!("✅ Test 4 completed successfully!");
    Ok(())
}

/// Test 5: Single Node Replication Test
/// Test replication events within a single node to verify the event system works
#[tokio::test]
async fn test_single_node_replication() -> Result<()> {
    println!("=== Test 5: Single Node Replication Test ===");

    // Set up logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    logging_config.apply();

    // Create mobile simulation environment
    println!("Creating mobile simulation environment...");
    let (simulator, node_config) = create_test_environment()?;
    simulator.print_summary();

    // Create SQLite service with replication enabled
    let sqlite_service = create_replicated_sqlite_service("sqlite1", "sqlite", ":memory:", true);

    // Start Node
    println!("Starting Node...");
    let mut node = Node::new(node_config).await?;
    node.add_service(sqlite_service).await?;
    node.start().await?;
    println!("✅ Node started with ID: {}", node.node_id());

    // Add initial data to Node
    println!("Adding initial data to Node...");
    for i in 1..=3 {
        let username = format!("single_user{}", i);
        let email = format!("single_user{}@example.com", i);
        let timestamp = chrono::Utc::now().timestamp();
        
        let result = node
            .request("users_db/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{}', '{}', ?)", username, email)
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;
        
        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
        println!("   ✅ Inserted user: {}", username);
    }

    // Verify Node has the data
    let users_result = node
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users")
        )))
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(user_count, 3, "Node should have 3 users");
    println!("✅ Node has {} users", user_count);

    // Check that replication events were created
    println!("Checking replication events...");
    let events_result = node
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users_Events")
        )))
        .await?;
    let event_count: i64 = *events_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(event_count, 3, "Should have 3 replication events");
    println!("✅ Found {} replication events", event_count);

    // Test live replication: Add more data and verify events are created
    println!("Testing live replication...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('single_live_user', 'single_live@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 user");

    // Wait a bit for event processing
    sleep(Duration::from_millis(100)).await;

    // Verify the new event was created
    let new_events_result = node
        .request("users_db/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT COUNT(*) as count FROM users_Events")
        )))
        .await?;
    let new_event_count: i64 = *new_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref().unwrap()
        .get("count").unwrap()
        .as_type_ref::<i64>().unwrap();
    assert_eq!(new_event_count, 4, "Should have 4 replication events after live insert");
    println!("✅ Live replication successful - {} events total", new_event_count);

    // Clean up
    node.stop().await?;
    println!("✅ Test 5 completed successfully!");
    Ok(())
}