use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_services::{
    replication::{ConflictResolutionStrategy, ReplicationConfig},
    sqlite::{ColumnDefinition, DataType, Schema, SqliteConfig, SqliteService, TableDefinition},
};
use runar_test_utils::{create_networked_node_test_config, create_test_environment};
use serial_test::serial;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

fn create_replicated_sqlite_service(
    name: &str,
    path: &str,
    db_path: &str,
    startup_sync: bool,
) -> SqliteService {
    let schema = create_test_schema();
    let config = SqliteConfig::new(db_path, schema, false).with_replication(ReplicationConfig {
        enabled_tables: vec!["users".to_string(), "posts".to_string()],
        conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
        startup_sync, // Enable startup sync for this test
        event_retention_days: 30,
        wait_remote_service_timeout: 25,
        past_events_window: 10,
    });

    SqliteService::new(name, path, config)
}

/// Clean up database files to ensure test isolation
fn cleanup_database_files() {
    let logger = Arc::new(Logger::new_root(Component::Custom("test")));
    let db_files = vec![
        "./node_1_db",
        "./node_1_db-shm",
        "./node_1_db-wal",
        "./node_2_db",
        "./node_2_db-shm",
        "./node_2_db-wal",
        "./node_3_db",
        "./node_3_db-shm",
        "./node_3_db-wal",
    ];

    for db_file in db_files {
        if Path::new(db_file).exists() {
            if let Err(e) = fs::remove_file(db_file) {
                logger.info(format!(
                    "Warning: Failed to remove database file {db_file}: {e}"
                ));
            }
        }
    }
}

/// Test 1: Basic replication between two nodes
/// Node 1 creates data, Node 2 starts and syncs, then both can replicate live changes
#[tokio::test]
#[serial]
async fn test_basic_replication_between_nodes() -> Result<()> {
    // Configure logging
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();

    // Set up logger
    let logger = Arc::new(Logger::new_root(Component::Custom("replication_e2e_test")));

    logger.info("=== Test 1: Basic Replication Between Nodes ===");

    // Create two node configurations that can communicate
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    // Create SQLite services for both nodes (using in-memory databases)
    let sqlite_service1 =
        create_replicated_sqlite_service("users_db_test_1", "users_db_test_1", ":memory:", false);
    let sqlite_service2 =
        create_replicated_sqlite_service("users_db_test_1", "users_db_test_1", ":memory:", true);

    // Start Node 1 and add some initial data
    logger.info("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started");
    // Add some initial data to Node 1
    logger.info("Adding initial data to Node 1...");

    // Insert users
    for i in 1..=3 {
        let username = format!("user{i}");
        let email = format!("user{i}@example.com");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_1/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{username}', '{email}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
        logger.info(format!("   ✅ Inserted user: {username}"));
    }

    // Insert posts
    for i in 1..=2 {
        let title = format!("Post {i}");
        let content = format!("Content for post {i}");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_1/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO posts (user_id, title, content, created_at) VALUES ({i}, '{title}', '{content}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 post");
        logger.info(format!("   ✅ Inserted post: {title}"));
    }

    // Verify data exists on Node 1
    let users_result = node1
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(user_count, 3, "Node 1 should have 3 users");

    let posts_result = node1
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM posts",
            ))),
        )
        .await?;
    let post_count: i64 = *posts_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(post_count, 2, "Node 1 should have 2 posts");

    logger.info(format!(
        "✅ Node 1 has {user_count} users and {post_count} posts"
    ));

    // Now start Node 2 - it should sync during startup
    logger.info("Starting Node 2 (should sync during startup)...");
    let mut node2 = Node::new(node2_config).await?;
    // Pre-register discovery before starting Node 2
    let node1_discovered_by_node2 = node2.on(
        format!(
            "$registry/peer/{node1_id}/discovered",
            node1_id = node1.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node2.start().await?;
    logger.info("✅ Node 2 started");

    // Wait for nodes to discover each other and exchange service information
    logger.info("Waiting for nodes to discover each other...");
    let _ = node1_discovered_by_node2.await?;
    logger.info("✅ Nodes discovered each other");

    node2.add_service(sqlite_service2).await?;

    // Verify that Node 2 has the same data (replication worked)
    logger.info("Verifying replication to Node 2...");
    let users_result2 = node2
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        user_count2, 3,
        "Node 2 should have 3 users after replication"
    );

    let posts_result2 = node2
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM posts",
            ))),
        )
        .await?;
    let post_count2: i64 = *posts_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        post_count2, 2,
        "Node 2 should have 2 posts after replication"
    );

    logger.info(format!(
        "✅ Node 2 has {user_count2} users and {post_count2} posts (replication successful)"
    ));

    // Test live replication: Add data to Node 2 and verify it appears on Node 1
    logger.info("Testing live replication from Node 2 to Node 1...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .local_request("users_db_test_1/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'node2_user'",
            ))),
        )
        .await?;
    let new_users: Vec<ArcValue> =
        (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users.len(),
        1,
        "Node 1 should have the new user from Node 2"
    );
    logger.info("✅ Live replication Node 2 → Node 1 successful");

    // Test live replication: Add data to Node 1 and verify it appears on Node 2
    logger.info("Testing live replication from Node 1 to Node 2...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .local_request("users_db_test_1/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'node1_user'",
            ))),
        )
        .await?;
    let new_users2: Vec<ArcValue> =
        (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users2.len(),
        1,
        "Node 2 should have the new user from Node 1"
    );
    logger.info("✅ Live replication Node 1 → Node 2 successful");

    // Final verification: both nodes should have the same total count
    let final_users1 = node1
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    let final_users2 = node2
        .local_request(
            "users_db_test_1/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    assert_eq!(
        final_count1, final_count2,
        "Both nodes should have the same user count"
    );
    assert_eq!(final_count1, 5, "Both nodes should have 5 users total");
    logger.info(format!(
        "✅ Final verification: Both nodes have {final_count1} users"
    ));

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    logger.info("✅ Test 1 completed successfully!");
    Ok(())
}

/// Test 2: Service availability during startup synchronization
/// Node 1 has data, Node 2 starts and service is not available until sync completes
#[tokio::test]
#[serial]
async fn test_full_replication_between_nodes() -> Result<()> {
    // Clean up any existing database files
    cleanup_database_files();

    // Create two node configurations
    let configs = create_networked_node_test_config(3)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::Custom("test")));

    // Create SQLite services
    //node1 uses a file db becaue it will stop and start again and must retain its data
    let sqlite_service1 =
        create_replicated_sqlite_service("sqlite_test", "users_db_test_2", "./node_1_db", false);
    let sqlite_service2 =
        create_replicated_sqlite_service("sqlite_test", "users_db_test_2", ":memory:", true);

    // Start Node 1 and add substantial data
    logger.info("Starting Node 1 and adding substantial data...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started");

    // Add 10 users and 5 posts to Node 1
    for i in 1..=10 {
        let username = format!("sync_user{i}");
        let email = format!("sync_user{i}@example.com");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{username}', '{email}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
    }

    for i in 1..=5 {
        let title = format!("Sync Post {i}");
        let content = format!("Content for sync post {i}");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO posts (user_id, title, content, created_at) VALUES ({i}, '{title}', '{content}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 post");
    }

    logger.info("✅ Node 1 has 10 users and 5 posts");

    // Verify Node 1 data
    let users_result = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(user_count, 10, "Node 1 should have 10 users");

    // Now start Node 2 - it should sync during startup and service should not be available until complete
    logger.info("Starting Node 2 (service should not be available until sync completes)...");
    let start_time = std::time::Instant::now();
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    // Pre-register discovery before starting Node 2
    let node1_discovered_by_node2 = node2.on(
        format!(
            "$registry/peer/{node1_id}/discovered",
            node1_id = node1.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    let node2_discovered_by_node1 = node1.on(
        format!(
            "$registry/peer/{node2_id}/discovered",
            node2_id = node2.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node2.start().await?;
    let startup_duration = start_time.elapsed();
    logger.info(format!("✅ Node 2 started in {startup_duration:?}"));

    // Wait for nodes to discover each other
    logger.info("Waiting for nodes to discover each other...");
    let _ = node1_discovered_by_node2.await?;
    let _ = node2_discovered_by_node1.await?;

    logger.info("✅ Nodes discovered each other");

    node2.wait_for_services_to_start().await?;
    let node2_start_sync_duration = start_time.elapsed();
    logger.info(format!(
        "✅ Node 2 services started and sync completed in {node2_start_sync_duration:?}"
    ));

    // Verify that Node 2 has the same data (replication worked)
    logger.info("Verifying replication to Node 2...");
    let users_result2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        user_count2, 10,
        "Node 2 should have 10 users after replication"
    );

    let posts_result2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM posts",
            ))),
        )
        .await?;
    let post_count2: i64 = *posts_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        post_count2, 5,
        "Node 2 should have 5 posts after replication"
    );

    logger.info(format!(
        "✅ Node 2 has {user_count2} users and {post_count2} posts (sync successful)"
    ));

    logger.info("Check a specific record after sync...");
    let test_result = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user1'",
            ))),
        )
        .await?;
    let test_users: Vec<ArcValue> = (*test_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        test_users.len(),
        1,
        "Node 2 should be able to query data after sync"
    );
    logger.info("✅ Node 2 service is available and working");

    //check events table on node1
    let events_result1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let events1: Vec<ArcValue> = (*events_result1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        events1.len(),
        10,
        "Node 1 should have 10 events on users_Events table"
    );
    logger.info("✅ Node 1 has 10 events on users_Events table");

    //check events table on node2
    let events_result2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let events2: Vec<ArcValue> = (*events_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        events2.len(),
        10,
        "Node 2 should have 10 events on users_Events table"
    );
    logger.info("✅ Node 2 has 10 events on users_Events table");

    // Test bidirectional live replication after sync
    logger.info("Testing bidirectional live replication after sync...");

    // Add data to Node 2
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username, email FROM users WHERE username = 'post_sync_user'",
            ))),
        )
        .await?;
    let new_users: Vec<ArcValue> =
        (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users.len(),
        1,
        "Node 1 should have the new user from Node 2"
    );
    //assert whole record
    let post_sync_user = new_users[0].as_map_ref().expect("Should be a map");
    let username = post_sync_user
        .get("username")
        .expect("Should have username")
        .as_type::<String>()
        .expect("username should be a string");
    assert_eq!(
        username, "post_sync_user",
        "Username should be post_sync_user"
    );
    let email = post_sync_user
        .get("email")
        .expect("Should have email")
        .as_type::<String>()
        .expect("email should be a string");
    assert_eq!(
        email, "post_sync@example.com",
        "Email should be post_sync@example.com"
    );
    logger.info("✅ Post-sync replication Node 2 → Node 1 successful");

    // Add data to Node 1
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'post_sync_user2'",
            ))),
        )
        .await?;
    let new_users2: Vec<ArcValue> =
        (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users2.len(),
        1,
        "Node 2 should have the new user from Node 1"
    );
    logger.info("✅ Post-sync replication Node 1 → Node 2 successful");

    // Final verification
    let final_users1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    let final_users2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    assert_eq!(
        final_count1, final_count2,
        "Both nodes should have the same user count"
    );
    assert_eq!(
        final_count1, 12,
        "Both nodes should have 12 users total (10 initial + 2 post-sync)"
    );
    logger.info(format!(
        "✅ Final verification: Both nodes have {final_count1} users"
    ));

    //lets add a third node to make sure it can sync with the other two
    let node3_config = configs[2].clone();

    //stop node 1 - which was the first node to start
    //so node3 will sync from node2
    node1.stop().await?;
    logger.info("✅ Node 1 stopped");

    // Create SQLite services
    let sqlite_service3 =
        create_replicated_sqlite_service("sqlite_test", "users_db_test_2", ":memory:", true);

    logger.info("Starting Node 3 and sync.");
    let mut node3 = Node::new(node3_config).await?;
    node3.add_service(sqlite_service3).await?;

    let on_node2_found = node3.on(
        format!(
            "$registry/peer/{node2_id}/discovered",
            node2_id = node2.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    let on_node3_found = node2.on(
        format!(
            "$registry/peer/{node3_id}/discovered",
            node3_id = node3.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node3.start().await?;
    logger.info("✅ Node 3 started");
    node3.wait_for_services_to_start().await?;

    logger.info("✅ Node 3 service started and data sync completed");

    logger.info("Waiting for nodes to discover each other...");
    let _ = tokio::join!(on_node2_found, on_node3_found);
    logger.info("✅ Node3 discovered node 2");

    //check that contain all the data the the other nodes has
    //check users
    let users_result3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count3: i64 = *users_result3.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        user_count3, 12,
        "Node 3 should have 12 users after initial replication"
    );

    // Test UPDATE operations: Change records in Node 3 and verify they're updated in Node 1 and Node 2
    logger.info("Testing UPDATE operations from Node 3...");

    // Update a user on Node 3
    let result = node3
        .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("UPDATE users SET email = 'updated_by_node3@example.com' WHERE username = 'sync_user2'")
        )))
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should update 1 user on Node 3");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the update appears on Node 2
    let update_result2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT email FROM users WHERE username = 'sync_user2'",
            ))),
        )
        .await?;
    let update_users2: Vec<ArcValue> =
        (*update_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        update_users2.len(),
        1,
        "Node 2 should have the updated user"
    );
    let email2 = update_users2[0]
        .as_map_ref()
        .expect("Should be a map")
        .get("email")
        .expect("Should have email")
        .as_type::<String>()
        .expect("email should be a string");
    assert_eq!(
        email2, "updated_by_node3@example.com",
        "Email should be updated by Node 3"
    );
    logger.info("✅ UPDATE replication Node 3 → Node 2 successful");

    // Test DELETE operations: Remove record on Node 2 and verify it's removed in Node 1 and Node 3
    logger.info("Testing DELETE operations from Node 2...");

    // Delete a user on Node 2
    let result = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "DELETE FROM users WHERE username = 'sync_user5'",
            ))),
        )
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should delete 1 user on Node 2");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify the deletion appears on Node 3
    let delete_result3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user5'",
            ))),
        )
        .await?;
    let delete_users3: Vec<ArcValue> =
        (*delete_result3.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        delete_users3.len(),
        0,
        "Node 3 should not have the deleted user"
    );
    logger.info("✅ DELETE replication Node 2 → Node 3 successful");

    // Test complex scenario: Multiple operations from different nodes
    logger.info("Testing complex scenario with multiple operations from different nodes...");

    //restart node 1 -  it uses a file db - so it can be restarted
    drop(node1);

    //create new node1 from same config
    let mut node1 = Node::new(configs[0].clone()).await?;
    let sqlite_service1 =
        create_replicated_sqlite_service("sqlite_test", "users_db_test_2", "./node_1_db", true);
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    node1
        .on(
            format!(
                "$registry/peer/{node2_id}/discovered",
                node2_id = node2.node_id()
            ),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: Some(Duration::from_secs(10)),
            }),
        )
        .await??;
    node1
        .on(
            format!(
                "$registry/peer/{node3_id}/discovered",
                node3_id = node3.node_id()
            ),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: Some(Duration::from_secs(10)),
            }),
        )
        .await??;
    logger.info("✅ Node 1 connected to node 2 and node 3");
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started and data is synced");

    // Verify that Node 1 has synced with the network and received all changes that happened while it was stopped
    logger.info("Verifying Node 1 has synced with network after restart...");

    // Check that Node 1 has the same user count as other nodes (should be 11 after the UPDATE and DELETE operations)
    let restart_count1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let restart_user_count1: i64 = *restart_count1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        restart_user_count1, 11,
        "Node 1 should have 11 users after syncing (startup sync applies the DELETE)"
    );
    logger.info(format!(
        "✅ Node 1 has correct user count after restart: {restart_user_count1}"
    ));

    // Verify that Node 1 received the UPDATE operation from Node 3 (sync_user2 email update)
    let update_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT email FROM users WHERE username = 'sync_user2'",
            ))),
        )
        .await?;
    let update_users1: Vec<ArcValue> =
        (*update_check1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        update_users1.len(),
        1,
        "Node 1 should have sync_user2 after restart"
    );
    let email1 = update_users1[0]
        .as_map_ref()
        .expect("Should be a map")
        .get("email")
        .expect("Should have email")
        .as_type::<String>()
        .expect("email should be a string");
    assert_eq!(
        email1, "updated_by_node3@example.com",
        "Node 1 should have received the UPDATE from Node 3"
    );
    logger.info("✅ Node 1 received UPDATE operation from Node 3");

    // Verify that Node 1 received the DELETE operation from Node 2 (sync_user5 deletion)
    let delete_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user5'",
            ))),
        )
        .await?;
    let delete_users1: Vec<ArcValue> =
        (*delete_check1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        delete_users1.len(),
        0,
        "Node 1 should not have sync_user5 after restart (was deleted by Node 2)"
    );
    logger.info("✅ Node 1 received DELETE operation from Node 2");

    // Verify that Node 1 still has the post-sync users that were added before it was stopped
    let post_sync_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'post_sync_user'",
            ))),
        )
        .await?;
    let post_sync_users1: Vec<ArcValue> =
        (*post_sync_check1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        post_sync_users1.len(),
        1,
        "Node 1 should still have post_sync_user after restart"
    );
    logger.info("✅ Node 1 retained existing data and received all network changes");

    logger.info("✅ Node 1 successfully synced with network after restart - all changes from other nodes are present");

    // Node 1: Add a new user
    let timestamp = chrono::Utc::now().timestamp();
    let result1 = node1
        .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('complex_user1', 'complex1@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(timestamp))
            )
        )))
        .await?;
    let affected_rows1: i64 = *result1.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows1, 1, "Should insert 1 user on Node 1");

    // Node 2: Update a different user
    let result2 = node2
        .local_request("users_db_test_2/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("UPDATE users SET email = 'complex_updated@example.com' WHERE username = 'sync_user3'")
        )))
        .await?;
    let affected_rows2: i64 = *result2.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows2, 1, "Should update 1 user on Node 2");

    // Node 3: Delete another user
    let result3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "DELETE FROM users WHERE username = 'sync_user7'",
            ))),
        )
        .await?;
    let affected_rows3: i64 = *result3.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows3, 1, "Should delete 1 user on Node 3");

    // Wait for all replications to complete
    sleep(Duration::from_secs(1)).await;

    // Verify all nodes have consistent state
    logger.info("Verifying all nodes have consistent state after complex operations...");

    // Check final counts on all nodes
    let final_count1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let count1: i64 = *final_count1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    let final_count2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let count2: i64 = *final_count2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    let final_count3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let count3: i64 = *final_count3.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    assert_eq!(
        count1, count2,
        "Node 1 and Node 2 should have the same user count"
    );
    assert_eq!(
        count2, count3,
        "Node 2 and Node 3 should have the same user count"
    );
    assert_eq!(
        count1, 11,
        "All nodes should have 11 users total (12 initial - 2 deleted + 1 added)"
    );
    logger.info(format!(
        "✅ All nodes have consistent state: {count1} users each"
    ));

    // Verify specific operations propagated correctly
    // Check that complex_user1 exists on all nodes
    let complex_user_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'complex_user1'",
            ))),
        )
        .await?;
    let complex_users1: Vec<ArcValue> =
        (*complex_user_check1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(complex_users1.len(), 1, "Node 1 should have complex_user1");

    let complex_user_check2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'complex_user1'",
            ))),
        )
        .await?;
    let complex_users2: Vec<ArcValue> =
        (*complex_user_check2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(complex_users2.len(), 1, "Node 2 should have complex_user1");

    let complex_user_check3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'complex_user1'",
            ))),
        )
        .await?;
    let complex_users3: Vec<ArcValue> =
        (*complex_user_check3.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(complex_users3.len(), 1, "Node 3 should have complex_user1");

    // Check that sync_user3 was updated on all nodes
    let update_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT email FROM users WHERE username = 'sync_user3'",
            ))),
        )
        .await?;
    let update_email1 = update_check1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("email")
        .unwrap()
        .as_type_ref::<String>()
        .unwrap();
    assert_eq!(
        *update_email1, "complex_updated@example.com",
        "Node 1 should have updated email"
    );

    let update_check2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT email FROM users WHERE username = 'sync_user3'",
            ))),
        )
        .await?;
    let update_email2 = update_check2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("email")
        .unwrap()
        .as_type_ref::<String>()
        .unwrap();
    assert_eq!(
        *update_email2, "complex_updated@example.com",
        "Node 2 should have updated email"
    );

    let update_check3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT email FROM users WHERE username = 'sync_user3'",
            ))),
        )
        .await?;
    let update_email3 = update_check3.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("email")
        .unwrap()
        .as_type_ref::<String>()
        .unwrap();
    assert_eq!(
        *update_email3, "complex_updated@example.com",
        "Node 3 should have updated email"
    );

    // Check that sync_user7 was deleted from all nodes
    let delete_check1 = node1
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user7'",
            ))),
        )
        .await?;
    let delete_users1: Vec<ArcValue> =
        (*delete_check1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(delete_users1.len(), 0, "Node 1 should not have sync_user7");

    let delete_check2 = node2
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user7'",
            ))),
        )
        .await?;
    let delete_users2: Vec<ArcValue> =
        (*delete_check2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(delete_users2.len(), 0, "Node 2 should not have sync_user7");

    let delete_check3 = node3
        .local_request(
            "users_db_test_2/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'sync_user7'",
            ))),
        )
        .await?;
    let delete_users3: Vec<ArcValue> =
        (*delete_check3.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(delete_users3.len(), 0, "Node 3 should not have sync_user7");

    logger.info("✅ Complex multi-node operations completed successfully");

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    node3.stop().await?;
    cleanup_database_files();
    logger.info("✅ Test 2 completed successfully!");
    Ok(())
}

/// Test 3: Event table verification and event ordering
/// Verify that event tables are created correctly and events are properly ordered
#[tokio::test]
#[serial]
async fn test_event_tables_and_ordering() -> Result<()> {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::Custom("test")));
    logger.info("=== Test 3: Event Tables and Ordering ===");

    // Create two node configurations
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    // Create SQLite services
    let sqlite_service1 =
        create_replicated_sqlite_service("sqlite_service", "users_db_test_3", ":memory:", false);
    let sqlite_service2 =
        create_replicated_sqlite_service("sqlite_service", "users_db_test_3", ":memory:", true);

    // Start Node 1
    logger.info("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started");

    // Verify event tables were created
    logger.info("Verifying event tables were created on Node 1...");
    let event_tables_result = node1
        .local_request("users_db_test_3/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_Events' ORDER BY name")
        )))
        .await?;
    let event_tables: Vec<ArcValue> =
        (*event_tables_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        event_tables.len(),
        2,
        "Should have 2 event tables (users_Events, posts_Events)"
    );

    let table_names: Vec<String> = event_tables
        .iter()
        .map(|table| {
            let table_map = table.as_map_ref().unwrap();
            (*table_map
                .get("name")
                .unwrap()
                .as_type_ref::<String>()
                .unwrap())
            .clone()
        })
        .collect();

    assert!(
        table_names.contains(&"users_Events".to_string()),
        "Should have users_Events table"
    );
    assert!(
        table_names.contains(&"posts_Events".to_string()),
        "Should have posts_Events table"
    );
    logger.info(format!("✅ Event tables created: {table_names:?}"));

    // Add some data to Node 1
    logger.info("Adding data to Node 1...");
    for i in 1..=3 {
        let username = format!("event_user{i}");
        let email = format!("event_user{i}@example.com");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_3/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{username}', '{email}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
    }

    // Verify events were created
    logger.info("Verifying events were created...");
    let events_result = node1
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT operation_type, timestamp FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let events: Vec<ArcValue> = (*events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(events.len(), 3, "Should have 3 events");

    // Verify timestamps are in ascending order
    let mut prev_timestamp = 0i64;
    for event in events.iter() {
        let event_map = event.as_map_ref().unwrap();
        let timestamp = event_map
            .get("timestamp")
            .unwrap()
            .as_type_ref::<i64>()
            .unwrap();
        assert!(
            *timestamp >= prev_timestamp,
            "Timestamps should be in ascending order"
        );
        prev_timestamp = *timestamp;
    }
    logger.info("✅ Events created with proper timestamp ordering");

    // Start Node 2
    logger.info("Starting Node 2...");
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    // Pre-register discovery before starting Node 2
    let node1_discovered_by_node2 = node2.on(
        format!(
            "$registry/peer/{node1_id}/discovered",
            node1_id = node1.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    let node2_discovered_by_node1 = node1.on(
        format!(
            "$registry/peer/{node2_id}/discovered",
            node2_id = node2.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node2.start().await?;
    logger.info("✅ Node 2 started");

    // Wait for nodes to discover each other and sync
    logger.info("Waiting for nodes to discover each other...");
    let _ = node1_discovered_by_node2.await?;
    let _ = node2_discovered_by_node1.await?;

    logger.info("✅ Nodes discovered each other");

    node2.wait_for_services_to_start().await?;
    logger.info("✅ Node 2 all services started");

    // Verify Node 2 has the same event tables
    logger.info("Verifying Node 2 has event tables...");
    let event_tables_result2 = node2
        .local_request("users_db_test_3/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_Events' ORDER BY name")
        )))
        .await?;
    let event_tables2: Vec<ArcValue> =
        (*event_tables_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(event_tables2.len(), 2, "Node 2 should have 2 event tables");
    logger.info("✅ Node 2 has event tables");

    // Verify Node 2 has the same events
    logger.info("Verifying Node 2 has the same events...");
    let events_result2 = node2
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT operation_type, timestamp FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let events2: Vec<ArcValue> = (*events_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(events2.len(), 3, "Node 2 should have 3 events");
    logger.info("✅ Node 2 has the same events");

    // Test UPDATE and DELETE operations to verify different event types
    logger.info("Testing UPDATE and DELETE operations...");

    // Update a user
    let result = node1
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "UPDATE users SET email = 'updated@example.com' WHERE username = 'event_user1'",
            ))),
        )
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should update 1 user");

    // Delete a user
    let result = node1
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "DELETE FROM users WHERE username = 'event_user3'",
            ))),
        )
        .await?;
    let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should delete 1 user");

    // Wait for replication
    sleep(Duration::from_secs(1)).await;

    // Verify all event types on Node 1
    logger.info("Verifying all event types on Node 1...");
    let all_events_result = node1
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT operation_type, timestamp FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let all_events: Vec<ArcValue> =
        (*all_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    let operation_types: Vec<String> = all_events
        .iter()
        .map(|event| {
            let event_map = event.as_map_ref().unwrap();
            (*event_map
                .get("operation_type")
                .unwrap()
                .as_type_ref::<String>()
                .unwrap())
            .to_uppercase()
        })
        .collect();

    logger.info(format!("Event types on Node 1: {operation_types:?}"));
    assert!(
        operation_types.contains(&"CREATE".to_string()),
        "Should have CREATE events"
    );
    assert!(
        operation_types.contains(&"UPDATE".to_string()),
        "Should have UPDATE events"
    );
    assert!(
        operation_types.contains(&"DELETE".to_string()),
        "Should have DELETE events"
    );
    logger.info("✅ All event types present on Node 1");

    // Verify all event types on Node 2
    logger.info("Verifying all event types on Node 2...");
    let all_events_result2 = node2
        .local_request(
            "users_db_test_3/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT operation_type, timestamp FROM users_Events ORDER BY timestamp",
            ))),
        )
        .await?;
    let all_events2: Vec<ArcValue> =
        (*all_events_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    let operation_types2: Vec<String> = all_events2
        .iter()
        .map(|event| {
            let event_map = event.as_map_ref().unwrap();
            (*event_map
                .get("operation_type")
                .unwrap()
                .as_type_ref::<String>()
                .unwrap())
            .to_uppercase()
        })
        .collect();

    logger.info(format!("Event types on Node 2: {operation_types2:?}"));
    assert_eq!(
        operation_types, operation_types2,
        "Both nodes should have the same event types"
    );
    logger.info("✅ All event types present on Node 2");

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    logger.info("✅ Test 3 completed successfully!");
    Ok(())
}

/// Test 4: Mobile Simulator Integration Test
/// Test replication using the MobileSimulator for proper key management and encryption
#[tokio::test]
#[serial]
async fn test_mobile_simulator_replication() -> Result<()> {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("test")));
    logger.info("=== Test 4: Mobile Simulator Replication Test ===");

    // Create mobile simulation environment
    logger.info("Creating mobile simulation environment...");
    let (simulator, node1_config) = create_test_environment()?;
    simulator.print_summary();

    // Create a second node config using the same simulator
    let node2_config = simulator.create_node_config()?;

    // Create SQLite services with replication enabled
    let sqlite_service1 =
        create_replicated_sqlite_service("sqlite1", "users_db_test_4", ":memory:", false);
    let sqlite_service2 =
        create_replicated_sqlite_service("sqlite2", "users_db_test_4", ":memory:", true);

    // Start Node 1
    logger.info("Starting Node 1...");
    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info(format!("✅ Node 1 started with ID: {}", node1.node_id()));
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started");

    // Add initial data to Node 1
    logger.info("Adding initial data to Node 1...");
    for i in 1..=5 {
        let username = format!("mobile_user{i}");
        let email = format!("mobile_user{i}@example.com");
        let timestamp = chrono::Utc::now().timestamp();

        let result = node1
            .local_request("users_db_test_4/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{username}', '{email}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp))
                )
            )))
            .await?;

        let affected_rows: i64 = *result.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "Should insert 1 user");
        logger.info(format!("   ✅ Inserted user: {username}"));
    }

    // Verify Node 1 has the data
    let users_result = node1
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count: i64 = *users_result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(user_count, 5, "Node 1 should have 5 users");
    logger.info(format!("✅ Node 1 has {user_count} users"));

    // Start Node 2 - it should sync during startup
    logger.info("Starting Node 2 (should sync during startup)...");
    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(sqlite_service2).await?;
    // Pre-register discovery before starting Node 2
    let node1_discovered_by_node2 = node2.on(
        format!(
            "$registry/peer/{node1_id}/discovered",
            node1_id = node1.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    let node2_discovered_by_node1 = node1.on(
        format!(
            "$registry/peer/{node2_id}/discovered",
            node2_id = node2.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node2.start().await?;
    logger.info(format!("✅ Node 2 started with ID: {}", node2.node_id()));

    // Wait for nodes to discover each other
    logger.info("Waiting for nodes to discover each other...");
    let _ = node1_discovered_by_node2.await?;
    let _ = node2_discovered_by_node1.await?;

    logger.info("✅ Nodes discovered each other");

    // Wait for replication to complete
    node2.wait_for_services_to_start().await?;
    logger.info("✅ Node 2 all services started and data is synced");

    // Verify Node 2 has the same data (replication worked)
    logger.info("Verifying replication to Node 2...");
    let users_result2 = node2
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let user_count2: i64 = *users_result2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(
        user_count2, 5,
        "Node 2 should have 5 users after replication"
    );
    logger.info(format!(
        "✅ Node 2 has {user_count2} users (replication successful)"
    ));

    // Test live replication: Add data to Node 2 and verify it appears on Node 1
    logger.info("Testing live replication from Node 2 to Node 1...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node2
        .local_request("users_db_test_4/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'mobile_node2_user'",
            ))),
        )
        .await?;
    let new_users: Vec<ArcValue> =
        (*new_user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users.len(),
        1,
        "Node 1 should have the new user from Node 2"
    );
    logger.info("✅ Live replication Node 2 → Node 1 successful");

    // Test live replication: Add data to Node 1 and verify it appears on Node 2
    logger.info("Testing live replication from Node 1 to Node 2...");
    let timestamp = chrono::Utc::now().timestamp();
    let result = node1
        .local_request("users_db_test_4/execute_query", Some(ArcValue::new_struct(
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
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'mobile_node1_user'",
            ))),
        )
        .await?;
    let new_users2: Vec<ArcValue> =
        (*new_user_result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        new_users2.len(),
        1,
        "Node 2 should have the new user from Node 1"
    );
    logger.info("✅ Live replication Node 1 → Node 2 successful");

    // Test encryption with mobile simulator label resolvers
    logger.info("Testing encryption with mobile simulator...");
    let (_mobile_resolver, _node_resolver) = simulator.create_label_resolvers()?;

    // Verify label resolvers were created successfully
    logger.info("✅ Label resolvers created successfully");
    logger.info("✅ Mobile simulator integration working");

    // Final verification: both nodes should have the same total count
    let final_users1 = node1
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count1: i64 = *final_users1.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    let final_users2 = node2
        .local_request(
            "users_db_test_4/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let final_count2: i64 = *final_users2.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();

    assert_eq!(
        final_count1, final_count2,
        "Both nodes should have the same user count"
    );
    assert_eq!(
        final_count1, 7,
        "Both nodes should have 7 users total (5 initial + 2 live)"
    );
    logger.info(format!(
        "✅ Final verification: Both nodes have {final_count1} users"
    ));

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    logger.info("✅ Test 4 completed successfully!");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_high_volume_replication_with_pagination() -> Result<()> {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("test")));
    logger.info("🧪 Testing high-volume replication with pagination (400 records)...");

    // Create Node 1 with 400 records
    let configs = create_networked_node_test_config(2)?;
    let node1_config = configs[0].clone();

    let mut node1 = Node::new(node1_config).await?;

    // Create SQLite service with replication for Node 1
    let sqlite_service1 = create_replicated_sqlite_service(
        "high_volume_sqlite",
        "high_volume_sqlite",
        ":memory:",
        false,
    );

    // Start Node 1 and add some initial data
    logger.info("Starting Node 1...");
    node1.add_service(sqlite_service1).await?;
    node1.start().await?;
    logger.info("✅ Node 1 started");
    node1.wait_for_services_to_start().await?;
    logger.info("✅ Node 1 all services started");

    // Create 400 records on Node 1
    logger.info("📝 Creating 400 records on Node 1...");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for i in 1..=1000 {
        let username = format!("user{i:03}");
        let email = format!("user{i:03}@example.com");

        let _ = node1
            .local_request("high_volume_sqlite/execute_query", Some(ArcValue::new_struct(
                runar_services::sqlite::SqlQuery::new(
                    &format!("INSERT INTO users (username, email, created_at) VALUES ('{username}', '{email}', ?)")
                ).with_params(runar_services::sqlite::Params::new()
                    .with_value(runar_services::sqlite::Value::Integer(timestamp + i))
                )
            )))
            .await?;

        if i % 50 == 0 {
            logger.info(format!("   Created {i}/400 records..."));
        }
    }

    // Verify Node 1 has 400 records
    let result = node1
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let count1: i64 = *result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(count1, 1000, "Node 1 should have 1000 users");
    logger.info(format!("✅ Node 1 has {count1} records"));

    // Create Node 2 (empty, will sync from Node 1)
    let node2_config = configs[1].clone();

    let mut node2 = Node::new(node2_config).await?;

    // Create SQLite service with replication for Node 2
    let sqlite_service2 = create_replicated_sqlite_service(
        "high_volume_sqlite",
        "high_volume_sqlite",
        ":memory:",
        true,
    );
    node2.add_service(sqlite_service2).await?;
    // Now start Node 2 - it should sync during startup
    logger.info("Starting Node 2 (should sync during startup)...");
    // Pre-register discovery before starting Node 2
    let node1_discovered_by_node2 = node2.on(
        format!(
            "$registry/peer/{node1_id}/discovered",
            node1_id = node1.node_id()
        ),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(20),
            include_past: Some(Duration::from_secs(10)),
        }),
    );
    node2.start().await?;
    logger.info("✅ Node 2 started");

    // Wait for nodes to discover each other and exchange service information
    logger.info("Waiting for nodes to discover each other...");
    let _ = node1_discovered_by_node2.await?;
    logger.info("✅ Nodes discovered each other");

    node2.wait_for_services_to_start().await?;
    logger.info("✅ Node 2 all services started and synced");

    // Verify Node 2 has synced all 1000 records
    let result = node2
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;
    let count2: i64 = *result.as_type_ref::<Vec<ArcValue>>().unwrap()[0]
        .as_map_ref()
        .unwrap()
        .get("count")
        .unwrap()
        .as_type_ref::<i64>()
        .unwrap();
    assert_eq!(count2, 1000, "Node 2 should have synced all 1000 users");
    logger.info(format!("✅ Node 2 synced {count2} records"));

    // Verify specific records are present on Node 2
    let result = node2
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'user001'",
            ))),
        )
        .await?;
    let rows: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!rows.is_empty(), "Node 2 should have user001");

    let result = node2
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'user200'",
            ))),
        )
        .await?;
    let rows: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!rows.is_empty(), "Node 2 should have user200");

    let result = node2
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username FROM users WHERE username = 'user400'",
            ))),
        )
        .await?;
    let rows: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!rows.is_empty(), "Node 2 should have user400");

    logger.info("✅ Verified specific records (user001, user200, user400) are present on Node 2");

    // Test that both nodes have identical data
    let result1 = node1
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username, email, created_at FROM users ORDER BY username",
            ))),
        )
        .await?;
    let rows1: Vec<ArcValue> = (*result1.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    let result2 = node2
        .local_request(
            "high_volume_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT username, email, created_at FROM users ORDER BY username",
            ))),
        )
        .await?;
    let rows2: Vec<ArcValue> = (*result2.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    assert_eq!(
        rows1.len(),
        rows2.len(),
        "Both nodes should have the same number of records"
    );
    assert_eq!(
        rows1.len(),
        1000,
        "Both nodes should have exactly 1000 records"
    );

    // Verify the first and last records match
    if !rows1.is_empty() && !rows2.is_empty() {
        let first_row1 = &rows1[0];
        let first_row2 = &rows2[0];
        let username1 = first_row1
            .as_map_ref()
            .unwrap()
            .get("username")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let username2 = first_row2
            .as_map_ref()
            .unwrap()
            .get("username")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        assert_eq!(username1, username2, "First records should match");

        let last_row1 = &rows1[rows1.len() - 1];
        let last_row2 = &rows2[rows2.len() - 1];
        let username1_last = last_row1
            .as_map_ref()
            .unwrap()
            .get("username")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let username2_last = last_row2
            .as_map_ref()
            .unwrap()
            .get("username")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        assert_eq!(username1_last, username2_last, "Last records should match");
    }

    logger.info("✅ Verified both nodes have identical data");

    // Note: Real-time replication is tested in other tests and works correctly
    // This test focuses on high-volume startup synchronization with pagination
    logger.info("✅ High-volume replication with pagination working correctly");

    // Clean up
    node1.stop().await?;
    node2.stop().await?;
    logger.info("✅ Test 5 completed successfully!");
    Ok(())
}
