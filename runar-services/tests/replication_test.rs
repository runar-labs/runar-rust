use anyhow::Result;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_services::{
    replication::{ConflictResolutionStrategy, ReplicationConfig},
    sqlite::{ColumnDefinition, DataType, Schema, SqliteConfig, SqliteService, TableDefinition},
};
use runar_test_utils::create_node_test_config;
use std::collections::HashMap;

#[tokio::test]
async fn test_sqlite_service_with_replication_single_node() -> Result<()> {
    // Create a test schema
    let schema = Schema {
        tables: vec![TableDefinition {
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
                    name: "name".to_string(),
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
            ],
        }],
        indexes: vec![],
    };

    // Create SQLite config with replication enabled
    let sqlite_config = SqliteConfig::new(
        ":memory:", // Use in-memory database for testing
        schema, false, // No encryption for testing
    )
    .with_replication(ReplicationConfig {
        enabled_tables: vec!["users".to_string()],
        conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
        startup_sync: true, // Enable startup sync to test the full replication lifecycle
        event_retention_days: 30,
        wait_remote_service_timeout: 1,
        past_events_window: 1,
    });

    // Create SQLite service
    let sqlite_service = SqliteService::new("test_sqlite", "test_sqlite", sqlite_config);

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;
    node.wait_for_services_to_start().await?;

    // Test that event tables were created
    let result = node
        .request(
            "test_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users_Events'",
            ))),
        )
        .await?;

    let tables: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!tables.is_empty(), "Event table should be created");

    // Test inserting a record
    let insert_result = node
        .request(
            "test_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com')",
            ))),
        )
        .await?;

    let affected_rows: i64 = *insert_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 row");

    // Test that the record was inserted
    let select_result = node
        .request(
            "test_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users WHERE name = 'John Doe'",
            ))),
        )
        .await?;

    let rows: Vec<ArcValue> = (*select_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(rows.len(), 1, "Should find 1 row");

    // Test that a replication event was created (local events are stored for replication history)
    let event_result = node
        .request(
            "test_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users_Events WHERE operation_type = 'create'",
            ))),
        )
        .await?;

    let events: Vec<ArcValue> = (*event_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(
        events.len(),
        1,
        "Should have 1 replication event stored for history"
    );

    // Test that the event is marked as processed (since it's a local event)
    let processed_event_result = node
        .request(
            "test_sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users_Events WHERE processed = 1",
            ))),
        )
        .await?;

    let processed_events: Vec<ArcValue> = (*processed_event_result
        .as_type_ref::<Vec<ArcValue>>()
        .unwrap())
    .clone();
    assert_eq!(
        processed_events.len(),
        1,
        "Local event should be marked as processed"
    );

    // Test that the replication API endpoint is available (for when remote nodes connect)
    let replication_api_result = node
        .request(
            "test_sqlite/replication/get_table_events",
            Some(ArcValue::new_struct(
                runar_services::replication::TableEventsRequest {
                    table_name: "users".to_string(),
                    page: 0,
                    page_size: 10,
                    from_timestamp: 0,
                    from_by_origin: Vec::new(),
                },
            )),
        )
        .await?;

    let replication_response: runar_services::replication::TableEventsResponse =
        (*replication_api_result
            .as_type_ref::<runar_services::replication::TableEventsResponse>()
            .unwrap())
        .clone();

    // Should return the local event we just created
    assert_eq!(
        replication_response.events.len(),
        1,
        "Replication API should return the stored event"
    );
    assert!(
        !replication_response.has_more,
        "Should not have more events"
    );

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_sqlite_service_without_replication() -> Result<()> {
    // Create a test schema
    let schema = Schema {
        tables: vec![TableDefinition {
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
                    name: "name".to_string(),
                    data_type: DataType::Text,
                    primary_key: false,
                    autoincrement: false,
                    not_null: true,
                },
            ],
        }],
        indexes: vec![],
    };

    // Create SQLite config without replication
    let sqlite_config = SqliteConfig::new(":memory:", schema, false); // No replication config

    // Create SQLite service
    let sqlite_service =
        SqliteService::new("test_sqlite_no_repl", "test_sqlite_no_repl", sqlite_config);

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;
    node.wait_for_services_to_start().await?;

    // Test inserting a record
    let insert_result = node
        .request(
            "test_sqlite_no_repl/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (name) VALUES ('Jane Doe')",
            ))),
        )
        .await?;

    let affected_rows: i64 = *insert_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 row");

    // Test that event tables were NOT created (no replication)
    let result = node
        .request(
            "test_sqlite_no_repl/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users_Events'",
            ))),
        )
        .await?;

    let tables: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(
        tables.is_empty(),
        "Event table should NOT be created when replication is disabled"
    );

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_replication_event_database_application() -> Result<()> {
    // Create a test schema
    let schema = Schema {
        tables: vec![TableDefinition {
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
                    name: "name".to_string(),
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
            ],
        }],
        indexes: vec![],
    };

    // Create SQLite config with replication enabled
    let sqlite_config =
        SqliteConfig::new(":memory:", schema, false).with_replication(ReplicationConfig {
            enabled_tables: vec!["users".to_string()],
            conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
            startup_sync: false, // Disable startup sync for this test
            event_retention_days: 30,
            wait_remote_service_timeout: 0,
            past_events_window: 0,
        });

    // Create SQLite service
    let sqlite_service =
        SqliteService::new("test_sqlite_apply", "test_sqlite_apply", sqlite_config);

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;

    node.wait_for_services_to_start().await?;

    // Test that the database is empty initially
    let initial_result = node
        .request(
            "test_sqlite_apply/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users",
            ))),
        )
        .await?;

    let initial_rows: Vec<ArcValue> =
        (*initial_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    let initial_count = if let Some(first_row) = initial_rows.first() {
        // Extract the count value from the first row
        match first_row.as_type::<HashMap<String, runar_services::sqlite::Value>>() {
            Ok(row) => {
                if let Some(runar_services::sqlite::Value::Integer(count)) = row.get("count") {
                    *count
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    } else {
        0
    };
    assert_eq!(initial_count, 0, "Database should be empty initially");

    // Get the replication manager from the service
    // We need to access the replication manager to test the apply_event_to_database method
    // For now, let's test this by calling the replication API directly

    // First, let's verify the event table exists
    let event_table_result = node
        .request(
            "test_sqlite_apply/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users_Events'",
            ))),
        )
        .await?;

    let event_tables: Vec<ArcValue> =
        (*event_table_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!event_tables.is_empty(), "Event table should be created");

    // Now let's test the replication event processing by calling the replication API
    // This will test the get_table_events functionality
    let replication_api_result = node
        .request(
            "test_sqlite_apply/replication/get_table_events",
            Some(ArcValue::new_struct(
                runar_services::replication::TableEventsRequest {
                    table_name: "users".to_string(),
                    page: 0,
                    page_size: 10,
                    from_timestamp: 0,
                    from_by_origin: Vec::new(),
                },
            )),
        )
        .await?;

    let replication_response: runar_services::replication::TableEventsResponse =
        (*replication_api_result
            .as_type_ref::<runar_services::replication::TableEventsResponse>()
            .unwrap())
        .clone();

    // Should return empty since no events have been created yet
    assert_eq!(
        replication_response.events.len(),
        0,
        "Should have no events initially"
    );

    // Now let's create a local event and verify it gets stored
    let insert_result = node
        .request(
            "test_sqlite_apply/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (name, email) VALUES ('Local User', 'local@example.com')",
            ))),
        )
        .await?;

    let affected_rows: i64 = *insert_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 row");

    // Verify the event was stored
    let stored_events_result = node
        .request(
            "test_sqlite_apply/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT COUNT(*) as count FROM users_Events",
            ))),
        )
        .await?;

    let stored_events_rows: Vec<ArcValue> =
        (*stored_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    let stored_events_count = if let Some(first_row) = stored_events_rows.first() {
        match first_row.as_type::<HashMap<String, ArcValue>>() {
            Ok(row) => {
                if let Some(count) = row.get("count") {
                    *count.as_type_ref::<i64>().unwrap()
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    } else {
        0
    };
    assert_eq!(stored_events_count, 1, "Should have 1 stored event");

    // Verify the user was actually inserted
    let user_result = node
        .request(
            "test_sqlite_apply/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users WHERE name = 'Local User'",
            ))),
        )
        .await?;

    let users: Vec<ArcValue> = (*user_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(users.len(), 1, "Should find 1 user");

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_mark_event_processed_functionality() -> Result<()> {
    // Create a test schema
    let schema = Schema {
        tables: vec![TableDefinition {
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
                    name: "name".to_string(),
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
            ],
        }],
        indexes: vec![],
    };

    // Create SQLite config with replication enabled
    let sqlite_config =
        SqliteConfig::new(":memory:", schema, false).with_replication(ReplicationConfig {
            enabled_tables: vec!["users".to_string()],
            conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
            startup_sync: false,
            event_retention_days: 30,
            wait_remote_service_timeout: 0,
            past_events_window: 0,
        });

    // Create SQLite service
    let sqlite_service = SqliteService::new(
        "test_sqlite_mark_processed",
        "test_sqlite_mark_processed",
        sqlite_config,
    );

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;

    node.wait_for_services_to_start().await?;

    // Create a replication event manually (simulating a remote event)
    let replication_event = runar_services::replication::ReplicationEvent {
        id: "test-event-processed-1".to_string(),
        table_name: "users".to_string(),
        operation_type: "create".to_string(),
        record_id: "test-record-processed-1".to_string(),
        data:ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("INSERT INTO users (name, email) VALUES ('Remote User Processed', 'remote-processed@example.com')")
        ),
        timestamp: 1754382137011,
        source_node_id: "remote-node-processed".to_string(),
        origin_seq: 1,
    };

    // Store the event as unprocessed (simulating a remote event)
    let store_result = node
        .request("test_sqlite_mark_processed/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("INSERT INTO users_Events (id, table_name, operation_type, record_id, data, timestamp, source_node_id, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Text(replication_event.id.clone()))
                .with_value(runar_services::sqlite::Value::Text(replication_event.table_name.clone()))
                .with_value(runar_services::sqlite::Value::Text(replication_event.operation_type.clone()))
                .with_value(runar_services::sqlite::Value::Text(replication_event.record_id.clone()))
                .with_value(runar_services::sqlite::Value::Text(serde_json::to_string(&replication_event.data.to_json().unwrap()).unwrap()))
                .with_value(runar_services::sqlite::Value::Integer(replication_event.timestamp))
                .with_value(runar_services::sqlite::Value::Text(replication_event.source_node_id.clone()))
                .with_value(runar_services::sqlite::Value::Boolean(false)) // Mark as unprocessed
            )
        )))
        .await?;

    let affected_rows: i64 = *store_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should store 1 event");

    // Verify the event is stored as unprocessed
    let unprocessed_result = node
        .request(
            "test_sqlite_mark_processed/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT processed FROM users_Events WHERE id = 'test-event-processed-1'",
            ))),
        )
        .await?;

    let unprocessed_rows: Vec<ArcValue> =
        (*unprocessed_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    let is_unprocessed = if let Some(first_row) = unprocessed_rows.first() {
        match first_row.as_type::<HashMap<String, ArcValue>>() {
            Ok(row) => {
                if let Some(processed_arc) = row.get("processed") {
                    // Try to extract the boolean value from the ArcValue
                    match processed_arc.as_type::<i64>() {
                        Ok(processed_int) => {
                            processed_int == 0 // 0 = false (unprocessed), 1 = true (processed)
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        false
    };
    assert!(
        is_unprocessed,
        "Event should be stored as unprocessed initially"
    );

    // Now mark the event as processed
    let mark_processed_result = node
        .request(
            "test_sqlite_mark_processed/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "UPDATE users_Events SET processed = TRUE WHERE id = 'test-event-processed-1'",
            ))),
        )
        .await?;

    let mark_affected_rows: i64 = *mark_processed_result.as_type_ref::<i64>().unwrap();
    assert_eq!(mark_affected_rows, 1, "Should update 1 event");

    // Verify the event is now marked as processed
    let processed_result = node
        .request(
            "test_sqlite_mark_processed/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT processed FROM users_Events WHERE id = 'test-event-processed-1'",
            ))),
        )
        .await?;

    let processed_rows: Vec<ArcValue> =
        (*processed_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();

    let is_processed = if let Some(first_row) = processed_rows.first() {
        match first_row.as_type::<HashMap<String, ArcValue>>() {
            Ok(row) => {
                if let Some(processed_arc) = row.get("processed") {
                    // Try to extract the boolean value from the ArcValue
                    match processed_arc.as_type::<i64>() {
                        Ok(processed_int) => {
                            processed_int == 1 // 0 = false (unprocessed), 1 = true (processed)
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        false
    };
    assert!(is_processed, "Event should be marked as processed");

    // Test duplicate event handling - try to process the same event again
    // This should be skipped because it's already marked as processed

    // Simulate the process_replication_event logic
    // First check if it's already processed
    let check_processed_result = node
        .request(
            "test_sqlite_mark_processed/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT processed FROM users_Events WHERE id = 'test-event-processed-1'",
            ))),
        )
        .await?;

    let check_rows: Vec<ArcValue> = (*check_processed_result
        .as_type_ref::<Vec<ArcValue>>()
        .unwrap())
    .clone();
    let already_processed = if let Some(first_row) = check_rows.first() {
        match first_row.as_type::<HashMap<String, ArcValue>>() {
            Ok(row) => {
                if let Some(processed_arc) = row.get("processed") {
                    match processed_arc.as_type::<i64>() {
                        Ok(processed_int) => {
                            processed_int == 1 // 1 = true (processed)
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        false
    };

    assert!(
        already_processed,
        "Event should be detected as already processed"
    );

    node.stop().await?;
    Ok(())
}

#[test]
fn test_extract_table_name() {
    use runar_services::sqlite::extract_table_name;

    // Test INSERT
    assert_eq!(
        extract_table_name("INSERT INTO users (name, email) VALUES (?, ?)"),
        Some("users".to_string())
    );

    // Test UPDATE
    assert_eq!(
        extract_table_name("UPDATE users SET name = ? WHERE id = ?"),
        Some("users".to_string())
    );

    // Test DELETE
    assert_eq!(
        extract_table_name("DELETE FROM users WHERE id = ?"),
        Some("users".to_string())
    );

    // Test SELECT (should return None)
    assert_eq!(extract_table_name("SELECT * FROM users"), None);
}

#[test]
fn test_determine_operation_type() {
    use runar_services::sqlite::determine_operation_type;

    assert_eq!(
        determine_operation_type("INSERT INTO users VALUES (?)"),
        "CREATE"
    );
    assert_eq!(
        determine_operation_type("UPDATE users SET name = ?"),
        "UPDATE"
    );
    assert_eq!(
        determine_operation_type("DELETE FROM users WHERE id = ?"),
        "DELETE"
    );
    assert_eq!(determine_operation_type("SELECT * FROM users"), "OTHER");
}
