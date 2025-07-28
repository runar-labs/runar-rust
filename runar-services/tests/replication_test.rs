use anyhow::Result;
use runar_services::{
    replication::{ConflictResolutionStrategy, ReplicationConfig},
    sqlite::{DataType, Schema, SqliteConfig, SqliteService, TableDefinition, ColumnDefinition},
};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;

#[tokio::test]
async fn test_sqlite_service_with_replication_single_node() -> Result<()> {
    // Create a test schema
    let schema = Schema {
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
            },
        ],
        indexes: vec![],
    };

    // Create SQLite config with replication enabled
    let sqlite_config = SqliteConfig::new(
        ":memory:".to_string(), // Use in-memory database for testing
        schema,
        false, // No encryption for testing
    ).with_replication(ReplicationConfig {
        enabled_tables: vec!["users".to_string()],
        conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
        startup_sync: true, // Enable startup sync to test the full replication lifecycle
        event_retention_days: 30,
    });

    // Create SQLite service
    let sqlite_service = SqliteService::new(
        "test_sqlite".to_string(),
        "test_sqlite".to_string(),
        sqlite_config,
    );

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;

    // Test that event tables were created
    let result = node
        .request("test_sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name='users_Events'")
        )))
        .await?;

    let tables: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(!tables.is_empty(), "Event table should be created");

    // Test inserting a record
    let insert_result = node
        .request("test_sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com')")
        )))
        .await?;

    let affected_rows: i64 = *insert_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 row");

    // Test that the record was inserted
    let select_result = node
        .request("test_sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT * FROM users WHERE name = 'John Doe'")
        )))
        .await?;

    let rows: Vec<ArcValue> = (*select_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(rows.len(), 1, "Should find 1 row");

    // Test that a replication event was created (local events are stored for replication history)
    let event_result = node
        .request("test_sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT * FROM users_Events WHERE operation_type = 'create'")
        )))
        .await?;

    let events: Vec<ArcValue> = (*event_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(events.len(), 1, "Should have 1 replication event stored for history");

    // Test that the event is marked as processed (since it's a local event)
    let processed_event_result = node
        .request("test_sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT * FROM users_Events WHERE processed = 1")
        )))
        .await?;

    let processed_events: Vec<ArcValue> = (*processed_event_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert_eq!(processed_events.len(), 1, "Local event should be marked as processed");

    // Test that the replication API endpoint is available (for when remote nodes connect)
    let replication_api_result = node
        .request("test_sqlite/replication/get_table_events", Some(ArcValue::new_struct(
            runar_services::replication::TableEventsRequest {
                table_name: "users".to_string(),
                page: 0,
                page_size: 10,
                from_sequence: 0,
            }
        )))
        .await?;

    let replication_response: runar_services::replication::TableEventsResponse = 
        (*replication_api_result.as_type_ref::<runar_services::replication::TableEventsResponse>().unwrap()).clone();
    
    // Should return the local event we just created
    assert_eq!(replication_response.events.len(), 1, "Replication API should return the stored event");
    assert_eq!(replication_response.has_more, false, "Should not have more events");

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_sqlite_service_without_replication() -> Result<()> {
    // Create a test schema
    let schema = Schema {
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
                        name: "name".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: true,
                    },
                ],
            },
        ],
        indexes: vec![],
    };

    // Create SQLite config without replication
    let sqlite_config = SqliteConfig::new(
        ":memory:".to_string(),
        schema,
        false,
    ); // No replication config

    // Create SQLite service
    let sqlite_service = SqliteService::new(
        "test_sqlite_no_repl".to_string(),
        "test_sqlite_no_repl".to_string(),
        sqlite_config,
    );

    // Create test node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;

    // Test inserting a record
    let insert_result = node
        .request("test_sqlite_no_repl/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("INSERT INTO users (name) VALUES ('Jane Doe')")
        )))
        .await?;

    let affected_rows: i64 = *insert_result.as_type_ref::<i64>().unwrap();
    assert_eq!(affected_rows, 1, "Should insert 1 row");

    // Test that event tables were NOT created (no replication)
    let result = node
        .request("test_sqlite_no_repl/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT name FROM sqlite_master WHERE type='table' AND name='users_Events'")
        )))
        .await?;

    let tables: Vec<ArcValue> = (*result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    assert!(tables.is_empty(), "Event table should NOT be created when replication is disabled");

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
    assert_eq!(
        extract_table_name("SELECT * FROM users"),
        None
    );
}

#[test]
fn test_determine_operation_type() {
    use runar_services::sqlite::determine_operation_type;

    assert_eq!(determine_operation_type("INSERT INTO users VALUES (?)"), "CREATE");
    assert_eq!(determine_operation_type("UPDATE users SET name = ?"), "UPDATE");
    assert_eq!(determine_operation_type("DELETE FROM users WHERE id = ?"), "DELETE");
    assert_eq!(determine_operation_type("SELECT * FROM users"), "OTHER");
} 