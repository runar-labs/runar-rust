use anyhow::Result;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_services::{
    replication::{ConflictResolutionStrategy, ReplicationConfig},
    sqlite::{ColumnDefinition, DataType, Schema, SqliteConfig, SqliteService, TableDefinition},
};
use runar_test_utils::create_node_test_config;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== SQLite Service with Replication Example ===\n");

    // Create a schema for a simple user management system
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
    };

    // Create SQLite config with replication enabled for both tables
    let sqlite_config = SqliteConfig::new(
        "replication_example.db",
        schema,
        false, // No encryption for this example
    )
    .with_replication(ReplicationConfig {
        enabled_tables: vec!["users".to_string(), "posts".to_string()],
        conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
        startup_sync: false, // Disable startup sync for this example
        event_retention_days: 30,
        wait_remote_service_timeout: 0,
        past_events_window: 0,
    });

    // Create SQLite service
    let sqlite_service = SqliteService::new("replication_example", "sqlite", sqlite_config);

    // Create and start the node
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Info);
    let config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(config).await.unwrap();

    node.add_service(sqlite_service).await?;
    node.start().await?;

    println!("✅ SQLite service with replication started successfully!\n");

    // Demonstrate basic operations
    println!("=== Basic Operations ===\n");

    // Insert a user
    println!("1. Inserting a user...");
    let insert_user_result = node
        .request("sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO users (username, email, created_at) VALUES ('john_doe', 'john@example.com', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(chrono::Utc::now().timestamp()))
            )
        )))
        .await?;

    let affected_rows: i64 = *insert_user_result.as_type_ref::<i64>().unwrap();
    println!("   ✅ User inserted successfully. Affected rows: {affected_rows}\n");

    // Insert a post
    println!("2. Inserting a post...");
    let insert_post_result = node
        .request("sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new(
                "INSERT INTO posts (user_id, title, content, created_at) VALUES (1, 'My First Post', 'Hello, World!', ?)"
            ).with_params(runar_services::sqlite::Params::new()
                .with_value(runar_services::sqlite::Value::Integer(chrono::Utc::now().timestamp()))
            )
        )))
        .await?;

    let affected_rows: i64 = *insert_post_result.as_type_ref::<i64>().unwrap();
    println!("   ✅ Post inserted successfully. Affected rows: {affected_rows}\n");

    // Query users
    println!("3. Querying users...");
    let users_result = node
        .request(
            "sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM users",
            ))),
        )
        .await?;

    let users: Vec<ArcValue> = (*users_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    println!("   ✅ Found {} users", users.len());
    for (i, user) in users.iter().enumerate() {
        let user_map = user.as_map_ref().unwrap();
        let username = user_map
            .get("username")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let email = user_map
            .get("email")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        println!("   User {}: {} ({})", i + 1, username, email);
    }
    println!();

    // Query posts
    println!("4. Querying posts...");
    let posts_result = node
        .request(
            "sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "SELECT * FROM posts",
            ))),
        )
        .await?;

    let posts: Vec<ArcValue> = (*posts_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    println!("   ✅ Found {} posts", posts.len());
    for (i, post) in posts.iter().enumerate() {
        let post_map = post.as_map_ref().unwrap();
        let title = post_map
            .get("title")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let content = post_map
            .get("content")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        println!("   Post {}: '{}' - {}", i + 1, title, content);
    }
    println!();

    // Check replication events
    println!("=== Replication Events ===\n");

    // Check users events
    let users_events_result = node
        .request("sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, record_id, timestamp FROM users_Events ORDER BY sequence_number")
        )))
        .await?;

    let users_events: Vec<ArcValue> =
        (*users_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    println!("5. Users replication events: {} events", users_events.len());
    for (i, event) in users_events.iter().enumerate() {
        let event_map = event.as_map_ref().unwrap();
        let operation = event_map
            .get("operation_type")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let record_id = event_map
            .get("record_id")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let timestamp = event_map
            .get("timestamp")
            .unwrap()
            .as_type_ref::<i64>()
            .unwrap();
        println!(
            "   Event {}: {} (record: {}, timestamp: {})",
            i + 1,
            operation,
            record_id,
            timestamp
        );
    }
    println!();

    // Check posts events
    let posts_events_result = node
        .request("sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, record_id, timestamp FROM posts_Events ORDER BY sequence_number")
        )))
        .await?;

    let posts_events: Vec<ArcValue> =
        (*posts_events_result.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
    println!("6. Posts replication events: {} events", posts_events.len());
    for (i, event) in posts_events.iter().enumerate() {
        let event_map = event.as_map_ref().unwrap();
        let operation = event_map
            .get("operation_type")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let record_id = event_map
            .get("record_id")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let timestamp = event_map
            .get("timestamp")
            .unwrap()
            .as_type_ref::<i64>()
            .unwrap();
        println!(
            "   Event {}: {} (record: {}, timestamp: {})",
            i + 1,
            operation,
            record_id,
            timestamp
        );
    }
    println!();

    // Demonstrate update operation
    println!("=== Update Operation ===\n");

    println!("7. Updating user email...");
    let update_result = node
        .request(
            "sqlite/execute_query",
            Some(ArcValue::new_struct(runar_services::sqlite::SqlQuery::new(
                "UPDATE users SET email = 'john.doe@example.com' WHERE username = 'john_doe'",
            ))),
        )
        .await?;

    let affected_rows: i64 = *update_result.as_type_ref::<i64>().unwrap();
    println!("   ✅ User updated successfully. Affected rows: {affected_rows}\n");

    // Check that a new replication event was created
    let updated_users_events_result = node
        .request("sqlite/execute_query", Some(ArcValue::new_struct(
            runar_services::sqlite::SqlQuery::new("SELECT operation_type, record_id, timestamp FROM users_Events ORDER BY sequence_number")
        )))
        .await?;

    let updated_users_events: Vec<ArcValue> = (*updated_users_events_result
        .as_type_ref::<Vec<ArcValue>>()
        .unwrap())
    .clone();
    println!(
        "8. Updated users replication events: {} events",
        updated_users_events.len()
    );
    for (i, event) in updated_users_events.iter().enumerate() {
        let event_map = event.as_map_ref().unwrap();
        let operation = event_map
            .get("operation_type")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let record_id = event_map
            .get("record_id")
            .unwrap()
            .as_type_ref::<String>()
            .unwrap();
        let timestamp = event_map
            .get("timestamp")
            .unwrap()
            .as_type_ref::<i64>()
            .unwrap();
        println!(
            "   Event {}: {} (record: {}, timestamp: {})",
            i + 1,
            operation,
            record_id,
            timestamp
        );
    }
    println!();

    // Clean up
    node.stop().await?;
    println!("✅ Example completed successfully!");

    Ok(())
}
