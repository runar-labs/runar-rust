// Test for the service and action macros
//
// This test demonstrates how to use the service and action macros
// to create a simple service with actions.

use std::collections::HashMap;

use runar_services::sqlite::{
    ColumnDefinition, DataType, Params, Schema, SqlQuery, SqliteConfig, SqliteService,
    TableDefinition, Value,
};
use serde::{Deserialize, Serialize}; // For User and MyData structs

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct User {
    id: Option<i64>,
    name: String,
    age: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct MyData {
    id: i32,
    text_field: String,
    number_field: i32,
    boolean_field: bool,
    float_field: f64,
    vector_field: Vec<i32>,
    map_field: HashMap<String, String>,
}

// Helper struct to ensure test database is cleaned up
struct TestDbGuard {
    db_path: String,
}

impl TestDbGuard {
    fn new() -> Self {
        let current_dir = std::env::current_dir().unwrap();
        let db_path = format!("{}/users_db_test.db", current_dir.display());
        Self { db_path }
    }

    fn path(&self) -> &str {
        &self.db_path
    }
}

impl Drop for TestDbGuard {
    fn drop(&mut self) {
        // Clean up the test database file if it exists
        if std::path::Path::new(&self.db_path).exists() {
            let _ = std::fs::remove_file(&self.db_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runar_common::logging::LoggingConfig;
    use runar_node::config::LogLevel;
    use runar_node::Node;
    use runar_serializer::ArcValue;
    use runar_test_utils::create_node_test_config;

    #[tokio::test]
    async fn test_insert() {
        //set log to debug
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);

        // Create a node with a test network ID
        let config = create_node_test_config()
            .expect("Debug creating test config")
            .with_logging_config(logging_config);
        let node = Node::new(config).await.unwrap();

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
                        name: "age".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false, // Age can be null for this test example
                    },
                ],
            }],
            indexes: vec![], // Ensure all fields of Schema are initialized
        };

        let service_name = "users_db_test";
        let service_path = "users_db";

        // Create a test database guard that will clean up after the test
        let db_guard = TestDbGuard::new();

        let sqlite_config = SqliteConfig {
            db_path: db_guard.path().to_string(),
            schema,
            encryption: true,
            replication: None,
        };

        let service = SqliteService::new(service_name, service_path, sqlite_config);

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();
        // Wait for non-internal services to fully start (reach Running state)
        node.wait_for_services_to_start().await.unwrap();

        // Test SQLite INSERT operation
        let insert_params = Params::new()
            .with_value(Value::Text("Test User From SqlQuery".to_string()))
            .with_value(Value::Integer(33));
        let insert_query =
            SqlQuery::new("INSERT INTO users (name, age) VALUES (?, ?)").with_params(insert_params);
        let arc_insert_query = ArcValue::new_struct(insert_query.clone());

        let insert_response: ArcValue = node
            .request("users_db/execute_query", Some(arc_insert_query))
            .await
            .unwrap();
        let affected_rows: i64 = *insert_response.as_type_ref::<i64>().unwrap();
        assert_eq!(affected_rows, 1, "INSERT should affect 1 row");

        // Test SQLite SELECT operation
        let select_params =
            Params::new().with_value(Value::Text("Test User From SqlQuery".to_string()));
        let select_query = SqlQuery::new("SELECT id, name, age FROM users WHERE name = ?")
            .with_params(select_params);
        let arc_select_query = ArcValue::new_struct(select_query.clone());

        let select_response: ArcValue = node
            .request("users_db/execute_query", Some(arc_select_query))
            .await
            .unwrap();
        let result_list: Vec<ArcValue> =
            (*select_response.as_type_ref::<Vec<ArcValue>>().unwrap()).clone();
        assert_eq!(result_list.len(), 1, "SELECT should return one user");

        let user_map_av = result_list[0].clone();
        let user_map = user_map_av.as_map_ref().expect("User data should be a map");

        let name_av = user_map
            .get("name")
            .expect("User map should have 'name'")
            .clone();
        assert_eq!(
            *name_av.as_type_ref::<String>().unwrap(),
            "Test User From SqlQuery"
        );

        let age_av = user_map
            .get("age")
            .expect("User map should have 'age'")
            .clone();
        assert_eq!(*age_av.as_type_ref::<i64>().unwrap(), 33);
    }
}
