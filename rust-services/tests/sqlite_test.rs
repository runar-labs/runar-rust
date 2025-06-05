// Test for the service and action macros
//
// This test demonstrates how to use the service and action macros
// to create a simple service with actions.

use std::collections::HashMap;

// use futures::lock::Mutex; // Unused import removed
// use runar_common::ServiceInfo; // Unused import removed
use runar_common::types::ArcValueType; // Removed ErasedArc and ValueCategory
                                       // use runar_node::node::Node; // Unused import removed
                                       // use std::sync::Arc; // Duplicate import removed
                                       // use std::time::Duration; // Unused import removed
                                       // use tempfile::tempdir; // Unused import removed
use rust_services::sqlite::{
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

#[cfg(test)]
mod tests {
    use super::*;
    use runar_node::config::LogLevel;
    use runar_node::config::LoggingConfig;
    use runar_node::Node;
    use runar_node::NodeConfig;

    #[tokio::test]
    async fn test_insert() {
        //set log to debug
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);

        // Create a node with a test network ID
        let config =
            NodeConfig::new("test-node", "test_network").with_logging_config(logging_config);
        let mut node = Node::new(config).await.unwrap();

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

        let service_name = "users_db_test".to_string();
        let service_path = "users_db".to_string();
        //let service_version = "0.1.0".to_string();
        //let service_description = "Test SQLite User Service".to_string();
        let sqlite_config = SqliteConfig {
            db_path: ":memory:".to_string(), // Use in-memory database for tests
            schema,
        };

        let service = SqliteService::new(service_name, service_path, sqlite_config);

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();

        // Test SQLite INSERT operation
        let insert_params = Params::new()
            .with_value(Value::Text("Test User From SqlQuery".to_string()))
            .with_value(Value::Integer(33));
        let insert_query =
            SqlQuery::new("INSERT INTO users (name, age) VALUES (?, ?)").with_params(insert_params);
        let arc_insert_query = ArcValueType::from_struct(insert_query.clone());

        let insert_response: i64 = node
            .request("users_db/execute_query", Some(arc_insert_query))
            .await
            .unwrap();
        let affected_rows = insert_response;
        assert_eq!(affected_rows, 1, "INSERT should affect 1 row");

        // Test SQLite SELECT operation
        let select_params =
            Params::new().with_value(Value::Text("Test User From SqlQuery".to_string()));
        let select_query = SqlQuery::new("SELECT id, name, age FROM users WHERE name = ?")
            .with_params(select_params);
        let arc_select_query = ArcValueType::from_struct(select_query.clone());

        let select_response: Vec<ArcValueType> = node
            .request("users_db/execute_query", Some(arc_select_query))
            .await
            .unwrap();
        let result_list = select_response;
        assert_eq!(result_list.len(), 1, "SELECT should return one user");

        let mut user_map_av = result_list[0].clone();
        let user_map = user_map_av
            .as_map_ref::<String, ArcValueType>()
            .expect("User data should be a map");

        let mut name_av = user_map
            .get("name")
            .expect("User map should have 'name'")
            .clone();
        assert_eq!(
            name_av.as_type::<String>().unwrap(),
            "Test User From SqlQuery"
        );

        let mut age_av = user_map
            .get("age")
            .expect("User map should have 'age'")
            .clone();
        assert_eq!(age_av.as_type::<i64>().unwrap(), 33);
    }
}
