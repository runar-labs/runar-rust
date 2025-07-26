use runar_services::sqlite::{
    ColumnDefinition, DataType, Schema as SqliteSchema, SqliteConfig, SqliteService,
    TableDefinition,
};

/// Database schema for the microservices demo
pub fn create_database_schema() -> SqliteSchema {
    SqliteSchema {
        tables: vec![
            // Users table - system fields + user encrypted blob
            TableDefinition {
                name: "users".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "username".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "email".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "created_at".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "user_encrypted_data".to_string(),
                        data_type: DataType::Blob,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
            // Profiles table - system fields + user encrypted blob
            TableDefinition {
                name: "profiles".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "user_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "full_name".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "last_updated".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "user_encrypted_data".to_string(),
                        data_type: DataType::Blob,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
            // Accounts table - system fields + user encrypted blob
            TableDefinition {
                name: "accounts".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "name".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "account_type".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "created_at".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "user_encrypted_data".to_string(),
                        data_type: DataType::Blob,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
            // Orders table - system fields + user encrypted blob
            TableDefinition {
                name: "orders".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "user_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "product_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "quantity".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "status".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "created_at".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "user_encrypted_data".to_string(),
                        data_type: DataType::Blob,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
        ],
        indexes: vec![],
    }
}

/// Setup database services for the microservices demo
pub fn setup_database_services() -> (
    SqliteService,
    runar_services::crud_sqlite::CrudSqliteService,
) {
    // Create database schema
    let schema = create_database_schema();

    // Setup SqliteService (in-memory for demo)
    let sqlite_config = SqliteConfig {
        db_path: ":memory:".to_string(),
        schema: schema.clone(),
        encryption: false,
    };
    let sqlite_service = SqliteService::new(
        "sqlite_service".to_string(),
        "internal_db".to_string(),
        sqlite_config,
    );

    // Setup CrudSqliteService
    let crud_service = runar_services::crud_sqlite::CrudSqliteService::new(
        "crud_service".to_string(),
        "crud_db".to_string(),
        "internal_db".to_string(),
        schema,
    );

    (sqlite_service, crud_service)
}
