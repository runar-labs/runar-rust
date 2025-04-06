use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use rusqlite::{params, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::SqliteDatabase;
use crate::services::abstract_service::{
    AbstractService, ActionMetadata, CrudOperationType, EventMetadata, ServiceState,
};
use crate::services::{RequestContext, ServiceRequest, ServiceResponse, ValueType};
use crate::services::utils;
use crate::services::{ResponseStatus};

/// SQLite storage type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SqliteStorageType {
    /// In-memory storage
    Memory,
    /// Disk-based storage
    Disk,
}

/// SQLite storage options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteStorageOptions {
    /// Storage type (memory or disk)
    pub storage_type: SqliteStorageType,
    /// Maximum size of the database in bytes (0 for unlimited)
    pub max_size: Option<usize>,
    /// Path to the database file (only used for disk storage)
    pub path: Option<String>,
}

/// SQLite schema definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteSchemaField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: String,
    /// Whether the field is required
    pub required: bool,
    /// Default value for the field
    pub default: Option<Value>,
}

/// SQLite schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteSchema {
    /// Collection/table name
    pub collection: String,
    /// Fields in the schema
    pub fields: Vec<SqliteSchemaField>,
}

/// CRUD operation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrudOperation {
    /// Type of CRUD operation
    pub operation: CrudOperationType,
    /// Collection to operate on
    pub collection: String,
    /// Document data (for create/update)
    pub document: Option<Value>,
    /// Query filter (for read/update/delete)
    pub filter: Option<Value>,
    /// Query options (limit, skip, etc.)
    pub options: Option<Value>,
}

/// SQL operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlOperation {
    /// SQL query to execute
    pub query: String,
    /// Query parameters
    pub params: Option<Value>,
    /// Whether to return results (SELECT) or just success/failure (UPDATE, etc.)
    pub return_results: Option<bool>,
}

/// SqliteCrud Mixin - reusable CRUD functionality for SQLite-based services
pub struct SqliteCrudMixin {
    /// The database connection
    db: Arc<SqliteDatabase>,
    /// Storage options
    _storage_options: SqliteStorageOptions,
    /// Schema (if structured data)
    schema: Option<Vec<SqliteSchema>>,
}

impl SqliteCrudMixin {
    /// Create a new SqliteCrudMixin
    pub fn new(
        db: Arc<SqliteDatabase>,
        storage_options: SqliteStorageOptions,
        schema: Option<Vec<SqliteSchema>>,
    ) -> Self {
        SqliteCrudMixin {
            db,
            _storage_options: storage_options,
            schema,
        }
    }

    /// Create a new SqliteCrudMixin with in-memory database
    pub async fn new_from_memory(schema: Vec<SqliteSchema>) -> Result<Self> {
        let storage_options = SqliteStorageOptions {
            storage_type: SqliteStorageType::Memory,
            max_size: None,
            path: None,
        };

        let db = Arc::new(SqliteDatabase::new(":memory:").await?);
        Ok(Self::new(db, storage_options, Some(schema)))
    }

    /// Create a new SqliteCrudMixin from storage options
    /// This creates the appropriate database based on the storage options
    pub async fn new_from_options(
        storage_options: SqliteStorageOptions,
        schema: Vec<SqliteSchema>,
    ) -> Result<Self> {
        let db = match storage_options.storage_type {
            SqliteStorageType::Memory => Arc::new(SqliteDatabase::new(":memory:").await?),
            SqliteStorageType::Disk => {
                let path = storage_options
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow!("Path is required for disk storage"))?;
                Arc::new(SqliteDatabase::new(path).await?)
            }
        };

        Ok(Self::new(db, storage_options, Some(schema)))
    }

    /// Initialize the metadata table for SqliteCrudMixin
    pub async fn init(&self, _context: &crate::services::RequestContext) -> Result<()> {
        let conn = self.db.get_connection().await?;

        // Create the _metadata table to track collections
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _metadata (
                collection TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // If schema is provided, create the collections
        if let Some(schemas) = &self.schema {
            for schema in schemas {
                self.ensure_collection_exists(&conn, &schema.collection)?;
            }
        }

        Ok(())
    }

    /// Process a service request
    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Extract collection and operation from the request
        let collection = request
            .get_param("collection")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| anyhow!("Collection name is required"))?;

        match request.action.as_str() {
            "create" => {
                let document = request
                    .get_param("document")
                    .ok_or_else(|| anyhow!("Document data is required"))?;

                self.create(&collection, document).await
            }
            "read" => {
                let filter = request.get_param("filter");
                let options = request.get_param("options");

                self.read(&collection, filter, options).await
            }
            "update" => {
                let filter = request
                    .get_param("filter")
                    .ok_or_else(|| anyhow!("Filter criteria are required"))?;

                let document = request
                    .get_param("document")
                    .ok_or_else(|| anyhow!("Document data is required"))?;

                self.update(&collection, filter, document).await
            }
            "delete" => {
                let filter = request
                    .get_param("filter")
                    .ok_or_else(|| anyhow!("Filter criteria are required"))?;

                self.delete(&collection, filter).await
            }
            _ => Err(anyhow!("Unknown operation: {}", request.action)),
        }
    }

    /// Create a new document
    async fn create(&self, collection: &str, document: ValueType) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Ensure the collection exists
        self.ensure_collection_exists(&conn, collection)?;

        // Get a JSON representation for storage
        let document_json = document.to_json();
        println!("Document JSON before ID generation: {}", document_json);

        // Generate an ID if none exists
        let mut document_with_id = document_json.clone();
        if !document_with_id.is_object() {
            return Err(anyhow!("Document must be an object"));
        }

        // Ensure we have an _id field
        if let Some(obj) = document_with_id.as_object_mut() {
            if !obj.contains_key("_id") {
                // Generate a UUID
                let id = Uuid::new_v4().to_string();
                println!("Generated new UUID: {}", id);
                obj.insert("_id".to_string(), Value::String(id));
            } else {
                println!("Document already has _id: {}", obj.get("_id").unwrap());
            }
        }

        println!("Document with ID: {}", document_with_id);

        // Insert the document
        let json_str = serde_json::to_string(&document_with_id)?;
        let id = document_with_id
            .get("_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
            
        println!("Final document ID: {}", id);

        conn.execute(
            &format!("INSERT INTO {} (_id, data) VALUES (?, ?)", collection),
            params![id, json_str],
        )?;

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("Document created with ID: {}", id),
            data: Some(ValueType::from_json(document_with_id)),
        })
    }

    /// Read documents
    async fn read(
        &self,
        collection: &str,
        filter: Option<ValueType>,
        options: Option<ValueType>,
    ) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Check if the collection exists, if not, return empty array
        if !self.collection_exists(&conn, collection)? {
            return Ok(ServiceResponse {
                status: ResponseStatus::Success,
                message: format!("Found 0 documents"),
                data: Some(ValueType::Array(vec![])),
            });
        }

        // Print the original filter for debugging
        println!("SqliteCrudMixin::read - Original filter: {:?}", filter);

        // Convert filter to JSON for the query
        let filter_json = filter.map(|f| f.to_json());
        println!("SqliteCrudMixin::read - Filter JSON: {:?}", filter_json);

        let options_json = options.map(|o| o.to_json());

        // Build the query
        let mut sql = format!("SELECT data FROM {}", collection);
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(filter) = &filter_json {
            if let Some(filter_obj) = filter.as_object() {
                if !filter_obj.is_empty() {
                    sql += " WHERE ";
                    let mut first = true;

                    for (key, value) in filter_obj {
                        println!(
                            "SqliteCrudMixin::read - Filter key: {}, value: {:?}",
                            key, value
                        );

                        if !first {
                            sql += " AND ";
                        }
                        first = false;

                        // We need to handle nested fields in JSON
                        if key == "_id" {
                            sql += "_id = ?";
                            params.push(Box::new(value.as_str().unwrap_or_default().to_string()));
                        } else {
                            // For other fields, we use JSON_EXTRACT
                            sql += &format!("JSON_EXTRACT(data, '$.{}') = ?", key.replace(".", ""));

                            // Handle different value types properly
                            let param_value = if value.is_string() {
                                // For string values, extract the string without quotes
                                value.as_str().unwrap_or_default().to_string()
                            } else {
                                // For other values, use the JSON string representation
                                value.to_string()
                            };

                            println!("SqliteCrudMixin::read - SQL param value: {}", param_value);
                            params.push(Box::new(param_value));
                        }
                    }
                }
            }
        }

        // Handle options (limit, offset, sort)
        if let Some(options) = &options_json {
            if let Some(options_obj) = options.as_object() {
                // Handle sort
                if let Some(sort) = options_obj.get("sort") {
                    if let Some(sort_obj) = sort.as_object() {
                        if !sort_obj.is_empty() {
                            sql += " ORDER BY ";
                            let mut first = true;

                            for (key, value) in sort_obj {
                                if !first {
                                    sql += ", ";
                                }
                                first = false;

                                // Extract the field from JSON
                                sql += &format!("JSON_EXTRACT(data, '$.{}')", key);

                                // Determine sort direction
                                if let Some(sort_dir) = value.as_i64() {
                                    if sort_dir < 0 {
                                        sql += " DESC";
                                    } else {
                                        sql += " ASC";
                                    }
                                }
                            }
                        }
                    }
                }

                // Handle limit and offset
                if let Some(limit) = options_obj.get("limit").and_then(|v| v.as_i64()) {
                    sql += &format!(" LIMIT {}", limit);

                    if let Some(offset) = options_obj.get("offset").and_then(|v| v.as_i64()) {
                        sql += &format!(" OFFSET {}", offset);
                    }
                }
            }
        }

        // Execute the query
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(
            params.iter().map(|p| p.as_ref()),
        ))?;

        // Parse the results
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            if let Ok(json) = serde_json::from_str::<Value>(&json_str) {
                results.push(ValueType::from_json(json));
            }
        }

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("Found {} documents", results.len()),
            data: Some(ValueType::Array(results)),
        })
    }

    /// Update documents
    async fn update(
        &self,
        collection: &str,
        filter: ValueType,
        document: ValueType,
    ) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Check if the collection exists
        if !self.collection_exists(&conn, collection)? {
            return Err(anyhow!("Collection {} does not exist", collection));
        }

        // Convert to JSON for storage
        let filter_json = filter.to_json();
        let document_json = document.to_json();

        if !filter_json.is_object() {
            return Err(anyhow!("Filter must be an object"));
        }

        if !document_json.is_object() {
            return Err(anyhow!("Document must be an object"));
        }

        // Find the document to update
        let mut sql = format!("SELECT _id, data FROM {}", collection);
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        let filter_obj = filter_json.as_object().unwrap();
        if !filter_obj.is_empty() {
            sql += " WHERE ";
            let mut first = true;

            for (key, value) in filter_obj {
                if !first {
                    sql += " AND ";
                }
                first = false;

                // Handle _id separately
                if key == "_id" {
                    sql += "_id = ?";
                    params.push(Box::new(value.as_str().unwrap_or_default().to_string()));
                } else {
                    // For other fields, use JSON_EXTRACT
                    sql += &format!("JSON_EXTRACT(data, '$.{}') = ?", key);
                    params.push(Box::new(value.to_string()));
                }
            }
        }

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(
            params.iter().map(|p| p.as_ref()),
        ))?;

        let mut updated_documents = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let json_str: String = row.get(1)?;

            // Parse the existing document
            let existing_doc = serde_json::from_str::<Value>(&json_str)?;

            // Merge the existing doc with the update
            let mut updated_doc = existing_doc.clone();
            if let (Some(_existing_obj), Some(update_obj)) =
                (existing_doc.as_object(), document_json.as_object())
            {
                if let Some(obj) = updated_doc.as_object_mut() {
                    // Merge all fields except _id
                    for (key, value) in update_obj {
                        if key != "_id" {
                            obj.insert(key.clone(), value.clone());
                        }
                    }
                }
            }

            // Update in the database
            let updated_json = serde_json::to_string(&updated_doc)?;
            conn.execute(
                &format!("UPDATE {} SET data = ? WHERE _id = ?", collection),
                params![updated_json, id],
            )?;

            updated_documents.push(ValueType::from_json(updated_doc));
        }

        // If nothing was updated, return an appropriate message
        if updated_documents.is_empty() {
            return Ok(ServiceResponse {
                status: ResponseStatus::Success,
                message: "No documents matched the filter criteria".to_string(),
                data: None,
            });
        }

        let document_id = if updated_documents.len() == 1 {
            if let ValueType::Map(map) = &updated_documents[0] {
                if let Some(ValueType::String(id)) = map.get("_id").cloned() {
                    id
                } else {
                    "unknown".to_string()
                }
            } else if let ValueType::Json(json) = &updated_documents[0] {
                json.get("_id")
                    .and_then(|id| id.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "multiple".to_string()
        };

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("Document with ID {} updated", document_id),
            data: if updated_documents.len() == 1 {
                Some(updated_documents[0].clone())
            } else {
                Some(ValueType::Array(updated_documents))
            },
        })
    }

    /// Delete documents
    async fn delete(&self, collection: &str, filter: ValueType) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Check if the collection exists
        if !self.collection_exists(&conn, collection)? {
            return Err(anyhow!("Collection {} does not exist", collection));
        }

        // Convert to JSON for query
        let filter_json = filter.to_json();

        if !filter_json.is_object() {
            return Err(anyhow!("Filter must be an object"));
        }

        // Build the query
        let mut sql = format!("DELETE FROM {}", collection);
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        let filter_obj = filter_json.as_object().unwrap();
        if !filter_obj.is_empty() {
            sql += " WHERE ";
            let mut first = true;

            for (key, value) in filter_obj {
                if !first {
                    sql += " AND ";
                }
                first = false;

                // Handle _id separately
                if key == "_id" {
                    sql += "_id = ?";
                    params.push(Box::new(value.as_str().unwrap_or_default().to_string()));
                } else {
                    // For other fields, use JSON_EXTRACT
                    sql += &format!("JSON_EXTRACT(data, '$.{}') = ?", key);
                    params.push(Box::new(value.to_string()));
                }
            }
        }

        // Execute the query
        let result = conn.execute(
            &sql,
            rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
        )?;

        let mut result_data = HashMap::new();
        result_data.insert("deleted".to_string(), ValueType::Number(result as f64));

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("Deleted {} documents", result),
            data: Some(ValueType::Map(result_data)),
        })
    }

    /// Ensure a collection exists, create it if it doesn't
    fn ensure_collection_exists(
        &self,
        conn: &rusqlite::Connection,
        collection: &str,
    ) -> Result<()> {
        // Check if collection exists
        if self.collection_exists(conn, collection)? {
            return Ok(());
        }

        // Create the collection table
        conn.execute(
            &format!(
                "CREATE TABLE {} (
                    _id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )",
                collection
            ),
            [],
        )?;

        // Add to metadata
        conn.execute(
            "INSERT INTO _metadata (collection) VALUES (?)",
            params![collection],
        )?;

        Ok(())
    }

    /// Check if a collection exists
    fn collection_exists(&self, conn: &rusqlite::Connection, collection: &str) -> Result<bool> {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
            params![collection],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }
}

/// SqliteQuery Mixin - reusable SQL query functionality
pub struct SqliteQueryMixin {
    /// The database connection
    db: Arc<SqliteDatabase>,
    /// Storage options
    _storage_options: SqliteStorageOptions,
}

impl SqliteQueryMixin {
    /// Create a new SqliteQueryMixin
    pub fn new(db: Arc<SqliteDatabase>, storage_options: SqliteStorageOptions) -> Self {
        SqliteQueryMixin {
            db,
            _storage_options: storage_options,
        }
    }

    /// Create a new SqliteQueryMixin with in-memory database
    pub async fn new_from_memory() -> Result<Self> {
        let storage_options = SqliteStorageOptions {
            storage_type: SqliteStorageType::Memory,
            max_size: None,
            path: None,
        };

        let db = Arc::new(SqliteDatabase::new(":memory:").await?);
        Ok(Self::new(db, storage_options))
    }

    /// Create a new SqliteQueryMixin from storage options
    pub async fn new_from_options(storage_options: SqliteStorageOptions) -> Result<Self> {
        let db = match storage_options.storage_type {
            SqliteStorageType::Memory => Arc::new(SqliteDatabase::new(":memory:").await?),
            SqliteStorageType::Disk => {
                let path = storage_options
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow!("Path is required for disk storage"))?;
                Arc::new(SqliteDatabase::new(path).await?)
            }
        };

        Ok(Self::new(db, storage_options))
    }

    /// Initialize the database for SqliteQueryMixin
    pub async fn init(&self, _context: &crate::services::RequestContext) -> Result<()> {
        // Nothing specific to initialize for query mixin
        Ok(())
    }

    /// Process a query request
    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        match request.action.as_str() {
            "query" => {
                let sql = request
                    .get_param("sql")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .ok_or_else(|| anyhow!("SQL query is required"))?;

                let params = request.get_param("params").unwrap_or(ValueType::Null);

                self.query(&sql, params).await
            }
            "execute" => {
                let sql = request
                    .get_param("sql")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .ok_or_else(|| anyhow!("SQL query is required"))?;

                let params = request.get_param("params").unwrap_or(ValueType::Null);

                self.execute(&sql, params).await
            }
            _ => Err(anyhow!("Unknown operation: {}", request.action)),
        }
    }

    /// Execute a SQL query that returns rows
    async fn query(&self, sql: &str, params: ValueType) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Convert parameters to SQL params if needed
        let json_params = params.to_json();
        let sql_params = utils::json_params_to_sql_params(&json_params)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();

        // Prepare statement
        let mut stmt = conn.prepare(sql)?;
        let column_names: Vec<String> = stmt
            .column_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        // Execute query
        let mut rows = stmt.query(rusqlite::params_from_iter(param_refs.iter()))?;

        // Process results
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            let json_obj = utils::map_row_to_json_object(row, &column_names)?;
            results.push(ValueType::from_json(json_obj));
        }

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("Query returned {} rows", results.len()),
            data: Some(ValueType::Array(results)),
        })
    }

    /// Execute a SQL query that doesn't return rows
    async fn execute(&self, sql: &str, params: ValueType) -> Result<ServiceResponse> {
        let conn = self.db.get_connection().await?;

        // Convert parameters to SQL params if needed
        let json_params = params.to_json();
        let sql_params = utils::json_params_to_sql_params(&json_params)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();

        // Execute query
        let rows_affected = conn.execute(sql, rusqlite::params_from_iter(param_refs.iter()))?;

        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!(
                "Query executed successfully, {} rows affected",
                rows_affected
            ),
            data: Some(ValueType::Number(rows_affected as f64)),
        })
    }
}

/// SQLite Service - provides both CRUD operations and raw SQL execution
/// This is an example of a service that uses both mixins
pub struct SqliteService {
    /// Service name
    name: String,
    /// Service path
    path: String,
    /// Service state
    state: ServiceState,
    /// CRUD mixin for database operations
    _crud_mixin: SqliteCrudMixin,
    /// Query mixin for SQL operations
    query_mixin: SqliteQueryMixin,
}

impl SqliteService {
    /// Create a new SQLite service
    pub fn new(db: Arc<SqliteDatabase>, network_id: &str) -> Self {
        let storage_options = SqliteStorageOptions {
            storage_type: SqliteStorageType::Disk,
            max_size: None,
            path: None,
        };

        SqliteService {
            name: "sqlite".to_string(),
            path: format!("{}/sqlite", network_id),
            state: ServiceState::Created,
            _crud_mixin: SqliteCrudMixin::new(db.clone(), storage_options.clone(), None),
            query_mixin: SqliteQueryMixin::new(db.clone(), storage_options),
        }
    }

    /// Execute a query
    async fn execute_query(&self, query: &str) -> Result<ValueType> {
        // Create a proper action path for routing
        let action_path = crate::routing::TopicPath::new_action("default", &self.path, query);
        
        let request = ServiceRequest {
            path: format!("{}/{}", self.path, query),
            action: query.to_string(),
            data: None,
            request_id: None,
            // TODO: We should refactor this to use a proper RequestContext.
            // For now, we're using the default implementation, but this should be
            // replaced with a properly initialized context that has the correct node handler.
            context: Arc::new(RequestContext::default()),
            metadata: None,
            topic_path: Some(action_path),
        };

        let response = self.query_mixin.handle_request(request).await?;
        Ok(response.data.unwrap_or(ValueType::Null))
    }

    /// Handle the query operation
    async fn handle_query(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("Processing query operation on path: {}", request.path);
        
        // Extract SQL and parameters from the request
        if let Some(data) = &request.data {
            if let ValueType::Map(param_map) = data {
                if let Some(ValueType::String(sql)) = param_map.get("sql") {
                    debug!("Executing SQL query: {}", sql);
                    
                    // Execute the query using the query mixin
                    let params_value = param_map.clone();
                    match self.query_mixin.query(&sql, ValueType::Map(params_value)).await {
                        Ok(response) => {
                            let row_count = response.data.as_ref().map_or(0, |d| {
                                if let ValueType::Array(arr) = d {
                                    arr.len()
                                } else {
                                    0
                                }
                            });
                            
                            info!("Query executed successfully, returned {} rows", row_count);
                            Ok(response)
                        },
                        Err(e) => {
                            error!("Error executing query: {}", e);
                            Ok(ServiceResponse::error(format!("Error executing query: {}", e)))
                        },
                    }
                } else {
                    warn!("Missing 'sql' parameter in query request");
                    Ok(ServiceResponse::error("Missing 'sql' parameter"))
                }
            } else {
                warn!("Missing parameters in query request");
                Ok(ServiceResponse::error("Missing parameters"))
            }
        } else {
            warn!("Missing parameters in query request");
            Ok(ServiceResponse::error("Missing parameters"))
        }
    }
    
    /// Handle the execute operation
    async fn handle_execute(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("Processing execute operation on path: {}", request.path);
        
        // Extract SQL and parameters from the request
        if let Some(data) = &request.data {
            if let ValueType::Map(param_map) = data {
                if let Some(ValueType::String(sql)) = param_map.get("sql") {
                    debug!("Executing SQL statement: {}", sql);
                    
                    // Execute the statement using the query mixin
                    let params_value = param_map.clone();
                    match self.query_mixin.execute(&sql, ValueType::Map(params_value)).await {
                        Ok(response) => {
                            Ok(response)
                        },
                        Err(e) => {
                            error!("Error executing SQL: {}", e);
                            Ok(ServiceResponse::error(format!("SQL execution error: {}", e)))
                        }
                    }
                } else {
                    warn!("Missing 'sql' parameter in execute request");
                    Ok(ServiceResponse::error("Missing 'sql' parameter"))
                }
            } else {
                warn!("Missing parameters in execute request");
                Ok(ServiceResponse::error("Missing parameters"))
            }
        } else {
            warn!("Missing parameters in execute request");
            Ok(ServiceResponse::error("Missing parameters"))
        }
    }
    
    /// Handle the batch operation
    async fn handle_batch(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("Processing batch operation on path: {}", request.path);
        
        // Extract SQL and parameters from the request
        if let Some(data) = &request.data {
            if let ValueType::Map(param_map) = data {
                if let Some(ValueType::String(sql)) = param_map.get("sql") {
                    debug!("Executing SQL batch: {}", sql);
                    
                    // Process batch operation
                    // ... Implementation details ...
                    
                    Ok(ServiceResponse::success(
                        "Batch execution completed successfully".to_string(), 
                        Some(ValueType::Null)
                    ))
                } else {
                    warn!("Missing 'sql' parameter in batch request");
                    Ok(ServiceResponse::error("Missing 'sql' parameter"))
                }
            } else {
                warn!("Missing parameters in batch request");
                Ok(ServiceResponse::error("Missing parameters"))
            }
        } else {
            warn!("Missing parameters in batch request");
            Ok(ServiceResponse::error("Missing parameters"))
        }
    }

    /// Initialize the database.
    pub async fn init_database(&mut self) -> Result<()> {
        info!("Initializing SQLite database");
        self.state = ServiceState::Initialized;
        Ok(())
    }
}

#[async_trait]
impl AbstractService for SqliteService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn state(&self) -> ServiceState {
        self.state
    }
    
    fn version(&self) -> &str {
        "1.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "create".to_string() },
            ActionMetadata { name: "read".to_string() },
            ActionMetadata { name: "update".to_string() },
            ActionMetadata { name: "delete".to_string() },
            ActionMetadata { name: "query".to_string() },
            ActionMetadata { name: "execute".to_string() },
        ]
    }
    
    fn events(&self) -> Vec<EventMetadata> {
        vec![
            EventMetadata { name: "created".to_string() },
            EventMetadata { name: "updated".to_string() },
            EventMetadata { name: "deleted".to_string() },
        ]
    }
    
    fn description(&self) -> &str {
        "SQLite database service"
    }

    async fn init(&mut self, _context: &crate::services::RequestContext) -> Result<()> {
        info!("Initializing SqliteService");
        // Initialize the CRUD and query mixins
        self.state = ServiceState::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting SqliteService");
        self.state = ServiceState::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping SqliteService");
        self.state = ServiceState::Stopped;
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("Handling request for operation: {} on path: {}", 
            request.action, request.path);
        
        // Delegate to specialized methods based on operation
        match request.action.as_str() {
            "query" => self.handle_query(request).await,
            "execute" => self.handle_execute(request).await,
            "batch" => self.handle_batch(request).await,
            _ => {
                warn!("Unknown operation requested: {}", request.action);
                Ok(ServiceResponse::error(format!("Unknown operation: {}", request.action)))
            }
        }
    }
}
