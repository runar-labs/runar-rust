use anyhow::{anyhow, Result};
use async_trait::async_trait;
use runar_common::logging::Logger;
use runar_node::services::{EventContext, LifecycleContext, RequestContext, ServiceFuture};
use runar_node::AbstractService;
use runar_serializer::{ArcValue, Plain};
use rusqlite::types::ToSqlOutput;
use rusqlite::types::{Null, ValueRef as RusqliteValueRef};
use rusqlite::{params_from_iter, Connection, Result as RusqliteResult, ToSql};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot}; // Added mpsc, oneshot, thread // Added for Arc<Logger>

// Constants for action names to avoid hardcoding
const EXECUTE_QUERY_ACTION: &str = "execute_query";
const REPLICATION_GET_TABLE_EVENTS_ACTION: &str = "replication/get_table_events";

// Schema definition structs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DataType {
    Integer,
    Real,
    Text,
    Blob,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnDefinition {
    pub name: String,
    pub data_type: DataType,
    pub primary_key: bool,
    pub autoincrement: bool,
    pub not_null: bool,
    // Consider adding: unique, default_value, foreign_key constraints if needed later
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableDefinition {
    pub name: String,
    pub columns: Vec<ColumnDefinition>,
    // Consider adding: table-level constraints (e.g., composite primary keys, foreign keys) if needed later
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexDefinition {
    pub name: String,
    pub table_name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    pub tables: Vec<TableDefinition>,
    pub indexes: Vec<IndexDefinition>,
}

// Command enum for the SQLite worker thread
pub enum SqliteWorkerCommand {
    ApplySchema {
        schema: Schema, // Schema must be Send
        reply_to: oneshot::Sender<Result<(), String>>,
    },
    Execute {
        query: SqlQuery, // Changed: Now takes SqlQuery
        reply_to: oneshot::Sender<Result<usize, String>>,
    },
    Query {
        query: SqlQuery, // Changed: Now takes SqlQuery
        reply_to: oneshot::Sender<Result<Vec<HashMap<String, Value>>, String>>, // Changed to Value
    },
    Shutdown {
        // Added Shutdown command
        reply_to: oneshot::Sender<Result<(), String>>,
    },
}

// The SQLite worker struct
pub struct SqliteWorker {
    connection: Connection,
    receiver: mpsc::Receiver<SqliteWorkerCommand>,
    logger: Arc<Logger>,                   // Added logger
    ready_tx: Option<oneshot::Sender<()>>, // To signal when worker is ready
}

impl SqliteWorker {
    pub fn new(
        db_path: String,
        receiver: mpsc::Receiver<SqliteWorkerCommand>,
        logger: Arc<Logger>,
        ready_tx: oneshot::Sender<()>,  // Add ready channel sender
        symmetric_key: Option<Vec<u8>>, // Direct symmetric key bytes for encryption
    ) -> Result<Self, String> {
        let connection = Connection::open(db_path.clone()).map_err(|e| {
            let err_msg = format!("Failed to open SQLite connection to '{db_path}': {e}");
            logger.error(&err_msg);
            err_msg
        })?;

        // If a symmetric key is provided, use it for encryption
        if let Some(key_bytes) = symmetric_key {
            // Convert the key bytes to a hex string for SQLCipher
            // SQLCipher expects the key as a hex string when using raw keys
            let hex_key = format!("x'{}'", hex::encode(&key_bytes));

            // Set the raw key using PRAGMA
            connection
                .pragma_update(None, "key", &hex_key)
                .map_err(|e| {
                    let err_msg = format!("Failed to set database key: {e}");
                    logger.error(&err_msg);
                    err_msg
                })?;
            logger.debug("Database key set successfully using provided symmetric key.");
        }

        // TODO: Apply any pragmas or initial setup to the connection here if needed
        // E.g., conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
        logger.debug(
            "SqliteWorker::new: Connection opened. TODO: Apply pragmas/initial setup if needed.",
        );
        Ok(Self {
            connection,
            receiver,
            logger,
            ready_tx: Some(ready_tx),
        })
    }

    // Main loop for the worker thread
    pub async fn run(mut self) {
        // Signal that the worker is ready
        if let Some(tx) = self.ready_tx.take() {
            if tx.send(()).is_err() {
                self.logger
                    .error("Failed to send ready signal; receiver was dropped.");
                return; // Early exit if we can't signal readiness
            }
        }
        self.logger.info("SqliteWorker started processing loop.");
        while let Some(command) = self.receiver.recv().await {
            match command {
                SqliteWorkerCommand::ApplySchema { schema, reply_to } => {
                    self.logger.debug("Processing ApplySchema command");
                    let res = apply_schema_internal(&self.connection, &schema, &self.logger);
                    let _ = reply_to.send(res); // Ignore error if receiver dropped
                }
                SqliteWorkerCommand::Execute { query, reply_to } => {
                    self.logger.debug("Processing Execute command");
                    let res = execute_internal(
                        &self.connection,
                        &query.statement,
                        &query.params,
                        &self.logger,
                    );
                    let _ = reply_to.send(res);
                }
                SqliteWorkerCommand::Query { query, reply_to } => {
                    self.logger.debug("Processing Query command");
                    let res = query_internal(
                        &self.connection,
                        &query.statement,
                        &query.params,
                        &self.logger,
                    );
                    let _ = reply_to.send(res);
                }
                SqliteWorkerCommand::Shutdown { reply_to } => {
                    self.logger.info("SqliteWorker received Shutdown command.");
                    let _ = reply_to.send(Ok(()));
                    break; // Exit the loop to terminate the worker
                }
            }
        }
        self.logger.info("SqliteWorker finished.");
    }
}

// Internal helper function for applying schema
fn apply_schema_internal(
    conn: &Connection,
    schema: &Schema,
    logger: &Arc<Logger>,
) -> Result<(), String> {
    logger.info("Applying schema...");
    // This function generates DDL for tables and indexes based on the provided schema.
    // It aims for idempotency using IF NOT EXISTS.
    // Limitations: Does not yet handle composite primary keys, foreign keys, complex column constraints (DEFAULT, CHECK, etc.)
    // as these are not fully represented in the current schema definition structs.

    let mut ddl_batch = String::new();

    // Table Creation DDLs
    for table_def in &schema.tables {
        let columns_ddl: Vec<String> = table_def
            .columns
            .iter()
            .map(|col| {
                let col_type_str = match col.data_type {
                    DataType::Integer => "INTEGER",
                    DataType::Real => "REAL",
                    DataType::Text => "TEXT",
                    DataType::Blob => "BLOB",
                    DataType::Boolean => "INTEGER", // Booleans often stored as 0/1 in SQLite
                };
                let mut col_ddl = format!("{} {}", col.name, col_type_str);
                if col.primary_key {
                    col_ddl.push_str(" PRIMARY KEY");
                    if col.autoincrement {
                        // AUTOINCREMENT typically requires INTEGER PRIMARY KEY
                        col_ddl.push_str(" AUTOINCREMENT");
                    }
                }
                if col.not_null {
                    col_ddl.push_str(" NOT NULL");
                }
                // TODO: Extend ColumnDefinition to support DEFAULT, UNIQUE (column-level), CHECK constraints
                // and update DDL generation here accordingly.
                col_ddl
            })
            .collect();

        // TODO: Extend TableDefinition to support composite PRIMARY KEY, table-level UNIQUE, CHECK, FOREIGN KEY constraints
        // and update DDL generation here.
        logger.debug(format!("Preparing to create table: {}", table_def.name));
        let table_ddl = format!(
            "CREATE TABLE IF NOT EXISTS {} ({});\n",
            table_def.name,
            columns_ddl.join(", ")
        );
        ddl_batch.push_str(&table_ddl);
    }

    // Index Creation DDLs
    for index_def in &schema.indexes {
        if index_def.columns.is_empty() {
            logger.warn(format!(
                "Skipping index '{}' for table '{}' as it has no columns defined.",
                index_def.name, index_def.table_name
            ));
            continue;
        }
        let unique_str = if index_def.unique { "UNIQUE " } else { "" };
        let columns_list = index_def.columns.join(", ");
        logger.debug(format!(
            "Preparing to create index: {} on table {}",
            index_def.name, index_def.table_name
        ));
        let index_ddl = format!(
            "CREATE {}INDEX IF NOT EXISTS {} ON {} ({});\n",
            unique_str, index_def.name, index_def.table_name, columns_list
        );
        ddl_batch.push_str(&index_ddl);
    }

    if ddl_batch.is_empty() {
        logger.debug("No DDL statements to execute for the provided schema.");
        return Ok(());
    }

    conn.execute_batch(&ddl_batch).map_err(|e| {
        let err_msg = format!("Failed to apply schema batch: {e}. DDL:\n{ddl_batch}");
        logger.error(&err_msg);
        err_msg
    })
}

// Internal helper function for executing non-query SQL
fn execute_internal(
    conn: &Connection,
    sql: &str,
    params: &Params, // Changed: Now takes &Params
    logger: &Arc<Logger>,
) -> Result<usize, String> {
    logger.debug(format!("Executing SQL: {sql}"));

    let rusqlite_params_results: Result<Vec<Box<dyn ToSql + Send + Sync>>, String> =
        params.values.iter().map(value_to_to_sql).collect(); // Changed: uses value_to_to_sql

    match rusqlite_params_results {
        Ok(rusqlite_params) => {
            let params_for_iter: Vec<&(dyn rusqlite::types::ToSql + Send + Sync)> =
                rusqlite_params.iter().map(|b| b.as_ref()).collect();
            logger.debug(format!("Executing SQL: {sql} with params: {params:?}"));
            conn.execute(sql, params_from_iter(params_for_iter))
                .map_err(|e| {
                    let err_msg = format!("Failed to execute SQL '{sql}': {e}");
                    logger.error(&err_msg);
                    err_msg
                })
        }
        Err(e) => Err(format!(
            "Failed to convert Value params to SQL params: {e}", // Updated error message
        )),
    }
}

// Internal helper function for executing query SQL
fn query_internal(
    conn: &Connection,
    sql: &str,
    params: &Params, // Changed: Now takes &Params
    logger: &Arc<Logger>,
) -> Result<Vec<HashMap<String, Value>>, String> {
    let rusqlite_params_results: Result<Vec<Box<dyn ToSql + Send + Sync>>, String> =
        params.values.iter().map(value_to_to_sql).collect(); // Changed: uses value_to_to_sql

    let rusqlite_params = match rusqlite_params_results {
        Ok(p) => p,
        Err(e) => {
            return Err(format!(
                "Failed to convert Value params to SQL params for query: {e}", // Updated error message
            ));
        }
    };

    let params_for_iter: Vec<&(dyn rusqlite::types::ToSql + Send + Sync)> =
        rusqlite_params.iter().map(|b| b.as_ref()).collect();

    logger.debug(format!(
        "Preparing SQL query: {sql} with params: {params:?}",
    ));
    let mut stmt = conn.prepare(sql).map_err(|e| {
        let err_msg = format!("Error preparing statement for SQL '{sql}': {e}");
        logger.error(&err_msg);
        err_msg
    })?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    logger.debug(format!(
        "Executing SQL query: {sql} with params: {params:?}",
    ));
    let rows_iter = stmt
        .query_map(params_from_iter(params_for_iter.into_iter()), |row| {
            let mut map = HashMap::new();
            for (i, name) in column_names.iter().enumerate() {
                map.insert(name.clone(), value_ref_to_value(row.get_ref_unwrap(i)));
            }
            Ok(map) // Ok for rusqlite::Result for this row
        })
        .map_err(|e| {
            let err_msg = format!("Error executing query '{sql}': {e}");
            logger.error(&err_msg);
            err_msg
        })?;

    rows_iter
        .collect::<RusqliteResult<Vec<HashMap<String, Value>>>>()
        .map_err(|e| {
            let err_msg = format!("Error collecting query results for '{sql}': {e}");
            logger.error(&err_msg);
            err_msg
        })
}

// Helper to convert local Value enum to a ToSql-compatible boxed trait object.
fn value_to_to_sql(val: &Value) -> Result<Box<dyn ToSql + Send + Sync>, String> {
    match val {
        Value::Null => Ok(Box::new(Null)),
        Value::Integer(i) => Ok(Box::new(*i)),
        Value::Real(f) => Ok(Box::new(*f)),
        Value::Text(s) => Ok(Box::new(s.clone())),
        Value::Blob(b) => Ok(Box::new(b.clone())),
        Value::Boolean(b) => Ok(Box::new(if *b { 1i64 } else { 0i64 })), // SQLite uses 0/1 for booleans
    }
}

// Helper to convert rusqlite's ValueRef to Value.
// This is used when processing query results.
fn value_ref_to_value(value_ref: RusqliteValueRef<'_>) -> Value {
    match value_ref {
        RusqliteValueRef::Null => Value::Null,
        RusqliteValueRef::Integer(i) => Value::Integer(i),
        RusqliteValueRef::Real(f) => Value::Real(f),
        RusqliteValueRef::Text(t_bytes) => {
            Value::Text(String::from_utf8_lossy(t_bytes).into_owned())
        }
        RusqliteValueRef::Blob(blob_bytes) => Value::Blob(blob_bytes.to_vec()),
    }
}

// Helper to convert internal Value enum to ArcValue for service responses.
fn internal_value_to_arc_value(value: &Value) -> ArcValue {
    match value {
        Value::Null => ArcValue::null(), // Changed to ArcValue::null()
        Value::Integer(i) => ArcValue::new_primitive(*i),
        Value::Real(f) => ArcValue::new_primitive(*f),
        Value::Text(s) => ArcValue::new_primitive(s.clone()),
        Value::Blob(b) => {
            // Ensure this matches how ArcValue expects Bytes. ErasedArc is appropriate here.
            ArcValue::new_bytes(b.clone())
        }
        Value::Boolean(b) => ArcValue::new_primitive(*b),
    }
}

/// Core value types for SQLite operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Boolean(bool),
}

/// Represents a single row returned from an SQL query.
///
/// Intention: Provides a structured, documented, and type-safe way to access query results.
/// Each row consists of a mapping from column names to values, preserving column order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlRow {
    /// Column values by name, as returned from the database.
    pub columns: HashMap<String, Value>,
}

impl ToSql for Value {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, rusqlite::Error> {
        match self {
            Value::Null => Ok(ToSqlOutput::from(Null)),
            Value::Integer(i) => Ok(ToSqlOutput::from(*i)),
            Value::Real(f) => Ok(ToSqlOutput::from(*f)),
            Value::Text(s) => Ok(ToSqlOutput::from(s.as_str())),
            Value::Blob(b) => Ok(ToSqlOutput::from(b.as_slice())),
            Value::Boolean(b) => Ok(ToSqlOutput::from(if *b { 1i64 } else { 0i64 })),
        }
    }
}

// Conversion from rusqlite::types::Value to our Value type
impl From<rusqlite::types::Value> for Value {
    fn from(db_value: rusqlite::types::Value) -> Self {
        match db_value {
            rusqlite::types::Value::Null => Value::Null,
            rusqlite::types::Value::Integer(i) => Value::Integer(i),
            rusqlite::types::Value::Real(f) => Value::Real(f),
            rusqlite::types::Value::Text(s) => Value::Text(s),
            rusqlite::types::Value::Blob(b) => Value::Blob(b),
        }
    }
}

/// Parameter bindings for SQL queries (positional only)
///
/// Intention: Encapsulates positional parameter values for SQLite queries.
/// Only supports positional binding, not named parameters.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Params {
    pub values: Vec<Value>,
}

impl Params {
    /// Create a new Params object
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a value to the parameter list (positional)
    pub fn with_value(mut self, value: impl Into<Value>) -> Self {
        self.values.push(value.into());
        self
    }
} // No more named parameter logic

/// SQL Query with typed parameters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
pub struct SqlQuery {
    pub statement: String,
    pub params: Params,
}

impl SqlQuery {
    pub fn new(statement: &str) -> Self {
        Self {
            statement: statement.to_string(),
            params: Params::new(),
        }
    }
    pub fn with_params(mut self, params: Params) -> Self {
        self.params = params;
        self
    }
}

/// Query operators for building advanced queries
#[derive(Debug, Clone, PartialEq)]
pub enum QueryOperator {
    Equal(Value),
    NotEqual(Value),
    GreaterThan(Value),
    GreaterThanOrEqual(Value),
    LessThan(Value),
    LessThanOrEqual(Value),
    Like(String),
    In(Vec<Value>),
}

/// Query builder for composable, immutable queries
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Query {
    pub conditions: HashMap<String, QueryOperator>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_condition(mut self, field: &str, op: QueryOperator) -> Self {
        self.conditions.insert(field.to_string(), op);
        self
    }
}

/// CRUD operation types
#[derive(Debug, Clone, PartialEq)]
pub struct CreateOperation {
    pub table: String,
    pub data: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadOperation {
    pub table: String,
    pub query: Query,
    pub fields: Option<Vec<String>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub order_by: Option<Vec<(String, bool)>>, // (field, is_ascending)
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateOperation {
    pub table: String,
    pub query: Query,
    pub updates: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteOperation {
    pub table: String,
    pub query: Query,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrudOperation {
    Create(CreateOperation),
    Read(ReadOperation),
    Update(UpdateOperation),
    Delete(DeleteOperation),
}

// Intention: Implementation logic, connection pooling, and service trait integration will be added only after tests and documentation are aligned with this API.

/// Configuration for the SQLite service.
#[derive(Clone, Debug, Serialize, Deserialize)] // Ensure SqliteConfig is Clone + Debug + Send + Sync
pub struct SqliteConfig {
    /// Path to the SQLite database file
    pub db_path: String,
    /// Schema definition for the database
    pub schema: Schema,
    /// Encryption flag
    pub encryption: bool,
    /// Optional replication configuration
    pub replication: Option<crate::replication::ReplicationConfig>,
}

impl SqliteConfig {
    /// Create a new SQLite config with path and schema
    pub fn new(db_path: impl Into<String>, schema: Schema, encryption: bool) -> Self {
        Self {
            db_path: db_path.into(),
            schema,
            encryption,
            replication: None,
        }
    }

    /// Add replication configuration to the SQLite config
    pub fn with_replication(mut self, replication: crate::replication::ReplicationConfig) -> Self {
        self.replication = Some(replication);
        self
    }
}

pub struct SqliteService {
    pub name: String,
    pub path: String,
    pub version: String,
    pub description: String,
    pub config: SqliteConfig,
    worker_tx: Arc<RwLock<Option<mpsc::Sender<SqliteWorkerCommand>>>>,
    network_id: Option<String>,
    /// Optional replication manager
    replication_manager: Arc<RwLock<Option<Arc<crate::replication::ReplicationManager>>>>,
}

// Manual Clone implementation because mpsc::Sender is Clone but not Copy.
impl Clone for SqliteService {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            version: self.version.clone(),
            description: self.description.clone(),
            config: self.config.clone(),
            worker_tx: self.worker_tx.clone(),
            network_id: self.network_id.clone(),
            replication_manager: self.replication_manager.clone(),
        }
    }
}

impl SqliteService {
    // Common for service constructors
    pub fn new(name: String, path: String, config: SqliteConfig) -> Self {
        Self {
            name,
            path,
            version: "0.0.1".to_string(),
            description: "SQLite service".to_string(),
            config,
            worker_tx: Arc::new(RwLock::new(None)),
            network_id: None,
            replication_manager: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn send_command<T: Send + 'static>(
        &self,
        constructor: impl FnOnce(oneshot::Sender<Result<T, String>>) -> SqliteWorkerCommand,
    ) -> Result<T, String> {
        let maybe_sender = {
            let guard = self
                .worker_tx
                .read()
                .map_err(|e| format!("Failed to acquire read lock on worker_tx: {e}"))?;
            // Clone the Option<Sender> out of the guard to release the lock ASAP
            // mpsc::Sender is Clone.
            guard.clone()
        };

        if let Some(cloned_sender) = maybe_sender {
            // cloned_sender is mpsc::Sender
            let (reply_tx, reply_rx) = oneshot::channel();
            let command = constructor(reply_tx);

            if cloned_sender.is_closed() {
                return Err("SqliteWorker channel is closed. Worker may have panicked.".to_string());
            }

            cloned_sender // Use the cloned sender
                .send(command)
                .await
                .map_err(|e| format!("Failed to send command to SqliteWorker: {e}"))?;

            match reply_rx.await {
                Ok(result) => result,
                Err(e) => Err(format!("Failed to receive reply from SqliteWorker: {e}")),
            }
        } else {
            Err(
                "SqliteWorker sender is not initialized. Service may not have been started."
                    .to_string(),
            )
        }
    }

    /// Manually trigger startup synchronization after network connections are established
    async fn apply_schema(&self, schema: Schema, context: &LifecycleContext) -> Result<()> {
        let schema_to_apply = schema; // Use the passed schema argument
        context.info(format!(
            "Attempting to apply schema for SqliteService: {}",
            self.name
        ));
        match self
            .send_command(|reply_tx| SqliteWorkerCommand::ApplySchema {
                schema: schema_to_apply.clone(), // Clone the schema for the command
                reply_to: reply_tx,
            })
            .await
        {
            Ok(_) => {
                // Successfully sent command and worker confirmed schema application
                context.info(format!("Schema application command successfully processed by worker for SqliteService: {}", self.name));
                Ok(())
            }
            Err(e) => {
                // Error from send_command or from worker's schema application logic
                let err_msg = format!(
                    "Failed to apply schema for SqliteService '{}': {}",
                    self.name, e
                );
                context.error(err_msg.clone());
                Err(anyhow!(err_msg))
            }
        }
    }
}

#[async_trait]
impl AbstractService for SqliteService {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn path(&self) -> &str {
        &self.path
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn network_id(&self) -> Option<String> {
        self.network_id.clone()
    }
    fn set_network_id(&mut self, network_id: String) {
        self.network_id = Some(network_id);
    }

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("Initializing SqliteService: {}", self.name));

        // Note: Replication manager will be initialized in start() method
        // since we need mutable access to store it in the service

        // Register 'execute_query' action
        let service_arc = Arc::new(self.clone()); // SqliteService must be Clone

        let execute_query_handler = {
            let s_arc = service_arc.clone();
            Arc::new(
                move |params_opt: Option<ArcValue>, req_ctx: RequestContext| {
                    let service_clone = s_arc.clone();
                    Box::pin(async move {
                        let query_arc_value = params_opt // Made mutable
                            .ok_or_else(|| anyhow!("Missing payload for 'execute_query' action. Expected ArcValue wrapping SqlQuery."))?;

                        let sql_query_struct = query_arc_value.as_type_ref::<SqlQuery>()
                            .map_err(|original_error_from_as_type| {
                                anyhow!(format!(
                                    "Invalid payload type for 'execute_query'. Expected SqlQuery, got {:?}. Original error: {:?}",
                                    query_arc_value.category, // Use Debug formatting for category
                                    original_error_from_as_type
                                ))
                            })?;

                        let sql_statement = sql_query_struct.statement.clone(); // Keep a copy for the SELECT check
                        let query_to_send = sql_query_struct.as_ref().clone(); // Clone the whole SqlQuery for the command

                        let trimmed_sql = sql_statement.trim_start().to_uppercase();
                        if trimmed_sql.starts_with("SELECT") {
                            // The worker now returns Vec<HashMap<String, Value>> for queries
                            let internal_results: Vec<HashMap<String, Value>> = service_clone
                                .send_command(|reply_tx| SqliteWorkerCommand::Query {
                                    query: query_to_send,
                                    reply_to: reply_tx,
                                })
                                .await
                                .map_err(|e: String| anyhow!(e))?;

                            // Convert Vec<HashMap<String, Value>> to Vec<HashMap<String, ArcValue>>
                            let arc_results: Vec<HashMap<String, ArcValue>> = internal_results
                                .into_iter()
                                .map(|hmap| {
                                    hmap.into_iter()
                                        .map(|(k, v_internal)| {
                                            (k, internal_value_to_arc_value(&v_internal))
                                        })
                                        .collect::<HashMap<String, ArcValue>>()
                                })
                                .collect();

                            let result_list: Vec<ArcValue> = arc_results
                                .into_iter()
                                .map(|hmap_arc| ArcValue::new_map(hmap_arc.into_iter().collect())) // VMap from HashMap
                                .collect();
                            Ok(ArcValue::new_list(result_list))
                        } else {
                            let affected_rows: usize = service_clone
                                .send_command(|reply_tx| SqliteWorkerCommand::Execute {
                                    query: query_to_send,
                                    reply_to: reply_tx,
                                })
                                .await
                                .map_err(|e: String| anyhow!(e))?;

                            // Emit event for non-SELECT operations if replication is enabled
                            if let Some(replication_config) = &service_clone.config.replication {
                                // Extract table name from SQL statement
                                if let Some(table_name) = extract_table_name(&sql_statement) {
                                    let table_name = table_name.clone();
                                    if replication_config.enabled_tables.contains(&table_name) {
                                        let event = crate::replication::SqliteEvent {
                                            operation: determine_operation_type(&trimmed_sql)
                                                .to_lowercase(),
                                            table: table_name.clone(),
                                            data: query_arc_value.clone(),
                                            timestamp: SystemTime::now(),
                                        };

                                        // Use proper namespacing: <service_path>/<table_name>/<operation>
                                        let service_path = service_clone.path.clone();
                                        let event_path = format!(
                                            "{}/{}/{}",
                                            service_path, table_name, event.operation
                                        );

                                        req_ctx.info(format!(
                                            "📤 Publishing SQLite event: path={}, table={}, operation={}",
                                            event_path, table_name, event.operation
                                        ));

                                        req_ctx
                                            .publish(event_path, Some(ArcValue::new_struct(event)))
                                            .await?;

                                        req_ctx.info("✅ SQLite event published successfully");
                                    } else {
                                        req_ctx.debug(format!(
                                            "⏭️  Skipping event for table '{}' - not in enabled_tables: {:?}",
                                            table_name, replication_config.enabled_tables
                                        ));
                                    }
                                } else {
                                    req_ctx.debug(
                                        "⏭️  Could not extract table name from SQL statement",
                                    );
                                }
                            }

                            Ok(ArcValue::new_primitive(affected_rows as i64))
                        }
                    }) as ServiceFuture // ServiceFuture is Pin<Box<dyn Future<Output = Result<ArcValue>> + Send>>
                },
            )
        };
        context
            .register_action(EXECUTE_QUERY_ACTION, execute_query_handler)
            .await?;
        context.info(format!(
            "'{}' action registered for SqliteService: {}",
            EXECUTE_QUERY_ACTION, self.name
        ));

        // Register paginated API for replication if enabled
        context.info(format!(
            "Checking replication config for service {}: {:?}",
            self.name,
            self.config.replication.is_some()
        ));
        if let Some(replication_config) = &self.config.replication {
            context.info("Initializing replication manager...");

            let node_id = self
                .network_id
                .clone()
                .ok_or_else(|| anyhow!("Network ID is required for replication"))?;

            let replication_manager = Arc::new(crate::replication::ReplicationManager::new(
                Arc::new(self.clone()),
                replication_config.clone(),
                context.logger.clone(),
                node_id,
            ));

            let get_table_events_handler = {
                let replication_manager_clone = replication_manager.clone();
                Arc::new(
                    move |params_opt: Option<ArcValue>, _req_ctx: RequestContext| {
                        let replication_manager_clone = replication_manager_clone.clone();
                        Box::pin(async move {
                            if let Some(request_data) = params_opt {
                                let request = request_data
                                    .as_type_ref::<crate::replication::TableEventsRequest>()?;
                                let response =
                                    replication_manager_clone.get_table_events(request).await?;
                                Ok(ArcValue::new_struct(response))
                            } else {
                                Err(anyhow!("No request data provided"))
                            }
                        }) as ServiceFuture
                    },
                )
            };

            context
                .register_action(
                    REPLICATION_GET_TABLE_EVENTS_ACTION,
                    get_table_events_handler,
                )
                .await?;

            // Store the replication manager
            {
                let mut manager_guard = self.replication_manager.write().map_err(|e| {
                    anyhow!("Failed to acquire write lock on replication_manager: {e}")
                })?;
                *manager_guard = Some(replication_manager.clone());
            }

            // Subscribe to all events for enabled tables with proper namespacing
            for table in &self.config.replication.as_ref().unwrap().enabled_tables {
                let create_path = format!("{}/{}/create", self.path, table);
                let update_path = format!("{}/{}/update", self.path, table);
                let delete_path = format!("{}/{}/delete", self.path, table);

                // Create a single handler for all operation types
                let event_handler = {
                    let replication_manager_clone = replication_manager.clone(); // Just clone the Arc
                    Arc::new(move |ctx: Arc<EventContext>, event: Option<ArcValue>| {
                        let replication_manager_clone = replication_manager_clone.clone(); // Just clone the Arc
                        Box::pin(async move {
                            ctx.info("🎯 Event handler triggered");

                            if let Some(event_data) = event {
                                ctx.info("📦 Event data received");

                                let sqlite_event = (*event_data
                                    .as_type_ref::<crate::replication::SqliteEvent>()?)
                                .clone();
                                let is_local = ctx.is_local();

                                ctx.info(format!(
                                    "🔄 Processing SQLite event: table={}, operation={}, is_local={}",
                                    sqlite_event.table, sqlite_event.operation, is_local
                                ));

                                replication_manager_clone
                                    .handle_sqlite_event(sqlite_event, is_local)
                                    .await?;

                                ctx.info("✅ Event processing completed");
                            } else {
                                ctx.debug("📭 No event data provided");
                            }
                            Ok(())
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    })
                };

                // Subscribe to all operation types for this table
                context
                    .subscribe(create_path, event_handler.clone(), None)
                    .await?;
                context
                    .subscribe(update_path, event_handler.clone(), None)
                    .await?;
                context.subscribe(delete_path, event_handler, None).await?;
            }
        }

        context.info("Event handlers registered for replication");

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        let service_arc = Arc::new(self.clone());
        context.info(format!(
            "SqliteService '{}' starting worker and applying schema.",
            self.name
        ));

        let (tx, rx) = mpsc::channel(32);
        let (ready_tx, ready_rx) = oneshot::channel(); // Channel for ready signal

        // Store the command sender in self.worker_tx
        {
            let mut worker_tx_guard = self
                .worker_tx
                .write()
                .map_err(|e| anyhow!("Failed to acquire write lock on worker_tx: {}", e))?;
            *worker_tx_guard = Some(tx);
        }

        let db_path_clone = self.config.db_path.clone();
        let schema_clone = self.config.schema.clone();
        let logger_clone_for_thread = context.logger.clone();

        let mut encryption_key: Option<Vec<u8>> = None;

        if self.config.encryption {
            context.info("SqliteService encryption enabled - requesting symmetric key.");
            // request a symmetric key for this service,
            // if one exists it will be returned, if not one will be created, stored and returned
            let key_name = format!(
                "sqlite_{}_{}_{}",
                self.path,
                self.version,
                self.network_id.as_ref().expect("network_id is required")
            );
            let key_arc = context
                .request(
                    "$keys/ensure_symmetric_key",
                    Some(ArcValue::new_primitive(key_name)),
                )
                .await?;
            let key = key_arc.as_type_ref::<Vec<u8>>()?;
            encryption_key = Some(key.as_ref().clone());
        } else {
            context.warn("SqliteService encryption disabled.");
        }

        thread::spawn(move || {
            let worker_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime for SqliteWorker");

            worker_runtime.block_on(async move {
                match SqliteWorker::new(
                    db_path_clone,
                    rx,
                    logger_clone_for_thread.clone(),
                    ready_tx, // Pass the ready signal sender
                    encryption_key,
                ) {
                    Ok(worker) => {
                        logger_clone_for_thread.info("SqliteWorker thread starting run loop.");
                        worker.run().await;
                        logger_clone_for_thread.info("SqliteWorker thread finished.");
                    }
                    Err(e) => {
                        // If new fails, ready_tx is dropped, and the await below will fail.
                        logger_clone_for_thread
                            .error(format!("Failed to initialize SqliteWorker in thread: {e}",));
                    }
                }
            });
        });

        // Wait for the worker to signal that it's ready
        ready_rx
            .await
            .map_err(|e| anyhow!("SqliteWorker failed to start: {}", e))?;
        context.debug("SqliteWorker has signaled it is ready.");

        // Now that the worker is confirmed to be running, apply the schema
        self.apply_schema(schema_clone, &context).await?;

        // If replication is enabled, initialize the replication manager
        if let Some(replication_config) = &self.config.replication {
            context.info("Starting replication manager...");

            // let node_id = self.network_id.clone()
            //     .ok_or_else(|| anyhow!("Network ID is required for replication"))?;

            if let Some(replication_manager) = {
                let manager_guard = service_arc.replication_manager.read().map_err(|e| {
                    anyhow!("Failed to acquire read lock on replication_manager: {e}")
                })?;
                manager_guard.clone()
            } {
                // Create event tables
                replication_manager.create_event_tables(&context).await?;

                // Perform startup sync if enabled
                if replication_config.startup_sync {
                    context.info("Starting replication synchronization...");
                    replication_manager.sync_on_startup(&context).await?;
                    context.info("Replication synchronization completed");
                }
            }
        }

        context.info(format!(
            "SqliteService '{}' started successfully.",
            self.name
        ));
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("Stopping SqliteService: {}", self.name));
        match self.send_command(|reply_tx| SqliteWorkerCommand::Shutdown { reply_to: reply_tx }).await {
            Ok(_) => context.info(format!("SqliteService '{}' worker acknowledged shutdown.", self.name)),
            Err(e) => context.error(format!("Error sending Shutdown to SqliteService '{}' worker: {e}. Worker might have already terminated.", self.name)),
        }
        // The channel will be dropped, and the worker thread should exit gracefully.
        Ok(())
    }
}

// Helper functions for replication
pub fn extract_table_name(sql: &str) -> Option<String> {
    let sql_upper = sql.trim_start().to_uppercase();

    if let Some(after_insert) = sql_upper.strip_prefix("INSERT INTO ") {
        // Extract table name after "INSERT INTO "
        if let Some(space_pos) = after_insert.find(' ') {
            return Some(after_insert[..space_pos].to_lowercase());
        }
    } else if let Some(after_update) = sql_upper.strip_prefix("UPDATE ") {
        // Extract table name after "UPDATE "
        if let Some(space_pos) = after_update.find(' ') {
            return Some(after_update[..space_pos].to_lowercase());
        }
    } else if let Some(after_delete) = sql_upper.strip_prefix("DELETE FROM ") {
        // Extract table name after "DELETE FROM "
        if let Some(space_pos) = after_delete.find(' ') {
            return Some(after_delete[..space_pos].to_lowercase());
        }
    }

    None
}

pub fn determine_operation_type(sql: &str) -> String {
    let sql_upper = sql.trim_start().to_uppercase();

    if sql_upper.starts_with("INSERT") {
        "CREATE".to_string()
    } else if sql_upper.starts_with("UPDATE") {
        "UPDATE".to_string()
    } else if sql_upper.starts_with("DELETE") {
        "DELETE".to_string()
    } else {
        "OTHER".to_string()
    }
}
