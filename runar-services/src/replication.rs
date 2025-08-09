use anyhow::{anyhow, Result};
use runar_common::logging::Logger;
use runar_node::AbstractService;
use runar_node::{services::LifecycleContext, ServiceState};
use runar_serializer::{ArcValue, Plain};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::sqlite::{SqlQuery, SqliteService, Value};

// Constants for action names to avoid hardcoding
const REPLICATION_GET_TABLE_EVENTS_ACTION: &str = "replication/get_table_events";
const EVENT_TABLE_SUFFIX: &str = "_Events";

// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    pub enabled_tables: Vec<String>,
    pub conflict_resolution: ConflictResolutionStrategy,
    pub startup_sync: bool,
    pub event_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolutionStrategy {
    LastWriteWins,
    Custom(String), // Name of custom resolver function
}

// Event structures
#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct SqliteEvent {
    pub operation: String, // "CREATE", "UPDATE", "DELETE"
    pub table: String,
    pub data: ArcValue, // Original SQL query data
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct ReplicationEvent {
    pub id: String,
    pub table_name: String,
    pub operation_type: String,
    pub record_id: String,
    pub data: ArcValue,
    pub timestamp: i64,
    pub source_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableState {
    pub table_name: String,
    pub last_event_timestamp: i64,
    pub record_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableEventsRequest {
    pub table_name: String,
    pub page: u32,
    pub page_size: u32,
    pub from_timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableEventsResponse {
    pub events: Vec<ReplicationEvent>,
    pub has_more: bool,
    pub total_count: u32,
    pub page: u32,
    pub page_size: u32,
}

// Replication manager
pub struct ReplicationManager {
    sqlite_service: Arc<SqliteService>,
    // config: ReplicationConfig,
    enabled_tables: Arc<Vec<String>>,
    logger: Arc<Logger>,
    node_id: String,
}

impl ReplicationManager {
    pub fn new(
        sqlite_service: Arc<SqliteService>,
        config: ReplicationConfig,
        logger: Arc<Logger>,
        node_id: String,
    ) -> Self {
        let enabled_tables = Arc::new(config.enabled_tables.clone());

        Self {
            sqlite_service,
            // config,
            enabled_tables,
            logger,
            node_id,
        }
    }

    // Handles startup synchronization
    pub async fn sync_on_startup(&self, context: &LifecycleContext) -> Result<()> {
        context.info("Starting replication synchronization - waiting for node discovery...");

        // Wait for service discovery
        let service_path = self.sqlite_service.path();

        // Check if remote service is already running (we want remote services, not local)
        let service_running = match context
            .request(
                format!("$registry/services/{service_path}/state"),
                Some(ArcValue::new_primitive(false)),
            )
            .await
        {
            Ok(response) => match response.as_type::<ServiceState>() {
                Ok(ServiceState::Running) => {
                    context.debug(format!(
                        "Service already running in the network for: {service_path}"
                    ));
                    true
                }
                Ok(state) => {
                    context.debug(format!(
                        "Service found but not running (state: {state:?}) for: {service_path}"
                    ));
                    false
                }
                Err(e) => {
                    context.error(format!(
                        "Failed to parse service state for {service_path}: {e}"
                    ));
                    return Err(e);
                }
            },
            Err(e) => {
                context.error(format!(
                    "Service state request failed for {service_path}: {e}"
                ));
                return Err(e);
            }
        };

        // If service is not running, wait for it to become available
        if !service_running {
            context.debug(format!("Service not running for: {service_path}"));
            let on_running = context
                .on(
                    format!("$registry/services/{service_path}/state/running"),
                    Duration::from_secs(10),
                )
                .await;

            if on_running.is_ok() {
                context.info(format!("Service found in the network for: {service_path}"));
            } else {
                context.info(format!("Service discovery timed out - No service found in the network for: {service_path}"));
                return Ok(());
            }
        }

        // Request latest state from network for each enabled table
        for table in self.enabled_tables.iter() {
            let mut page = 0;
            let mut has_more = true;
            let mut total_events = 0;

            while has_more {
                match self.request_table_events(table, page, context).await {
                    Ok(sync_response) => {
                        // Apply events from this page
                        for event in sync_response.events.clone() {
                            self.process_replication_event(event).await?;
                        }

                        total_events += sync_response.events.len();

                        // Check if there are more events to fetch
                        has_more = sync_response.has_more;
                        page += 1;

                        context.info(format!(
                            "Synced table '{}' page {} - {} events",
                            table,
                            page,
                            sync_response.events.len()
                        ));
                    }
                    Err(e) => {
                        // If no remote services are available, that's okay for startup
                        if e.to_string().contains("No handler found")
                            || e.to_string().contains("No remote nodes")
                        {
                            context.info(format!(
                                "No remote services available for table '{table}' - skipping sync"
                            ));
                            break;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

            if total_events > 0 {
                context.info(format!(
                    "Completed sync for table '{table}' - {total_events} total events"
                ));
            }
        }

        context.info("Replication synchronization completed");
        Ok(())
    }

    // Handles incoming ephemeral events from SQLite operations
    pub async fn handle_sqlite_event(&self, event: SqliteEvent, is_local: bool) -> Result<()> {
        self.logger.debug(format!(
            "Handling SQLite event: table={}, operation={}, is_local={}",
            event.table, event.operation, is_local
        ));

        if is_local {
            self.logger
                .debug("Local event: storing for replication history, not processing");
            // Local event: just store for replication history, don't process
            let replication_event = self
                .create_replication_event(&event.operation, &event.table, event.data)
                .await?;
            self.store_event(&replication_event, true).await?; // Mark as processed
            self.logger.debug("Local event stored and broadcasted");
        } else {
            self.logger.debug("Remote event: storing and processing");
            // Remote event: store and process
            let replication_event = self
                .create_replication_event(&event.operation, &event.table, event.data)
                .await?;
            self.process_replication_event(replication_event).await?;
            self.logger.debug("Remote event stored and processed");
        }

        Ok(())
    }

    // Processes incoming replication events from other nodes
    pub async fn process_replication_event(&self, event: ReplicationEvent) -> Result<()> {
        // Apply event to local database
        self.apply_event_to_database(&event).await?;

        //store event as processed
        self.store_event(&event, true).await?;

        Ok(())
    }

    // Returns current state of a table for startup synchronization
    pub async fn get_table_state(&self, table_name: &str) -> Result<TableState> {
        // Query the event table to get latest timestamp
        let event_table_name = format!("{table_name}{EVENT_TABLE_SUFFIX}");

        let query = SqlQuery::new(&format!(
            "SELECT MAX(timestamp) as max_time FROM {event_table_name}"
        ));

        let result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to query event table: {e}"))?;

        let max_time = if let Some(row) = result.first() {
            row.get("max_time")
                .map(|v| match v {
                    Value::Integer(i) => *i,
                    _ => 0,
                })
                .unwrap_or(0)
        } else {
            0
        };

        // Count records in the main table
        let count_query = SqlQuery::new(&format!("SELECT COUNT(*) as count FROM {table_name}"));
        let count_result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query: count_query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to count records: {e}"))?;

        let record_count = if let Some(row) = count_result.first() {
            row.get("count")
                .map(|v| match v {
                    Value::Integer(i) => *i,
                    _ => 0,
                })
                .unwrap_or(0)
        } else {
            0
        };

        Ok(TableState {
            table_name: table_name.to_string(),
            last_event_timestamp: max_time,
            record_count,
        })
    }

    // Helper methods
    async fn create_replication_event(
        &self,
        operation: &str,
        table: &str,
        data: ArcValue,
    ) -> Result<ReplicationEvent> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let event_id = Uuid::new_v4().to_string();
        let record_id = Uuid::new_v4().to_string(); // This should be extracted from the data

        Ok(ReplicationEvent {
            id: event_id,
            table_name: table.to_string(),
            operation_type: operation.to_string(),
            record_id,
            data,
            timestamp,
            source_node_id: self.node_id.clone(),
        })
    }

    async fn store_event(&self, event: &ReplicationEvent, processed: bool) -> Result<()> {
        let event_table_name = format!("{}{}", event.table_name, EVENT_TABLE_SUFFIX);

        self.logger.debug(format!(
            "Storing replication event: id={}, table={}, operation={}, processed={}",
            event.id, event.table_name, event.operation_type, processed
        ));

        let data_json = event.data.to_json()?;
        let data_json_str = serde_json::to_string(&data_json)?;

        let query = SqlQuery::new(&format!(
            "INSERT INTO {event_table_name} (id, table_name, operation_type, record_id, data, timestamp, source_node_id, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )).with_params(crate::sqlite::Params::new()
            .with_value(Value::Text(event.id.clone()))
            .with_value(Value::Text(event.table_name.clone()))
            .with_value(Value::Text(event.operation_type.clone()))
            .with_value(Value::Text(event.record_id.clone()))
            .with_value(Value::Text(data_json_str))
            .with_value(Value::Integer(event.timestamp))
            .with_value(Value::Text(event.source_node_id.clone()))
            .with_value(Value::Boolean(processed)) // Use the processed parameter
        );

        self.sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to store event: {e}"))?;

        self.logger
            .debug(format!("Replication event stored in {event_table_name}"));
        Ok(())
    }

    async fn apply_event_to_database(&self, event: &ReplicationEvent) -> Result<()> {
        self.logger.debug(format!(
            "Applying replication event to database: id={}, table={}, operation={}",
            event.id, event.table_name, event.operation_type
        ));

        // Parse the event data back into ArcValue
        // let event_data: ArcValue = serde_json::from_str(event.data)
        //     .map_err(|e| anyhow!("Failed to parse event data: {e}"))?;

        self.logger
            .debug(format!("Parsed event data: {:?}", event.data));

        // Extract the SQL query from the event data
        // The event data should contain the original SqlQuery that was executed
        let sql_query = event.data.as_type::<crate::sqlite::SqlQuery>()?;

        self.logger
            .debug(format!("Executing SQL query: {}", sql_query.statement));

        // Execute the SQL query against the database
        let result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query: sql_query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to execute replicated SQL query: {}", e))?;

        self.logger
            .debug(format!("SQL query executed successfully: {result:?}"));

        Ok(())
    }

    // Requests paginated events from other nodes
    async fn request_table_events(
        &self,
        table: &str,
        page: u32,
        context: &LifecycleContext,
    ) -> Result<TableEventsResponse> {
        let request = TableEventsRequest {
            table_name: table.to_string(),
            page,
            page_size: 100,
            from_timestamp: 0, // Start from beginning for startup sync
        };

        // Request from remote nodes with the same SQLite service
        // Use proper namespacing: <sqlite_service_path>/replication/get_table_events
        let service_path = self.sqlite_service.path();
        let remote_path = format!("{service_path}/{REPLICATION_GET_TABLE_EVENTS_ACTION}");

        context.debug(format!(
            "Requesting events from remote nodes: {remote_path}"
        ));

        match context
            .remote_request(&remote_path, Some(ArcValue::new_struct(request)))
            .await
        {
            Ok(response) => {
                let events_response = (*response.as_type_ref::<TableEventsResponse>()?).clone();
                context.debug(format!(
                    "Received {} events from remote nodes",
                    events_response.events.len()
                ));
                Ok(events_response)
            }
            Err(e) => {
                // Handle case where no remote nodes have this service
                context.info(format!(
                    "No remote nodes with service '{service_path}' available: {e}"
                ));
                // Return empty response when no remote nodes are available
                Ok(TableEventsResponse {
                    events: Vec::new(),
                    has_more: false,
                    total_count: 0,
                    page,
                    page_size: 100,
                })
            }
        }
    }

    // Returns paginated events for a table (for startup sync)
    pub async fn get_table_events(
        &self,
        request: Arc<TableEventsRequest>,
    ) -> Result<TableEventsResponse> {
        let event_table_name = format!("{}{EVENT_TABLE_SUFFIX}", request.table_name);

        self.logger.debug(format!(
            "Querying events from {}: page={}, page_size={}, from_timestamp={}",
            event_table_name, request.page, request.page_size, request.from_timestamp
        ));

        let query = SqlQuery::new(&format!(
            "SELECT * FROM {event_table_name} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        ))
        .with_params(
            crate::sqlite::Params::new()
                .with_value(Value::Integer(request.page_size as i64))
                .with_value(Value::Integer((request.page * request.page_size) as i64)),
        );

        let result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to query events: {e}"))?;

        self.logger
            .debug(format!("Found {} raw rows in event table", result.len()));

        // Convert rows to ReplicationEvent objects
        let events: Vec<ReplicationEvent> = result
            .into_iter()
            .map(|row| {
                let event = ReplicationEvent {
                    id: match row.get("id") {
                        Some(Value::Text(s)) => s.clone(),
                        _ => "".to_string(),
                    },
                    table_name: match row.get("table_name") {
                        Some(Value::Text(s)) => s.clone(),
                        _ => "".to_string(),
                    },
                    operation_type: match row.get("operation_type") {
                        Some(Value::Text(s)) => s.clone(),
                        _ => "".to_string(),
                    },
                    record_id: match row.get("record_id") {
                        Some(Value::Text(s)) => s.clone(),
                        _ => "".to_string(),
                    },
                    data: match row.get("data") {
                        Some(Value::Text(s)) => {
                            let data_json = serde_json::from_str(s).unwrap_or_default();
                            let json_arc = ArcValue::new_json(data_json);
                            match json_arc.as_type::<crate::sqlite::SqlQuery>() {
                                Ok(sql_query) => ArcValue::new_struct(sql_query),
                                Err(_) => json_arc,
                            }
                        }
                        _ => ArcValue::null(),
                    },
                    timestamp: match row.get("timestamp") {
                        Some(Value::Integer(i)) => *i,
                        _ => 0,
                    },
                    source_node_id: match row.get("source_node_id") {
                        Some(Value::Text(s)) => s.clone(),
                        _ => "".to_string(),
                    },
                };

                self.logger.debug(format!(
                    "Event: id={}, table={}, operation={}, source={}, timestamp={}",
                    event.id,
                    event.table_name,
                    event.operation_type,
                    event.source_node_id,
                    event.timestamp
                ));

                event
            })
            .collect();

        // Check if there are more events
        let total_query =
            SqlQuery::new(&format!("SELECT COUNT(*) as count FROM {event_table_name}"));
        let total_result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query: total_query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to count total events: {e}"))?;

        let total_count = if let Some(row) = total_result.first() {
            row.get("count")
                .map(|v| match v {
                    Value::Integer(i) => *i,
                    _ => 0,
                })
                .unwrap_or(0)
        } else {
            0
        };

        let has_more = (request.page + 1) * request.page_size < total_count as u32;

        self.logger.debug(format!(
            "Returning {} events, total_count={}, has_more={}",
            events.len(),
            total_count,
            has_more
        ));

        Ok(TableEventsResponse {
            events,
            has_more,
            total_count: total_count as u32,
            page: request.page,
            page_size: request.page_size,
        })
    }

    // Creates event tables for enabled tables
    pub async fn create_event_tables(&self, context: &LifecycleContext) -> Result<()> {
        for table in self.enabled_tables.iter() {
            let event_table_name = format!("{table}{EVENT_TABLE_SUFFIX}");

            let create_table_sql = format!(
                "CREATE TABLE IF NOT EXISTS {event_table_name} (
                    id TEXT PRIMARY KEY,
                    table_name TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    data TEXT,
                    timestamp INTEGER NOT NULL,
                    source_node_id TEXT NOT NULL,
                    processed BOOLEAN DEFAULT FALSE
                )"
            );

            let query = SqlQuery::new(&create_table_sql);
            self.sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query,
                    reply_to: reply_tx,
                })
                .await
                .map_err(|e| anyhow!("Failed to create event table: {e}"))?;

            // Create indexes
            let index1_sql = format!(
                "CREATE INDEX IF NOT EXISTS idx_{table}_events_timestamp ON {event_table_name} (timestamp)"
            );
            let index1_query = SqlQuery::new(&index1_sql);
            self.sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query: index1_query,
                    reply_to: reply_tx,
                })
                .await
                .map_err(|e| anyhow!("Failed to create timestamp index: {e}"))?;

            context.info(format!("Created event table: {event_table_name}"));
        }

        Ok(())
    }
}
