use anyhow::{anyhow, Result};
use runar_common::logging::Logger;
use runar_node::services::LifecycleContext;
use runar_node::AbstractService;
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
    pub origin_node_id: String,
    pub origin_seq: i64,
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
    pub origin_seq: i64,
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
    pub from_by_origin: Vec<OriginCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct OriginCheckpoint {
    pub origin_node_id: String,
    pub origin_seq: i64,
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

        // Always rely on on_with_options with include_past to eliminate race.
        // This blocks startup until either we get the running signal or timeout.
        context.debug(format!(
            "Waiting (with include_past) for remote service running: {service_path}"
        ));
        let on_running = context
            .on(
                format!("$registry/services/{service_path}/state/running"),
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_secs(20),
                    include_past: Some(Duration::from_secs(10)),
                }),
            )
            .await;

        if on_running.is_ok() {
            context.info(format!("Service found in the network for: {service_path}"));
        } else {
            // Fallback: attempt remote request once to cover long-delay service add after start
            context.warn(format!(
                "Running event not observed skipping startup sync for: {service_path}"
            )); 
            return Ok(()); 
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

        // Build replication event preserving origin metadata
        let replication_event = self.replication_event_from_sqlite_event(event).await?;

        if is_local {
            // Local events are already applied to base tables; store for history only
            self.store_event(&replication_event, true).await?;
            self.logger.debug("Local event stored (processed=true)");
        } else {
            // Remote events: idempotent store + apply
            self.process_replication_event(replication_event).await?;
            self.logger.debug("Remote event stored/applied if new");
        }

        Ok(())
    }

    // Processes incoming replication events from other nodes
    pub async fn process_replication_event(&self, event: ReplicationEvent) -> Result<()> {
        self.logger.debug(format!(
            "Processing replication event on node {}",
            self.node_id
        ));
        // Idempotent ingest in a transaction:
        // 1) Try to insert the event row first (OR IGNORE semantics via SQL)
        // 2) If inserted, apply SQL to base table; otherwise skip (already applied)
        // 3) Commit; on error, rollback

        // Begin transaction
        let _ = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query: SqlQuery::new("BEGIN IMMEDIATE"),
                reply_to: reply_tx,
            })
            .await;

        // Attempt to store event with OR IGNORE semantics
        let apply_needed: bool = match self.store_event_or_ignore(&event).await {
            Ok(rows) => rows > 0,
            Err(e) => {
                // Rollback and surface error
                let _ = self
                    .sqlite_service
                    .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                        query: SqlQuery::new("ROLLBACK"),
                        reply_to: reply_tx,
                    })
                    .await;
                return Err(e);
            }
        };

        if apply_needed {
            if let Err(apply_err) = self.apply_event_to_database(&event).await {
                // Rollback and surface error
                let _ = self
                    .sqlite_service
                    .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                        query: SqlQuery::new("ROLLBACK"),
                        reply_to: reply_tx,
                    })
                    .await;
                return Err(apply_err);
            }

            // Update replication checkpoint for this table and origin
            let upsert_checkpoint_sql = "INSERT INTO replication_checkpoints (table_name, origin_node_id, origin_seq)
                VALUES (?, ?, ?)
                ON CONFLICT(table_name, origin_node_id)
                DO UPDATE SET origin_seq = MAX(replication_checkpoints.origin_seq, excluded.origin_seq)";
            let cp_params = crate::sqlite::Params::new()
                .with_value(Value::Text(event.table_name.clone()))
                .with_value(Value::Text(event.source_node_id.clone()))
                .with_value(Value::Integer(event.origin_seq));
            let _ = self
                .sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query: SqlQuery::new(upsert_checkpoint_sql).with_params(cp_params),
                    reply_to: reply_tx,
                })
                .await
                .map_err(|e| anyhow!("Failed to upsert replication checkpoint: {e}"))?;
        }

        // Commit transaction
        let commit_res = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query: SqlQuery::new("COMMIT"),
                reply_to: reply_tx,
            })
            .await;

        if commit_res.is_err() {
            // Best-effort rollback if commit fails
            let _ = self
                .sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query: SqlQuery::new("ROLLBACK"),
                    reply_to: reply_tx,
                })
                .await;
            return Err(anyhow!("Failed to commit replication event transaction"));
        }

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
    async fn replication_event_from_sqlite_event(
        &self,
        ev: SqliteEvent,
    ) -> Result<ReplicationEvent> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let event_id = Uuid::new_v4().to_string();
        let record_id = Uuid::new_v4().to_string();
        Ok(ReplicationEvent {
            id: event_id,
            table_name: ev.table,
            operation_type: ev.operation,
            record_id,
            data: ev.data,
            timestamp,
            source_node_id: ev.origin_node_id,
            origin_seq: ev.origin_seq,
        })
    }

    async fn store_event(&self, event: &ReplicationEvent, processed: bool) -> Result<()> {
        let event_table_name = format!("{}{}", event.table_name, EVENT_TABLE_SUFFIX);

        self.logger.debug(format!(
            "Storing replication event: id={}, table={}, operation={}, origin_seq={}, processed={}",
            event.id, event.table_name, event.operation_type, event.origin_seq, processed
        ));

        let data_json = event.data.to_json()?;
        let data_json_str = serde_json::to_string(&data_json)?;

        let query = SqlQuery::new(&format!(
            "INSERT INTO {event_table_name} (id, table_name, operation_type, record_id, data, timestamp, source_node_id, origin_seq, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .with_params(crate::sqlite::Params::new()
            .with_value(Value::Text(event.id.clone()))
            .with_value(Value::Text(event.table_name.clone()))
            .with_value(Value::Text(event.operation_type.clone()))
            .with_value(Value::Text(event.record_id.clone()))
            .with_value(Value::Text(data_json_str))
            .with_value(Value::Integer(event.timestamp))
            .with_value(Value::Text(event.source_node_id.clone()))
            .with_value(Value::Integer(event.origin_seq))
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

    // Insert event row using OR IGNORE semantics. Returns rows affected (0 if existed).
    async fn store_event_or_ignore(&self, event: &ReplicationEvent) -> Result<usize> {
        let event_table_name = format!("{}{}", event.table_name, EVENT_TABLE_SUFFIX);

        self.logger.debug(format!(
            "Storing replication event (OR IGNORE): id={}, table={}, operation={}, origin_seq={}",
            event.id, event.table_name, event.operation_type, event.origin_seq
        ));

        let data_json = event.data.to_json()?;
        let data_json_str = serde_json::to_string(&data_json)?;

        let query = SqlQuery::new(&format!(
            "INSERT OR IGNORE INTO {event_table_name} (id, table_name, operation_type, record_id, data, timestamp, source_node_id, origin_seq, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .with_params(crate::sqlite::Params::new()
            .with_value(Value::Text(event.id.clone()))
            .with_value(Value::Text(event.table_name.clone()))
            .with_value(Value::Text(event.operation_type.clone()))
            .with_value(Value::Text(event.record_id.clone()))
            .with_value(Value::Text(data_json_str))
            .with_value(Value::Integer(event.timestamp))
            .with_value(Value::Text(event.source_node_id.clone()))
            .with_value(Value::Integer(event.origin_seq))
            .with_value(Value::Boolean(true))
        );

        let rows = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to store event (OR IGNORE): {e}"))?;

        Ok(rows)
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
        let mut sql_query = event.data.as_type::<crate::sqlite::SqlQuery>()?;

        // Idempotence for CREATE operations: force INSERT OR IGNORE
        if event.operation_type.eq_ignore_ascii_case("create") {
            let trimmed = sql_query.statement.trim_start();
            if let Some(rest) = trimmed.strip_prefix("INSERT INTO ") {
                let rewritten = format!("INSERT OR IGNORE INTO {rest}");
                sql_query.statement = rewritten;
            }
        }

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
            .map_err(|e| anyhow!("Failed to execute replicated SQL query: {e}"))?;

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
        let checkpoints = self.compute_origin_checkpoints(table).await?;
        let request = TableEventsRequest {
            table_name: table.to_string(),
            page,
            page_size: 100,
            from_timestamp: 0,
            from_by_origin: checkpoints,
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

        self.logger.info(format!(
            "Querying events from {}: page={}, page_size={}, from_by_origin={} entries",
            event_table_name,
            request.page,
            request.page_size,
            request.from_by_origin.len()
        ));

        // Build base query: support from_by_origin filtering if provided
        // Important: When filtering by origins, we do NOT use OFFSET based on `page`,
        // because the client recomputes checkpoints between pages. Using OFFSET against
        // the filtered set would skip new ranges. We always use OFFSET 0 in that mode.
        let base_select = if !request.from_by_origin.is_empty() {
            // We must include:
            // - Events from origins NOT in the checkpoint set
            // - Events from origins IN the set but with origin_seq > checkpoint
            let mut greater_clauses: Vec<String> = Vec::new();
            for _ in &request.from_by_origin {
                greater_clauses.push("(source_node_id = ? AND origin_seq > ?)".to_string());
            }
            let mut where_parts: Vec<String> = Vec::new();
            // Part 1: sources not in checkpoint set
            let not_in_list = request
                .from_by_origin
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(", ");
            where_parts.push(format!(
                "(source_node_id NOT IN ({}))",
                if not_in_list.is_empty() {
                    "''".to_string()
                } else {
                    not_in_list
                }
            ));
            // Part 2: greater-than clauses per known origin
            if !greater_clauses.is_empty() {
                where_parts.push(format!("({})", greater_clauses.join(" OR ")));
            }
            format!(
                "SELECT * FROM {event_table_name} WHERE {} ORDER BY source_node_id ASC, origin_seq ASC, id ASC LIMIT ? OFFSET 0",
                where_parts.join(" OR ")
            )
        } else {
            format!(
                "SELECT * FROM {event_table_name} ORDER BY source_node_id ASC, origin_seq ASC, id ASC LIMIT ? OFFSET ?"
            )
        };

        let mut params = crate::sqlite::Params::new();
        // params for NOT IN list
        for oc in &request.from_by_origin {
            params = params.with_value(Value::Text(oc.origin_node_id.clone()));
        }
        // params for each (source = ? AND origin_seq > ?)
        for oc in &request.from_by_origin {
            params = params
                .with_value(Value::Text(oc.origin_node_id.clone()))
                .with_value(Value::Integer(oc.origin_seq));
        }
        params = params.with_value(Value::Integer(request.page_size as i64));
        if request.from_by_origin.is_empty() {
            params = params.with_value(Value::Integer((request.page * request.page_size) as i64));
        }

        let query = SqlQuery::new(&base_select).with_params(params);

        let result = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to query events: {e}"))?;

        self.logger.info(format!(
            "Found {} rows for this page before mapping",
            result.len()
        ));

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
                    origin_seq: match row.get("origin_seq") {
                        Some(Value::Integer(i)) => *i,
                        _ => 0,
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
        let (total_count, has_more) = if request.from_by_origin.is_empty() {
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
            (total_count as u32, has_more)
        } else {
            // In origin-filtered mode, client recomputes checkpoints; just indicate more if we filled a page
            (
                events.len() as u32,
                events.len() as u32 == request.page_size,
            )
        };

        let mut origin_min_max: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        for e in &events {
            let entry = origin_min_max
                .entry(e.source_node_id.clone())
                .or_insert((e.origin_seq, e.origin_seq));
            if e.origin_seq < entry.0 {
                entry.0 = e.origin_seq;
            }
            if e.origin_seq > entry.1 {
                entry.1 = e.origin_seq;
            }
        }
        self.logger.info(format!(
            "Returning {} events, total_count={}, has_more={}, origin_ranges={:?}",
            events.len(),
            total_count,
            has_more,
            origin_min_max
        ));

        Ok(TableEventsResponse {
            events,
            has_more,
            total_count,
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
                    origin_seq INTEGER NOT NULL DEFAULT 0,
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

            // Composite index to accelerate origin filtering
            let index2_sql = format!(
                "CREATE INDEX IF NOT EXISTS idx_{table}_events_origin ON {event_table_name} (source_node_id, origin_seq)"
            );
            let index2_query = SqlQuery::new(&index2_sql);
            self.sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query: index2_query,
                    reply_to: reply_tx,
                })
                .await
                .map_err(|e| anyhow!("Failed to create origin index: {e}"))?;

            // Unique index to enforce per-origin monotonic uniqueness
            let uniq_sql = format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS uniq_{table}_events_origin ON {event_table_name} (source_node_id, origin_seq)"
            );
            let uniq_query = SqlQuery::new(&uniq_sql);
            self.sqlite_service
                .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                    query: uniq_query,
                    reply_to: reply_tx,
                })
                .await
                .map_err(|e| anyhow!("Failed to create unique origin index: {e}"))?;

            context.info(format!("Created event table: {event_table_name}"));
        }

        // Ensure replication metadata and checkpoints tables exist
        let meta_table_sql = "CREATE TABLE IF NOT EXISTS replication_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)";
        self.sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query: SqlQuery::new(meta_table_sql),
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to create replication_meta table: {e}"))?;

        // Create checkpoints table
        let checkpoints_sql = "CREATE TABLE IF NOT EXISTS replication_checkpoints (
            table_name TEXT NOT NULL,
            origin_node_id TEXT NOT NULL,
            origin_seq INTEGER NOT NULL,
            PRIMARY KEY(table_name, origin_node_id)
        )";
        self.sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Execute {
                query: SqlQuery::new(checkpoints_sql),
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to create replication_checkpoints table: {e}"))?;

        Ok(())
    }

    // Compute per-origin checkpoints from local storage for a table
    async fn compute_origin_checkpoints(&self, table: &str) -> Result<Vec<OriginCheckpoint>> {
        // Prefer dedicated checkpoints table
        let cp_query = SqlQuery::new(
            "SELECT origin_node_id, origin_seq FROM replication_checkpoints WHERE table_name = ?",
        )
        .with_params(crate::sqlite::Params::new().with_value(Value::Text(table.to_string())));
        let cp_rows = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query: cp_query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to read replication checkpoints: {e}"))?;

        let mut out = Vec::new();
        if !cp_rows.is_empty() {
            for row in cp_rows {
                let origin_node_id = match row.get("origin_node_id") {
                    Some(Value::Text(s)) => s.clone(),
                    _ => continue,
                };
                let origin_seq = match row.get("origin_seq") {
                    Some(Value::Integer(i)) => *i,
                    _ => 0,
                };
                out.push(OriginCheckpoint {
                    origin_node_id,
                    origin_seq,
                });
            }
            return Ok(out);
        }

        // Fallback to scanning local event store if checkpoints empty (first run/migration)
        let event_table_name = format!("{table}{EVENT_TABLE_SUFFIX}");
        let query = SqlQuery::new(&format!(
            "SELECT source_node_id, MAX(origin_seq) as max_seq FROM {event_table_name} GROUP BY source_node_id"
        ));
        let rows = self
            .sqlite_service
            .send_command(|reply_tx| crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            })
            .await
            .map_err(|e| anyhow!("Failed to compute origin checkpoints from events: {e}"))?;
        for row in rows {
            let origin_node_id = match row.get("source_node_id") {
                Some(Value::Text(s)) => s.clone(),
                _ => continue,
            };
            let origin_seq = match row.get("max_seq") {
                Some(Value::Integer(i)) => *i,
                _ => 0,
            };
            out.push(OriginCheckpoint {
                origin_node_id,
                origin_seq,
            });
        }
        Ok(out)
    }
}
