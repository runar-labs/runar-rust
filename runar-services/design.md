# Data Replication Technical Design

## Overview

This document outlines the technical design for implementing data replication as an integrated feature of the SQLite service. The replication system consumes ephemeral events from SQLite operations and creates persistent replication events for cross-node synchronization.

## Architecture Analysis

### Current SQLite Service Architecture

The `SqliteService` provides:
- **Single Action**: `execute_query` - handles all SQL operations
- **Worker Pattern**: Uses a dedicated worker thread with message passing
- **Schema Management**: Automatic table/index creation
- **Encryption Support**: Optional database encryption
- **No Event Emission**: Currently doesn't emit events for operations

### Event Flow Design

**Correct Event Flow:**
```
Local Node: SQL INSERT → user_db/users/created (ephemeral) → Replication stores as persistent event
Remote Node: Receives user_db/users/created (ephemeral) → Replication stores AND processes it
```

**Event Namespacing:**
- Events should be namespaced by database and table: `user_db/<table_name>/<operation>`
- Examples: `user_db/users/created`, `user_db/posts/updated`, `user_db/comments/deleted`

**Local vs Remote Event Handling:**
- **Local events**: Already processed by originating node, just store for replication history
- **Remote events**: Need to be processed (applied to database) AND stored
- **Event Context**: Requires `is_local()` method to distinguish event source

## Proposed Replication Service Design

### 1. Service Structure

```rust
pub struct SqliteService {
    name: String,
    path: String,
    version: String,
    description: String,
    config: SqliteConfig,
    worker_tx: Arc<RwLock<Option<mpsc::Sender<SqliteWorkerCommand>>>>,
    network_id: Option<String>,
    // New: Optional replication manager
    replication_manager: Arc<RwLock<Option<Arc<ReplicationManager>>>>,
}

pub struct SqliteConfig {
    pub db_path: String,
    pub schema: Schema,
    pub encryption: bool,
    // New: Optional replication configuration
    pub replication: Option<ReplicationConfig>,
}

pub struct ReplicationConfig {
    pub enabled_tables: Vec<String>,  // Tables to replicate
    pub conflict_resolution: ConflictResolutionStrategy,
    pub startup_sync: bool,  // Whether to sync on startup
    pub event_retention_days: u32,  // How long to keep events
}
```

### 2. Replication Manager

```rust
pub struct ReplicationManager {
    sqlite_service: Arc<SqliteService>,  // Reference back to parent service
    config: ReplicationConfig,
    enabled_tables: Arc<Vec<String>>,
    logger: Arc<Logger>,
    event_sequence_counter: Arc<AtomicI64>,
    node_id: String,
}

impl ReplicationManager {
    // Handles startup synchronization with pagination
    async fn sync_on_startup(&self, context: &LifecycleContext) -> Result<()> {
        context.info("Starting replication synchronization...");
        
        // Request latest state from network for each enabled table
        for table in self.enabled_tables.iter() {
            let mut page = 0;
            let mut has_more = true;
            
            while has_more {
                let sync_response = self.request_table_events(table, page, context).await?;
                
                // Apply events from this page
                for event in sync_response.events {
                    self.process_replication_event(event).await?;
                }
                
                // Check if there are more events to fetch
                has_more = sync_response.has_more;
                page += 1;
                
                context.info(format!("Synced table '{}' page {} - {} events", 
                                   table, page, sync_response.events.len()));
            }
        }
        
        context.info("Replication synchronization completed");
        Ok(())
    }
    
    // Requests paginated events from other nodes
    async fn request_table_events(&self, table: &str, page: u32, context: &LifecycleContext) -> Result<TableEventsResponse> {
        let request = TableEventsRequest {
            table_name: table.to_string(),
            page,
            page_size: 100,
            from_sequence: 0, // Start from beginning for startup sync
        };
        
        // Request from all available nodes
        let response = context.request("*/get_table_events", Some(ArcValue::new_struct(request))).await?;
        response.as_type_ref::<TableEventsResponse>()
    }
    
    // Handles SQLite operations and creates replication events (for local operations)
    async fn handle_sqlite_operation(&self, operation: &str, table: &str, data: &ArcValue) -> Result<()> {
        // Create persistent event
        let event = self.create_replication_event(operation, table, data).await?;
        
        // Store event in database (mark as processed since it's local)
        self.store_event(&event, true).await?;
        
        // Broadcast event to network
        self.broadcast_event(&event).await?;
        
        Ok(())
    }
    
    // Processes incoming replication events from other nodes
    async fn process_replication_event(&self, event: ReplicationEvent) -> Result<()> {
        // Check if we've already processed this event
        if self.is_event_processed(&event.id).await? {
            return Ok(());
        }
        
        // Apply event to local database (only for remote events)
        self.apply_event_to_database(&event).await?;
        
        // Mark event as processed
        self.mark_event_processed(&event.id).await?;
        
        Ok(())
    }
    
    // Handles incoming ephemeral events from SQLite operations
    async fn handle_sqlite_event(&self, event: SqliteEvent, is_local: bool) -> Result<()> {
        if is_local {
            // Local event: just store for replication history, don't process
            let replication_event = self.create_replication_event(&event.operation, &event.table, &event.data.unwrap()).await?;
            self.store_event(&replication_event, true).await?; // Mark as processed
            self.broadcast_event(&replication_event).await?;
        } else {
            // Remote event: store and process
            let replication_event = self.create_replication_event(&event.operation, &event.table, &event.data.unwrap()).await?;
            self.store_event(&replication_event, false).await?; // Mark as not processed
            self.process_replication_event(replication_event).await?;
        }
        
        Ok(())
    }
    
    // Returns current state of a table for startup synchronization
    async fn get_table_state(&self, table_name: &str) -> Result<TableState> {
        // Query the event table to get latest sequence number
        let event_table_name = format!("{}_Events", table_name);
        
        let query = SqlQuery::new(&format!(
            "SELECT MAX(sequence_number) as max_seq, MAX(timestamp) as max_time FROM {}",
            event_table_name
        ));
        
        let result = self.sqlite_service.send_command(|reply_tx| {
            crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            }
        }).await.map_err(|e| anyhow!("Failed to query event table: {e}"))?;
        
        let max_seq = if let Some(row) = result.first() {
            row.get("max_seq").map(|v| match v {
                Value::Integer(i) => *i,
                _ => 0,
            }).unwrap_or(0)
        } else {
            0
        };
        
        let max_time = if let Some(row) = result.first() {
            row.get("max_time").map(|v| match v {
                Value::Integer(i) => *i,
                _ => 0,
            }).unwrap_or(0)
        } else {
            0
        };
        
        // Count records in the main table
        let count_query = SqlQuery::new(&format!("SELECT COUNT(*) as count FROM {}", table_name));
        let count_result = self.sqlite_service.send_command(|reply_tx| {
            crate::sqlite::SqliteWorkerCommand::Query {
                query: count_query,
                reply_to: reply_tx,
            }
        }).await.map_err(|e| anyhow!("Failed to count records: {e}"))?;
        
        let record_count = if let Some(row) = count_result.first() {
            row.get("count").map(|v| match v {
                Value::Integer(i) => *i,
                _ => 0,
            }).unwrap_or(0)
        } else {
            0
        };
        
        Ok(TableState {
            table_name: table_name.to_string(),
            last_event_sequence: max_seq,
            last_event_timestamp: max_time,
            record_count,
        })
    }
    
    // Returns paginated events for a table (for startup sync)
    async fn get_table_events(&self, request: TableEventsRequest) -> Result<TableEventsResponse> {
        let event_table_name = format!("{}_Events", request.table_name);
        
        let query = SqlQuery::new(&format!(
            "SELECT * FROM {} ORDER BY sequence_number ASC LIMIT ? OFFSET ?",
            event_table_name
        )).with_params(Params::new()
            .with_value(Value::Integer(request.page_size as i64))
            .with_value(Value::Integer((request.page * request.page_size) as i64))
        );
        
        let result = self.sqlite_service.send_command(|reply_tx| {
            crate::sqlite::SqliteWorkerCommand::Query {
                query,
                reply_to: reply_tx,
            }
        }).await.map_err(|e| anyhow!("Failed to query events: {e}"))?;
        
        // Convert rows to ReplicationEvent objects
        let events = result.into_iter().map(|row| {
            ReplicationEvent {
                id: row.get("id").unwrap().as_text().unwrap().to_string(),
                table_name: row.get("table_name").unwrap().as_text().unwrap().to_string(),
                operation_type: row.get("operation_type").unwrap().as_text().unwrap().to_string(),
                record_id: row.get("record_id").unwrap().as_text().unwrap().to_string(),
                data: row.get("data").unwrap().as_text().unwrap().to_string(),
                timestamp: row.get("timestamp").unwrap().as_integer().unwrap(),
                source_node_id: row.get("source_node_id").unwrap().as_text().unwrap().to_string(),
                sequence_number: row.get("sequence_number").unwrap().as_integer().unwrap(),
            }
        }).collect();
        
        // Check if there are more events
        let total_query = SqlQuery::new(&format!("SELECT COUNT(*) as count FROM {}", event_table_name));
        let total_result = self.sqlite_service.send_command(|reply_tx| {
            crate::sqlite::SqliteWorkerCommand::Query {
                query: total_query,
                reply_to: reply_tx,
            }
        }).await.map_err(|e| anyhow!("Failed to count total events: {e}"))?;
        
        let total_count = if let Some(row) = total_result.first() {
            row.get("count").map(|v| match v {
                Value::Integer(i) => *i,
                _ => 0,
            }).unwrap_or(0)
        } else {
            0
        };
        
        let has_more = (request.page + 1) * request.page_size < total_count as u32;
        
        Ok(TableEventsResponse {
            events,
            has_more,
            total_count: total_count as u32,
            page: request.page,
            page_size: request.page_size,
        })
    }
}
```

## Implementation Approach

### Phase 1: Event Emission Enhancement

**Problem**: SQLite service doesn't emit events for operations.

**Solution**: Add event emission to SQLite service operations with proper namespacing.

```rust
// In SqliteService::init()
let execute_query_handler = {
    let s_arc = service_arc.clone();
    Arc::new(
        move |params_opt: Option<ArcValue>, req_ctx: RequestContext| {
            let service_clone = s_arc.clone();
            Box::pin(async move {
                // ... existing logic ...
                
                // Emit event after successful operation
                if !trimmed_sql.starts_with("SELECT") {
                    let table_name = extract_table_name(&sql_statement).unwrap_or("unknown".to_string());
                    let event = SqliteEvent {
                        operation: if trimmed_sql.starts_with("INSERT") { "created" } 
                                  else if trimmed_sql.starts_with("UPDATE") { "updated" }
                                  else if trimmed_sql.starts_with("DELETE") { "deleted" }
                                  else { "other" },
                        table: table_name.clone(),
                        data: Some(ArcValue::new_struct(sql_query_struct)),
                        timestamp: SystemTime::now(),
                    };
                    
                    // Use proper namespacing: user_db/<table_name>/<operation>
                    let event_path = format!("user_db/{}/{}", table_name, event.operation);
                    
                    req_ctx.publish(event_path, Some(ArcValue::new_struct(event))).await?;
                }
                
                // ... return result ...
            })
        },
    )
};
```

### Phase 2: Event Context Enhancement

**Code Feature Request**: Add `is_local()` method to `EventContext` to distinguish local vs remote events.

```rust
// In runar-node/src/services/event_context.rs
impl EventContext {
    /// Check if this event originated from the local node
    pub fn is_local(&self) -> bool {
        // Implementation depends on how source node ID is tracked
        // This should compare the event's source with the current node's ID
        self.source_node_id() == self.node_delegate.node_id()
    }
    
    /// Get the source node ID for this event
    pub fn source_node_id(&self) -> &str {
        // Implementation needed - this should return the node ID that originated the event
        // This might need to be added to the event delivery system
    }
}
```

### Phase 3: Integrated Replication Implementation

```rust
impl SqliteService {
    async fn execute_query(&self, query: SqlQuery, ctx: &RequestContext) -> Result<ArcValue> {
        // ... existing query execution logic ...
        
        // Emit event after successful operation with proper namespacing
        if !trimmed_sql.starts_with("SELECT") {
            let table_name = extract_table_name(&sql_statement).unwrap_or("unknown".to_string());
            let event = SqliteEvent {
                operation: determine_operation_type(&trimmed_sql).to_lowercase(),
                table: table_name.clone(),
                data: Some(ArcValue::new_struct(query)),
                timestamp: SystemTime::now(),
            };
            
            // Use proper namespacing: user_db/<table_name>/<operation>
            let event_path = format!("user_db/{}/{}", table_name, event.operation);
            
            ctx.publish(event_path, Some(ArcValue::new_struct(event))).await?;
        }
        
        // ... return result ...
    }
    
    // Handle incoming SQLite events (both local and remote)
    async fn handle_sqlite_event(&self, event: SqliteEvent, ctx: &EventContext) -> Result<()> {
        if let Some(replication_manager) = &self.replication_manager {
            let is_local = ctx.is_local();
            replication_manager.handle_sqlite_event(event, is_local).await?;
        }
        Ok(())
    }
    
    // Paginated API for startup synchronization
    async fn get_table_events(&self, request: TableEventsRequest, ctx: &RequestContext) -> Result<ArcValue> {
        if let Some(replication_manager) = &self.replication_manager {
            let response = replication_manager.get_table_events(request).await?;
            Ok(ArcValue::new_struct(response))
        } else {
            Err(anyhow!("Replication not enabled"))
        }
    }
    
    // Subscribe to all SQLite events with proper namespacing
    async fn subscribe_to_sqlite_events(&self, context: &LifecycleContext) -> Result<()> {
        if let Some(_replication_config) = &self.config.replication {
            // Subscribe to all user_db events for enabled tables
            for table in &self.config.replication.as_ref().unwrap().enabled_tables {
                let create_path = format!("user_db/{}/created", table);
                let update_path = format!("user_db/{}/updated", table);
                let delete_path = format!("user_db/{}/deleted", table);
                
                // Subscribe to all operation types for this table
                context.subscribe(create_path, self.create_event_handler()).await?;
                context.subscribe(update_path, self.create_event_handler()).await?;
                context.subscribe(delete_path, self.create_event_handler()).await?;
            }
        }
        Ok(())
    }
}
```

### Phase 4: Event Schema and Data Structures

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct SqliteEvent {
    pub operation: String,  // "created", "updated", "deleted"
    pub table: String,
    pub data: Option<ArcValue>,  // Original SQL query data
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct ReplicationEvent {
    pub id: String,
    pub table_name: String,
    pub operation_type: String,
    pub record_id: String,
    pub data: String,  // JSON serialized data
    pub timestamp: i64,
    pub source_node_id: String,
    pub sequence_number: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableState {
    pub table_name: String,
    pub last_event_sequence: i64,
    pub last_event_timestamp: i64,
    pub record_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableEventsRequest {
    pub table_name: String,
    pub page: u32,
    pub page_size: u32,
    pub from_sequence: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Plain)]
pub struct TableEventsResponse {
    pub events: Vec<ReplicationEvent>,
    pub has_more: bool,
    pub total_count: u32,
    pub page: u32,
    pub page_size: u32,
}
```

### Phase 5: Event Table Creation

```sql
-- Generated for each replicated table
CREATE TABLE IF NOT EXISTS {table_name}_Events (
    id TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    data TEXT,
    timestamp INTEGER NOT NULL,
    source_node_id TEXT NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    sequence_number INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_{table_name}_events_timestamp 
ON {table_name}_Events (timestamp);

CREATE INDEX IF NOT EXISTS idx_{table_name}_events_sequence 
ON {table_name}_Events (sequence_number);

CREATE INDEX IF NOT EXISTS idx_{table_name}_events_source 
ON {table_name}_Events (source_node_id);
```

## Service Lifecycle Integration

### Startup Sequence

1. **Replication Service Starts**
   - Registers event handlers for `user_db/*` events
   - Creates event tables
   - Subscribes to SQLite service events with proper namespacing

2. **SQLite Service Starts**
   - Applies schema (including event tables)
   - Begins accepting requests
   - Emits events for operations with `user_db/<table>/<operation>` namespacing

3. **Startup Synchronization** (if enabled)
   - Replication service requests latest state from network using paginated API
   - Fetches events in pages of 100 until all events are retrieved
   - Applies missing events
   - Signals SQLite service ready

### Runtime Operation

1. **Write Operation (Local)**
   - Client calls SQLite service
   - SQLite service executes operation
   - SQLite service emits ephemeral event: `user_db/users/created`
   - Replication service receives event (is_local = true)
   - Replication service stores event as processed (no re-processing)
   - Replication service broadcasts to network

2. **Write Operation (Remote)**
   - Remote node emits ephemeral event: `user_db/users/created`
   - Local replication service receives event (is_local = false)
   - Replication service stores event as not processed
   - Replication service processes event (applies to database)
   - Replication service marks event as processed

## Configuration and Usage

### Service Registration

```rust
// Create SQLite service with replication enabled
let sqlite_config = SqliteConfig::new(
    "my_database.db".to_string(),
    schema,
    false,  // encryption disabled
).with_replication(ReplicationConfig {
    enabled_tables: vec!["users".to_string(), "orders".to_string()],
    conflict_resolution: ConflictResolutionStrategy::LastWriteWins,
    startup_sync: true,
    event_retention_days: 30,
});

let sqlite_service = SqliteService::new(
    "my_db".to_string(),
    "user_db".to_string(),  // This becomes the event namespace prefix
    sqlite_config,
);

// Register single service with replication
node.add_service(sqlite_service).await?;
```

### Event Subscription

```rust
// Other services can subscribe to specific table events
context.subscribe("user_db/users/created", handler).await?;
context.subscribe("user_db/orders/updated", handler).await?;

// Or subscribe to all events for a table
context.subscribe("user_db/users/*", handler).await?;

// Or subscribe to all database events
context.subscribe("user_db/*", handler).await?;
```

## Advantages of Updated Design

1. **Proper Event Namespacing**: Clear separation between database, table, and operation
2. **Local vs Remote Handling**: Correctly distinguishes between local and remote events
3. **No Event Loops**: Local events are stored but not re-processed
4. **Paginated Startup Sync**: Efficient synchronization for large datasets
5. **Framework Compliance**: Uses EventContext.is_local() for proper event handling
6. **Scalable**: Can handle large numbers of events during startup sync

## Code Feature Request: EventContext.is_local()

**Request**: Add `is_local()` method to `EventContext` to distinguish local vs remote events.

**Implementation Location**: `runar-node/src/services/event_context.rs`

**Purpose**: Enable replication system to correctly handle local vs remote events without creating processing loops.

**Impact**: Critical for proper replication functionality and preventing data duplication issues. 