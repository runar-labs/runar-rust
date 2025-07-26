# Data Replication Requirements Specification

## Overview

To enable easy development of distributed applications using the Runar technology stack, one of the key features to improve developer UX is the ability to add data replication to storage services without requiring developers to implement replication logic themselves.

## Problem Statement

Currently, developers using SQLite services must manually implement:
- Cross-node data synchronization
- Conflict resolution strategies
- Event sourcing patterns
- Replication state management
- Network event handling

This creates significant development overhead and potential for inconsistencies across different implementations.

## Solution Vision

The data replication feature should be implemented to work with SQLite services. The specific architectural approach (add-on service, wrapper, or integrated feature) will be determined during the design phase based on the requirements analysis and technical constraints.

## Functional Requirements

### FR-1: Replication Configuration
**Requirement**: Developers must be able to enable replication for specific tables/entities within their SQLite service.

**Acceptance Criteria**:
- Replication can be enabled/disabled per table
- Configuration includes conflict resolution policy
- Configuration is declarative and schema-driven

### FR-2: Event Sourcing Implementation
**Requirement**: For each table/entity with replication enabled, implement a CQRS approach where persistent events are created for all data modifications.

**Acceptance Criteria**:
- Automatic creation of event tables for replicated entities (one per entity)
- Persistent events are created for CREATE, UPDATE, and DELETE operations
- Events include metadata (timestamp, source node, operation type)
- Events are stored persistently in the database
- Events are broadcasted to the network via ephemeral events

### FR-3: Network Event Broadcasting
**Requirement**: When data modifications occur, persistent events must be broadcasted to other replicas of the same service in the network using ephemeral events.

**Acceptance Criteria**:
- Persistent events are published as ephemeral events using the existing event system
- Ephemeral events include all necessary data for replication
- Ephemeral events reach all nodes hosting the same service
- Failed ephemeral event delivery is handled gracefully


### FR-4: Event Processing and Replication
**Requirement**: Replicas must receive ephemeral events, convert them to persistent events, and process them to maintain data consistency.

**Acceptance Criteria**:
- Ephemeral events are received and converted to persistent events
- Persistent events are stored in local event tables (per entity)
- Events are processed in order (based on timestamp)
- CREATE events result in local record creation
- UPDATE events result in local record updates
- DELETE events result in local record removal
- Processing failures are logged and handled

### FR-5: Conflict Resolution
**Requirement**: The system must handle conflicts that arise when the same data is modified on multiple nodes.

**Note**: Conflicts are extremely rare. Only one node changes data at a time. The default policy is last-change-wins. Developers can implement their own conflict resolution by providing a function that takes all the context: the current records, the local event, and the new event that creates the conflict. The result needs to be a new event that solves the issue. This function should not modify data directly but create a new event that solves the issue, so the event can also be replicated to all nodes and the same effect can take effect in all places.

**Acceptance Criteria**:
- Default conflict resolution strategy is last-change-wins
- Conflict detection based on timestamps and node IDs
- Developers can implement custom conflict resolution logic
- Custom conflict resolution functions return new events (not direct data modifications)
- Conflict resolution events are logged and replicated

### FR-6: Service Composition
**Requirement**: The replication feature should first be tried to be implemented as a service that adds on to SQLite services. If requirements like FR-7 make it difficult, we can consider doing this as a feature of the SQLite service itself.

**Acceptance Criteria**:
- SQLite services already emit ephemeral events for all operations (if any are missing, we need to add them)
- Replication service listens to all ephemeral events from SQLite and creates persistent events from them
- Local ephemeral events should not be re-processed since they were already applied to the local aggregate (main entity)
- Replication service can be added to any SQLite service
- Minimal changes required to existing SQLite service code (only if ephemeral events are missing)
- Ability to turn off ephemeral events for a table (e.g., the events table does not need to emit ephemeral events since the replication service will do that in a specialized way)

### FR-7: Startup and Initialization
**Requirement**: When a new node is set up and starts running, the database will be empty. The replication service must request the latest state of each entity from the network.

**Acceptance Criteria**:
- Replication service requests latest state of each entity from the network
- Based on the returned state, the local replication service decides if replication is needed
- If replication is needed, the SQLite service is NOT READY until replication completes
- This prevents local services from trying to use the empty or incomplete SQLite service
- If a local service needs data during initialization, it will request from a remote node
- When the local SQLite service is ready, other local services can start consuming the data


## Non-Functional Requirements

### NFR-1: Performance
**Requirement**: Replication must not significantly impact the performance of the underlying SQLite service.

**Acceptance Criteria**:
- Event creation and broadcasting adds <10ms latency to operations
- Event processing does not block normal service operations
- Database schema changes are optimized for replication

### NFR-2: Reliability
**Requirement**: Replication must be reliable and handle network failures gracefully.

**Acceptance Criteria**:
- Events are persisted before broadcasting
- Failed event delivery is retried with exponential backoff
- Network partitions are handled without data loss
- Event ordering is maintained across network failures

### NFR-3: Scalability
**Requirement**: The replication system must scale to support multiple nodes and large datasets.

**Acceptance Criteria**:
- System supports 10+ replicas per service
- Event processing scales with available resources
- Database performance remains acceptable with event tables
- Memory usage is bounded and predictable

### NFR-4: Consistency
**Requirement**: The system must provide eventual consistency guarantees.

**Acceptance Criteria**:
- All replicas eventually converge to the same state
- Event ordering is preserved across all replicas
- No data loss occurs during normal operation
- Consistency violations are detected and reported
 

## Technical Architecture

### Service Structure
*Note: The exact service structure will be determined during the design phase. Possible approaches include:*

**Option 1: Add-on Service**
```
ReplicationService (listens to SqliteService events)
└── SqliteService (existing, emits events)
```

**Option 2: Integrated Feature**
```
SqliteService (with replication capabilities)
├── EventManager
├── ReplicationManager
└── ConflictResolver
```

**Option 3: Wrapper Service**
```
ReplicatedSqliteService
├── SqliteService (internal)
├── EventManager
├── ReplicationManager
└── ConflictResolver
```

## Event Types

### Ephemeral Events
Ephemeral events are Runar events using `context.publish()` and `subscribe()` APIs. These events travel the network and reach all nodes and services subscribed to them. They are used for real-time communication and coordination between services.

### Persistent Events
Persistent events are CQRS events that the replication system stores in the database. These events represent the complete history of data changes and are used for replication and audit purposes.

### Event Schema
Each entity/table that has replication enabled will have its own event table. The naming convention is `<TABLE_NAME>_Events`.

```sql
CREATE TABLE <TABLE_NAME>_Events (
    id TEXT PRIMARY KEY,
    operation_type TEXT NOT NULL, -- CREATE, UPDATE, DELETE
    record_id TEXT NOT NULL,
    data TEXT, -- JSON serialized data
    timestamp INTEGER NOT NULL,
    source_node_id TEXT NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    sequence_number INTEGER NOT NULL
);
```

### Event Flow
1. **Write Operation**: Client calls SqliteService
2. **Local Write**: SqliteService performs update and fires ephemeral event (context.publish())
3. **Event Creation**: EventManager (which is listening to all events for the SQLite service) receives ephemeral event and creates and stores a persistent event
4. **Event Broadcast**: EventManager broadcasts persistent event to network
5. **Remote Processing**: Other replicas receive and process persistent event
6. **Local Update**: Remote replicas update their local data
 sssss