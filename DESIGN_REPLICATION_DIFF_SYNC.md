## Replication Diff Sync: origin_seq, Checkpoints, Idempotence, Retention/GC, Snapshots

### Goals
- Fetch only diffs on startup sync; avoid full history replay
- Make ingestion idempotent and safe under retries/races
- Be robust to restarts, network partitions, and moderate clock skew
- Provide bounded storage via retention and optional snapshots

### Terminology
- Origin: node where an event was originally produced
- Event: durable record describing a change (CREATE/UPDATE/DELETE) on a table
- Event store: per-table `*_Events` table containing events

### Event identity and schema
- Each event carries:
  - `id TEXT PRIMARY KEY` (UUID)
  - `table_name TEXT NOT NULL`
  - `operation_type TEXT NOT NULL` (create/update/delete)
  - `record_id TEXT NOT NULL`
  - `data TEXT` (serialized SqlQuery or other payload)
  - `timestamp INTEGER NOT NULL` (ms since epoch)
  - `origin_node_id TEXT NOT NULL` (equals the producing node id)
  - `origin_seq INTEGER NOT NULL` (monotonic per origin)
  - `processed BOOLEAN DEFAULT FALSE`

Indexes:
- Primary key on `id`
- Composite index on `(origin_node_id, origin_seq)`
- Index on `(timestamp, id)` for time-based scans (fallback)

Notes:
- `origin_node_id` reuses existing `source_node_id` semantics; we will standardize on `origin_*` naming for clarity.

### Origin sequence generation (origin_seq)
- Each node maintains a persistent, monotonic counter per service that produces events.
- On local event creation: `origin_node_id = self.node_id`, `origin_seq = ++counter`.
- Sequence must persist across restarts to remain monotonic; stored in a meta table.

Meta table example:
- `replication_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`
- Keys used:
  - `origin_seq::<service_path>` -> last issued origin_seq (integer)

### Preservation of origin identity across the network
- When forwarding events, do not regenerate event identifiers; forward `origin_node_id` and `origin_seq` as-is.
- Receivers persist exactly those values.

### Checkpoint tracking (per-origin high-water marks)
- Maintain per table, per origin high-water mark of the highest applied event.
- Persisted in a dedicated table:
  - `replication_checkpoints(table_name TEXT, origin_node_id TEXT, origin_seq INTEGER, PRIMARY KEY(table_name, origin_node_id))`
- On successful apply of an event from `(origin_node_id, origin_seq)`, update the checkpoint to that `origin_seq`.

### Startup sync protocol (diff-only)
Client side (requester):
- For a given table T, assemble the map `{origin_node_id -> last_seq}` from `replication_checkpoints`.
- Send `TableEventsRequest` extended with `from_by_origin` (list of `(origin_node_id, origin_seq)`), and optionally a `from_timestamp` fallback.

Server side (responder):
- Filter events for T where `(origin_node_id, origin_seq) > from_by_origin[origin_node_id]`.
- Exclude events where `origin_node_id == requester_id` (optional optimization).
- Order by `(origin_node_id, origin_seq)` or simply by `(timestamp, id)` while respecting the origin filter.
- Paginate (page_size, page) as today.

Skew fallback:
- If client has no checkpoints yet, server can also accept `from_timestamp` and include events with `timestamp > from_timestamp` to reduce volume.
- Clients should apply idempotence to handle overlaps.

### Idempotent ingest and apply (no dupes, safe retries)
- Ingestion rule, per event, inside a transaction:
  1) Insert into `*_Events` with `INSERT OR IGNORE` on `(id)` and also ensure uniqueness on `(origin_node_id, origin_seq)`.
  2) If the insert affected 0 rows (already present), skip applying SQL (already applied) and return success.
  3) If inserted, apply SQL to base table with idempotent semantics:
     - CREATE: prefer `INSERT OR IGNORE` (or treat duplicate key errors as success with 0 rows)
     - UPDATE/DELETE: normal SQL; applying twice should be a no-op (0 rows) when already applied
  4) Commit; update checkpoints.

Error policy:
- If step 3 fails with a duplicate error on CREATE, treat as success (idempotent replay).
- For other SQL failures, roll back the transaction to avoid partial state (event row without data change) and surface the error.

### Retention and garbage collection (GC)
Goals:
- Bound the growth of `*_Events` while preserving recovery and late joiners.

Policy:
- Retain events for at least `N` days (configurable per service/table).
- Do not delete events newer than the minimum checkpoint across known peers minus a safety window.
- Keep a global floor watermark per table:
  - `gc_floor_seq_by_origin(origin) = min(checkpoint_by_peer[origin])`
  - Events with `origin_seq <= gc_floor_seq_by_origin(origin)` older than retention window are eligible for deletion.

Implementation:
- Background task periodically computes GC candidates and deletes eligible rows in batches.
- Maintain simple metrics (rows deleted, table sizes).

### Snapshots (optional, for faster bootstrap and deep history)
Goals:
- Allow pruning very old events while enabling new peers to catch up quickly.

Concept:
- Periodically create a snapshot per table: a consistent dump at a certain global cut 
  across `(origin_node_id, origin_seq)` checkpoints.
- Store snapshot metadata: `snapshot_id`, `created_at`, `per_origin_seq_cut`, and a digest.
- New peers can fetch the latest snapshot plus events after the cut.

Implementation options:
- Snapshot to a file/object store or into an internal snapshot table.
- Export/import interfaces (stream chunks, verify digest, apply bulk load, then replay events).

### Migrations and compatibility
- Add `origin_node_id` (reuse `source_node_id`) and new `origin_seq` columns (with default 0 for existing rows).
- Backfill origin_seq for existing local events with a monotonic assignment per origin ordered by timestamp/id (best-effort).
- Add composite index on `(origin_node_id, origin_seq)`.
- Introduce `replication_meta` and `replication_checkpoints` tables.
- Maintain compatibility: if a peer doesn’t support per-origin requests yet, fall back to `from_timestamp`.

### Phased rollout
Phase 1 (stabilization):
- Idempotent ingest now: insert-or-ignore event first; skip SQL if already present; treat duplicate INSERTs as success.
- Reorder apply to eliminate partial state.

Phase 2 (diff protocol core):
- Add `origin_seq` generation/persistence and carry through the pipeline.
- Extend `TableEventsRequest` with `from_by_origin` and implement server-side filtering.
- Update checkpoints on apply.

Phase 3 (retention/GC):
- Implement GC floor based on checkpoints + retention window.
- Add a background cleanup task.

Phase 4 (snapshots):
- Design and implement snapshot creation, verification, distribution, and bootstrap.

### Testing plan
- Unit tests for idempotent ingest for CREATE/UPDATE/DELETE (duplicate events do not mutate base tables again).
- E2E: restart scenarios where history is replayed; verify no duplicates and correct counts.
- Mixed-version peers: fallback to timestamp works and remains idempotent.
- GC safety: no deletion below peer floors; retention respected.
- Snapshot bootstrap: applying snapshot + post-cut events yields identical state.


