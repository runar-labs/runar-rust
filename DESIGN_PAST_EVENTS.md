## Past-event delivery for Node event system

Goal: allow subscribers to receive the most recent matching event if it occurred shortly before subscription, eliminating startup races while keeping `$`-prefixed topics local-only and preserving existing transport semantics.

Key ideas
- Wildcards unchanged: Wildcard semantics do not change. We will store retained events indexed by exact full topic, and use a PathTrie to resolve wildcard subscriptions to their matched exact topics.
- Event retention window: per-topic (exact topic) in-memory buffer of recent events with timestamps. Default small (e.g., 2–5s), configurable per-node. Publishers can opt-in per event with `retain_for`.
- Subscription lookback: subscribers can request delivery of past events within a lookback window using `include_past`.
- Hot subscription remains: `on(...)` registers immediately. New `on_with_options(...)`/`subscribe_with_options(...)` accept lookback.

API additions (non-breaking)
- PublishOptions { retain_for: Option<Duration>, .. }
- SubscribeOptions { include_past: Option<Duration>, .. }
- OnOptions { include_past: Option<Duration>, timeout: Duration }
- Node:
  - fn on_with_options(topic, options: OnOptions) -> JoinHandle<Result<Option<ArcValue>>>
  - async fn subscribe_with_options(topic, handler, options: SubscribeOptions) -> SubscriptionId (extend existing options)

Behavior
- On publish: if retain_for > 0 (or node default applies), store (ts, data) in the retained store for the exact full topic, and update the PathTrie index. Prune strictly by time and also cap entries per topic (e.g., 16).
- On subscribe_with_options(include_past):
  - Resolve the subscription topic via trie: for exact topics, use that key; for wildcards, enumerate matched exact topics.
  - Look across matched topics’ deques for the newest event within the lookback window and deliver it once immediately (the same retained event may be delivered independently to multiple listeners).
  - Then proceed with normal live subscription flow.
- On on_with_options: register live subscription immediately and concurrently check retained store as above. Whichever arrives first completes the future; then unsubscribe. Timeout still enforced.

Scope and semantics
- Local-only: retention and lookback are local, no cross-node effects; `$registry/...` events keep local-only semantics.
- Wildcards: fully supported via the PathTrie index (no change to delivery semantics at subscribe time).
- Back-pressure: cap per-topic entries (e.g., 16) and prune strictly by time; no payload-size heuristics.

Configuration (NodeConfig.events)
- default_retain_for: Option<Duration> (applies when publisher omits retain_for)
- max_retain_entries_per_topic: usize (e.g., 16)
- prune_interval: Duration (e.g., 1s)

Data structures
- DashMap<String, VecDeque<(Instant, ArcValue)>> for retained_by_topic (keyed by exact full topic)
- PathTrie over exact full topics for wildcard resolution
- Background prune task periodically removes expired entries; on write, also trim by size.

Testing
- Unit tests: publish event, then subscribe with include_past=50ms and ensure delivery; ensure subscribe without include_past does not deliver.
- E2E: replication startup waits on `$registry/services/{service}/state/running` using include_past≈2s to eliminate race.

Non-goals
- No cross-node retention or broadcast of `$` topics.
- No guaranteed delivery beyond lookback window.

Migration
- Keep existing `on(...)` hot semantics; adopt `on_with_options`/`subscribe_with_options` where races can occur (e.g., replication startup gates).


