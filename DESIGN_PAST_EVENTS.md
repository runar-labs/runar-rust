## Past-event delivery for Node event system

Goal: allow subscribers to receive the most recent matching event if it occurred shortly before subscription, eliminating startup races while keeping `$`-prefixed topics local-only and preserving existing transport semantics.

Key ideas
- Event retention window: per-topic in-memory buffer of recent events with timestamps. Default small (e.g., 2–5s), configurable per-node. Publishers can opt-in per event with `retain_for`.
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
- On publish: if retain_for > 0 (or node default applies), store (ts, data) in per-topic VecDeque, prune by age/size.
- On subscribe_with_options(include_past): immediately check retained store for newest event within lookback; if found, deliver once to the handler before live flow, then proceed with normal streaming events.
- On on_with_options: register live subscription immediately and concurrently query retained store; whichever arrives first wins; then unsubscribe and return. Timeout still enforced.

Scope and semantics
- Local-only: retention and lookback are local, no cross-node effects; `$registry/...` events keep local-only semantics.
- Wildcards: v1 supports exact-topic past delivery. Wildcard past-delivery is optional follow-up; if enabled, return newest among matched topics.
- Back-pressure: cap per-topic entries (e.g., 16) and prune by time; large payloads avoided unless publisher opts in.

Configuration (NodeConfig.events)
- default_retain_for: Option<Duration> (applies when publisher omits retain_for)
- max_retain_entries_per_topic: usize (e.g., 16)
- prune_interval: Duration (e.g., 1s)

Data structures
- DashMap<String, VecDeque<(Instant, ArcValue)>> for retained_by_topic
- Background prune task periodically removes expired entries; on write, also trim by size.

Testing
- Unit tests: publish event, then subscribe with include_past=50ms and ensure delivery; ensure subscribe without include_past does not deliver.
- E2E: replication startup waits on `$registry/services/{service}/state/running` using include_past≈2s to eliminate race.

Non-goals
- No cross-node retention or broadcast of `$` topics.
- No guaranteed delivery beyond lookback window.

Migration
- Keep existing `on(...)` hot semantics; adopt `on_with_options`/`subscribe_with_options` where races can occur (e.g., replication startup gates).


