# Code Improvement Checklist

This document defines how we improve core crates with state-of-the-art Rust practices. We proceed one file at a time, with measurable improvements and zero regressions.

## Process and Guardrails

- [ ] One file at a time. If an API change impacts other files, change only the minimal impacted surface required for that file. Do not batch unrelated refactors.
- [ ] After finishing a file: run tests and Clippy, update the Progress section below, and post a short summary.
- [ ] Commands (strict Clippy, deny warnings):
  - `cargo check`
  - `cargo test --all`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - For node crate specifically: `cargo clippy -p runar-node --all-targets --all-features -- -D warnings`
- [ ] Formatting and error messages must follow Rust idioms, e.g. `format!("PKCS#8 encoding error: {e}")`.
- [ ] API changes are allowed and encouraged when they improve correctness or performance. If a function can accept references instead of owned values, change the signature and refactor all impacted call sites (across crates if needed). Do not skip improvements due to API breakage concerns.

## Performance & Memory Efficiency

### Ownership and Borrowing
- [ ] Prefer `&str`/`&[u8]`/`&T` over owned `String`/`Vec<u8>`/`T` when ownership is not needed.
- [ ] Accept `impl AsRef<str>`/`AsRef<[u8]>` on APIs instead of `impl Into<String>` where practical. Return references or `Arc<T>` instead of cloning.
- [ ] Replace `clone()` on `Arc<T>` with `Arc::clone(&arc)` when not using method syntax.
- [ ] Proactively migrate function parameters to take references (`&T`, `&str`, `&[u8]`) whenever ownership is unnecessary. Refactor all call sites accordingly; breaking changes are acceptable.

### Allocation and Copy Reduction
- [ ] Avoid intermediate allocations in hot paths; use iterators and adapters that do not materialize temporary `Vec`s.
- [ ] Pre-allocate with `with_capacity` when size is known or can be guessed conservatively.
- [ ] Use `Cow<'_, str>` for borrowed-or-owned strings at boundaries where copies are sometimes necessary.
- [ ] Reuse buffers across calls (e.g., arena or thread-local scratch) where safe, or pool via a small wrapper when profiling shows wins.

### Collections
- [ ] Iterate by reference: `for item in &collection` or map APIs that avoid ownership changes.
- [ ] Prefer `VecDeque` for FIFO queues, `SmallVec`/`arrayvec` for short fixed upper-bounds, `IndexMap` when deterministic order is needed.
- [ ] Avoid `collect()` unless you need a materialized collection; prefer `for_each`, `try_for_each`, or streaming.

### Concurrency & Locking
- [ ] Never hold locks across `await`. Split critical sections or clone cheap state out before awaiting.
- [ ] Use `tokio::sync::{Mutex,RwLock}` in async code; avoid `std::sync::Mutex/RwLock` on async paths.
- [ ] Use `DashMap` for highly concurrent maps where appropriate, but prefer storing `Arc<T>` values to avoid large moves.
- [ ] Keep lock scope minimal and avoid nested locks. Consider `parking_lot` for sync contexts if profiling shows contention.
- [ ] Choose atomics with the weakest ordering that is correct (often `Relaxed` for simple flags/counters).

### Logging and Errors
- [ ] Use only logging macros for emission: `log_debug!`, `log_info!`, `log_warn!`, `log_error!`. Do not call `logger.debug/info/warn/error` directly in hot paths.
- [ ] Macro usage specifics (no ambiguity):
  - Prefer implicit capture for clarity and speed: `log_debug!(logger, "topic={topic} id={id}");`
  - Positional formatting is also fine: `log_info!(logger, "started {} services", count);`
  - For static text, still use the macro: `log_info!(logger, "service started");`
  - Never write `logger.info(format!(...))` or build `String`s for logs.
- [ ] Choose correct levels consistently: use `debug` for high-frequency tracing and detailed internals; use `info` for state transitions, lifecycle milestones, or user-visible summaries; keep `warn`/`error` as is for exceptional conditions.
- [ ] Use concise, actionable errors. Prefer `{e}` formatting over `{}` with explicit variables: `format!("Failed to parse: {e}")`.
- [ ] Avoid logging the same error multiple times across layers.

### Serialization/Deserialization
- [ ] Avoid re-serialization of unchanged values; cache or reuse encoded buffers where feasible.
- [ ] Prefer zero-copy deserialization when libraries permit; avoid unnecessary intermediate `String` conversions.
- [ ] Pass shared context (e.g., key store, label resolver) by `Arc` to avoid rebuilding per call.

## Code Quality & Correctness

- [ ] Compiler clean: `cargo check` passes.
- [ ] Clippy clean with `-D warnings` across all targets and features.
- [ ] Async best practices: no blocking calls in async contexts; use `spawn_blocking` if necessary.
- [ ] Public APIs documented with clear invariants and error semantics.
- [ ] Tighten encapsulation: make struct fields private by default; expose only via methods/traits. Avoid `pub(crate)` unless cross-module access is required and justified.

## Testing, Validation, and Benchmarking

- [ ] Unit tests: happy-path and edge cases for modified code.
- [ ] Integration tests across crates remain green.
- [ ] Add micro-benchmarks for any hot path changed (criterion). Keep flamegraphs to validate improvements.
- [ ] Add instrumentation (e.g., `tracing`) around hot paths to verify reductions in allocations, lock hold times, and latency.

## Before & After Examples

### Borrowing over ownership
```rust
// Before
fn process_data(data: String) -> String {
    let mut result = String::new();
    for item in data.split(',') {
        result.push_str(&item.trim().to_uppercase());
        result.push(',');
    }
    result
}

// After
fn process_data(data: &str) -> String {
    let mut out = String::with_capacity(data.len());
    for (i, item) in data.split(',').map(|s| s.trim()).enumerate() {
        if i > 0 { out.push(','); }
        out.push_str(&item.to_uppercase());
    }
    out
}
```

### Avoid cloning large maps
```rust
// Before
let peers = self.state.peers.clone();
for (peer_id, peer_state) in peers.iter() {
    /* ... */
}

// After
for entry in self.state.peers.iter() {
    let peer_id = entry.key();
    let peer_state = entry.value();
    /* ... */
}
```

## File-by-file Plan (start at runar-node/src/node.rs)

We begin at `runar-node/src/node.rs`, then fan out to the registry, transport, discovery, and serializer layers. Each file must reach “Definition of Done” below before moving to the next.

### 1) runar-node/src/node.rs
- Locking and contention
  - Replace `std::sync::Mutex` in async paths with `tokio::sync::Mutex` (e.g., `keys_manager_mut`).
  - Avoid holding locks across `await` (audit `start/stop`, networking, and subscription flows).
  - Evaluate `AtomicBool`/`AtomicI64` orderings; prefer `Relaxed` where applicable.
- Allocation and cloning
  - Reduce string allocations in `TopicPath` building; prefer borrowed `&str` and `AsRef<str>` for API surfaces.
  - Remove double clones in config/setup (e.g., redundant `clone()` on `network_ids`).
  - Avoid repeated `format!` in hot paths; use structured logging or guard on level.
- Concurrency
  - Convert service start fan-out to `FuturesUnordered` or join sets to limit concurrency and track completion.
  - Review debounce logic to ensure no lost notifications and minimal overhead.
- Retained events
  - Ensure pruning is O(k) on expiration and cap memory with clear limits; consider `SmallVec` for tiny histories.
  - Index operations: ensure wildcard matching uses pre-normalized keys and avoids transient allocations.
- Networking path
  - Ensure decoding/encoding avoids intermediate copies; reuse serialization contexts.
  - Guard outbound calls with timeouts and propagate structured errors without double-logging.
- API ergonomics
  - Where feasible, migrate public `impl Into<String>` parameters to `impl AsRef<str>` (cross-crate change; stage carefully).

### 2) runar-node/src/services/service_registry.rs
- Ensure map keys use canonical topic representations to avoid duplicate allocations.
- Return references or `Arc<T>` instead of cloning. Ensure handler registration extracts params without temporary `String`s.
- Audit subscription management to avoid holding locks during callbacks; move work out of critical sections.

### 3) Transport (e.g., runar-node/src/network/transport/*.rs)
- QUIC: reuse connections and streams; ensure backpressure and bounded buffering.
- Avoid per-request heap allocations; reuse buffers and encode directly into I/O buffers where practical.
- Ensure connect path is idempotent and coalesces duplicate attempts under load (single-flight).

### 4) Discovery (runar-node/src/network/discovery/*)
- Keep debouncing cheap; deduplicate frequent updates; avoid unnecessary clones of peer data.
- Make all socket operations non-blocking in async contexts; isolate blocking operations in `spawn_blocking` if needed.

### 5) runar-serializer
- Reuse serialization contexts and key lookups; avoid double encode/decode.
- Prefer zero-copy paths; avoid converting bytes to `String` unless required.

### 6) Cross-cutting quick wins
- Replace expensive logging on hot paths with level checks or structured fields.
- Normalize error creation sites to avoid repeated allocations.

## Definition of Done (per file)

- [ ] Green: `cargo test --all`.
- [ ] Clean: `cargo clippy --all-targets --all-features -- -D warnings` (and `-p runar-node` when scoped).
- [ ] No async blocking; no locks held across `await`.
- [ ] Profiling or micro-bench evidence of neutral or improved performance in targeted hot paths.
- [ ] Document notable changes and migration notes (if any API surfaces changed).
- [ ] Logging migrated to `log_*` macros where applicable and log level usage audited (debug vs info) in modified areas.

## Progress

- [ ] `runar-node/src/node.rs`
- [ ] `runar-node/src/services/service_registry.rs`
- [ ] `runar-node/src/network/transport/*.rs`
- [ ] `runar-node/src/network/discovery/*.rs`
- [ ] `runar-serializer/src/*.rs`

