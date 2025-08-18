## Transporter pre-FFI improvements (actionable checklist)

Goal: harden and simplify the `runar-transporter` API and implementation before adding any FFI wrappers. Focus on security-by-default, configuration correctness, logging, runtime ownership, and stable wire contracts. Keep changes backward-compatible where reasonable; deprecate footguns.

### 0) Ground rules for this work
- Ensure clean compilation, clippy, tests: `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`.
- No regressions to existing `runar-node` tests.
- Prefer small, independent edits; land in small PRs.

---

### 1) Security and TLS/PKI integration
- [x] Remove `SkipServerVerification` from production code paths; restrict to tests/dev-only.
  - Done: Removed from transporter; tests now define local test-only verifier where needed.

- [x] Replace `dangerous().with_custom_certificate_verifier(...)` default with strict verification.
  - Done: Client config now uses a strict rustls root store from configured roots.

- [x] Integrate `runar-keys` directly for identity and trust.
  - Files: `src/transport/quic_transport.rs`, `src/transport/mod.rs`
  - Action: added `with_key_manager(...)`; transporter fetches certs/keys/roots; explicit cert/key kept for tests.
  - Validation: constructor requires either key manager or (cert+key). Done.
  - Acceptance: QUIC uses materials from key manager when present. Done.

---

### 2) Message model and framing correctness
- [x] Enforce message size limits from options (not hard-coded 1MB).
  - Files: `src/transport/quic_transport.rs::read_message`, `src/transport/mod.rs::TransportOptions`
  - Done: Added `QuicTransportOptions::with_max_message_size` and enforce in `read_message`. Added test.

- [x] Remove `NetworkMessageType` enum in favor of numeric constants.
  - Files: `src/transport/mod.rs`
  - Done: Enum removed; numeric codes retained. Re-exports updated.

- [ ] Fix doc/comments about payloads: single payload only.
  - Files: `src/transport/mod.rs` (`NetworkMessage` comment), any other references.
  - Action: update comments to reflect `payload: NetworkMessagePayloadItem` (not list). If a vector is reintroduced later, do it deliberately.
  - Status: Pending (code already single-payload; docs need updating).

- [x] Make handshake and stream timeouts configurable.
  - Files: `src/transport/quic_transport.rs`
  - Action: introduce options on `QuicTransportOptions`: `handshake_response_timeout`, `open_stream_timeout` (Durations). Replace hard-coded `2s` and other implicit timings.
  - Status: Both added and enforced.

---

### 3) Address handling robustness
- [x] Iterate all addresses in `PeerInfo.addresses` with fallback/backoff.
  - Files: `src/transport/quic_transport.rs::connect_peer`
  - Action: Parse/try each address, prefer first valid; per-address errors logged; maintain/backoff state. (Further dial attempts per-address can be expanded.)
  - Acceptance: Path implemented; covered by tests.

---

### 4) Logging simplification and context
- [x] Allow constructing internal logger from `node_id` and level; keep ability to pass a `Logger` directly.
  - Files: `src/transport/quic_transport.rs`, `src/discovery/multicast_discovery.rs`
  - Action: Added `with_logger_from_node_id(node_id: String)` to create Transporter logger and set node id.
  - Acceptance: Transport works without a prebuilt logger; logs include node id context.

- [x] Reduce noisy logs under non-debug levels; remove emojis.
  - Files: transport and discovery
  - Action: gate very verbose logs behind debug level; remove emojis from messages.
  - Acceptance: Info-level logs are succinct; debug retains detail, no emojis.
remove all emojis FROM LOGS.. THIS IS A BAD PRACTICE.
---

### 5) Runtime ownership and shutdown
- [ ] Audit start/stop to ensure no task leaks and no locks held across await in critical paths.
  - Files: `src/transport/quic_transport.rs`
  - Action: review loops and task abort handling; ensure graceful close drains; keep current "no locks across await" practice.
  - Acceptance: Add tests that start/stop repeatedly without leaks; clippy and loom-friendly patterns where feasible.

---

### 6) Configuration validation and ergonomics
- [x] Validate `QuicTransportOptions` at construction with precise errors.
  - Files: `src/transport/quic_transport.rs::new`
  - Action: return `NetworkError::ConfigurationError` for invalid/missing options.
  - Acceptance: Clippy/tested paths produce clear errors.

- [ ] Align `NetworkConfig` defaults and remove unused or duplicate fields for transporter scope.
  - Files: `src/network_config.rs`
  - Action: ensure `max_message_size` coherently maps to TransportOptions; consider removing `max_chunk_size` until chunking lands.
  - Acceptance: No dead fields; consistent defaults.

---
BEFORE DOING THSI.. STOP AND do an indepth analisys and solutions options before any chagnes.. e need to know that options we have for monile discovery.
### 7) Discovery polish and portability
wHAT IS THE ISSUE WITH iOS and Android ? that UDP needs entitlements ? or that thney do not work at all ?
what options we have for mobile for auto p2p network discovery.. without a centralized server ?

- [x] Multicast opt-in behavior and clear errors.
  - Files: `src/discovery/*`
  - Action: ensure discovery runs only when configured; when multicast unavailable, return actionable errors, not tight loops.
  - Acceptance: Discovery tests pass on platforms without multicast by skipping or reporting cleanly.

- [x] Listener lifecycle improvements.
  - Files: `src/discovery/multicast_discovery.rs`
  - Action: ensure tasks are stopped on `shutdown`; confirm no stray tasks after stop; add missing unsubscription if needed.
  - Acceptance: Repeated init/start/stop cycles are clean.

---

### 8) Dependencies and size hygiene
- [ ] Remove unused network/codegen deps.
  - Files: `Cargo.toml`
  - Action: drop `tokio-tungstenite`, `bincode`, `prost` if not used; keep `serde_cbor`, `quinn`, `rustls`, `x509-parser`.
  - Acceptance: Build green; binary size reduced.

---

### 9) Tests to add/adjust (pre-FFI)
- [x] Message size limit respected (custom limit and default).
- [x] Handshake timeout configurable.
- [x] Address iteration connects via fallback.
- [x] Strict TLS default rejects mismatched identity (behind real PKI or test CA).
- [x] Start/stop idempotence and no task leaks.
- [x] Discovery announce/listen happy-path with serialization errors handled.

---

### 10) Documentation updates
- [ ] Update `