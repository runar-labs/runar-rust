## Transporter pre-FFI improvements (actionable checklist)

Goal: harden and simplify the `runar-transporter` API and implementation before adding any FFI wrappers. Focus on security-by-default, configuration correctness, logging, runtime ownership, and stable wire contracts. Keep changes backward-compatible where reasonable; deprecate footguns.

### 0) Ground rules for this work
- Ensure clean compilation, clippy, tests: `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`.
- No regressions to existing `runar-node` tests.
- Prefer small, independent edits; land in small PRs.

---

### 1) Security and TLS/PKI integration
- [ ] Remove `SkipServerVerification` from production code paths; restrict to tests/dev-only.
  - Files: `src/transport/mod.rs`
  - Action: move the type behind `#[cfg(any(test, feature = "insecure_dev"))]`. Default build must not compile it.
  - Acceptance: Release build cannot reference or compile the skip verifier; tests can enable via feature or test cfg.

- [ ] Replace `dangerous().with_custom_certificate_verifier(...)` default with strict verification.
  - Files: `src/transport/quic_transport.rs::build_quinn_configs`
  - Action: create rustls client config from trusted roots and peer-auth using PKI from runar-keys (see next item). Keep an opt-in `feature = "insecure_dev"` to use the custom verifier only in tests/dev.
  - Acceptance: By default, chain/hostname validation occurs; integration test covers failure on mismatched identity.

- [ ] Integrate `runar-keys` directly for identity and trust.
  - Files: `src/transport/quic_transport.rs`, `src/transport/mod.rs`
  - Action: add an identity/trust provider path so callers do not pass raw certs/keys. Keep current cert/key options for tests but deprecate.
  - Suggested API: extend `QuicTransportOptions` with either
    - `with_key_manager(Arc<dyn KeyManager>)` (trait from runar-keys), or
    - `with_identity_profile(profile_id: &str)` and `with_network_id(&str)` so transporter asks runar-keys for the chain + verification policy.
  - Validation: constructor rejects configuration if neither key manager nor explicit certs/keys are provided.
  - Acceptance: QUIC config uses materials provided by runar-keys path when present; no cert/privkey required from top layers in normal flows.

---

### 2) Message model and framing correctness
- [ ] Enforce message size limits from options (not hard-coded 1MB).
  - Files: `src/transport/quic_transport.rs::read_message`, `src/transport/mod.rs::TransportOptions`
  - Action: thread an effective `max_message_size` (from `TransportOptions.max_message_size` with a sane default) into read/write validation. Reject too-large frames early with `NetworkError::MessageError`.
  - Acceptance: Unit test verifies configurable limit; exceeding size returns error; default aligns with options default.

- [ ] Remove `NetworkMessageType` enum in favor of numeric constants.
  - Files: `src/transport/mod.rs`
  - Action: delete the enum; keep and document the numeric constants; update any vestigial references (the code already uses numeric constants).
  - Acceptance: No remaining references to the enum; docs clearly state message codes and their semantics.

- [ ] Fix doc/comments about payloads: single payload only.
  - Files: `src/transport/mod.rs` (`NetworkMessage` comment), any other references.
  - Action: update comments to reflect `payload: NetworkMessagePayloadItem` (not list). If a vector is reintroduced later, do it deliberately.
  - Acceptance: Docs consistent; no misleading comments.

- [ ] Make handshake and stream timeouts configurable.
  - Files: `src/transport/quic_transport.rs`
  - Action: introduce options on `QuicTransportOptions`: `handshake_response_timeout`, `open_stream_timeout` (Durations). Replace hard-coded `2s` and other implicit timings.
  - Acceptance: Tests cover altered timeouts; defaults match current behavior.

---

### 3) Address handling robustness
- [ ] Iterate all addresses in `PeerInfo.addresses` with fallback/backoff.
  - Files: `src/transport/quic_transport.rs::connect_peer`
  - Action: try each address with per-attempt timeout and small jitter; optionally shuffle to reduce hotspots. On first success, stop; on all failure, maintain/backoff state.
  - Acceptance: Unit test simulates first-address failure and connects via second address; logs reflect attempts.

---

### 4) Logging simplification and context
- [ ] Allow constructing internal logger from `node_id` and level; keep ability to pass a `Logger` directly.
  - Files: `src/transport/quic_transport.rs`, `src/discovery/multicast_discovery.rs`
  - Action: extend options to accept either `Arc<Logger>` or `{ node_id: String, level: LogLevel }`. If `Logger` not provided, build one with component `Transporter` and ambient `node_id` context in Rust layer.
  - Acceptance: Transport works without a prebuilt logger; logs include node id context.

- [ ] Reduce noisy/emoji logs under non-debug levels.
  - Files: transport and discovery
  - Action: gate very verbose/emoji logs behind debug level.
  - Acceptance: Info-level logs are succinct; debug retains detail.
remove all emojis FROM LOGS.. THIS IS A BAD PRACTICE.
---

### 5) Runtime ownership and shutdown
- [ ] Audit start/stop to ensure no task leaks and no locks held across await in critical paths.
  - Files: `src/transport/quic_transport.rs`
  - Action: review loops and task abort handling; ensure graceful close drains; keep current "no locks across await" practice.
  - Acceptance: Add tests that start/stop repeatedly without leaks; clippy and loom-friendly patterns where feasible.

---

### 6) Configuration validation and ergonomics
- [ ] Validate `QuicTransportOptions` at construction with precise errors.
  - Files: `src/transport/quic_transport.rs::new`
  - Action: centralize validation (presence of identity path, timeouts > 0, size limits coherent, etc.).
  - Acceptance: Bad configs produce clear `NetworkError::ConfigurationError` messages.

- [ ] Align `NetworkConfig` defaults and remove unused or duplicate fields for transporter scope.
  - Files: `src/network_config.rs`
  - Action: ensure `max_message_size` coherently maps to TransportOptions; consider removing `max_chunk_size` until chunking lands.
  - Acceptance: No dead fields; consistent defaults.

---

### 7) Discovery polish and portability
wHAT IS THE ISSUE WITH iOS and Android ? that UDP needs entitlements ? or that thney do not work at all ?
what options we have for mobile for auto p2p network discovery.. without a centralized server ?

- [ ] Multicast opt-in behavior and clear errors.
  - Files: `src/discovery/*`
  - Action: ensure discovery runs only when configured; when multicast unavailable, return actionable errors, not tight loops.
  - Acceptance: Discovery tests pass on platforms without multicast by skipping or reporting cleanly.

- [ ] Listener lifecycle improvements.
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
- [ ] Message size limit respected (custom limit and default).
- [ ] Handshake timeout configurable.
- [ ] Address iteration connects via fallback.
- [ ] Strict TLS default rejects mismatched identity (behind real PKI or test CA).
- [ ] Start/stop idempotence and no task leaks.
- [ ] Discovery announce/listen happy-path with serialization errors handled.

---

### 10) Documentation updates
- [ ] Update `src/mod.rs` and `README`-level docs to reflect numeric message codes, single payload, and options’ new fields (timeouts, logger-from-node-id, keys integration).
- [ ] Document deprecations (explicit cert/key path) and recommended path (runar-keys integration) with code examples.

---

### Proposed option additions (pre-FFI, Rust-only)
- QuicTransportOptions
  - [ ] `with_handshake_response_timeout(Duration)`
  - [ ] `with_open_stream_timeout(Duration)`
  - [ ] `with_max_message_size(usize)` (or derive from `TransportOptions` consistently)
  - [ ] `with_key_manager(Arc<dyn KeyManager>)` or `with_identity_profile(&str)` (preferred over raw certs)
  - [ ] `with_logger_from_node_id(node_id: String, level: LogLevel)` (used only if `with_logger` not provided)
  - [ ] Deprecate: `with_certificates`, `with_private_key`, `with_root_certificates` for non-test usage; keep for tests.

---

### Execution plan (suggested order)
1. Remove insecure verifier by default; feature-gate.
2. Enforce message size from options; fix payload comments; remove enum.
3. Add configurable timeouts.
4. Implement address iteration/backoff.
5. Logger-from-node-id path; reduce noisy logs.
6. Integrate runar-keys identity/trust path and deprecate explicit certs.
7. Discovery polish.
8. Dependency cleanup.
9. Tests and docs.


