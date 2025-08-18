# MdnsDiscovery Provider (Bonjour/NSD) — Specification

## Scope
- Provide LAN peer discovery for iOS and Android using platform-native mDNS APIs:
  - iOS/macOS: Bonjour via Network.framework (NWBrowser/NWListener)
  - Android: NSD via NsdManager (or a robust mDNS lib if needed)
- Implemented in the native layer (Swift/Kotlin), not in Rust, to leverage platform capabilities, permissions, and lifecycle.
- Integrate with Rust `runar-transporter` via FFI: native layer emits discovery events that are bridged to `DiscoveryEvent` for consumers.

## Rationale
- Multicast UDP reliability varies on mobile and requires entitlements/locks; Bonjour/NSD are the supported, battery-aware, and policy-compliant mechanisms.
- Keeping platform-specific code in native layers avoids cross-platform UDP/mDNS edge cases and simplifies permissions/backgrounding.

## Service definition
- Service type: `_runar._quic`
  - Transport is QUIC over UDP; service name maps to the peer node identity.
  - SRV record provides host:port; A/AAAA resolves addresses.
- TXT keys (short, ASCII):
  - `id`: compact node id (derived from `node_public_key`)
  - `ver`: node info version (monotonic)
  - `net`: comma-separated network ids (optional if too long; can be omitted)
  - `proto`: `quic`
  - Addresses may be omitted from TXT; prefer SRV+DNS resolution.

## Permissions/entitlements
- iOS: `com.apple.developer.networking.multicast` entitlement; typically Wi‑Fi only; test on device.
- Android: NSD requires location permission on many OS versions; for multicast fallback, acquire `WifiManager.MulticastLock`.

## Lifecycle contract
- Native MdnsDiscovery has two modes:
  - Advertising (publish local node service)
  - Browsing (discover peers)
- Rust interface mapping:
  - `init(options)`: pass announce interval, debounce windows, and service type; native stores config.
  - `start_announcing()`: native starts advertising.
  - `stop_announcing()`: native stops advertising.
  - `subscribe(listener)`: Rust registers listener; adapter forwards native events as `DiscoveryEvent`.
  - `shutdown()`: native stops browse/advertise, releases resources.

## FFI bridge (high-level)
- Native → Rust: emit discovery events
  - `extern "C" fn runar_discovery_emit_discovered(node_public_key_ptr, len, addresses_json_cstr)`
  - `extern "C" fn runar_discovery_emit_updated(…)`
  - `extern "C" fn runar_discovery_emit_lost(node_id_cstr)`
  - Payload format:
    - `node_public_key`: bytes (Vec<u8>)
    - `addresses`: serialized as CBOR or compact JSON array of `"ip:port"`
- Rust adapter (to be implemented): `MdnsForeignDiscovery` implements `NodeDiscovery` and exposes thread-safe FFI entrypoints that push events into an internal channel; adapter broadcasts to `DiscoveryListener`s.
- Rust → Native: lifecycle control
  - `extern "C" fn runar_mdns_init(config_json_cstr)`
  - `extern "C" fn runar_mdns_start_advertise()`
  - `extern "C" fn runar_mdns_stop_advertise()`
  - `extern "C" fn runar_mdns_start_browse()`
  - `extern "C" fn runar_mdns_stop_browse()`
  - `extern "C" fn runar_mdns_shutdown()`
- Serialization across FFI:
  - For simple values (ids, strings): C strings
  - For structured lists: CBOR (preferred) or JSON for bootstrap simplicity

## Data model mapping
- Native service info → Rust `PeerInfo`:
  - `public_key` (required): recovered from TXT `id` or embedded binary advertisement (preferred: derive `id` from `public_key` that is also shared out-of-band during QUIC handshake)
  - `addresses`: `Vec<String>` built from SRV host:port and A/AAAA (include resolved numeric addresses)
- Rust will still perform QUIC/TLS authentication via `runar-keys`; discovery is not trusted for identity.

## Debounce and filtering
- Native side should coalesce rapid updates; also configurable debounce on Rust side via `DiscoveryOptions.debounce_window`.
- Emit `Updated` when TXT/SRV changes or IPs change; emit `Lost` when service removed or times out.

## Failure behavior
- If mDNS unsupported/denied:
  - Return clear error from `init` (Rust adapter maps to `NetworkError::DiscoveryError`)
  - Suggested fallback strategy by the app: use Rendezvous server or prompt user to enable permissions.

## Battery and session policy
- Discovery runs while the app is in active discovery mode.
- After peers are connected, caller may stop browsing and/or advertising to conserve battery; can re-enable on demand.
- On iOS backgrounding: pause browsing/advertising unless specific background modes are granted.

## Test plan
- Unit/adapter tests (Rust):
  - FFI emit functions enqueue the right `DiscoveryEvent` and notify all listeners.
  - Start/stop/shutdown are idempotent; no task leaks.
- Integration tests (native harness):
  - Two devices on Wi‑Fi discover each other and connect via QUIC.
  - Permissions denied → clear error path; app falls back.
  - Debounce behavior verified by rapid add/remove.

## Compatibility with existing `NodeDiscovery`
- Current trait is sufficient:
  - `init`, `start_announcing`, `stop_announcing`, `subscribe`, `shutdown`, `update_local_peer_info`.
- Implementation plan:
  - New `MdnsForeignDiscovery` struct in Rust implementing `NodeDiscovery`.
  - Expose FFI functions to receive events from Swift/Kotlin and forward to this instance.
  - No changes required to the trait; optional addition: structured `DiscoveryProviderKind` enum in higher-level config to choose provider.

## Minimal Rust tasks (future PRs)
1. Add `MdnsForeignDiscovery` adapter with channels and FFI entrypoints.
2. Add provider selection in the app/FFI layer; keep `MulticastDiscovery` opt-in.
3. Document platform setup: iOS entitlement, Android permissions.
4. Example native snippets for Swift/Kotlin that call FFI functions.
