# Runar Node FFI – Design & Technical Analysis

> **Crate name:** `runar-js-ffi`

---

## 1  Scope & Motivation
Runar currently runs natively in Rust.  Many teams write application logic in JavaScript/TypeScript—particularly on **Node.js** and the emerging **Bun** runtime.  Providing first-class bindings unlocks:

* **Embedded mode** – shipping Runar inside existing Node services.
* **Serverless / edge** deployments (Vercel, Cloudflare Workers w/ Bun).
* **Full-stack demo apps** where UI, server & Runar share one language.

The goal is to expose the same ergonomic API already enjoyed by Rust consumers while hiding all FFI complexity.

---

## 2  Goals & Non-Goals
### 2.1 Goals
1. Idiomatic **TypeScript** interface (type-safe, intellisense friendly).
2. Support **Node ≥ 18 LTS** and **Bun ≥ 1.0** (macOS & Linux x64/arm64).
3. Zero-copy or near-zero-copy data transfer for common primitives.
4. Async model that integrates with JS promises & the event loop.
5. Production-ready packaging (pre-built binaries, fallback to `cargo` build).
6. Observable via Runar's logging → JS console / user-supplied logger.

### 2.2 Non-Goals
* Running the entire Runar stack in **WASM** (may come later).
* Supporting legacy runtimes (Node < 18, Deno, older io.js).
* Generating bindings for every internal Runar crate—only the public Node API.

---

## 3  Typical Usage (Target API)
```ts
import { Node, Context } from "runar-ts";

const node = new Node({
  // same configuration JSON schema as Rust
});

const mathService = {
  name: "math-service",
  path: "math",
  actions: {
    add: (a: number, b: number, ctx: Context) => {
      ctx.logger.debug("from the JS/TS side!");
      return a + b;
    },
  },
};

node.addService(mathService);
await node.start();
```

---

## 4  High-Level Architecture
```
+----------------------+       N-API / C-ABI        +-------------------------+
|   JavaScript / TS    |  <-------------------------> |     runar-js-ffi (Rust)  |
| -------------------- |                            | ----------------------- |
| Node | Service | ... |                            |  ↳ wraps runar-node     |
+----------------------+                            +-------------------------+
                                                ↘︎ uses runar-common, etc.
```
Key idea: **`runar-js-ffi`** acts as a thin shim, delegating almost all business logic to existing Rust crates (`runar-node`, `runar-services`, …).  Only conversion glue and lifetime management live in the FFI layer.

---

## 5  FFI Technology Evaluation
| Option      | Pros                                              | Cons / Risks                                |
|-------------|---------------------------------------------------|---------------------------------------------|
| **`napi-rs`** (Node-API) | • Mature, actively maintained  • Bun 1.0 implements Node-API  • Works on Windows/macOS/Linux  • Generates TypeScript declarations | • Adds a dependency on `napi-rs` macros  • Requires tokio → Node event-loop coordination |
| **Neon**    | • Popular, good docs                               | • No Bun support  • GC boundary penalties   |
| Raw **C-ABI** + node-addon-api | • Lowest overhead | • Tons of boilerplate  • Manual memory mgmt, error mapping |
| **WIT / wasmtime** | • Future-proof interface-types | • Bun lacks wasm-host integration  • Higher latency |

**Decision:** Adopt **`napi-rs`** for both Node.js & Bun; fallback to Neon only if Bun's Node-API coverage proves insufficient.

---

## 6  Data Model Bridging
### 6.1 Primitive Mapping
| Rust                  | JS/Bun                        |
|-----------------------|-------------------------------|
| `bool`                | `boolean`                     |
| `i32`, `i64`, `u32`…  | `number` (lossy for >53-bit)  |
| `f64`                 | `number`                      |
| `String`, `&str`      | `string`                      |
| `Vec<T>`              | `T[]`                         |
| `HashMap<K,V>` / `BTreeMap` | `Record<string,V>` (keys as string) |
| `ArcValue`, `VMap`    | Custom proxy classes (serialize to plain objects when crossing boundary) |

### 6.2 Complex Structures
* **Config objects** will use **`serde_json`** to deserialize from JS `object` → Rust struct.
* **Service callbacks**: JS function pointer stored in `napi::JsFunction`, invoked from Rust via `threadsafe_function`.  Converts arguments & returns a `Promise` on JS side.

### 6.3 Zero-Copy Opportunities
* `Uint8Array` ↔ `&[u8]` via `napi::Env::create_buffer_with_data` (references shared memory, no copy).
* Strings shorter than 64 B can be small-string-optimized; otherwise one allocation.

---

## 7  Concurrency & Runtime Integration
* **Tokio runtime** inside Rust node continues to own async IO.
* Each **JS callback** is dispatched onto Tokio via `tokio::task::spawn_blocking` when called from Rust to avoid blocking worker thread.
* **ThreadsafeFunction** returns control to JS immediately; result passed back via `Promise` resolution.
* When JS code calls into Rust (`node.start()`), we expose an **async `Promise`** that awaits Tokio future completion.
* Shutdown handles drop gracefully on JS GC via `Finalize` impl.

---

## 8  Error Handling
1. Rust `Result<T, E>` → JS `throw new RunarError(...)` with `code`, `message`, and `stack`.
2. Multiple error categories (`ConfigError`, `NetworkError`, …) map to subclasses for ergonomic `instanceof` checks.
3. Panics: caught via `std::panic::catch_unwind` → converted to fatal JS exception.

---

## 9  Logging Integration
* Re-export Runar's `Logger` interface; accept user-supplied sink or default to `console.*`.
* Implement a `napi::bindgen_prelude::Callback` to push structured log events to JS listeners.

---

## 10  Packaging & Distribution Strategy
1. **Monorepo crate** `runar-ts-ffi` with `package.json` (type = "module").
2. Use `napi-rs` **`napi build --release --platform`** to pre-compile binaries for:
   * darwin-x64, darwin-arm64, linux-x64-gnu, linux-x64-musl, win32-x64 (optional)
3. Publish npm package containing
   * `index.js` (loader), `index.d.ts` (types), and `*.node` binaries.
4. Fallback to **source build** (`cargo` + `@napi-rs/cli` postinstall) when platform prebuild missing.

---

## 11  Testing Strategy
* **Rust unit tests** for FFI boundary functions using `napi::bindgen_test::*`.
* **Jest / Vitest** integration tests that require the compiled addon and start a real Runar node.
* Continuous Integration matrix covering Node 18/20, Bun 1.0, Linux/macOS.

---

## 12  Security Considerations
* Validate all config & service definitions from JS – reject unknown keys.
* Ensure no unsound lifetime leaks; use `Arc` + `Weak` to break cycles.
* Harden against malicious JS callbacks (timeout, panic-catch, backpressure).

---

## 13  Open Design Decisions (to be confirmed before code)
1. **Runtime strategy**
   * a. Single-threaded Node's libuv thread only
   * b. Dedicated Tokio multithread runtime (current prototype) (X)
2. **Error surface granularity** – comprehensive enum vs opaque string. start simpel with opaque string.
3. **Service callback sync vs async** – allow sync returns or force Promise. -> allow sync returns
4. **Transfer of large binary payloads** – copy vs shared buffer (requires careful lifetime).- start simple . copy
5. **Pre-build footprint** – which targets are officially supported. linux mac and windows. arm and x86
6. **Logging level mapping** – align Node's `debug/info/warn/error` with Rust. yes
7. **Versioning policy** – independent `runar-ts-ffi` semver vs Rust crate versions. Rust crate versions
8. **Bun edge case** – Bun currently lacks some Node-API symbols (v1.0.3).  Decide fallback path.

Documenting and agreeing on these items will prevent re-work during implementation.

---

## 14  Implementation Roadmap
| Milestone | Deliverable | Notes |
|-----------|-------------|-------|
| M1 | Skeleton `runar-ts-ffi` crate; expose `hello()` to JS | Validate napi-rs toolchain |
| M2 | Wrap Runar `Node::new` and `start/stop` | Basic config parsing, no services |
| M3 | **Service registration** – JS callback → Rust adapter | Handle primitive args |
| M4 | Data structures (ArcValue, VMap) bridging | Requires custom class wrappers |
| M5 | Logging & error mapping | Integrated logger sink |
| M6 | Pre-build CI & npm publish | GitHub Actions with `napi-rs/action` |
| M7 | Documentation site & examples | Showcase math-service demo |
 
 