## Runar Type Name Normalization and Registry

### Goal
- Use platform‑neutral wire type names instead of Rust `type_name()` paths.
- Keep simple defaults for most types (e.g., `User` on the wire).
- Allow disambiguation for same‑named types (e.g., `profile.User`, `metrics.User`).
- NO backward compatibility at all. This is a new codebase and new sytem.. change everywhere that uses old ways to use new ways.. 

### Scope
- Applies to `ArcValue` wire format and conversion helpers in `runar-serializer`.
- Extends `runar-serializer-macros` (`Plain`, `Encrypt`) to auto‑register names.
- Other platforms (Swift/TS) mirror the same naming rules and registration.

## Wire Format Changes
- Keep current header layout: `[category:u8][is_encrypted:u8][name_len:u8][name_bytes][payload]`.
- Replace `name_bytes` content from Rust path to a platform‑neutral "wire name".
  - Example: `alloc::string::String` → `string`; `crate::models::User` → `User` (default) or `profile.User` (override).
 - NO backward compatibility at all. 

### Constraints for wire names
- ASCII only; max 255 bytes (unchanged header limit).
- Allowed charset: `[A-Za-z0-9_.:-]` and must start with `[A-Za-z]`.
- No `::` allowed. A dot `.` separates optional namespace (e.g., `profile.User`).

## Name Resolution Rules
- Primitives use the following fixed wire names and cross‑platform mapping (see full table below):
  - `string`, `bool`, `bytes`, all exact integer/float variants (`i8`, `u32`, `f64`, ...).
- Containers DO NOT encode element type parameters in the wire name. We only use reserved container wire names: `list`, `map`, `json`.
  - Payload stays exactly as produced today: lists as `Vec<T>` and maps as `HashMap<String, T>` for the original `T` (including `ArcValue` when explicitly used). This preserves all current round‑trips like `Vec<String>`, `Vec<MyType>`, `HashMap<String, String>`, etc.
  - JSON category (`json`) stays as today, carrying a JSON value payload.
- User types default wire name: the simple Rust ident (no module/crate), e.g., `User`.
- Disambiguation: opt‑in override via macro attribute to set a custom wire name, e.g., `profile.User`.

### Cross‑Platform Primitive Mapping Table

| Wire name | Rust | Swift | Kotlin (JVM) | TypeScript |
| --- | --- | --- | --- | --- |
| string | String | String | String | string |
| bool | bool | Bool | Boolean | boolean |
| bytes | Vec<u8> | Data | ByteArray | Uint8Array |
| char | char | Character | Char | string (length 1) |
| i8 | i8 | Int8 | Byte | number |
| i16 | i16 | Int16 | Short | number |
| i32 | i32 | Int32 | Int | number |
| i64 | i64 | Int64 | Long | bigint (recommended) or number (lossy >53 bits) |
| i128 | i128 | BigInt (lib) or String | BigInteger (lib) or String | bigint (recommended) or string |
| u8 | u8 | UInt8 | UByte | number |
| u16 | u16 | UInt16 | UShort | number |
| u32 | u32 | UInt32 | UInt | number |
| u64 | u64 | UInt64 | ULong | bigint (recommended) or number (lossy >53 bits) |
| u128 | u128 | BigUInt (lib) or String | BigInteger (lib) or String | bigint (recommended) or string |
| f32 | f32 | Float | Float | number |
| f64 | f64 | Double | Double | number |

Notes:
- For JS/TS, use `bigint` for 64/128‑bit integers to avoid precision loss. SDKs should expose helpers and decode to `bigint` by default for `i64/u64/i128/u128`.
- Swift/Kotlin do not have native 128‑bit integers; SDKs should use BigInt libraries or string fallback for 128‑bit values.

## Registry Design
Add a new type‑name registry in `runar-serializer` in addition to current registries:

- rust_name → wire_name: `DashMap<&'static str, &'static str>`
- wire_name → json_fn: `DashMap<&'static str, ToJsonFn>`
- wire_name → plain_type_id: `DashMap<&'static str, TypeId>` (enables dynamic flows by name)
- wire_name → rust_name (diagnostics only): `DashMap<&'static str, &'static str>`
- Duplicate detection: `wire_name` collisions will log a warning and ignore the later registration (first‑wins to avoid flapping). Agreed.

Notes:
- Existing decrypt registry by `TypeId` remains as‑is for `as_type_ref::<T>()` flows. When needed, we can translate `wire_name → TypeId` using the new map for dynamic use cases.
- The current JSON registry keyed by Rust type stays, but we will bind `wire_name → json_fn` at registration time so all wire‑name lookups use a single path.

### Public API
- `register_type_name<T>(wire_name: &'static str)`
  - Registers `rust_name::<T>() → wire_name`, `wire_name → json_fn<T>`, `wire_name → TypeId::<T>`, and `wire_name → rust_name::<T>()` (for diagnostics).
  - The `json_fn` is the same function used elsewhere; the registry just exposes it by wire name as well. Internally we still mono‑morphise `to_json::<T>()` via `register_to_json::<T>()` and store its pointer.
  - On duplicate `wire_name`, log warning and keep the first registration.
- `lookup_wire_name(rust_name: &str) -> Option<&'static str>`
- `lookup_json_by_wire_name(wire_name: &str) -> Option<ToJsonFn>`
 - `lookup_type_id_by_wire_name(wire_name: &str) -> Option<TypeId>`
 - `lookup_rust_name_by_wire_name(wire_name: &str) -> Option<&'static str>`

### Pre‑Registered Primitives (single path)
- We will preload the type‑name registry at init with all primitives via `register_type_name::<T>()`, so containers and primitives use the same lookup path. No separate primitive table or fast path is required.
- Pre‑registrations include: `String→"string"`, `bool→"bool"`, `Vec<u8>→"bytes"`, all integer/float variants, and `char`.

## Macro Changes (`runar-serializer-macros`)

### Attributes
- At the type level, accept an optional name override.
  - Syntax (reuses `#[runar(...)]`): `#[runar(name = "profile.User")]`  Good. I see the exmaple below.. works fine.
  - If omitted, the macro computes the default wire name = simple ident (e.g., `User`).

### Behavior
- `#[derive(Plain)]` and `#[derive(Encrypt)]` emit a `#[ctor]` function that calls:
  - `register_type_name::<T>(WIRE_NAME)`
  - `register_to_json::<T>()` (existing) and additionally binds `WIRE_NAME → json_fn<T>`
  - `register_decrypt::<T, EncryptedT>()` (existing for `Encrypt`)

### Duplicate Wire Name Handling
- If another type has already claimed `WIRE_NAME`, log a warning like:
  - `log_warn!(logger, "duplicate_wire_name name={WIRE_NAME} first_type={first} second_type={second}")`
- Keep first registration, ignore the later one to prevent non‑determinism.

## ArcValue Integration

### Serialize
- When writing the header:
  - Resolve `inner.type_name()` → wire name via registry. If no mapping exists, return an error (this enforces a single, explicit path; users must derive `Plain`/`Encrypt` or register manually).
  - For primitives and containers, resolution succeeds due to pre‑registration.

### Deserialize
- Treat header `name` strictly as a wire name.
  - For primitives: map the wire name to the correct eager path using the registry (which knows Rust concrete types for eager decode).
  - For containers (`list`, `map`, `json`): create lazy structures. For `to_json()`, use generic container JSON conversion that first attempts `Vec<ArcValue>` / `HashMap<String, ArcValue>` and, if that fails, falls back to deserializing common primitive containers and finally to a generic CBOR→JSON path. Typed accessors like `as_type::<Vec<T>>()` and `as_type::<HashMap<String,T>>()` continue to work unchanged because payloads remain `Vec<T>` / `HashMap<String,T>`.
  - For `as_type_ref::<T>()`, the path remains unchanged (uses `TypeId` decrypt registry) and does not depend on the wire name.
  - Unknown wire names: return an error.

## Cross‑Platform Guidance (Swift/TS)
- Mirror the same wire names.
- Default to the simple type name; allow an opt‑in override when disambiguation is required.
- Provide a `registerTypeName<T>("profile.User")` helper in those SDKs.
- On duplicate wire name, print a warning at init time.

## Migration Plan
1. Implement the new type‑name registry and pre‑register primitives and containers.
2. Update macros to register `wire_name` at `#[ctor]` time.
3. Update `ArcValue::serialize` to emit wire names and fail if mapping is missing.
4. Update `ArcValue::deserialize` and `to_json()` to consult wire‑name paths only.
5. Keep container payloads as `Vec<T>` / `HashMap<String, T>` and implement generic container JSON conversion as described.
6. Add tests:
   - Primitive round‑trip using `wire_name`.
   - Struct with default name, cross‑crate decode.
   - Struct with overridden name `profile.User`.
   - Duplicate registration warning.
   - Container round‑trip list/map nesting relying on ArcValue element headers.
7. Document macro usage in `runar-serializer-macros/README.md`:
   - `#[derive(Plain)]`, `#[derive(Encrypt)]`
   - Optional `#[runar(name = "profile.User")]`.

## Examples

### Simple default
```rust
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Plain)]
struct User { id: i64, name: String }
// Wire name emitted: "User"
```

### Disambiguation
```rust
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Plain)]
#[runar(name = "profile.User")]
struct User { /* ... */ }

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Plain)]
#[runar(name = "metrics.User")]
struct User { /* ... */ }
```

## Non‑Goals (now)
- Encoding generic parameters into wire names. Default stays as the base ident; if generics could collide, require an explicit override via `#[runar(name = ...)]`.
- Automated name propagation across services; registration is per‑process at init via `#[ctor]`.

## Open Questions
- Should duplicate handling be configurable (first‑wins vs last‑wins)? Spec chooses first‑wins for determinism. NO.. just one path.. first WINS is the correct one.. with a warning. that is all


