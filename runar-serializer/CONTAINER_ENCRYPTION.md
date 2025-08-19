## Container element encryption design (lists & maps)

### Goals
- Field-level encryption applies to structs inside containers when a `SerializationContext` is provided.
- Support both heterogeneous containers (`Vec<ArcValue>`, `HashMap<String, ArcValue>`) and homogeneous containers (`Vec<T>`, `HashMap<String, T>`) where `T: RunarEncrypt`.
- Keep wire-name semantics consistent. No legacy/rust-name fallbacks.
- Preserve performance and avoid unnecessary allocations.
- Make the entire pipeline deterministic: no heuristic fallbacks; return explicit errors on mismatch.

### Parameterized wire-name grammar (deterministic)
- Primitives: `string`, `bool`, `i8` … `u128`, `f32`, `f64`
- Bytes: `bytes`
- JSON: `json`
- Structs: `<structWireName>` (from registry)
- Lists: `list<ElemWire>`
- Maps (key fixed to string): `map<string,ElemWire>`
- Heterogeneous (ArcValue elements): `list<any>`, `map<string,any>`

Terminology:
- `ElemWire` is the element type’s wire-name string resolved via the registry, not the literal text "ElemWire".
  - Example: if `TestProfile` is registered with wire name `profile`, then:
    - `Vec<TestProfile>` → typename `list<profile>`
    - `HashMap<String, TestProfile>` → typename `map<string,profile>`
  - For primitives: `Vec<u64>` → `list<u64>`; `HashMap<String, bool>` → `map<string,bool>`
- `any` means each element provides its own `{category, typename, value}` header (the ArcValue shape). It is used for heterogeneous containers only.

Rules:
- Header typename and serde CBOR typename must match the grammar exactly for the category.
- For typed containers, `ElemWire` must be the wire name of the element type; if unknown or unregistered, return an error.
- For `any` containers, each element must carry its own `{category, typename, value}` entry (ArcValue shape). No mixing: a `list<ElemWire>` must not contain `any` elements, and `list<any>` must not contain typed elements without embedded headers.

### Current behavior (baseline)
- Structs are encrypted at field-level only when serialized standalone as `ArcValue::new_struct(T)` and `serialize(Some(&SerializationContext))`, because the struct `SerializeFn` receives `(keystore, resolver)` and calls `RunarEncrypt::encrypt_with_keystore`.
- List/map `SerializeFn`s currently ignore `(keystore, resolver)` and emit plain CBOR for their contents (no field-level encryption per element). Envelope encryption may still wrap the whole container.
- JSON conversion prefers wire-name converters with no rust-name fallback.

### Problems
- `Vec<T>` / `HashMap<String, T>` (with `T: RunarEncrypt`) do not encrypt elements at field level.
- `Vec<ArcValue>` / `HashMap<String, ArcValue>` could in principle encrypt each element, but the current container `SerializeFn` does not propagate `(keystore, resolver)` into each element; it serializes the container via serde in one shot.

### Design overview
Introduce an Encrypt Registry to dynamically encrypt elements by type at runtime (no API additions for container constructors). Containers remain `Vec<T>` / `HashMap<String, T>` friendly while gaining element-level encryption when a `SerializationContext` is provided. All serialization uses parameterized wire names.

#### Encrypt Registry (new)
- Storage: `TypeId -> EncryptFn` in a `DashMap`.
- Function signature:
  - `type EncryptFn = fn(value_any: &dyn Any, ks: &Arc<KeyStore>, resolver: &dyn LabelResolver) -> Result<Vec<u8>>`
  - Returns CBOR bytes of the encrypted representation (`T::Encrypted`), with no envelope.
- Registration API (called by `#[derive(Encrypt)]` via `#[ctor]`):
  - `pub fn register_encrypt<Plain, Enc>()` where `Plain: RunarEncrypt<Encrypted = Enc>`, `Enc: Serialize`.
  - Impl erases `&Plain` to `&dyn Any`, calls `Plain::encrypt_with_keystore(ks, resolver)`, then `serde_cbor::to_vec(&enc)`.
- Lookup helpers:
  - `pub fn lookup_encryptor_for<T>() -> Option<EncryptFn>` or `pub fn lookup_encryptor_by_typeid(typeid: TypeId) -> Option<EncryptFn>`.

#### Container serialization changes (List/Map)
- In the `SerializeFn` of `new_list<T>` / `new_map<T>`:
  - Compute the container wire name deterministically:
    - If `T == ArcValue`: `list<any>` / `map<string,any>`.
    - Else resolve `ElemWire` via registry from the Rust type name: `list<ElemWire>` / `map<string,ElemWire>`; error if missing.
  - If `(keystore, resolver)` are present AND an encryptor is registered for `T`:
    - For each element `&T`, invoke the encryptor to get `Vec<u8>` (CBOR of `T::Encrypted`).
    - Emit the container payload as CBOR of byte-strings:
      - List: `Vec<Vec<u8>>`
      - Map: `HashMap<String, Vec<u8>>`
  - Else (no context or no encryptor):
    - For typed containers, CBOR-encode the plain `Vec<T>` / `HashMap<String, T>` deterministically.
    - For `any` containers, CBOR-encode `Vec<ArcValue>` / `HashMap<String, ArcValue>` by serializing each element with its `{category, typename, value}` map entry.

Note: Outer envelope encryption still applies at the `ArcValue::serialize(Some(ctx))` layer to the entire container payload.

#### Deserialization and accessors (strict)
- Parse the parameterized wire name and branch deterministically:
  - `list<any>` / `map<string,any>`: expect a CBOR collection of `{category, typename, value}` entries for elements. Decode each via the existing `ArcValue` path; error on mismatch.
  - `list<ElemWire>` / `map<string,ElemWire>`: expect a CBOR collection of either:
    - Byte-strings per element, which are `CBOR(Enc)`; decrypt each with `registry::try_decrypt_into::<T>(&bytes, ks)` to produce `T`.
    - Or plain `T` values when no encryption context was used at serialization time.
  - Error if the on-wire representation does not conform to the declared wire name.
- Accessors:
  - `as_typed_list_ref<T>` and `as_typed_map_ref<T>` detect which concrete container encoding was used and decode strictly; otherwise return errors.

#### Developer ergonomics
- Homogeneous containers: keep using `ArcValue::new_list(vec_of_T)` / `ArcValue::new_map(map_of_T)`.
- When `T: RunarEncrypt` and a `SerializationContext` is supplied, elements encrypt transparently; wire names become `list<ElemWire>` / `map<string,ElemWire>`.
- Heterogeneous containers use `Vec<ArcValue>` / `HashMap<String, ArcValue>` and wire names `list<any>` / `map<string,any>`.

#### Performance considerations
- The encryption-aware path pre-allocates the output vector/object capacity to match the input size.
- Only attempts the downcast once; if it fails we use the fast path.
- No locks are held across potentially expensive operations.

### Removing all fallbacks (determinism plan)
- JSON conversion for lazy structs/lists/maps:
  - Use only wire-name converters. Remove generic CBOR→JSON fallback. If no converter exists for a wire name, return an error.
- Primitive deserialization: already wire-name only; unknown wire type is an error.
- Container deserialization:
  - Strictly enforce declared `list<...>`/`map<string,...>` wire names; error on mismatch or mixed contents.
- Typename emission:
  - Always emit parameterized names according to the grammar. Do not fall back to rust idents. Error if a struct has no registered wire name.
- Registry lookups:
  - Missing encryptor/decryptor or wire-name mapping is an error.

### Testing plan
- `Vec<TestProfile>` element encryption with `SerializationContext` (list of bytes payload): decrypt per element with node/mobile and assert field-level visibility rules.
- `HashMap<String, TestProfile>`: same as above.
- Mixed-type containers (`Vec<ArcValue>`): ensure existing behavior unchanged; struct entries still get field-level encryption when a context is supplied at their own serialization.
- Ensure outer envelope still wraps the entire container when context is provided.
- Ensure primitives-only containers still round-trip unchanged.
- Negative tests: unknown wire names, missing registry entries, container type mismatches (declared `list<foo>` but `any` payload, etc.) must error.

### Migration and compatibility
- No legacy/rust-name fallbacks anywhere.
- Existing public constructors remain; new ones extend functionality without breaking current call sites.

### Optional future work
- Provide helper macros/builders to convert `Vec<T>`/`HashMap<String,T>` into their encryptable container representation with minimal boilerplate.
- Explore compile-time ergonomics (feature-gated) that route `new_list`/`new_map` to the encryptable path when `T: RunarEncrypt`, if/when stable specialization becomes viable.


