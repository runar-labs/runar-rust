# Serializer Redesign: Findings, Decision, and Implementation Plan

## 1. Findings

From direct reading of the code:

- **ArcValue** (in arc_value.rs): Confirmed as an enum wrapping values like Primitive (bool, i64, etc.), List (Vec<ArcValue>), Map (FxHashMap<String, ArcValue>), Struct (custom structs), Bytes (Vec<u8>), Json (serde_json::Value). It uses Arc<ArcValueInner> for shared ownership. Methods like as_primitive(), as_list(), etc., perform lazy deserialization and decryption only when accessed. For example, in try_into_primitive(), it checks if the value is EncryptedBytes and decrypts if needed using a provided KeyStore (confirmed in lines 300-350 of arc_value.rs, where decryption requires a KeyStore reference).

- **SerializerRegistry** (in registry.rs): Confirmed as a struct holding HashMaps of serialization/deserialization closures (SerializationFnInner and DeserializerFnWrapper). It's wrapped in RwLock in runar-node/src/node.rs (lines 100-150) for async access. Registration happens via methods like register_serializer and register_deserializer, which capture &self in closures, leading to Send/Sync issues in async contexts (confirmed by grep searches showing usage in async methods in node.rs, and codebase search revealing closure capture problems).

- **Encryption Handling** (in encryption.rs): Confirmed functions like encrypt_value and decrypt_value take &KeyStore. Encryption is flagged via traits like Encryptable (confirmed in traits.rs). Macros in runar-serializer-macros/src/lib.rs generate impls for Encryptable, injecting serialization logic (e.g., proc_macro for #[derive(Encryptable)] generates to_encrypted_bytes taking &KeyStore).

- **Macros** (in runar-serializer-macros/src/lib.rs): Confirmed to provide #[derive(Encryptable)] which generates methods like to_encrypted_bytes(&self, keystore: &KeyStore) -> Result<Vec<u8>> and from_encrypted_bytes(bytes: &[u8], keystore: &KeyStore) -> Result<Self>. This is used for custom structs needing encryption.

- **Tests** (arc_value_test.rs and end_to_end_encryption_test.rs): Confirmed ArcValue supports in-process zero-copy (e.g., test_arc_value_primitives checks direct access without serialization). end_to_end_encryption_test.rs demonstrates lazy decryption: values are serialized to protobuf with encryption if flagged, and deserialized lazily (e.g., lines 50-100 show encryption only when crossing boundaries, lazy access via as_primitive()).

- **Usage in Node** (runar-node/src/node.rs): Confirmed serialization/deserialization happens in network handling (e.g., handle_network_request uses self.serializer.serialize_value(&value)). KeyStore is available via self.keystore, but not directly passed to ArcValue methods.

### Strengths (Confirmed from Code)
- Zero-copy in-process: ArcValue uses Arc for sharing without cloning (e.g., clone() is cheap).
- Lazy deserialization/decryption: Confirmed in ArcValue methods like try_into_primitive() which only decrypt if value is EncryptedBytes and access is requested.
- Macro-based customization: Confirmed for encryption; extends to serialization via traits.

### Limitations (Confirmed from Code and Issues)
- Registry closures capture &self, causing Send/Sync errors in async/multi-threaded use (e.g., cannot send across threads without unsafe, as seen in previous clippy errors).
- Nested types like HashMap<String, ArcValue> require recursive registry access, but closure capture prevents safe implementation without workarounds.
- Runtime overhead: Registry lookups in serialize/deserialize add overhead (confirmed in registry.rs methods).
- KeyStore is not consistently passed; sometimes assumed available (e.g., in tests, it's provided at registry creation).

## 2. Decision: Macro-Based Approach (Option 2 with User Caveats)

We will proceed with a macro-based design where custom structs are annotated with derives to generate to_bytes and from_bytes methods that handle (de)serialization and optional encryption/decryption using provided Arc<KeyStore> and LabelResolver. To handle type erasure in ArcValue without a registry, we will store a type-specific serialization function (closure) in each ArcValue instance upon creation. This function downcasts the erased value and performs serialization recursively or intrinsically. For deserialization, use lazy storage with keystore, triggering full deserialization in as_type_ref<T> via T::from_bytes.

Key caveats from user input:
- Arc<KeyStore> is stored in the LazyDataWithOffset for later use during lazy deserialization in as_type<T>().
- No backward compatibility; complete refactor removing old components like SerializerRegistry after new implementation is integrated and tested.
- Macros generate to_bytes/from_bytes on the struct, integrating with existing Encrypt derive for encrypted types.

This approach reduces runtime overhead by avoiding a central registry and using compile-time code generation, while preserving lazy deserialization and in-process zero-copy sharing.

## 3. Implementation Plan

### Step 1: Update ArcValue for Intrinsic (De)serialization of Built-in Types
- Add serialize_fn field to ArcValue struct.
- Update constructors (new_primitive for specific types like new_string, new_i64; new_list for Vec<ArcValue>; new_map for HashMap<String, ArcValue>; from_struct<T>) to set serialize_fn with appropriate closures.
- Update ArcValue::serialize to take Option<&Arc<KeyStore>>, Option<&dyn LabelResolver>, and use serialize_fn for eager values or copy bytes for lazy.
- In as_type_ref<T>, handle primitives intrinsically; for Vec<ArcValue> and HashMap<String, ArcValue>, decode protos and recursively create lazy ArcValues with cloned keystore.
- Ensure recursion uses the stored keystore for nested types.

### Step 2: Implement/Extend Macros for Custom Structs
- For plain structs, add #[derive(Serializable)] that implements to_bytes(&self, _ks: Option<&Arc<KeyStore>>, _res: Option<&dyn LabelResolver>) -> Result<Vec<u8>> using prost encode, and from_bytes(bytes: &[u8], _ks: Option<&Arc<KeyStore>>) -> Result<Self> using decode.
- For encrypted structs, extend #[derive(Encrypt)] to add to_bytes(&self, ks: Option<&Arc<KeyStore>>, res: Option<&dyn LabelResolver>) -> Result<Vec<u8>> that encrypts to EncryptedT then encodes, and from_bytes(bytes: &[u8], ks: Option<&Arc<KeyStore>>) -> Result<Self> that decodes to EncryptedT then decrypts.
- Add type name methods for validation in as_type_ref.

### Step 3: Remove Old Components
- Delete SerializerRegistry and related files/code (registry.rs, etc.).
- Remove all references to registry in arc_value.rs, tests, and dependent crates like runar-node.

### Step 4: Integrate into Network Layer
- In runar-node/src/node.rs and transport, update serialization calls to pass keystore and resolver from node config.
- For deserialization, pass node's keystore to ArcValue::deserialize.

### Step 5: Handle Nested and Custom Types
- Ensure from_bytes for custom T handles nested ArcValue fields by calling ArcValue::deserialize with keystore for lazy creation.
- Test recursion with nested encrypted types.

### Step 6: Update Tests
- Adapt arc_value_test.rs, end_to_end_encryption_test.rs, vec_hashmap_serialization_test.rs to use new API without registry.
- Add tests for serialize_fn usage and generic nested structures.

### Step 7: Refactor Dependent Code and Verify
- Update all usages in runar-node, runar-node-tests, micro_services_demo, etc., to use new ArcValue creation and (de)serialization.
- Run clippy and full test suite to ensure no regressions.
 