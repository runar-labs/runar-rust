# Network Public Key Migration Analysis and Design

## Executive Summary

This document provides a comprehensive analysis for migrating the `runar-keys` crate from using `network_id` (derived string identifier) to using `network_public_key` (raw public key bytes) consistently throughout the encryption and decryption processes. This change will eliminate the current inconsistency where encryption uses public key bytes but decryption relies on string-based network IDs.

## Current Implementation Analysis

### Current EnvelopeEncryptedData Structure
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    /// The encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Network ID this data belongs to (DERIVED FROM PUBLIC KEY)
    pub network_id: Option<String>,
    /// Envelope key encrypted with network key (always required)
    pub network_encrypted_key: Vec<u8>,
    /// Envelope key encrypted with each profile key
    pub profile_encrypted_keys: HashMap<String, Vec<u8>>,
}
```

### Current Flow Problems

**Encryption Flow:**
1. Receives `network_public_key: Option<&[u8]>` 
2. Uses public key bytes directly for ECIES encryption
3. Derives `network_id = compact_id(network_public_key)` for storage
4. Stores derived `network_id` in `EnvelopeEncryptedData.network_id`

**Decryption Flow:**
1. Requires `EnvelopeEncryptedData.network_id` to be present
2. Uses `network_id` to lookup private key from `HashMap<String, P256SecretKey>`
3. **Problem**: Decryption process doesn't have access to original public key bytes

## Impact Assessment

### Files Requiring Changes

#### Core Files (runar-keys crate)
1. **`src/mobile.rs`** - High Impact
   - `EnvelopeEncryptedData` struct definition 
   - `encrypt_with_envelope()` method
   - `decrypt_with_network()` method
   - `MobileKeyManagerState` serialization
   - Network key storage and retrieval methods

2. **`src/node.rs`** - High Impact
   - `decrypt_envelope_data()` method
   - `encrypt_with_envelope()` method
   - `create_envelope_for_network()` method
   - `NodeKeyManagerState` serialization
   - Network key storage and retrieval methods

3. **`src/lib.rs`** - Medium Impact
   - `EnvelopeCrypto` trait definition
   - Re-exports and trait bounds

#### Dependent Crates
1. **`runar-serializer`** - Medium Impact
   - Uses `EnvelopeEncryptedData` in encryption utilities
   - Interfaces with key stores through traits

2. **`runar-nodejs-api`** - Low Impact
   - Uses envelope encryption through trait interface
   - Should be mostly isolated by trait abstraction

3. **`runar-ffi`** - Low Impact
   - Uses envelope encryption through trait interface
   - Should be mostly isolated by trait abstraction

4. **`runar-node`** - Medium Impact
   - Uses envelope encryption for service communication
   - May have direct dependencies on `EnvelopeEncryptedData`

### Test Files Requiring Updates
- `runar-keys/tests/end_to_end_test.rs`
- `runar-keys/tests/certs_integration_test.rs`
- All test files that create or validate `EnvelopeEncryptedData`

## Proposed Design

### New EnvelopeEncryptedData Structure
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    /// The encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Network public key this data belongs to (RAW BYTES)
    pub network_public_key: Option<Vec<u8>>,
    /// Envelope key encrypted with network key (always required)
    pub network_encrypted_key: Vec<u8>,
    /// Envelope key encrypted with each profile key
    pub profile_encrypted_keys: HashMap<String, Vec<u8>>,
}
```

### Key Storage Strategy Changes

#### Mobile Key Manager
```rust
// Current storage (by derived ID)
network_data_keys: HashMap<String, P256SecretKey>
network_public_keys: HashMap<String, Vec<u8>>

// New storage (by public key bytes)
network_data_keys: HashMap<Vec<u8>, P256SecretKey>  // Key = public key bytes
// Remove network_public_keys (redundant)
```

#### Node Key Manager  
```rust
// Current storage (by derived ID)
network_agreements: HashMap<String, P256SecretKey>
network_public_keys: HashMap<String, Vec<u8>>

// New storage (by public key bytes)
network_agreements: HashMap<Vec<u8>, P256SecretKey>  // Key = public key bytes
// Remove network_public_keys (redundant)
```

### Method Signature Changes

#### EnvelopeCrypto Trait
```rust
pub trait EnvelopeCrypto: Send + Sync {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_public_key: Option<&[u8]>,
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<EnvelopeEncryptedData>;

    fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> Result<Vec<u8>>;

    // CHANGED: Accept public key bytes instead of network_id string
    fn get_network_public_key(&self, network_public_key: &[u8]) -> Result<Vec<u8>>;
}
```

## Implementation Plan

### Phase 1: Core Structure Changes
1. **Update EnvelopeEncryptedData**
   - Change `network_id: Option<String>` to `network_public_key: Option<Vec<u8>>`
   - Add migration support for backward compatibility

2. **Update Key Storage**
   - Change HashMap keys from `String` (derived IDs) to `Vec<u8>` (public key bytes)
   - Update serialization structures for persistence

### Phase 2: Method Implementation Changes
1. **Mobile Key Manager Updates**
   - Update `encrypt_with_envelope()` to store public key bytes
   - Update `decrypt_with_network()` to use public key bytes for key lookup
   - Update network key generation and storage methods

2. **Node Key Manager Updates**
   - Update `decrypt_envelope_data()` to use public key bytes
   - Update `encrypt_with_envelope()` to store public key bytes
   - Update network key installation and retrieval methods

### Phase 3: Trait and Interface Updates
1. **Update EnvelopeCrypto trait**
   - Modify method signatures to use public key bytes
   - Update implementations in both MobileKeyManager and NodeKeyManager

2. **Update dependent interfaces**
   - Ensure serializer integration continues to work
   - Update any direct usage of network_id in higher-level crates

### Phase 4: Migration and Backward Compatibility
1. **State Migration**
   - Implement migration logic for existing persisted state
   - Convert network_id-based storage to public key-based storage

2. **API Compatibility**
   - Provide temporary bridge methods if needed
   - Ensure FFI and Node.js API compatibility

## Implementation Details

### Encryption Flow Changes
```rust
// NEW encryption implementation
pub fn encrypt_with_envelope(
    &self,
    data: &[u8],
    network_public_key: Option<&[u8]>,
    profile_public_keys: Vec<Vec<u8>>,
) -> Result<EnvelopeEncryptedData> {
    let envelope_key = self.create_envelope_key()?;
    let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

    let mut network_encrypted_key = Vec::new();
    let mut stored_network_public_key = None;
    
    if let Some(network_public_key) = network_public_key {
        // DIRECT USE - Store public key bytes directly
        network_encrypted_key = self.encrypt_key_with_ecdsa(&envelope_key, network_public_key)?;
        stored_network_public_key = Some(network_public_key.to_vec());
    }

    // ... profile encryption logic remains same ...

    Ok(EnvelopeEncryptedData {
        encrypted_data,
        network_public_key: stored_network_public_key,  // ← Store public key bytes
        network_encrypted_key,
        profile_encrypted_keys,
    })
}
```

### Decryption Flow Changes
```rust
// NEW decryption implementation
pub fn decrypt_with_network(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
    let network_public_key = envelope_data
        .network_public_key
        .as_ref()
        .ok_or_else(|| KeyError::DecryptionError("Envelope missing network_public_key".to_string()))?;

    // DIRECT LOOKUP using public key bytes as key
    let network_key = self.network_data_keys.get(network_public_key).ok_or_else(|| {
        KeyError::KeyNotFound(format!(
            "Network key not found for public key: {} bytes", 
            network_public_key.len()
        ))
    })?;

    let encrypted_envelope_key = &envelope_data.network_encrypted_key;
    let envelope_key = self.decrypt_key_with_agreement(encrypted_envelope_key, network_key)?;
    self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
}
```

### Key Storage Changes
```rust
// Mobile Manager - NEW storage approach
impl MobileKeyManager {
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {  // Return public key bytes
        let network_key = P256SecretKey::random(&mut thread_rng());
        let public_key = network_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        // Store using public key bytes as key
        self.network_data_keys.insert(public_key.clone(), network_key);
        
        log_info!(self.logger, "Network data key generated: {} bytes", public_key.len());
        Ok(public_key)  // Return public key bytes instead of derived ID
    }

    pub fn get_network_public_key(&self, network_public_key: &[u8]) -> Result<Vec<u8>> {
        // Direct access - no lookup needed, just validate we have the key
        if self.network_data_keys.contains_key(network_public_key) {
            Ok(network_public_key.to_vec())
        } else {
            Err(KeyError::KeyNotFound("Network key not found".to_string()))
        }
    }
}
```

## Backward Compatibility Strategy

### State Migration
```rust
// Migration function for existing persisted state
impl MobileKeyManager {
    fn migrate_state_to_public_key_storage(old_state: &OldMobileKeyManagerState) -> Result<MobileKeyManagerState> {
        let mut new_network_data_keys = HashMap::new();
        
        for (network_id, secret_key) in &old_state.network_data_keys {
            // Derive public key from secret key
            let public_key = secret_key
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
                
            // Verify the network_id matches what we'd derive from public key
            let derived_id = compact_id(&public_key);
            if derived_id != *network_id {
                log_warn!(logger, "Migration: network_id mismatch for {}", network_id);
            }
            
            new_network_data_keys.insert(public_key, secret_key.clone());
        }
        
        // ... migrate other fields ...
    }
}
```

### Envelope Data Migration
```rust
// Support for reading old format during transition
impl EnvelopeEncryptedData {
    pub fn migrate_from_legacy(old_data: &LegacyEnvelopeEncryptedData, keystore: &dyn EnvelopeCrypto) -> Result<Self> {
        let network_public_key = if let Some(network_id) = &old_data.network_id {
            // Try to resolve network_id to public key using keystore
            Some(keystore.get_network_public_key_by_id(network_id)?)
        } else {
            None
        };

        Ok(Self {
            encrypted_data: old_data.encrypted_data.clone(),
            network_public_key,
            network_encrypted_key: old_data.network_encrypted_key.clone(),
            profile_encrypted_keys: old_data.profile_encrypted_keys.clone(),
        })
    }
}
```

## Breaking Changes

### API Changes
1. **EnvelopeEncryptedData.network_id** removed, replaced with **network_public_key**
2. **Key storage maps** change from `HashMap<String, SecretKey>` to `HashMap<Vec<u8>, SecretKey>`
3. **Method signatures** in `EnvelopeCrypto` trait change to use public key bytes
4. **Return types** for network key generation methods change from `String` to `Vec<u8>`

### Serialization Changes
1. **State persistence** format changes require migration
2. **CBOR-encoded EnvelopeEncryptedData** format changes
3. **Network communication** protocols may need versioning

## Testing Strategy

### Unit Tests
1. **Round-trip encryption/decryption** with new public key approach
2. **Key storage and retrieval** using public key bytes as keys
3. **State migration** from old format to new format
4. **Error handling** for missing network keys

### Integration Tests
1. **End-to-end envelope encryption** across mobile/node boundary
2. **State persistence and restoration** with new format
3. **Cross-crate compatibility** with serializer and other dependent crates
4. **Performance testing** with public key-based lookups vs string-based lookups

### Compatibility Tests
1. **Migration testing** with various old state formats
2. **FFI interface** compatibility after changes
3. **Node.js API** compatibility after changes
4. **Serializer integration** testing

## Performance Considerations

### HashMap Key Performance
- **Vec<u8> keys**: Slightly slower than String keys due to variable length
- **Memory usage**: May increase due to storing full public key bytes vs compact IDs
- **Hash computation**: Vec<u8> hashing vs String hashing performance impact

### Mitigation Strategies
1. **Fixed-size arrays**: Consider using `[u8; 65]` for P-256 public keys instead of `Vec<u8>`
2. **Key caching**: Cache frequently-used network keys for faster access
3. **Benchmarking**: Compare performance before/after migration

## Security Considerations

### Benefits
1. **Eliminates derivation dependency**: No reliance on `compact_id` derivation consistency
2. **Direct key verification**: Can verify public key matches private key during decryption
3. **Reduced attack surface**: Eliminates potential issues with ID derivation algorithms

### Risks
1. **Larger attack surface**: Storing raw public key bytes vs derived strings
2. **Key format validation**: Need to validate public key format consistency
3. **Migration vulnerabilities**: Ensure state migration doesn't introduce security issues

## Timeline and Dependencies

### Dependencies
1. **runar-common**: May need updates to compact_id usage patterns
2. **runar-serializer**: Interface updates required
3. **runar-nodejs-api**: Minimal changes due to trait abstraction
4. **runar-ffi**: Minimal changes due to trait abstraction

### Estimated Timeline
- **Phase 1**: Core changes (1-2 weeks)
- **Phase 2**: Method implementations (1-2 weeks)  
- **Phase 3**: Trait updates (1 week)
- **Phase 4**: Migration and compatibility (1-2 weeks)
- **Testing and validation**: (1 week)

**Total**: 5-8 weeks for complete migration

## Conclusion

This migration will significantly improve the consistency and reliability of the envelope encryption system by eliminating the current asymmetry between encryption (using public key bytes) and decryption (using derived network IDs). While it requires substantial changes across the codebase, the benefits of a more consistent and secure design justify the investment.

The phased approach with backward compatibility support will minimize disruption during the transition period while ensuring all dependent systems continue to function correctly.
