# Runar Selective Field Encryption Design

This document outlines the design for a Rust macro system that enables selective field encryption in structs, integrated with the existing ArcValue serialization flow and runar-keys system.

## Overview

The system provides declarative field-level encryption through derive macros, allowing structs to specify which fields should be encrypted with which key types. This enables selective data access across different contexts:

- **User Profile Keys**: Encrypt data that only the user's device can decrypt
- **Network Keys**: Encrypt data that services running in the same network can decrypt

**Key Principle**: Encryption happens **during serialization** in the SerializerRegistry. 
If a struct is annotated with encryption macros, it will **always** be encrypted during 
serialization, regardless of context.

## Example Usage

```rust
#[derive(Encrypt, Decrypt, Serialize, Deserialize, Debug)]
struct Profile {
    pub id: String,
    
    #[runar(user)]
    pub name: String,
    
    #[runar(user, system)]
    pub age: i32,
    
    #[runar(user, system)]
    pub email: String,
    
    #[runar(user)]
    pub phone: String,
    
    #[runar(user)]
    pub address: String,
    
    // Fields without encryption annotations remain plaintext
    pub created_at: u64,
    pub version: String,
}

// Plain struct without encryption annotations
#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    pub created_by: String,
    pub timestamp: u64,
}
```

## Key Schema Architecture

The encryption system uses **abstract labels** in struct annotations that get resolved to actual keys through a configurable mapping system.

### Label-to-Key Mapping System

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMappingConfig {
    /// Maps abstract labels to actual key identifiers
    pub label_mappings: HashMap<String, KeyIdentifier>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyIdentifier {
    /// User profile key by profile ID - data accessible only on user's device
    UserProfile(String),
    /// Network key by network ID - data accessible to services in the network
    Network(String),
}

// Example configuration:
// {
//   "label_mappings": {
//     "user": {"UserProfile": "personal"},
//     "system": {"Network": "network_abc123"}
//   }
// }
```

### Key Resolution

```rust
pub trait KeyResolver {
    /// Resolve a label to an actual encryption key
    fn resolve_label(&self, label: &str) -> Result<Option<&EcdsaKeyPair>>;
    
    /// Get available labels in current context
    fn available_labels(&self) -> Vec<String>;
    
    /// Check if a label can be resolved
    fn can_resolve(&self, label: &str) -> bool;
}
// FEDDBACK we shuiold not have this... once u mapped from label system, user etc.., to the actual public key (which is what the mapping will have)
// then all intractions iwth the key store shold bne usign teh public key.. which is the uniquye identifieer of any key.. and then i will be able to either decrupt or encrupt for that key (if it has the key internally)
//we dont want keus leavein the key store evern.. the key store profgie encruypte methods that can be used with a keu identifier..
// Examples:
//
// let envelope_2 = mobile
//         .encrypt_with_envelope(test_data_2, &network_id, vec!["personal".to_string()])
//         .expect("Mobile failed to encrypt data after restoration");
// and
// Node should be able to decrypt with the network key
    // let decrypted_by_node_2 = node_hydrated
    //     .decrypt_envelope_data(&envelope_2)
    //     .expect("Hydrated node failed to decrypt envelope data");
pub struct ConfigurableKeyResolver {
    /// The mapping configuration
    config: KeyMappingConfig,
    /// Available user profile keys
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    /// Available network keys  
    network_keys: HashMap<String, EcdsaKeyPair>,
}

impl KeyResolver for ConfigurableKeyResolver {
    fn resolve_label(&self, label: &str) -> Result<Option<&EcdsaKeyPair>> {
        let key_id = self.config.label_mappings.get(label)
            .ok_or_else(|| anyhow!("Unknown label: {label}"))?;
            
        match key_id {
            KeyIdentifier::UserProfile(profile_id) => {
                Ok(self.user_profile_keys.get(profile_id))
            },
            KeyIdentifier::Network(network_id) => {
                Ok(self.network_keys.get(network_id))
            },
        }
    }
    
    fn available_labels(&self) -> Vec<String> {
        self.config.label_mappings.keys().cloned().collect()
    }
    
    fn can_resolve(&self, label: &str) -> bool {
        self.resolve_label(label).map(|k| k.is_some()).unwrap_or(false)
    }
}
```

## Integration with ArcValue Serialization

### Current Flow
```
Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → bincode → bytes
```

### Enhanced Flow with Encryption
```
Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → EncryptedStruct → bytes
```

**Key Principle**: Encryption happens **during serialization** in the SerializerRegistry, not when creating the ArcValue. When a struct is wrapped in ArcValue, nothing happens - it remains as-is for zero-copy operations. Only when serialization is called does encryption occur.

### Zero-Copy Local Operations

```rust
// Creating ArcValue - NO encryption happens
let profile = Profile { /* ... */ };
let arc_value = ArcValue::from_struct(profile);  // Zero-copy, plaintext

// Serialization - encryption happens HERE if struct has encryption traits
let bytes = registry.serialize_value(&arc_value)?;  // Encryption occurs during serialization
```

## Technical Design

### 1. Label-Grouped Encryption Container

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedLabelGroup {
    /// The label this group was encrypted with
    pub label: String,
    /// Encrypted data payload containing all fields for this label
    pub data: Vec<u8>,
    /// Encryption metadata (algorithm, nonce, etc.)
    pub metadata: EncryptionMetadata,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionMetadata {
    pub algorithm: String,      // "AES-GCM-256"
    pub nonce: Vec<u8>,        // 12 bytes for AES-GCM
    pub key_derivation: String, // "ECIES-P256"
    /// Envelope key encrypted for this label
    pub encrypted_envelope_key: Vec<u8>,
}

impl EncryptedLabelGroup {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
```

### 2. Derive Macro Implementation

```rust
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Field, Meta, NestedMeta};

#[proc_macro_derive(Encrypt, attributes(runar))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let encrypted_name = format_ident!("Encrypted{}", struct_name);
    
    let (encrypted_fields, encrypt_impl, decrypt_impl) = process_fields(&input);
    
    let expanded = quote! {
        #[derive(Serialize, Deserialize, Debug, Clone)]
        pub struct #encrypted_name {
            #(#encrypted_fields),*
        }
        
        impl RunarEncrypt for #struct_name {
            type Encrypted = #encrypted_name;
            
            fn encrypt_with_resolver(&self, resolver: &dyn KeyResolver) -> Result<Self::Encrypted> {
                #encrypt_impl
            }
        }
        
        impl RunarDecrypt for #encrypted_name {
            type Decrypted = #struct_name;
            
            fn decrypt_with_resolver(&self, resolver: &dyn KeyResolver) -> Result<Self::Decrypted> {
                #decrypt_impl
            }
        }
    };
    
    TokenStream::from(expanded)
}
```

### 3. Generated Struct Transformation

For the Profile example, the macro generates:

```rust
// Generated substruct for user-labeled fields
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileUserFields {
    pub name: String,
    pub age: i32,
    pub email: String,
    pub phone: String,
    pub address: String,
}

// Generated substruct for system-labeled fields  
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileSystemFields {
    pub age: i32,
    pub email: String,
}

// Main encrypted struct with label groups
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedProfile {
    // Plaintext fields (no encryption labels)
    pub id: String,
    pub created_at: u64,
    pub version: String,
    
    // Encrypted label groups
    pub user_encrypted: Option<EncryptedLabelGroup>,
    pub system_encrypted: Option<EncryptedLabelGroup>,
}
```

### 4. Grouped Encryption Implementation

```rust
impl RunarEncrypt for Profile {
    type Encrypted = EncryptedProfile;
    
    fn encrypt_with_resolver(&self, resolver: &dyn KeyResolver) -> Result<Self::Encrypted> {
        // Copy plaintext fields as-is
        let mut encrypted = EncryptedProfile {
            id: self.id.clone(),
            created_at: self.created_at,
            version: self.version.clone(),
            user_encrypted: None,
            system_encrypted: None,
        };
        
        // Encrypt user-labeled fields as a group
        if resolver.can_resolve("user") {
            let user_fields = ProfileUserFields {
                name: self.name.clone(),
                age: self.age,
                email: self.email.clone(),
                phone: self.phone.clone(),
                address: self.address.clone(),
            };
            encrypted.user_encrypted = Some(
                encrypt_label_group("user", &user_fields, resolver)?
            );
        }
        
        // Encrypt system-labeled fields as a group
        if resolver.can_resolve("system") {
            let system_fields = ProfileSystemFields {
                age: self.age,
                email: self.email.clone(),
            };
            encrypted.system_encrypted = Some(
                encrypt_label_group("system", &system_fields, resolver)?
            );
        }
        
        Ok(encrypted)
    }
}
```

### 5. Context-Aware Group Decryption

```rust
impl RunarDecrypt for EncryptedProfile {
    type Decrypted = Profile;
    
    fn decrypt_with_resolver(&self, resolver: &dyn KeyResolver) -> Result<Self::Decrypted> {
        // Start with default values
        let mut profile = Profile {
            id: self.id.clone(),
            created_at: self.created_at,
            version: self.version.clone(),
            name: String::default(),
            age: 0,
            email: String::default(),
            phone: String::default(),
            address: String::default(),
        };
        
        // Try to decrypt system fields first (network keys)
        if let Some(ref system_encrypted) = self.system_encrypted {
            if let Ok(system_fields) = decrypt_label_group::<ProfileSystemFields>(system_encrypted, resolver) {
                profile.age = system_fields.age;
                profile.email = system_fields.email;
            }
        }
        
        // Try to decrypt user fields second (user profile keys take precedence)
        if let Some(ref user_encrypted) = self.user_encrypted {
            if let Ok(user_fields) = decrypt_label_group::<ProfileUserFields>(user_encrypted, resolver) {
                profile.name = user_fields.name;
                profile.age = user_fields.age;      // Override system value
                profile.email = user_fields.email;  // Override system value
                profile.phone = user_fields.phone;
                profile.address = user_fields.address;
            }
        }
        
        Ok(profile)
    }
}

fn decrypt_label_group<T: for<'de> Deserialize<'de>>(
    encrypted_group: &EncryptedLabelGroup,
    resolver: &dyn KeyResolver,
) -> Result<T> {
    if encrypted_group.is_empty() {
        return Err(anyhow!("Empty encrypted group"));
    }
    
    // Resolve label to actual key
    let key = resolver.resolve_label(&encrypted_group.label)?
        .ok_or_else(|| anyhow!("Label '{}' not available in current context", encrypted_group.label))?;
    
    // Decrypt envelope key using ECIES
    let envelope_key = decrypt_key_with_ecies(&encrypted_group.metadata.encrypted_envelope_key, key)?;
    
    // Decrypt data using AES-GCM
    let plaintext = decrypt_with_aes_gcm(
        &encrypted_group.data,
        &encrypted_group.metadata.nonce,
        &envelope_key
    )?;
    
    // Deserialize the entire fields struct
    let fields_struct: T = bincode::deserialize(&plaintext)?;
    Ok(fields_struct)
}
```

### 6. Label Group Encryption Function

```rust
fn encrypt_label_group<T: Serialize>(
    label: &str,
    fields_struct: &T,
    resolver: &dyn KeyResolver,
) -> Result<EncryptedLabelGroup> {
    // Serialize all fields in this label group
    let plaintext = bincode::serialize(fields_struct)?;
    
    // Generate ephemeral envelope key for this label group
    let envelope_key = generate_envelope_key()?;
    
    // Encrypt data with envelope key
    let (encrypted_data, nonce) = encrypt_with_aes_gcm(&plaintext, &envelope_key)?;
    
    // Resolve label to actual key and encrypt the envelope key
    let key = resolver.resolve_label(label)?
        .ok_or_else(|| anyhow!("Label '{label}' not available in current context"))?;
    
    let encrypted_envelope_key = encrypt_key_with_ecies(&envelope_key, &key.public_key_bytes())?;
    
    // Store metadata for this label group
    let metadata = EncryptionMetadata {
        algorithm: "AES-GCM-256".to_string(),
        nonce,
        key_derivation: "ECIES-P256".to_string(),
        encrypted_envelope_key,
    };
    
    Ok(EncryptedLabelGroup {
        label: label.to_string(),
        data: encrypted_data,
        metadata,
    })
}

fn generate_envelope_key() -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut envelope_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut envelope_key);
    Ok(envelope_key.to_vec())
}
```

## Integration with ArcValue

### Simplified SerializerRegistry

```rust
pub struct SerializerRegistry {
    serializers: HashMap<String, Box<dyn SerializerFn>>,
    deserializers: HashMap<String, DeserializerFnWrapper>,
    /// Key manager for encryption/decryption operations
    key_manager: Option<Arc<dyn KeyResolver>>,
}

impl SerializerRegistry {
    pub fn with_key_manager(
        logger: Arc<Logger>,
        key_manager: Arc<dyn KeyResolver>,
    ) -> Self {
        Self {
            serializers: HashMap::new(),
            deserializers: HashMap::new(),
            key_manager: Some(key_manager),
        }
    }
    
    /// Register an encryptable type - always encrypts if annotated with macros
    pub fn register_encryptable<T>(&mut self) -> Result<()>
    where
        T: 'static + RunarEncrypt + RunarDecrypt + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
        T::Encrypted: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        let type_name = std::any::type_name::<T>();
        
        // Register serializer that always encrypts
        let key_manager = self.key_manager.clone();
        
        self.serializers.insert(
            type_name.to_string(),
            Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    if let Some(ref resolver) = key_manager {
                        // Always encrypt if object has encryption traits
                        let encrypted = typed_value.encrypt_with_resolver(resolver.as_ref())?;
                        bincode::serialize(&encrypted)
                            .map_err(|e| anyhow!("Encryption serialization error: {e}"))
                    } else {
                        // No key manager - serialize as plaintext with warning
                        log_warn!("No key manager available for encryption, serializing as plaintext");
                        bincode::serialize(typed_value)
                            .map_err(|e| anyhow!("Plaintext serialization error: {e}"))
                    }
                } else {
                    Err(anyhow!("Type mismatch during serialization"))
                }
            }),
        );
        
        // Register deserializer that handles both encrypted and plaintext
        let deserializer = DeserializerFnWrapper::new({
            let key_manager = self.key_manager.clone();
            move |bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                // Try encrypted format first, fallback to plaintext
                if let Ok(encrypted) = bincode::deserialize::<T::Encrypted>(bytes) {
                    if let Some(ref resolver) = key_manager {
                        let decrypted = encrypted.decrypt_with_resolver(resolver.as_ref())?;
                        Ok(Box::new(decrypted))
                    } else {
                        Err(anyhow!("Encrypted data received but no key manager available"))
                    }
                } else {
                    // Fallback to plaintext deserialization
                    let plaintext: T = bincode::deserialize(bytes)?;
                    Ok(Box::new(plaintext))
                }
            }
        });
        
        self.deserializers.insert(type_name.to_string(), deserializer);
        
        Ok(())
    }
    
    /// Register a regular type without encryption
    pub fn register<T>(&mut self) -> Result<()>
    where
        T: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        let type_name = std::any::type_name::<T>();
        
        // Regular serializer
        self.serializers.insert(
            type_name.to_string(),
            Box::new(|value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    bincode::serialize(typed_value)
                        .map_err(|e| anyhow!("Serialization error: {e}"))
                } else {
                    Err(anyhow!("Type mismatch during serialization"))
                }
            }),
        );
        
        // Regular deserializer
        let deserializer = DeserializerFnWrapper::new(|bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
            let value: T = bincode::deserialize(bytes)?;
            Ok(Box::new(value))
        });
        
        self.deserializers.insert(type_name.to_string(), deserializer);
        
        Ok(())
    }
}
```

## Phase 1 Implementation Plan

Focus on macros and SerializerRegistry for end-to-end testing:

### Test Setup

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end_encryption() {
        // Define test structs
        #[derive(Encrypt, Decrypt, Serialize, Deserialize, Debug, PartialEq)]
        struct TestProfile {
            pub id: String,
            #[runar(user)]
            pub name: String,
            #[runar(user, system)]
            pub email: String,
            #[runar(system)]
            pub admin_notes: String,
            pub created_at: u64,
        }
        
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct PlainData {
            pub value: String,
            pub count: u32,
        }
        
        // Create mobile key resolver (has both user and system keys)
        let mobile_config = KeyMappingConfig {
            label_mappings: HashMap::from([
                ("user".to_string(), KeyIdentifier::UserProfile("personal".to_string())),
                ("system".to_string(), KeyIdentifier::Network("network_123".to_string())),
            ])
        };
        
        let mut mobile_resolver = ConfigurableKeyResolver::new(mobile_config);
        // Add actual keys from runar-keys...
        
        // Create node key resolver (has only system keys)
        let node_config = KeyMappingConfig {
            label_mappings: HashMap::from([
                ("system".to_string(), KeyIdentifier::Network("network_123".to_string())),
            ])
        };
        
        let mut node_resolver = ConfigurableKeyResolver::new(node_config);
        // Add actual keys from runar-keys...
        
        // Create SerializerRegistry instances
        let mut mobile_registry = SerializerRegistry::with_key_manager(
            logger.clone(),
            Arc::new(mobile_resolver),
        );
        //Feedback.. not sure we need seaprate register and register_encryptable
        //what about the macro add a trait to the object.. so we can detect when we need
        // so we dont need this distinction ? if that is unime overhead.. then is fine to have 2
        //methds sicne thery wil also be genraete by macros.. so most of the time the dev
        //wil not do thisby hand.
        mobile_registry.register_encryptable::<TestProfile>()?;
        mobile_registry.register::<PlainData>()?;
        
        let mut node_registry = SerializerRegistry::with_key_manager(
            logger.clone(),
            Arc::new(node_resolver),
        );
        node_registry.register_encryptable::<TestProfile>()?;
        node_registry.register::<PlainData>()?;
        
        // Test data
        let profile = TestProfile {
            id: "user123".to_string(),
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
            admin_notes: "VIP user".to_string(),
            created_at: 1234567890,
        };
        
        let plain_data = PlainData {
            value: "test".to_string(),
            count: 42,
        };
        
        // Test 1: Mobile serialization (should encrypt)
        let mobile_arc = ArcValue::from_struct(profile.clone());
        let mobile_bytes = mobile_registry.serialize_value(&mobile_arc)?;
        
        // Test 2: Mobile deserialization (should get all data)
        let mobile_deserialized = mobile_registry.deserialize_value(&mobile_bytes)?;
        let mobile_profile = mobile_deserialized.as_struct_ref::<TestProfile>()?;
        assert_eq!(mobile_profile, &profile);
        
        // Test 3: Node deserialization (should only get system data)
        let node_deserialized = node_registry.deserialize_value(&mobile_bytes)?;
        let node_profile = node_deserialized.as_struct_ref::<TestProfile>()?;
        
        assert_eq!(node_profile.id, "user123");           // Plaintext
        assert_eq!(node_profile.name, "");                // Empty - no user key
        assert_eq!(node_profile.email, "alice@example.com"); // Decrypted - has system key
        assert_eq!(node_profile.admin_notes, "VIP user"); // Decrypted - has system key
        assert_eq!(node_profile.created_at, 1234567890);  // Plaintext
        
        // Test 4: Plain data should work normally
        let plain_arc = ArcValue::from_struct(plain_data.clone());
        let plain_bytes = mobile_registry.serialize_value(&plain_arc)?;
        let plain_deserialized = node_registry.deserialize_value(&plain_bytes)?;
        let plain_result = plain_deserialized.as_struct_ref::<PlainData>()?;
        assert_eq!(plain_result, &plain_data);
    }
}
```

### Implementation Steps

1. **Create derive macros** (`Encrypt`, `Decrypt`) that generate:
   - Label-specific substruct types (e.g., `ProfileUserFields`, `ProfileSystemFields`)
   - Main encrypted struct (e.g., `EncryptedProfile`)
   - `RunarEncrypt` and `RunarDecrypt` trait implementations

2. **Implement encryption primitives**:
   - `encrypt_label_group()` function
   - `decrypt_label_group()` function
   - `generate_envelope_key()` helper
   - Integration with existing runar-keys ECIES/AES-GCM functions

3. **Extend SerializerRegistry**:
   - Add `key_manager` field
   - Implement `register_encryptable<T>()` method
   - Update serializers to always encrypt when traits are present
   - Update deserializers to handle both encrypted and plaintext formats

4. **Create test suite**:
   - Test mobile→node data flow with partial decryption
   - Test plain structs work unchanged
   - Test graceful degradation when keys are missing
   - Performance benchmarks vs per-field encryption

## Conclusion

This refined design focuses purely on the core primitives needed for selective field encryption:

### Key Benefits

1. **Simple Rule**: If annotated with macros, always encrypt during serialization
2. **Zero-Copy Local Operations**: ArcValue creation has no encryption overhead
3. **Isolated Testing**: Can develop and test primitives without node integration
4. **Label-Grouped Efficiency**: Single crypto operation per access level
5. **Graceful Degradation**: Services decrypt only data they have keys for
6. **Leverages Existing Infrastructure**: Built on top of proven runar-keys system

### Development Approach

Similar to how we developed runar-keys, this allows us to:
- Test encryption primitives in isolation
- Validate the label-grouping approach
- Benchmark performance improvements
- Ensure compatibility with ArcValue serialization
- Build confidence before node integration

The design eliminates all the complexity around policies, storage, and node integration that was confusing the scope, focusing purely on the macro system and SerializerRegistry integration that forms the foundation for selective field encryption.
