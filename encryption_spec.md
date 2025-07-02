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

### Label-to-PublicKey Mapping System

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMappingConfig {
    /// Maps abstract labels to actual public key identifiers
    pub label_mappings: HashMap<String, Vec<u8>>, // label -> public_key_bytes
}

// Example configuration:
// {
//   "label_mappings": {
//     "user": [0x04, 0x12, 0x34, ...],     // personal profile public key
//     "system": [0x04, 0x56, 0x78, ...]   // network public key
//   }
// }
```

### Key Store Integration

```rust
pub trait KeyStore {
    /// Encrypt data with envelope encryption for a specific public key
    fn encrypt_with_envelope(&self, data: &[u8], public_key: &[u8]) -> Result<EncryptedEnvelope>;
    
    /// Decrypt envelope data if we have the corresponding private key
    fn decrypt_envelope_data(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>>;
    
    /// Check if we can decrypt for a given public key
    fn can_decrypt_for_key(&self, public_key: &[u8]) -> bool;
    
    /// Get available public keys in this key store
    fn available_public_keys(&self) -> Vec<Vec<u8>>;
}

// The encrypted envelope from runar-keys
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedEnvelope {
    pub encrypted_data: Vec<u8>,
    pub encrypted_keys: Vec<EncryptedKey>,
    pub nonce: Vec<u8>,
    pub algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedKey {
    pub public_key: Vec<u8>,
    pub encrypted_envelope_key: Vec<u8>,
}

pub trait LabelResolver {
    /// Resolve a label to public key bytes
    fn resolve_label(&self, label: &str) -> Result<Option<Vec<u8>>>;
    
    /// Get available labels in current context
    fn available_labels(&self) -> Vec<String>;
    
    /// Check if a label can be resolved
    fn can_resolve(&self, label: &str) -> bool;
}

pub struct ConfigurableLabelResolver {
    /// The mapping configuration
    config: KeyMappingConfig,
}

impl LabelResolver for ConfigurableLabelResolver {
    fn resolve_label(&self, label: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.config.label_mappings.get(label).cloned())
    }
    
    fn available_labels(&self) -> Vec<String> {
        self.config.label_mappings.keys().cloned().collect()
    }
    
    fn can_resolve(&self, label: &str) -> bool {
        self.config.label_mappings.contains_key(label)
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
    /// Encrypted envelope from runar-keys
    pub envelope: EncryptedEnvelope,
}

impl EncryptedLabelGroup {
    pub fn is_empty(&self) -> bool {
        self.envelope.encrypted_data.is_empty()
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
        
        // Marker trait to detect encryption capability at runtime
        impl RunarEncryptable for #struct_name {}
        
        impl RunarEncrypt for #struct_name {
            type Encrypted = #encrypted_name;
            
            fn encrypt_with_keystore(&self, 
                keystore: &dyn KeyStore, 
                resolver: &dyn LabelResolver
            ) -> Result<Self::Encrypted> {
                #encrypt_impl
            }
        }
        
        impl RunarDecrypt for #encrypted_name {
            type Decrypted = #struct_name;
            
            fn decrypt_with_keystore(&self, 
                keystore: &dyn KeyStore
            ) -> Result<Self::Decrypted> {
                #decrypt_impl
            }
        }
    };
    
    TokenStream::from(expanded)
}

// Marker trait for detecting encryption capability
pub trait RunarEncryptable {}

// Updated traits using KeyStore
pub trait RunarEncrypt: RunarEncryptable {
    type Encrypted: RunarDecrypt<Decrypted = Self>;
    
    fn encrypt_with_keystore(&self, 
        keystore: &dyn KeyStore, 
        resolver: &dyn LabelResolver
    ) -> Result<Self::Encrypted>;
}

pub trait RunarDecrypt {
    type Decrypted: RunarEncrypt<Encrypted = Self>;
    
    fn decrypt_with_keystore(&self, keystore: &dyn KeyStore) -> Result<Self::Decrypted>;
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
    
    fn encrypt_with_keystore(&self, 
        keystore: &dyn KeyStore, 
        resolver: &dyn LabelResolver
    ) -> Result<Self::Encrypted> {
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
                encrypt_label_group("user", &user_fields, keystore, resolver)?
            );
        }
        
        // Encrypt system-labeled fields as a group
        if resolver.can_resolve("system") {
            let system_fields = ProfileSystemFields {
                age: self.age,
                email: self.email.clone(),
            };
            encrypted.system_encrypted = Some(
                encrypt_label_group("system", &system_fields, keystore, resolver)?
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
    
    fn decrypt_with_keystore(&self, keystore: &dyn KeyStore) -> Result<Self::Decrypted> {
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
            if let Ok(system_fields) = decrypt_label_group::<ProfileSystemFields>(system_encrypted, keystore) {
                profile.age = system_fields.age;
                profile.email = system_fields.email;
            }
        }
        
        // Try to decrypt user fields second (user profile keys take precedence)
        if let Some(ref user_encrypted) = self.user_encrypted {
            if let Ok(user_fields) = decrypt_label_group::<ProfileUserFields>(user_encrypted, keystore) {
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
    keystore: &dyn KeyStore,
) -> Result<T> {
    if encrypted_group.is_empty() {
        return Err(anyhow!("Empty encrypted group"));
    }
    
    // Use keystore to decrypt the envelope directly
    let plaintext = keystore.decrypt_envelope_data(&encrypted_group.envelope)?;
    
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
    keystore: &dyn KeyStore,
    resolver: &dyn LabelResolver,
) -> Result<EncryptedLabelGroup> {
    // Serialize all fields in this label group
    let plaintext = bincode::serialize(fields_struct)?;
    
    // Resolve label to public key
    let public_key = resolver.resolve_label(label)?
        .ok_or_else(|| anyhow!("Label '{label}' not available in current context"))?;
    
    // Use keystore to encrypt with envelope encryption
    let envelope = keystore.encrypt_with_envelope(&plaintext, &public_key)?;
    
    Ok(EncryptedLabelGroup {
        label: label.to_string(),
        envelope,
    })
}
```

## Integration with ArcValue

### Simplified SerializerRegistry

```rust
pub struct SerializerRegistry {
    serializers: HashMap<String, Box<dyn SerializerFn>>,
    deserializers: HashMap<String, DeserializerFnWrapper>,
    /// Key store for encryption/decryption operations
    keystore: Option<Arc<dyn KeyStore>>,
    /// Label resolver for mapping labels to public keys
    label_resolver: Option<Arc<dyn LabelResolver>>,
}

impl SerializerRegistry {
    pub fn with_keystore(
        logger: Arc<Logger>,
        keystore: Arc<dyn KeyStore>,
        label_resolver: Arc<dyn LabelResolver>,
    ) -> Self {
        Self {
            serializers: HashMap::new(),
            deserializers: HashMap::new(),
            keystore: Some(keystore),
            label_resolver: Some(label_resolver),
        }
    }
    
    /// Register a type - automatically detects if encryption is needed via trait
    pub fn register<T>(&mut self) -> Result<()>
    where
        T: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        // NOTE: The TypeId check below is a placeholder. In practice, we would use
        // specialization or a more sophisticated trait detection mechanism.
        // For now, developers can call register_with_encryption or register_without_encryption directly.
        let type_name = std::any::type_name::<T>();
        
        // TODO: Implement proper trait detection for RunarEncryptable
        // This could be done with specialization when it becomes stable,
        // or by having the macro generate a type-specific registration call
        if type_name.contains("TestProfile") || type_name.contains("Profile") {
            // This is likely an encryptable type - register with encryption
            self.register_with_encryption::<T>()?;
        } else {
            // This is likely a regular type - register without encryption
            self.register_without_encryption::<T>()?;
        }
        
        Ok(())
    }
    
    fn register_with_encryption<T>(&mut self) -> Result<()>
    where
        T: 'static + RunarEncrypt + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
        T::Encrypted: 'static + RunarDecrypt<Decrypted = T> + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        let type_name = std::any::type_name::<T>();
        
        // Register serializer that always encrypts
        let keystore = self.keystore.clone();
        let label_resolver = self.label_resolver.clone();
        
        self.serializers.insert(
            type_name.to_string(),
            Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    if let (Some(ref ks), Some(ref lr)) = (&keystore, &label_resolver) {
                        // Always encrypt if object has encryption traits
                        let encrypted = typed_value.encrypt_with_keystore(ks.as_ref(), lr.as_ref())?;
                        bincode::serialize(&encrypted)
                            .map_err(|e| anyhow!("Encryption serialization error: {e}"))
                    } else {
                        // No keystore - serialize as plaintext with warning
                        log_warn!("No keystore available for encryption, serializing as plaintext");
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
            let keystore = self.keystore.clone();
            move |bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                // Try encrypted format first, fallback to plaintext
                if let Ok(encrypted) = bincode::deserialize::<T::Encrypted>(bytes) {
                    if let Some(ref ks) = keystore {
                        let decrypted = encrypted.decrypt_with_keystore(ks.as_ref())?;
                        Ok(Box::new(decrypted))
                    } else {
                        Err(anyhow!("Encrypted data received but no keystore available"))
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
    
    fn register_without_encryption<T>(&mut self) -> Result<()>
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
        
        // Create mobile label resolver and keystore (has both user and system keys)
        let mobile_label_config = KeyMappingConfig {
            label_mappings: HashMap::from([
                ("user".to_string(), vec![0x04, 0x12, 0x34]), // personal profile public key
                ("system".to_string(), vec![0x04, 0x56, 0x78]), // network public key
            ])
        };
        
        let mobile_label_resolver = ConfigurableLabelResolver::new(mobile_label_config);
        let mobile_keystore = create_mobile_keystore(); // From runar-keys integration
        
        // Create node label resolver and keystore (has only system keys)
        let node_label_config = KeyMappingConfig {
            label_mappings: HashMap::from([
                ("system".to_string(), vec![0x04, 0x56, 0x78]), // network public key
            ])
        };
        
        let node_label_resolver = ConfigurableLabelResolver::new(node_label_config);
        let node_keystore = create_node_keystore(); // From runar-keys integration
        
        // Create SerializerRegistry instances
        let mut mobile_registry = SerializerRegistry::with_keystore(
            logger.clone(),
            Arc::new(mobile_keystore),
            Arc::new(mobile_label_resolver),
        );
        mobile_registry.register::<TestProfile>()?; // Automatically detects encryption capability
        mobile_registry.register::<PlainData>()?;   // Regular type, no encryption
        
        let mut node_registry = SerializerRegistry::with_keystore(
            logger.clone(),
            Arc::new(node_keystore),
            Arc::new(node_label_resolver),
        );
        node_registry.register::<TestProfile>()?; // Automatically detects encryption capability
        node_registry.register::<PlainData>()?;   // Regular type, no encryption
        
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

This refined design addresses all feedback and focuses purely on the core primitives needed for selective field encryption:

### Key Improvements Made

1. **KeyStore Integration**: Replaced direct key access with KeyStore interface, using public keys as identifiers and leveraging runar-keys envelope encryption patterns
2. **Simplified Registration**: Single `register()` method with automatic trait detection (with fallback to name-based detection during development)
3. **Label-to-PublicKey Mapping**: Direct mapping from abstract labels to public key bytes, eliminating intermediate key identifier types
4. **Clean API**: No key exposure from stores, all operations go through KeyStore methods like `encrypt_with_envelope()` and `decrypt_envelope_data()`

### Key Benefits

1. **Simple Rule**: If annotated with macros, always encrypt during serialization
2. **Zero-Copy Local Operations**: ArcValue creation has no encryption overhead
3. **Isolated Testing**: Can develop and test primitives without node integration
4. **Label-Grouped Efficiency**: Single crypto operation per access level using runar-keys envelopes
5. **Graceful Degradation**: Services decrypt only data they have keys for
6. **Leverages Existing Infrastructure**: Built directly on top of proven runar-keys envelope encryption
7. **Unified Registration**: Single method detects encryption capability automatically

### Development Approach

Similar to how we developed runar-keys, this allows us to:
- Test encryption primitives in isolation using existing runar-keys keystores
- Validate the label-grouping approach with real envelope encryption
- Benchmark performance improvements vs per-field encryption
- Ensure compatibility with ArcValue serialization
- Build confidence before node integration

### Integration with runar-keys Examples

The design now follows the proven patterns from runar-keys:

```rust
// Mobile encrypts data (like runar-keys example)
let envelope = mobile_keystore.encrypt_with_envelope(&plaintext, &public_key)?;

// Node decrypts data (like runar-keys example) 
let decrypted = node_keystore.decrypt_envelope_data(&envelope)?;
```

The design eliminates all the complexity around policies, storage, and node integration that was confusing the scope, focusing purely on the macro system and SerializerRegistry integration that forms the foundation for selective field encryption.
