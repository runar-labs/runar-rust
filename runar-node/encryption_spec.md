# Runar Selective Field Encryption Design

This document outlines the design for a Rust macro system that enables selective field encryption in structs, integrated with the existing ArcValue serialization flow and runar-keys system.

## Overview

The system provides declarative field-level encryption through derive macros, allowing structs to specify which fields should be encrypted with which key types. This enables selective data access across different contexts:

- **User Profile Keys**: Encrypt data that only the user's device can decrypt
- **Network Keys**: Encrypt data that services running in the same network can decrypt

When these structs cross network boundaries, encryption and decryption happen automatically based on available keys in each context.

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
//     "system": {"Network": "network_abc123"},
//     "admin": {"UserProfile": "admin_profile"}
//   }
// }
```

### Enhanced Key Resolution

```rust
pub trait KeyResolver {
    /// Resolve a label to an actual encryption key
    fn resolve_label(&self, label: &str) -> Result<Option<&EcdsaKeyPair>>;
    
    /// Get available labels in current context
    fn available_labels(&self) -> Vec<String>;
    
    /// Check if a label can be resolved
    fn can_resolve(&self, label: &str) -> bool;
}

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
            .ok_or_else(|| anyhow!("Unknown label: {}", label))?;
            
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

### Context-Specific Resolvers

Different services/networks can have different label mappings:

```rust
// Mobile app resolver (has user profile keys)
let mobile_config = KeyMappingConfig {
    label_mappings: HashMap::from([
        ("user".to_string(), KeyIdentifier::UserProfile("personal".to_string())),
        ("system".to_string(), KeyIdentifier::Network("home_network".to_string())),
    ])
};

// Backend service resolver (has network keys only)  
let backend_config = KeyMappingConfig {
    label_mappings: HashMap::from([
        ("system".to_string(), KeyIdentifier::Network("home_network".to_string())),
        ("audit".to_string(), KeyIdentifier::Network("audit_network".to_string())),
        // Note: no "user" mapping - backend can't decrypt user-only data
    ])
};

// Service resolver (has network keys for backend operations)
let service_config = KeyMappingConfig {
    label_mappings: HashMap::from([
        ("system".to_string(), KeyIdentifier::Network("home_network".to_string())),
        ("analytics".to_string(), KeyIdentifier::Network("analytics_network".to_string())),
    ])
};
```

## Integration with ArcValue Serialization

### Current Flow
```
Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → bincode → bytes
```

### Enhanced Flow with Encryption
```
Struct → EncryptedStruct → ArcValue::from_struct() → SerializerRegistry::serialize() → bytes
```

The encryption happens **before** ArcValue creation, maintaining compatibility with existing serialization.

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

For the Profile example, the macro generates label-specific substruct and containers:

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

The macro generates encryption logic that groups fields by label:

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

### 5. Label Group Encryption Function

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
        .ok_or_else(|| anyhow!("Label '{}' not available in current context", label))?;
    
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

### 6. Context-Aware Group Decryption

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
        
        // Try to decrypt user fields group
        if let Some(ref user_encrypted) = self.user_encrypted {
            if let Ok(user_fields) = decrypt_label_group::<ProfileUserFields>(user_encrypted, resolver) {
                profile.name = user_fields.name;
                profile.age = user_fields.age;
                profile.email = user_fields.email;
                profile.phone = user_fields.phone;
                profile.address = user_fields.address;
            }
        }
        
        // Try to decrypt system fields group (may override some fields from user group)
        if let Some(ref system_encrypted) = self.system_encrypted {
            if let Ok(system_fields) = decrypt_label_group::<ProfileSystemFields>(system_encrypted, resolver) {
                profile.age = system_fields.age;
                profile.email = system_fields.email;
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

## Integration with ArcValue

### 1. Enhanced SerializerRegistry

```rust
impl SerializerRegistry {
    /// Register an encryptable type with automatic encryption support
    pub fn register_encryptable<T>(&mut self, resolver: Arc<dyn KeyResolver>) -> Result<()>
    where
        T: 'static + RunarEncrypt + RunarDecrypt + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
        T::Encrypted: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        let type_name = std::any::type_name::<T>();
        
        // Register custom serializer that encrypts before serialization
        self.serializers.insert(
            type_name.to_string(),
            Box::new(move |value: &dyn Any| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    let encrypted = typed_value.encrypt_with_resolver(resolver.as_ref())?;
                    bincode::serialize(&encrypted)
                        .map_err(|e| anyhow!("Encryption serialization error: {}", e))
                } else {
                    Err(anyhow!("Type mismatch during encryption serialization"))
                }
            }),
        );
        
        // Register custom deserializer that decrypts after deserialization
        let deserializer = DeserializerFnWrapper::new({
            let resolver = resolver.clone();
            move |bytes: &[u8]| -> Result<Box<dyn Any + Send + Sync>> {
                let encrypted: T::Encrypted = bincode::deserialize(bytes)?;
                let decrypted = encrypted.decrypt_with_resolver(resolver.as_ref())?;
                Ok(Box::new(decrypted))
            }
        });
        
        self.deserializers.insert(type_name.to_string(), deserializer);
        
        Ok(())
    }
}
```

### 2. Usage in Node Setup

```rust
// In node initialization
let mut registry = SerializerRegistry::with_defaults(logger.clone());

// Create key resolver with available keys
let key_resolver = NodeKeyResolver::new(node_key_manager);

// Register encryptable types
registry.register_encryptable::<Profile>(Arc::new(key_resolver))?;
registry.register::<User>()?;  // Regular types still work

// Use with ArcValue
let profile = Profile {
    id: "user123".to_string(),
    name: "John Doe".to_string(),
    email: "john@example.com".to_string(),
    age: 30,
    phone: "+1234567890".to_string(),
    address: "123 Main St".to_string(),
    created_at: 1234567890,
    version: "1.0".to_string(),
};

// When this gets serialized (e.g., for network transmission),
// encryption happens automatically
let arc_value = ArcValue::from_struct(profile);
let serialized = registry.serialize_value(&arc_value)?;

// When deserialized, decryption happens automatically
let deserialized = registry.deserialize_value(serialized)?;
let profile_ref = deserialized.as_struct_ref::<Profile>()?;
```

## Configuration Examples

### Service Configuration Files

Each service/context defines its own label-to-key mapping:

#### Mobile App Configuration
```json
{
  "encryption": {
    "label_mappings": {
      "user": {"UserProfile": "personal"},
      "work": {"UserProfile": "work_profile"},
      "system": {"Network": "home_network_abc123"},
      "backup": {"UserProfile": "backup_profile"}
    }
  }
}
```

#### Backend Service Configuration  
```json
{
  "encryption": {
    "label_mappings": {
      "system": {"Network": "home_network_abc123"},
      "audit": {"Network": "audit_network_def456"},
      "analytics": {"Network": "analytics_network_ghi789"}
    }
  }
}
```

#### Service Configuration
```json
{
  "encryption": {
    "label_mappings": {
      "system": {"Network": "home_network_abc123"},
      "audit": {"Network": "audit_network_def456"},
      "analytics": {"Network": "analytics_network_ghi789"}
    }
  }
}
```

### Dynamic Configuration Loading

```rust
impl ConfigurableKeyResolver {
    /// Load configuration from file or environment
    pub fn from_config_file(
        config_path: &Path,
        mobile_key_manager: Option<&MobileKeyManager>,
        service_key_manager: Option<&ServiceKeyManager>,
    ) -> Result<Self> {
        let config_data = std::fs::read_to_string(config_path)?;
        let config: KeyMappingConfig = serde_json::from_str(&config_data)?;
        
        let mut resolver = Self {
            config,
            user_profile_keys: HashMap::new(),
            network_keys: HashMap::new(),
        };
        
        // Populate available keys based on context
        if let Some(mobile) = mobile_key_manager {
            resolver.load_from_mobile(mobile)?;
        }
        
        if let Some(service) = service_key_manager {
            resolver.load_from_service(service)?;
        }
        
        Ok(resolver)
    }
    
    fn load_from_mobile(&mut self, mobile: &MobileKeyManager) -> Result<()> {
        // Load user profile keys
        for profile_id in mobile.get_profile_ids() {
            if let Some(key) = mobile.get_profile_key(&profile_id) {
                self.user_profile_keys.insert(profile_id, key.clone());
            }
        }
        
        // Load network keys
        for network_id in mobile.get_network_ids() {
            if let Some(key) = mobile.get_network_key(&network_id) {
                self.network_keys.insert(network_id, key.clone());
            }
        }
        
        Ok(())
    }
    
    fn load_from_service(&mut self, service: &ServiceKeyManager) -> Result<()> {
        // Load network keys available to this service
        for network_id in service.get_available_networks() {
            if let Some(key) = service.get_network_key(&network_id) {
                self.network_keys.insert(network_id, key.clone());
            }
        }
        
        Ok(())
    }
}
```

## Data Flow Examples

### Same Struct, Different Contexts

Given this struct:
```rust
#[derive(Encrypt, Decrypt, Serialize, Deserialize)]
struct UserProfile {
    pub id: String,
    #[runar(user)]
    pub name: String,
    #[runar(user, system)]
    pub email: String,
    #[runar(system)]
    pub last_login: u64,
}
```

#### Mobile App Context
**Configuration**: `user` → `personal_profile`, `system` → `home_network`

```rust
let profile = UserProfile {
    id: "user123".to_string(),
    name: "Alice".to_string(),
    email: "alice@example.com".to_string(),
    last_login: 1234567890,
};

// Mobile can encrypt all fields (has both user and system keys)
let encrypted = profile.encrypt_with_resolver(&mobile_resolver)?;
// Serialization: name→personal_profile, email→personal_profile+home_network, last_login→home_network
```

#### Backend Service Context  
**Configuration**: `system` → `home_network` (no `user` mapping)

```rust
// Backend receives the encrypted data and deserializes
let decrypted: UserProfile = encrypted.decrypt_with_resolver(&backend_resolver)?;

// Backend can only decrypt system-labeled fields (as one efficient group)
assert_eq!(decrypted.id, "user123");           // Plaintext - always available
assert_eq!(decrypted.name, "");                // Empty - no user key 
assert_eq!(decrypted.email, "alice@example.com"); // Decrypted - has system key
assert_eq!(decrypted.last_login, 1234567890);  // Decrypted - has system key

// Note: Only ONE decryption operation happened for all system fields together
```

#### Another Service Context
**Configuration**: `system` → `home_network`, `analytics` → `analytics_network`

```rust
// Another service in the same network has same access as backend
let decrypted: UserProfile = encrypted.decrypt_with_resolver(&service_resolver)?;
assert_eq!(decrypted.name, "");                // Still empty - no user key
assert_eq!(decrypted.email, "alice@example.com"); // Decrypted - has system key
assert_eq!(decrypted.last_login, 1234567890);  // Decrypted - has system key
```

### Multi-Network Service Example

A service that operates across multiple networks:

```rust
#[derive(Encrypt, Decrypt, Serialize, Deserialize)]
struct CrossNetworkData {
    pub id: String,
    #[runar(user)]
    pub user_preference: String,
    #[runar(system)]
    pub home_network_data: String,
    #[runar(analytics)]
    pub analytics_data: String,
}

// Different services can decrypt different parts based on their network access
let data = CrossNetworkData {
    id: "data123".to_string(),
    user_preference: "dark_mode".to_string(),
    home_network_data: "home_sensor_reading".to_string(),
    analytics_data: "usage_metrics".to_string(),
};

// Mobile encrypts all fields
let encrypted = data.encrypt_with_resolver(&mobile_resolver)?;

// Analytics service can only decrypt analytics_data
let decrypted: CrossNetworkData = encrypted.decrypt_with_resolver(&analytics_resolver)?;
assert_eq!(decrypted.id, "data123");           // Plaintext
assert_eq!(decrypted.user_preference, "");     // Empty - no user key
assert_eq!(decrypted.home_network_data, "");   // Empty - no system key  
assert_eq!(decrypted.analytics_data, "usage_metrics"); // Decrypted - has analytics key
```

## Efficiency Benefits

### 1. Reduced Encryption Overhead
- **Single encryption per label** instead of per-field
- **Shared envelope keys** for all fields with same label
- **Bulk serialization** of related fields together

### 2. Optimized Metadata
- **One metadata struct per label** instead of per field
- **Single nonce and algorithm** per label group
- **Smaller serialized payload** with fewer redundant headers

### 3. Performance Improvements
- **Fewer crypto operations** (one AES-GCM + one ECIES per label)
- **Better CPU cache usage** with grouped field access
- **Reduced memory allocations** for metadata structures

## Security Properties

### 1. Key Separation
- **User data** encrypted with profile keys (mobile-only)
- **System data** encrypted with network keys (backend accessible)

### 2. Graceful Degradation
- Missing keys result in empty/default values, not errors
- Services receive only data they're authorized to decrypt
- Serialization format remains stable regardless of key availability

### 3. Forward Compatibility
- New encryption labels can be added without breaking existing code
- Label mappings can be updated without code changes
- Plaintext fields remain unaffected

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] `EncryptedField` and metadata structures
- [ ] Basic derive macros for single-schema encryption
- [ ] Integration with existing runar-keys ECIES/AES-GCM

### Phase 2: ArcValue Integration  
- [ ] Enhanced `SerializerRegistry` with encryption support
- [ ] `KeyResolver` trait and implementations
- [ ] Testing with mobile/node key managers

### Phase 3: Multi-Schema Support
- [ ] Envelope encryption with multiple recipients
- [ ] Context-aware decryption with graceful fallbacks
- [ ] Performance optimization and caching

### Phase 4: Advanced Features
- [ ] Schema migration support
- [ ] Field-level TTL and expiration
- [ ] Audit logging for encryption/decryption events

This design leverages the existing runar-keys infrastructure [[memory:6938732877054023747]] while providing a clean, declarative interface for selective field encryption that integrates seamlessly with the ArcValue serialization flow.

The label-grouped approach provides significant efficiency improvements over per-field encryption while maintaining the same declarative syntax and security properties.






Feedback:
Current Flow
Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → bincode → bytes

Enhanced Flow with Encryption
Struct → EncryptedStruct → ArcValue::from_struct() → SerializerRegistry::serialize() → bytes

Enhanced Flow with Encryption is not correct..

Enctypt6in8 shuold happen just before serialization.. when struct is wrapped in a ArcxValut at the momoent nothing shouold happen.;. that ArcValut mighe be send to another service or event handler in the same network/context and nothing shuold happen to the struct. itn shuold be as is. (zero copy or serialization) .. only when serialiazt is neece to cross the network.. that is when encrtuptm needs to happens.. so

Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → EncryptedStruct → bytes
