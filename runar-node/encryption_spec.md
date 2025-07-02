# Runar Selective Field Encryption Design

This document outlines the design for a Rust macro system that enables selective field encryption in structs, integrated with the existing ArcValue serialization flow and runar-keys system.

## Overview

The system provides declarative field-level encryption through derive macros, allowing structs to specify which fields should be encrypted with which key types. This enables selective data access across different contexts:

- **User Profile Keys**: Encrypt data that only the user's device can decrypt
- **Network Keys**: Encrypt data that services running in the same network can decrypt

Encryption happens **during serialization** when data crosses network boundaries or when explicitly required by storage annotations. Within the same network context, data remains in plaintext for zero-copy operations.

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

// Data storage action with encryption enforcement
#[derive(Action)]
struct StoreProfile {
    #[runar(always_encrypt)]  // Forces encryption even for local storage
    pub profile: Profile,
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

### **Corrected** Enhanced Flow with Encryption
```
Struct → ArcValue::from_struct() → SerializerRegistry::serialize() → EncryptedStruct → bytes
```

**Key Principle**: Encryption happens **just before serialization** in the SerializerRegistry, not when creating the ArcValue. When a struct is wrapped in ArcValue, nothing happens - it remains as-is for zero-copy operations when sending to services in the same network/context. Only when serialization is needed to cross the network (or for storage) should encryption occur.

### Zero-Copy Local Operations

```rust
// Creating ArcValue - NO encryption happens
let profile = Profile { /* ... */ };
let arc_value = ArcValue::from_struct(profile);  // Zero-copy, plaintext

// Local service call in same network - NO encryption
let result = local_service.process_profile(arc_value).await;  // Direct access

// Network call - encryption happens during serialization
let bytes = registry.serialize_value(&arc_value)?;  // Encryption occurs HERE
network.send(bytes).await;
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
        
    //Feedback.. sicne the last one overrrives. we shuold do network decruption fiest and user profile later. so it takes precedence..

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
pub struct SerializerRegistry {
    serializers: HashMap<String, Box<dyn SerializerFn>>,
    deserializers: HashMap<String, DeserializerFnWrapper>,
    /// Key manager for encryption/decryption operations
    key_manager: Option<Arc<dyn KeyResolver>>,
    /// Configuration for when to apply encryption
    encryption_policy: EncryptionPolicy,
}

// Feedback
//we dont need this object EncryptionPolicy
//the rule is simple.. during serialization if the object in question 
// has the proper traits e.g. was anotated with the macros.. then
//encryption and decruption will take place.. alwyas.. and we do not n eed a exetrnal policy like this
#[derive(Debug, Clone)]
pub struct EncryptionPolicy {
    /// Force encryption for network serialization
    pub encrypt_on_network: bool,
    /// Force encryption for storage operations
    pub encrypt_on_storage: bool,
    /// Services/actions that require encryption even locally
    pub force_encrypt_annotations: HashSet<String>,
}

impl SerializerRegistry {
    pub fn with_key_manager(
        logger: Arc<Logger>,
        key_manager: Arc<dyn KeyResolver>,
        policy: EncryptionPolicy,
    ) -> Self {
        Self {
            serializers: HashMap::new(),
            deserializers: HashMap::new(),
            key_manager: Some(key_manager),
            encryption_policy: policy,
        }
    }
    
    /// Register an encryptable type with context-aware encryption
    pub fn register_encryptable<T>(&mut self) -> Result<()>
    where
        T: 'static + RunarEncrypt + RunarDecrypt + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
        T::Encrypted: 'static + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync,
    {
        let type_name = std::any::type_name::<T>();
        
        // Register context-aware serializer
        let key_manager = self.key_manager.clone();
        let policy = self.encryption_policy.clone();
        
        self.serializers.insert(
            type_name.to_string(),
            Box::new(move |value: &dyn Any, context: &SerializationContext| -> Result<Vec<u8>> {
                if let Some(typed_value) = value.downcast_ref::<T>() {
                    //Feedback.. as mentioned befgore we dont have a poplicuy like this
                    //the check neede is the obojct anotated iwth our amcros.. ifg yes then alwaus encruypt.. adn alwau decrupt.. 
                    // Determine if encryption is needed based on context
                    let should_encrypt = match context.purpose {
                        SerializationPurpose::NetworkTransport => policy.encrypt_on_network,
                        SerializationPurpose::LocalStorage => policy.encrypt_on_storage,
                        SerializationPurpose::ForceEncrypt => true,
                        SerializationPurpose::LocalCall => false,
                    };
                    
                    if should_encrypt {
                        if let Some(ref resolver) = key_manager {
                            // Encrypt before serialization
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
                        // Local operation - serialize as plaintext
                        bincode::serialize(typed_value)
                            .map_err(|e| anyhow!("Plaintext serialization error: {e}"))
                    }
                } else {
                    Err(anyhow!("Type mismatch during serialization"))
                }
            }),
        );
        
        // Register context-aware deserializer
        let deserializer = DeserializerFnWrapper::new({
            let key_manager = self.key_manager.clone();
            move |bytes: &[u8], context: &DeserializationContext| -> Result<Box<dyn Any + Send + Sync>> {
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
}
//feedback
//we dont need this eithyer..
//we never need to do this distinicipo. again LocalStorage is compelte separte andwhols not feature anywhere in this DOC>> compelte remove any notion of LocalStorage from there to avoid this kiund of conffusion..
//if serializat is either for netowrk transpor ot local call is irrelegvant.. the bejhavioounri the same and we dont need anyd distinction..  currently a local call never calls the serializat
// so after thjis wors we will cahg tehe node flows to decided if for a local call it will cal lthe serialiat or not.. so this is a decisdion makde externaly. this design does notn eed to concert about it at all. the serialiat needs to be simples.. and alçwaus encruypt if the objecvt is anotated with our macros.
#[derive(Debug, Clone)]
pub enum SerializationPurpose {
    /// Data being sent over network to another node
    NetworkTransport,
    /// Data being stored locally (database, file system)
    LocalStorage,
    /// Forced encryption due to annotation (always_encrypt)
    ForceEncrypt,
    /// Local service call within same network context
    LocalCall,
}

#[derive(Debug, Clone)]
pub struct SerializationContext {
    pub purpose: SerializationPurpose,
    pub target_network: Option<String>,
    pub source_service: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeserializationContext {
    pub source_network: Option<String>,
    pub target_service: Option<String>,
}
```

## Data Storage Annotations and Enforcement

//Feedback.. we dont need this.. as mentioned in the previou s ffedback seciotyn. the confir got actions is external t this design.. here we shuold focus only in the serializart and macros... so we can test them in isolation..
//the actions will be done externalu at the node level..
### Storage Action Annotations

```rust
#[derive(Action, Serialize, Deserialize)]
struct StoreUserProfile {
    #[runar(always_encrypt)]  // Forces encryption even for local calls
    pub profile: Profile,
    pub metadata: String,     // Not encrypted
}

#[derive(Action, Serialize, Deserialize)]
struct GetUserProfile {
    pub user_id: String,
    #[runar(decrypt_on_return)]  // Ensures returned data is decrypted appropriately
    pub include_sensitive: bool,
}

// Generated macro implementation
impl RunarAction for StoreUserProfile {
    fn requires_encryption(&self) -> bool {
        true  // Generated based on always_encrypt annotation
    }
    
    fn encryption_context(&self) -> SerializationContext {
        SerializationContext {
            purpose: SerializationPurpose::ForceEncrypt,  // Due to annotation
            target_network: None,
            source_service: Some(env!("SERVICE_NAME").to_string()),
        }
    }
}
```

### Storage Service Configuration

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageServiceConfig {
    /// Always encrypt data when storing, even for local operations
    pub always_encrypt_storage: bool,
    /// Specific types that must always be encrypted
    pub force_encrypt_types: Vec<String>,
    /// Network contexts that require encryption
    pub encrypt_for_networks: Vec<String>,
}

// Example storage service configuration
let storage_config = StorageServiceConfig {
    always_encrypt_storage: true,  // All stored data encrypted
    force_encrypt_types: vec!["Profile".to_string(), "UserData".to_string()],
    encrypt_for_networks: vec!["external_network".to_string()],
};
```

## Data Flow Scenarios

### Scenario 1: Cross-Network Profile Transfer

```rust
// Mobile app creates profile
let profile = Profile {
    id: "user123".to_string(),
    name: "Alice".to_string(),           // user label
    email: "alice@example.com".to_string(), // user + system labels  
    age: 30,                             // user + system labels
    phone: "+1234567890".to_string(),    // user label
    address: "123 Main St".to_string(),  // user label
    created_at: 1234567890,              // plaintext
    version: "1.0".to_string(),          // plaintext
};

// Step 1: Create ArcValue (NO encryption)
let arc_value = ArcValue::from_struct(profile);

// Step 2: Send to backend service (encryption happens during serialization)
let network_context = SerializationContext {
    purpose: SerializationPurpose::NetworkTransport,
    target_network: Some("backend_network".to_string()),
    source_service: Some("mobile_app".to_string()),
};

let encrypted_bytes = registry.serialize_value_with_context(&arc_value, &network_context)?;
// At this point: name,phone,address→user_key, email,age→user_key+system_key, id,created_at,version→plaintext

// Step 3: Backend receives and deserializes
let backend_context = DeserializationContext {
    source_network: Some("mobile_network".to_string()),
    target_service: Some("backend_service".to_string()),
};

let received_value = registry.deserialize_value_with_context(&encrypted_bytes, &backend_context)?;
let backend_profile = received_value.as_struct_ref::<Profile>()?;

// Backend result (has system key, no user key):
assert_eq!(backend_profile.id, "user123");           // Plaintext - available
assert_eq!(backend_profile.name, "");                // Empty - no user key
assert_eq!(backend_profile.email, "alice@example.com"); // Decrypted - has system key
assert_eq!(backend_profile.age, 30);                 // Decrypted - has system key  
assert_eq!(backend_profile.phone, "");               // Empty - no user key
assert_eq!(backend_profile.address, "");             // Empty - no user key
assert_eq!(backend_profile.created_at, 1234567890);  // Plaintext - available
assert_eq!(backend_profile.version, "1.0");          // Plaintext - available
```

### Scenario 2: Local Storage with Forced Encryption

```rust
// Backend service stores profile (using storage action)
let store_action = StoreUserProfile {
    profile: backend_profile.clone(),  // Profile from previous scenario
    metadata: "stored_by_backend".to_string(),
};

// Step 1: Action marked with always_encrypt forces encryption context
let storage_context = SerializationContext {
    purpose: SerializationPurpose::ForceEncrypt,  // Due to always_encrypt annotation
    target_network: None,
    source_service: Some("backend_service".to_string()),
};

// Step 2: Serialize for storage (encryption applied even locally)
let storage_bytes = registry.serialize_value_with_context(&store_action, &storage_context)?;

// Step 3: Store encrypted data in database
database.store("profiles", "user123", storage_bytes).await?;

// The stored data contains:
// - profile.email, profile.age → encrypted with system key (backend has this)
// - profile.name, profile.phone, profile.address → remain empty (backend never had user key)
// - profile.id, profile.created_at, profile.version → plaintext
// - metadata → plaintext (no encryption annotation)
```

### Scenario 3: Service Retrieval and Re-encryption

```rust
// Later: Another service retrieves stored profile
let stored_bytes = database.get("profiles", "user123").await?;

// Step 1: Deserialize stored action
let retrieval_context = DeserializationContext {
    source_network: None,  // Local storage
    target_service: Some("analytics_service".to_string()),
};

let stored_action = registry.deserialize_value_with_context::<StoreUserProfile>(&stored_bytes, &retrieval_context)?;

// Step 2: Analytics service (has system key) can decrypt system fields
let analytics_profile = &stored_action.profile;
assert_eq!(analytics_profile.email, "alice@example.com"); // Decrypted - has system key
assert_eq!(analytics_profile.age, 30);                    // Decrypted - has system key
assert_eq!(analytics_profile.name, "");                   // Still empty - no user key

// Step 3: Send processed data to external analytics network
let external_context = SerializationContext {
    purpose: SerializationPurpose::NetworkTransport,
    target_network: Some("external_analytics".to_string()),
    source_service: Some("analytics_service".to_string()),
};

// Re-encryption happens with different key context for external network
let external_bytes = registry.serialize_value_with_context(&analytics_profile, &external_context)?;
```

### Scenario 4: Mobile Retrieval with Full Decryption

```rust
// Mobile app retrieves user's profile with full access
let mobile_context = DeserializationContext {
    source_network: Some("backend_network".to_string()),
    target_service: Some("mobile_app".to_string()),
};

// Mobile has both user and system keys
let mobile_profile = registry.deserialize_value_with_context::<Profile>(&network_bytes, &mobile_context)?;

// Mobile result (has both user and system keys):
assert_eq!(mobile_profile.id, "user123");
assert_eq!(mobile_profile.name, "Alice");               // Decrypted - has user key
assert_eq!(mobile_profile.email, "alice@example.com");  // Decrypted - has both keys
assert_eq!(mobile_profile.age, 30);                     // Decrypted - has both keys
assert_eq!(mobile_profile.phone, "+1234567890");        // Decrypted - has user key
assert_eq!(mobile_profile.address, "123 Main St");      // Decrypted - has user key
assert_eq!(mobile_profile.created_at, 1234567890);
assert_eq!(mobile_profile.version, "1.0");
```

## Configuration for Different Contexts

### Mobile App Context Configuration
```json
{
  "encryption": {
    "policy": {
      "encrypt_on_network": true,
      "encrypt_on_storage": true,
      "force_encrypt_annotations": ["always_encrypt", "user_sensitive"]
    },
    "label_mappings": {
      "user": {"UserProfile": "personal"},
      "system": {"Network": "home_network_abc123"}
    }
  }
}
```

### Backend Service Context Configuration  
```json
{
  "encryption": {
    "policy": {
      "encrypt_on_network": true,
      "encrypt_on_storage": true,
      "force_encrypt_annotations": ["always_encrypt", "audit_required"]
    },
    "label_mappings": {
      "system": {"Network": "home_network_abc123"},
      "audit": {"Network": "audit_network_def456"}
    }
  }
}
```

### Storage Service Context Configuration
```json
{
  "encryption": {
    "policy": {
      "encrypt_on_network": true,
      "encrypt_on_storage": true,
      "force_encrypt_annotations": ["always_encrypt"]
    },
    "label_mappings": {
      "system": {"Network": "home_network_abc123"},
      "storage": {"Network": "storage_network_ghi789"}
    }
  }
}
```

## Node Integration

### Updated Node Setup with Context-Aware Encryption

```rust
impl RunarNode {
    pub fn new_with_encryption(
        config: NodeConfig,
        key_manager: Arc<dyn KeyResolver>,
        encryption_policy: EncryptionPolicy,
    ) -> Result<Self> {
        let logger = create_logger(&config.logging);
        
        // Create SerializerRegistry with key manager and encryption policy
        let mut registry = SerializerRegistry::with_key_manager(
            logger.clone(),
            key_manager,
            encryption_policy,
        );
        
        // Register encryptable types
        registry.register_encryptable::<Profile>()?;
        registry.register_encryptable::<UserData>()?;
        
        // Regular types still work without encryption
        registry.register::<ServiceMetadata>()?;
        
        Ok(RunarNode {
            config,
            logger,
            registry: Arc::new(registry),
            // ... other fields
        })
    }
    
    /// Send data over network (triggers encryption during serialization)
    pub async fn send_to_network<T>(&self, data: T, target_network: &str) -> Result<()>
    where
        T: Serialize + Send + Sync + 'static,
    {
        let arc_value = ArcValue::from_struct(data);
        
        let context = SerializationContext {
            purpose: SerializationPurpose::NetworkTransport,
            target_network: Some(target_network.to_string()),
            source_service: Some(self.config.service_name.clone()),
        };
        
        let bytes = self.registry.serialize_value_with_context(&arc_value, &context)?;
        self.transport.send(target_network, bytes).await
    }
    
    /// Store data locally (may trigger encryption based on annotations)
    pub async fn store_local<T>(&self, key: &str, data: T) -> Result<()>
    where
        T: Serialize + Send + Sync + 'static + RunarAction,
    {
        let arc_value = ArcValue::from_struct(data);
        
        let context = if data.requires_encryption() {
            SerializationContext {
                purpose: SerializationPurpose::ForceEncrypt,
                target_network: None,
                source_service: Some(self.config.service_name.clone()),
            }
        } else {
            SerializationContext {
                purpose: SerializationPurpose::LocalStorage,
                target_network: None,
                source_service: Some(self.config.service_name.clone()),
            }
        };
        
        let bytes = self.registry.serialize_value_with_context(&arc_value, &context)?;
        self.storage.store(key, bytes).await
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

## Performance Characteristics

### Zero-Copy Local Operations
- **ArcValue creation**: No encryption overhead
- **Local service calls**: Direct memory access, no serialization
- **Same-network calls**: Minimal overhead with plaintext serialization

### Efficient Network Encryption  
- **Label-grouped encryption**: Single crypto operation per label
- **Shared envelope keys**: Bulk encryption of related fields
- **Context-aware**: Only encrypt when crossing network boundaries

### Smart Storage
- **Annotation-driven**: Encrypt only when explicitly required
- **Configurable policies**: Per-service encryption requirements
- **Graceful degradation**: Services receive only data they can decrypt

## Conclusion

Feedback on implemention plan

Phase 1 - Focus on macros and the SerializerRegistry .. so we can have a end to end test that:

define structs using teh macros and also plain structs 
create a SerializerRegistry and provide the key mnaqnager Arc refercence to it..
once  SerializerRegistry for the mobile side.. with a mobile key store
and one SerializerRegistry for the node side.. with a node key store
and we call the mobile SerializerRegistry to serialize the structs 
it shuold be encrypted as specicified.
 and if we decrypt iun the mobile side.. ew get all the data avialable..

 then we try to decrypt with on the node side.. which only has network keys.. and only tyhe data that is mapped to be decrypte with netowrk  is propoerly done so..

 this shows how data can gbe encrypted on the mobile side and only network shared data can be decrypted on th other side..  like we did for runar-keys. 
 
 This llaewds us to develop and test these primitives and dataflows in isolation .. to later we integrate into the node..