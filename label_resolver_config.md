# Label Resolver Configuration Design

## Executive Summary

This document provides a comprehensive analysis and design for making label resolvers config-driven while properly handling the separation between static system labels and dynamic user profile keys.

## Current Architecture Analysis

### Label Resolver Structure

The current label resolver system consists of:

1. **LabelResolver Trait** (`runar-serializer/src/traits.rs`)
   - Maps labels (strings) to `LabelKeyInfo`
   - `LabelKeyInfo` contains profile public keys and network ID
   - Used for envelope encryption/decryption

2. **ConfigurableLabelResolver** implementation
   - Uses DashMap for concurrent access
   - Thread-safe and performant for read-heavy workloads

3. **SerializationContext** (`runar-serializer/src/traits.rs`) - UPDATED
   ```rust
   pub struct SerializationContext {
       pub keystore: Arc<KeyStore>,
       pub resolver: Arc<dyn LabelResolver>, // Now contains embedded network keys
       // pub network_id: String, // REMOVED - now embedded in label resolver
       pub profile_public_keys: Vec<Vec<u8>>, // CHANGED: Multiple profile keys instead of single
   }
   ```

### Current Usage Patterns

#### 1. Node Startup (runar-node/src/node.rs:588-596)
```rust
let label_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
    label_mappings: HashMap::from([(
        "system".to_string(),
        LabelKeyInfo {
            profile_public_keys: vec![],
            network_id: Some(default_network_id.clone()),
        },
    )]),
}));
```

**Issues:**
- Hardcoded "system" label
- No config-driven approach
- Single resolver shared across all contexts

#### 2. Transport Layer Usage (runar-transporter/src/transport/quic_transport.rs)
- Label resolver passed to QUIC transport via `with_label_resolver()`
- Used for network-level encryption/decryption
- Stored as `Arc<dyn LabelResolver>` in transport instance

#### 3. Request Handling (runar-node/src/node.rs:1847-1852)
```rust
let serialization_context = SerializationContext {
    keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
    resolver: self.label_resolver.clone(), // Always the same resolver
    network_id,
    profile_public_key: Some(profile_public_key.clone()),
};
```

#### 4. Remote Service Usage (runar-node/src/services/remote_service.rs:233-238)
```rust
let serialization_context = SerializationContext {
    keystore: keystore.clone(),
    resolver: resolver.clone(), // Passed from node, never changes
    network_id,
    profile_public_key: Some(profile_public_key.clone()),
};
```

#### 5. Serializer Usage (runar-serializer/src/arc_value.rs:567-574)
```rust
if let Some(ctx) = context {
    let ks = &ctx.keystore;
    let network_id = &ctx.network_id;
    let profile_public_key = &ctx.profile_public_key;
    let resolver = &ctx.resolver; // Used for encryption

    let bytes = ser_fn(inner, Some(ks), Some(resolver.as_ref()))
}
```

## Dataflow Analysis

### Label Resolver Creation Flow
```
NodeConfig (static)
    ↓
Node::new() creates ConfigurableLabelResolver (hardcoded "system")
    ↓
Resolver passed to:
├── Transport (QuicTransport::with_label_resolver)
├── RemoteService creation (RemoteServiceDependencies.resolver)
└── All SerializationContext instances
```

### Request Processing Flow
```
Network Request → Node::handle_network_request()
    ↓
Extract profile_public_key from RequestMessage
    ↓
Create SerializationContext with:
├── keystore (node's keystore)
├── resolver (node's static resolver) ← ISSUE: never user-specific
├── network_id (from topic path)
└── profile_public_key (from request)
    ↓
ArcValue::serialize() uses resolver for encryption
```

### Remote Service Flow
```
RemoteService::create_action_handler()
    ↓
Extract profile_public_key from request_context
    ↓
Create SerializationContext with:
├── keystore (service's keystore)
├── resolver (service's static resolver) ← ISSUE: never user-specific
├── network_id (from topic path)
└── profile_public_key (from request)
    ↓
Send encrypted request via transport
```

## Problems Identified

### 1. Static vs Dynamic Label Confusion
- **System labels** ("system", "admin", etc.) are static and known at startup
- **User profile labels** are dynamic and context-specific
- Current implementation mixes both in a single resolver

### 2. No Config-Driven System Labels
- System label mappings are hardcoded in node.rs
- No way to configure different label mappings per deployment
- NodeConfig doesn't include label resolver configuration

### 3. Context-Unaware Label Resolution
- Same label resolver used for all users and contexts
- No way to resolve user-specific labels dynamically
- Profile public keys carried separately but not used for label resolution

### 4. Missing User Label Integration
- `SerializationContext.profile_public_key` is used for envelope encryption recipients
- But label resolver doesn't know about current user's profile keys
- No mechanism to resolve "current_user" or similar dynamic labels

## Proposed Design

### 1. NodeConfig Extension

Add label resolver configuration to NodeConfig:

```rust
pub struct NodeConfig {
    // ... existing fields ...

    /// REQUIRED: Label resolver configuration for system labels
    /// These are static mappings known at node startup
    /// NO OPTION - This field is REQUIRED for all nodes
    pub label_resolver_config: LabelResolverConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LabelResolverConfig {
    /// Static label mappings for system labels
    /// These are config-driven and known at startup
    /// Supports both direct network public keys and dynamic keywords
    pub label_mappings: HashMap<String, LabelValue>,
}



### 2. Dynamic Label Resolver Creation with Keyword System

Replace single static resolver with dynamic resolver creation supporting keywords:

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LabelValue {
    /// Optional network public key for this label
    /// If None, will inherit from default network key
    pub network_public_key: Option<Vec<u8>>,
    /// Optional user key specification for this label
    pub user_key_spec: Option<LabelKeyword>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LabelKeyInfo {
    /// Single network public key for this label
    pub network_public_key: Vec<u8>,
    /// Multiple profile public keys that can decrypt this label
    pub profile_public_keys: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LabelKeyword {
    /// Maps to current user's profile public keys from request context
    CurrentUser,
    /// Reserved for future custom resolution functions
    Custom(String), // Function name for custom resolution
}

/// Creates a label resolver for a specific context
/// REQUIRES: Every label must have an explicit network_public_key - no defaults allowed
fn create_context_label_resolver(
    system_config: &LabelResolverConfig,
    user_profile_keys: Option<&[Vec<u8>]>, // From request context
) -> Result<Arc<dyn LabelResolver>> {
    let mut mappings = HashMap::new();

    // Process system label mappings
    for (label, label_value) in &system_config.label_mappings {
        let mut profile_public_keys = Vec::new();

        // Get network key if specified, or use empty for user-only labels
        let network_public_key = label_value.network_public_key.clone()
            .unwrap_or_else(|| vec![]); // Empty key for user-only labels

        // Process user key specification
        match &label_value.user_key_spec {
            Some(LabelKeyword::CurrentUser) => {
                if let Some(user_keys) = user_profile_keys {
                    profile_public_keys.extend_from_slice(user_keys);
                }
                // Note: If no user keys in context, profile_public_keys remains empty
                // This allows user-only labels to be valid even in system contexts
            },
            Some(LabelKeyword::Custom(custom_name)) => {
                // Future: Call custom resolution function
                // For now, profile_public_keys remains empty
                // Custom resolver would populate profile_public_keys here
            },
            None => {
                // No user keys - profile_public_keys remains empty
            },
        }

        // Validation: Label must have either network key OR user keys OR both
        // Empty network key + empty profile keys = invalid label
        if network_public_key.is_empty() && profile_public_keys.is_empty() {
            return Err(anyhow!("Label '{}' must specify either network_public_key or user_key_spec (or both)", label));
        }

        mappings.insert(label.clone(), LabelKeyInfo {
            network_public_key,
            profile_public_keys,
        });
    }

    Ok(Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: mappings,
    })))
}
```

### 3. Context-Aware Serialization Context

Extend SerializationContext to support dynamic resolver creation:

```rust
impl SerializationContext {
    pub fn new_with_dynamic_resolver(
        keystore: Arc<KeyStore>,
        system_label_config: &LabelResolverConfig,
        // network_id: String, // REMOVED - now embedded in label resolver
        profile_public_keys: Vec<Vec<u8>>,
        user_profile_keys: Option<&[Vec<u8>]>
    ) -> Self {
        let resolver = create_context_label_resolver(
            system_label_config,
            user_profile_keys,
        );

        Self {
            keystore,
            resolver,
            // network_id, // REMOVED
            profile_public_keys,
        }
    }
}
```

### 4. Updated Node Architecture

#### Node Fields Update
```rust
pub struct Node {
    // ... existing fields ...

    /// System label configuration (config-driven)
    system_label_config: LabelResolverConfig,

    /// Removed: No legacy resolver - complete replacement only
}
```

#### Node Startup Changes
```rust
impl Node {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Load system label config from NodeConfig - REQUIRED
        let system_label_config = config.label_resolver_config; // No Option - required field

        // Validate label config contains required mappings
        validate_label_config(&system_label_config)?;

        // No legacy resolver creation - complete replacement

        // ... rest of node creation ...
    }
}
```

#### Request Context with User Profile Keys
```rust
#[derive(Clone)]
pub struct RequestContext {
    /// User profile public keys from request initiator
    /// Carried throughout the entire request chain (like JWT tokens)
    pub user_profile_public_keys: Option<Vec<Vec<u8>>>,

    /// Other context data...
    pub correlation_id: String,
    pub timeout_ms: u64,
}

#[derive(Clone)]
pub struct EventContext {
    /// User profile public keys from event initiator
    /// Carried throughout the entire event chain
    pub user_profile_public_keys: Option<Vec<Vec<u8>>>,

    /// Other context data...
    pub correlation_id: String,
    pub event_topic: String,
}

fn validate_label_config(config: &LabelResolverConfig) -> Result<()> {
    // Ensure config has required label mappings
    if config.label_mappings.is_empty() {
        return Err(anyhow!("LabelResolverConfig must contain at least one label mapping"));
    }

    // Validate each label mapping
    for (label, label_value) in &config.label_mappings {
        // Check that label has either network key OR user key spec OR both
        let has_network_key = label_value.network_public_key.is_some();
        let has_user_spec = label_value.user_key_spec.is_some();

        if !has_network_key && !has_user_spec {
            return Err(anyhow!("Label '{}' must specify either network_public_key or user_key_spec (or both)", label));
        }

        // If network key is provided, validate it's not empty
        if let Some(network_key) = &label_value.network_public_key {
            if network_key.is_empty() {
                return Err(anyhow!("Label '{}' has empty network_public_key - use None for user-only labels", label));
            }
        }

        // Validate user key spec if provided
        if let Some(user_spec) = &label_value.user_key_spec {
            match user_spec {
                LabelKeyword::CurrentUser => {
                    // CurrentUser is always valid
                },
                LabelKeyword::Custom(resolver_name) => {
                    if resolver_name.is_empty() {
                        return Err(anyhow!("Label '{}' has empty custom resolver name", label));
                    }
                    // Future: Could validate that custom resolver exists
                }
            }
        }
    }

    Ok(())
}
```

### 5. Request Processing Updates

#### Network Request Handler
```rust
async fn handle_network_request(&self, message: RequestMessage) -> Result<ResponseMessage> {
    // Extract user profile keys from incoming request
    // These are carried from the original request initiator (client/mobile/web)
    let user_profile_keys = if message.profile_public_key.is_empty() {
        None // System request - no current user
    } else {
        Some(vec![message.profile_public_key.clone()])
    };

    // Create request context that will be carried throughout the chain
    let request_context = RequestContext {
        user_profile_public_keys: user_profile_keys.clone(),
        correlation_id: message.correlation_id.clone(),
        timeout_ms: self.config.request_timeout_ms,
    };

    // Create context-aware label resolver
    // REQUIRES: All labels must have explicit network keys - no defaults
    let label_resolver = create_context_label_resolver(
        &self.system_label_config,
        user_profile_keys.as_ref().map(|v| v.as_slice()),
    )?;

    // Create serialization context with dynamic resolver
    let serialization_context = SerializationContext {
        keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
        resolver: label_resolver,
        network_id,
        profile_public_keys: user_profile_keys.clone().unwrap_or_default(),
    };

    // ... rest of request processing ...
    // All subsequent calls in this request chain will use the same request_context
}
```

#### Local Request Handler
```rust
async fn local_request(&self, topic_path: &TopicPath, params: Option<ArcValue>, context: &RequestContext) -> Result<ArcValue> {
    // Extract user profile keys from request context
    // IMPROVED: Direct access, no unnecessary cloning
    let user_profile_keys = &context.user_profile_public_keys;

    // Create context-aware label resolver with user profile keys
    // IMPROVED: Direct slice conversion without map() call
    let user_keys_slice = user_profile_keys.as_ref().map(|v| v.as_slice());
    let label_resolver = create_context_label_resolver(
        &self.system_label_config,
        user_keys_slice,
    )?;


    let serialization_context = SerializationContext {
        keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
        resolver: label_resolver,
        // IMPROVED: Use ALL profile keys, not just the first one
        profile_public_keys: user_profile_keys.clone().unwrap_or_default(),
    };

    // IMPROVED: Pass reference instead of cloning the entire context
    // This ensures user identity flows through the entire chain efficiently
    let service_call_context = context;

    // ... rest of local request processing ...
    // All subsequent service calls will receive the same request context reference
}
```

#### Service Method Calls
```rust
async fn call_service_with_context(
    &self,
    service_path: &str,
    params: ArcValue,
    request_context: &RequestContext, // Carried through entire chain
) -> Result<ArcValue> {
    // Create resolver with user context for this service call
    // REQUIRES: All labels must have explicit network keys - no defaults
    let label_resolver = create_context_label_resolver(
        &self.system_label_config,
        request_context.user_profile_public_keys.as_ref().map(|v| v.as_slice()),
    )?;

    let serialization_context = SerializationContext {
        keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
        resolver: label_resolver,
        // network_id removed - now embedded in label resolver
        profile_public_keys: request_context.user_profile_public_keys.clone().unwrap_or_default(),
    };

    // Serialize parameters with user context
    let serialized_params = params.serialize(Some(&serialization_context))?;

    // Call service with the same request context
    // The context continues to flow through the chain
    self.service_registry.call_service_with_context(
        service_path,
        serialized_params,
        request_context,
    ).await
}
```

### 6. Remote Service Updates

#### RemoteService Creation
```rust
pub struct RemoteServiceDependencies {
    // ... existing fields ...
    system_label_config: LabelResolverConfig, // Instead of static resolver
}
```

#### Action Handler Creation
```rust
pub fn create_action_handler(&self, action_name: String) -> ActionHandler {
    let service = self.clone();

    Arc::new(move |params, request_context| {
        // Extract user profile keys from request context
        // These are carried from the original request initiator
        let user_profile_keys = request_context.user_profile_public_keys.as_ref();

        // Create context-aware label resolver
        // Create context-aware label resolver for remote call
        // REQUIRES: All labels must have explicit network keys - no defaults
        let label_resolver = create_context_label_resolver(
            &service.system_label_config,
            user_profile_keys.map(|v| v.as_slice()),
        )?;

        let serialization_context = SerializationContext {
            keystore: service.keystore.clone(),
            resolver: label_resolver,
            // network_id removed - now embedded in label resolver
            profile_public_keys: user_profile_keys.cloned().unwrap_or_default(),
        };

        // Serialize parameters with user context
        let params_bytes = params
            .unwrap_or(ArcValue::null())
            .serialize(Some(&serialization_context))
            .unwrap_or_default();

        // Create request message with user context carried through
        let request_message = RequestMessage {
            path: topic_path_str.to_string(),
            correlation_id,
            payload_bytes: params_bytes,
            profile_public_key: user_profile_keys.and_then(|v| v.first()).cloned().unwrap_or_default(),
        };

        // Send request via transport with user context preserved
        match service.network_transport
            .request(
                &request_message.path,
                &request_message.correlation_id,
                request_message.payload_bytes,
                &peer_node_id,
                request_message.profile_public_key,
            )
            .await
        {
            // ... handle response ...
        }
    })

}
```

### 7. Request Flow Patterns - User Profile Key Propagation

#### Request Chain Flow with User Context

The user profile keys flow through the entire request chain similar to JWT tokens in web applications:

```
Client/Mobile/Web Request
        ↓
NetworkMessage.profile_public_key (user's profile key)
        ↓
Node::handle_network_request()
  ├── Creates RequestContext { user_profile_public_keys: Some([user_key]) }
  ├── Creates dynamic label resolver with user context
  └── Calls local_request() with RequestContext
        ↓
Service A (with user context)
  ├── Resolves "current_user" → user's profile keys
  ├── Calls Service B (passes RequestContext)
  └── Service B resolves "current_user" → same user's profile keys
        ↓
Remote Service Call (with user context)
  ├── Serializes with user's label resolver
  ├── Sends RequestMessage with profile_public_key
  └── Remote node receives user context
        ↓
Remote Node processes with user's context
  └── Any nested calls maintain user context
```

#### Request Context Types

**1. Client-Initiated Requests**
```rust
// Mobile/Web client provides user profile keys
let request_context = RequestContext {
    user_profile_public_keys: Some(vec![user_profile_public_key]),
    correlation_id: generate_id(),
    timeout_ms: 30000,
};
```

**2. System/Background Requests**
```rust
// Background service - no current user
let request_context = RequestContext {
    user_profile_public_keys: None, // System request
    correlation_id: generate_id(),
    timeout_ms: 30000,
};
```

**3. Background Service on Behalf of User**
```rust
// Background service acting for a specific user
let request_context = RequestContext {
    user_profile_public_keys: Some(vec![user_profile_public_key]),
    correlation_id: generate_id(),
    timeout_ms: 30000,
};
```

#### Event Context for Event Propagation

Events also carry user profile keys to maintain user context throughout event chains:

```rust
#[derive(Clone)]
pub struct EventContext {
    /// User profile public keys from event initiator
    /// Carried throughout the entire event chain
    pub user_profile_public_keys: Option<Vec<Vec<u8>>>,

    /// Other context data...
    pub correlation_id: String,
    pub event_topic: String,
}

async fn handle_event_with_context(&self, event: EventMessage, context: &EventContext) -> Result<()> {
    // Extract user profile keys from event context
    let user_profile_keys = &context.user_profile_public_keys;

    // Create context-aware label resolver for event processing
    let user_keys_slice = user_profile_keys.as_ref().map(|v| v.as_slice());
    let label_resolver = create_context_label_resolver(
        &self.system_label_config,
        user_keys_slice,
    )?;

    let serialization_context = SerializationContext {
        keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
        resolver: label_resolver,
        profile_public_keys: user_profile_keys.clone().unwrap_or_default(),
    };

    // Process event with user context
    // Event subscribers receive the same context
    self.process_event_with_context(event, context, &serialization_context).await
}
```

#### Label Resolution Examples

**NodeConfig.LabelResolverConfig:**
```rust
LabelResolverConfig {
    label_mappings: HashMap::from([
        // System label - specific network key, no user keys
        ("system".to_string(), LabelValue {
            network_public_key: Some(system_network_key),
            user_key_spec: None,
        }),

        // Admin label - specific network key, no user keys
        ("admin".to_string(), LabelValue {
            network_public_key: Some(admin_network_key),
            user_key_spec: None,
        }),

        // Current user label - explicit network key, current user keys
        ("current_user".to_string(), LabelValue {
            network_public_key: Some(default_network_key), // MUST be explicit
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),

        // Custom label - specific network key + custom user resolution
        ("custom_role".to_string(), LabelValue {
            network_public_key: Some(role_network_key),
            user_key_spec: Some(LabelKeyword::Custom("role_resolver".to_string())),
        }),

        // USER-ONLY label - no network key, only current user keys
        ("my_private_data".to_string(), LabelValue {
            network_public_key: None, // User-only encryption
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),

        // User-only label with explicit network (mixed)
        ("user_data".to_string(), LabelValue {
            network_public_key: Some(default_network_key),
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),

        // Network-only label - specific network key, no user keys
        ("public_data".to_string(), LabelValue {
            network_public_key: Some(public_network_key),
            user_key_spec: None,
        }),
    ]),
}
```

**Runtime Label Resolution:**
```rust
// For a request with user profile key: [user_key_123]
// ALL labels must have explicit network keys - no defaults allowed
let resolver = create_context_label_resolver(
    &config,
    Some(&[user_key_123]),
)?;

// Label resolution results:
// "system" → LabelKeyInfo { network_public_key: system_network_key, profile_public_keys: [] }
// "admin" → LabelKeyInfo { network_public_key: admin_network_key, profile_public_keys: [] }
// "current_user" → LabelKeyInfo { network_public_key: default_network_key, profile_public_keys: [user_key_123] }
// "custom_role" → LabelKeyInfo { network_public_key: role_network_key, profile_public_keys: [] } (custom function would populate)
// "my_private_data" → LabelKeyInfo { network_public_key: [], profile_public_keys: [user_key_123] } // USER-ONLY!
// "user_data" → LabelKeyInfo { network_public_key: default_network_key, profile_public_keys: [user_key_123] }
// "public_data" → LabelKeyInfo { network_public_key: public_network_key, profile_public_keys: [] }

// Usage in SerializationContext - network keys embedded in resolver!
let serialization_context = SerializationContext {
    keystore: keystore,
    resolver: resolver, // Contains embedded network keys for all labels
    profile_public_keys: vec![user_key_123],
};
```

### 7. Transport Layer Updates

#### QuicTransport Configuration
```rust
pub struct QuicTransportOptions {
    // ... existing fields ...
    system_label_config: LabelResolverConfig, // REQUIRED - no Option, complete replacement
}
```

#### Transport Request Method with User Context Flow
```rust
async fn request(
    &self,
    topic_path: &str,
    correlation_id: &str,
    payload: Vec<u8>,
    target_node_id: &str,
    profile_public_key: Vec<u8>,
) -> Result<Vec<u8>> {
    // Extract user context from profile_public_key
    // This is carried from the original request initiator
    let user_profile_keys = if profile_public_key.is_empty() {
        None // System request
    } else {
        Some(vec![profile_public_key.clone()])
    };

    // Create context-aware resolver for this specific request
    // REQUIRES: All labels must have explicit network keys - no defaults
    let resolver = create_context_label_resolver(
        &self.system_label_config,
        user_profile_keys.as_ref().map(|v| v.as_slice()),
    )?;

    // Create serialization context for decryption with user context
    let serialization_context = SerializationContext {
        keystore: self.keystore.clone(),
        resolver,
        // network_id removed - now embedded in label resolver
        profile_public_keys: user_profile_keys.clone().unwrap_or_default(),
    };

    // Decrypt incoming payload with user context
    let decrypted_payload = ArcValue::deserialize(&payload, Some(self.keystore.clone()))?;

    // Process request with user context
    let response_payload = self.process_request_with_context(
        topic_path,
        correlation_id,
        decrypted_payload,
        &RequestContext {
            user_profile_public_keys: user_profile_keys,
            correlation_id: correlation_id.to_string(),
            timeout_ms: 30000,
        }
    ).await?;

    // Create response resolver with same user context
    // REQUIRES: All labels must have explicit network keys - no defaults
    let response_resolver = create_context_label_resolver(
        &self.system_label_config,
        user_profile_keys.as_ref().map(|v| v.as_slice()),
    )?;

    let response_context = SerializationContext {
        keystore: self.keystore.clone(),
        resolver: response_resolver,
        // network_id removed - now embedded in label resolver
        profile_public_keys: user_profile_keys.clone().unwrap_or_default(),
    };

    // Serialize response with user context and return
    response_payload.serialize(Some(&response_context))

}
```

### 8. Custom Resolution Functions - Future Extensibility

#### Custom Label Resolution Framework

The `LabelKeyword::Custom(String)` variant allows for future extensibility without requiring changes to the core label resolution system:

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LabelKeyword {
    /// Maps to current user's profile public keys from request context
    CurrentUser,
    /// Reserved for future custom resolution functions
    Custom(String), // Function name for custom resolution
}

// Future custom resolution registry
type CustomResolverFn = Arc<dyn Fn(&RequestContext, &str) -> Result<Vec<Vec<u8>>> + Send + Sync>;

struct CustomResolverRegistry {
    resolvers: DashMap<String, CustomResolverFn>,
}

impl CustomResolverRegistry {
    fn register_resolver(&self, name: String, resolver: CustomResolverFn) {
        self.resolvers.insert(name, resolver);
    }

    fn resolve(&self, name: &str, context: &RequestContext, label: &str) -> Result<Vec<Vec<u8>>> {
        let resolver = self.resolvers.get(name)
            .ok_or_else(|| anyhow!("Custom resolver '{}' not found", name))?;
        resolver(context, label)
    }
}

// Example future custom resolver
fn user_role_based_resolver(context: &RequestContext, label: &str) -> Result<Vec<Vec<u8>>> {
    // Custom logic to resolve user role-based keys
    // e.g., "admin_users", "premium_users", "department_managers"
    match label {
        "admin_users" => get_admin_user_keys(),
        "premium_users" => get_premium_user_keys(),
        "department_managers" => get_department_manager_keys(context),
        _ => Err(anyhow!("Unknown role: {}", label)),
    }
}
```

#### Configuration Example with Flexible Label Combinations

```rust
LabelResolverConfig {
    label_mappings: HashMap::from([
        // System labels - specific network key only
        ("system".to_string(), LabelValue {
            network_public_key: Some(system_network_key),
            user_key_spec: None,
        }),
        ("admin".to_string(), LabelValue {
            network_public_key: Some(admin_network_key),
            user_key_spec: None,
        }),

        // User-specific labels - explicit network + current user
        ("current_user".to_string(), LabelValue {
            network_public_key: Some(default_network_key),
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),

        // USER-ONLY labels - no network encryption, only user keys
        ("my_private_data".to_string(), LabelValue {
            network_public_key: None, // User-only encryption
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),
        ("personal_settings".to_string(), LabelValue {
            network_public_key: None, // User-only
            user_key_spec: Some(LabelKeyword::Custom("user_settings_resolver".to_string())),
        }),

        // Mixed user label
        ("my_data".to_string(), LabelValue {
            network_public_key: Some(default_network_key),
            user_key_spec: Some(LabelKeyword::CurrentUser),
        }),

        // Mixed labels - specific network + dynamic user
        ("user_role".to_string(), LabelValue {
            network_public_key: Some(role_network_key),
            user_key_spec: Some(LabelKeyword::Custom("user_role_resolver".to_string())),
        }),
        ("department".to_string(), LabelValue {
            network_public_key: Some(dept_network_key),
            user_key_spec: Some(LabelKeyword::Custom("department_resolver".to_string())),
        }),
        ("security_clearance".to_string(), LabelValue {
            network_public_key: Some(sec_network_key),
            user_key_spec: Some(LabelKeyword::Custom("security_resolver".to_string())),
        }),

        // Public labels - specific network, no user keys
        ("public_data".to_string(), LabelValue {
            network_public_key: Some(public_network_key),
            user_key_spec: None,
        }),
    ]),
}
```

#### Benefits of Flexible Label Design

1. **Maximum Flexibility**: Labels can be network-only, user-only, or both
2. **Explicit and Unambiguous**: Network keys are explicit (or empty for user-only labels)
3. **Independent Network & User Key Specification**: Each label can specify network and user keys independently
4. **Supports User-Only Encryption**: Pure user-specific data without network encryption
5. **No Hardcoded Label Strings**: Developers can use any label names they want
6. **Future-Proof**: New resolution types can be added without core changes
7. **Separation of Concerns**: Network encryption vs user authorization clearly separated
8. **Extensibility**: Custom resolution functions can implement complex logic
9. **Performance**: Only relevant resolvers are loaded/called

#### Label Validation Requirements

**VALIDATION RULES:**
- Every label **MUST** have either `network_public_key` OR `user_key_spec` (or both)
- `network_public_key` can be `None` for user-only labels (will use empty key `[]`)
- `user_key_spec` can be `None` for network-only labels
- Configuration validation will fail if a label has neither network nor user specification
- Empty network key `[]` + no user keys = **INVALID** (caught by validation)

**WHY THIS MATTERS:**
- Supports both network-only and user-only encryption patterns
- Prevents invalid labels with no encryption at all
- Maintains flexibility while ensuring security
- Allows pure user-specific data without network encryption

#### Label Combination Examples

| Label Type | Network Key | User Key Spec | Use Case |
|------------|-------------|---------------|----------|
| **System Labels** | **EXPLICIT** network key | None | System-wide encrypted data |
| **Network-Only** | **EXPLICIT** network key | None | Publicly readable data |
| **User-Only** | None (empty `[]`) | CurrentUser | Private user data only |
| **User Labels** | **EXPLICIT** network key | CurrentUser | User data in specific network |
| **Role-Based** | **EXPLICIT** network key | Custom resolver | Department/role access |
| **Custom User-Only** | None (empty `[]`) | Custom resolver | Complex user-only logic |
| **Mixed Labels** | **EXPLICIT** network key | CurrentUser | User data in specific network |
| **Dynamic Labels** | **EXPLICIT** network key | Custom resolver | Complex authorization logic |

**FLEXIBLE VALIDATION:** Labels can have network key only, user key only, or both - but not neither!

## SerializationContext Current Usage Analysis

### Field Usage Investigation Results

**1. `keystore: Arc<KeyStore>` - REQUIRED for both operations**
- **Serialization**: Passed to `encrypt_with_envelope()` and serialization functions
- **Deserialization**: Passed to `decrypt_bytes()` for decryption
- **Usage**: Essential for all cryptographic operations

**2. `resolver: Arc<dyn LabelResolver>` - Serialization ONLY**
- **Serialization**: Passed to serialization functions for label resolution
- **Deserialization**: NOT USED (decryption uses keystore directly)
- **Current Issue**: Uses static resolver, needs to be dynamic per context

**3. `network_id: String` - OUTER ENVELOPE ENCRYPTION**
- **Serialization**: Passed as `Some(network_id.as_str())` to `encrypt_with_envelope()` for outer envelope
- **Deserialization**: NOT USED
- **Purpose**: Network context for message-level envelope encryption
- **Impact**: **MUST KEEP** - Required for outer envelope encryption, separate from label-based field encryption

**4. `profile_public_key: Option<Vec<u8>>` - Serialization ONLY**
- **Serialization**: Converted to `recipients: Vec<Vec<u8>>` for `encrypt_with_envelope()`
- **Deserialization**: NOT USED
- **Current Issue**: Single key, but we need multiple profile keys

### Key Insights

**Two-Layer Encryption Architecture:**

**Inner Layer (Field/Struct Encryption):**
- Uses `resolver` to resolve labels to keys for individual field/struct encryption
- Called via `plain.encrypt_with_keystore(ks, resolver)` in registry
- Handles label-based encryption within data structures

**Outer Layer (Message Envelope Encryption):**
- Uses `network_id` and `profile_public_key` for message-level envelope encryption
- Called via `encrypt_with_envelope(&bytes, Some(network_id.as_str()), recipients)`
- Provides additional encryption layer around the entire serialized content

**Serialization vs Deserialization Asymmetry:**
- All four fields (`resolver`, `network_id`, `profile_public_key`, `keystore`) are used during serialization
- Deserialization only uses `keystore` for decryption
- The asymmetry exists because decryption context is embedded in the encrypted data

**Current Construction Patterns:**
```rust
// Network request handler
SerializationContext {
    keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
    resolver: self.label_resolver.clone(), // Static - PROBLEM (will be dynamic)
    network_id, // From topic path - STAYS (for outer envelope)
    profile_public_key: Some(profile_public_key), // Single key - PROBLEM (will be Vec)
}

// Event handler
SerializationContext {
    keystore: Arc::new(NodeKeyManagerWrapper(self.keys_manager.clone())),
    resolver: self.label_resolver.clone(), // Static - PROBLEM (will be dynamic)
    network_id, // From topic path - STAYS (for outer envelope)
    profile_public_key: None, // No user context - PROBLEM (will be Vec)
}
```

### Required Changes to SerializationContext

**PROPOSED NEW STRUCTURE:**
```rust
#[derive(Clone)]
pub struct SerializationContext {
    pub keystore: Arc<KeyStore>, // UNCHANGED - still required
    pub resolver: Arc<dyn LabelResolver>, // CHANGED - will be dynamic per context
    pub network_id: String, // UNCHANGED - REQUIRED for outer envelope encryption
    pub profile_public_keys: Vec<Vec<u8>>, // CHANGED - multiple keys instead of single
}
```

**Migration Impact:**
- `network_id`: **NO CHANGE** - Still required for outer envelope encryption
- `profile_public_key` → `profile_public_keys`: BREAKING CHANGE - affects recipients logic
- `resolver` dynamic: LOGIC CHANGE - requires context-aware resolver creation
- **LABEL KEYS EMBEDDING**: Network keys for labels will be embedded in resolver, but `network_id` stays for envelope

**Impact on arc_value.rs Serialization Logic:**
```rust
// CURRENT (lines 566-588):
if let Some(ctx) = context {
    let ks = &ctx.keystore;
    let network_id = &ctx.network_id;           // STAYS - for outer envelope
    let profile_public_key = &ctx.profile_public_key; // WILL BE CHANGED to profile_public_keys

    let recipients: Vec<Vec<u8>> = match profile_public_key.as_ref() {
        Some(pk) => vec![pk.clone()], // Single key
        None => Vec::new(),
    };
    let data = ks.encrypt_with_envelope(&bytes, Some(network_id.as_str()), recipients)?;
}

// NEW (proposed):
if let Some(ctx) = context {
    let ks = &ctx.keystore;
    let network_id = &ctx.network_id;           // STAYS - for outer envelope
    let resolver = &ctx.resolver;               // Dynamic resolver for inner encryption
    // profile_public_keys: Vec<Vec<u8>> - all recipient keys

    let recipients = ctx.profile_public_keys.clone(); // All profile keys as recipients
    let data = ks.encrypt_with_envelope(&bytes, Some(network_id.as_str()), recipients)?;
}
```

**Breaking Changes Required:**
1. **Update recipients logic** - Use all profile_public_keys instead of single key
2. **Update all SerializationContext constructions** - Change profile_public_key to profile_public_keys
3. **Update resolver creation** - Make resolvers dynamic per context
4. **Update test files** - All test SerializationContext constructions need updating
5. **`network_id` field stays unchanged** - Still required for outer envelope encryption

## Detailed Analysis: Network ID vs Network Public Key Architecture

### **Current Architecture (Network ID in API)**

#### **Network ID Flow:**
```
Topic Path ("network_123/service/method")
    ↓
TopicPath::network_id() → "network_123"
    ↓
SerializationContext { network_id: "network_123", ... }
    ↓
encrypt_with_envelope(data, Some("network_123"), recipients)
    ↓
INTERNAL: get_network_public_key("network_123") → network_public_key_bytes
    ↓
encrypt_key_with_ecdsa(envelope_key, network_public_key_bytes)
```

#### **Current encrypt_with_envelope API:**
```rust
pub trait EnvelopeCrypto: Send + Sync {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: Option<&str>,           // ← NETWORK ID
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<EnvelopeEncryptedData>;
}
```

### **Proposed Architecture (Network Public Key in API)**

#### **Network Public Key Flow:**
```
Topic Path ("network_123/service/method")
    ↓
TopicPath::network_id() → "network_123"
    ↓
get_network_public_key("network_123") → network_public_key_bytes
    ↓
SerializationContext { network_public_key: network_public_key_bytes, ... }
    ↓
encrypt_with_envelope(data, Some(&network_public_key_bytes), recipients)
    ↓
DIRECT: encrypt_key_with_ecdsa(envelope_key, network_public_key_bytes)
```

#### **Proposed encrypt_with_envelope API:**
```rust
pub trait EnvelopeCrypto: Send + Sync {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_public_key: Option<&[u8]>,  // ← NETWORK PUBLIC KEY
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<EnvelopeEncryptedData>;
}
```

### **Breaking Changes Impact Analysis**

#### **HIGH IMPACT (Breaking Changes):**
1. **EnvelopeCrypto Trait Definition** (`runar-keys/src/lib.rs`)
2. **NodeKeyManager::encrypt_with_envelope** (`runar-keys/src/node.rs`)
3. **MobileKeyManager::encrypt_with_envelope** (`runar-keys/src/mobile.rs`)
4. **SerializationContext Structure** (`runar-serializer/src/traits.rs`)
5. **~40 Call Sites** - All locations calling encrypt_with_envelope
6. **FFI Functions** (`runar-ffi/src/lib.rs`)
7. **Test Files** - All encryption tests

#### **MODERATE IMPACT:**
1. **SerializationContext Construction** - Add network ID resolution
2. **Error Handling** - Network validation moves earlier in flow
3. **arc_value.rs Serialization Logic** - Update to use public key directly

#### **LOW IMPACT:**
1. **Topic Path Handling** - Unchanged
2. **Network ID Storage** - Unchanged in configs and paths

### **SerializationContext Changes**

#### **CURRENT:**
```rust
#[derive(Clone)]
pub struct SerializationContext {
    pub keystore: Arc<KeyStore>,
    pub resolver: Arc<dyn LabelResolver>, // Dynamic per context
    pub network_id: String, // ← REQUIRES RESOLUTION
    pub profile_public_keys: Vec<Vec<u8>>,
}
```

#### **PROPOSED:**
```rust
#[derive(Clone)]
pub struct SerializationContext {
    pub keystore: Arc<KeyStore>,
    pub resolver: Arc<dyn LabelResolver>, // Dynamic per context
    pub network_public_key: Vec<u8>, // ← PRE-RESOLVED
    pub profile_public_keys: Vec<Vec<u8>>,
}
```

### **Updated Construction Pattern:**

#### **CURRENT:**
```rust
let serialization_context = SerializationContext {
    keystore: keystore,
    resolver: dynamic_resolver,
    network_id: topic_path.network_id(), // ← ID, requires resolution later
    profile_public_keys: user_profile_keys,
};
```

#### **PROPOSED:**
```rust
// Resolve network ID to public key during construction
let network_public_key = keystore.get_network_public_key(&topic_path.network_id())?;

let serialization_context = SerializationContext {
    keystore: keystore,
    resolver: dynamic_resolver,
    network_public_key: network_public_key, // ← Pre-resolved public key
    profile_public_keys: user_profile_keys,
};
```

### **Benefits of Network Public Key API:**

#### **✅ Advantages:**
1. **Early Validation**: Network ID resolution fails fast before encryption attempt
2. **Explicit Security**: Public keys are explicit, no hidden resolution
3. **Performance**: Resolution happens once at context creation, not per encryption
4. **Consistency**: Aligns with label resolver design (explicit keys, not IDs)
5. **Error Clarity**: Clear errors about network access vs encryption failures

#### **❌ Disadvantages:**
1. **Breaking Change**: Major API change affecting many components
2. **Complexity**: Network resolution logic moves to call sites
3. **Error Handling**: More complex error propagation

### **Migration Strategy:**

#### **Phase 1: Core API Changes**
1. Update EnvelopeCrypto trait to use `network_public_key: Option<&[u8]>`
2. Update NodeKeyManager and MobileKeyManager implementations
3. Update FFI layer functions
4. Update SerializationContext structure

#### **Phase 2: Call Site Updates**
1. Update arc_value.rs serialization logic
2. Update all SerializationContext constructions
3. Update test files
4. Update encryption.rs usage

#### **Phase 3: Integration Updates**
1. Update transport layer usage
2. Update remote service usage
3. Update Node.js API bindings

## Complete Refactor Requirements

### **MAJOR BREAKING CHANGE: Network Public Key API**

#### **Phase 1: Core Encryption API Overhaul (HIGH PRIORITY)**
1. **Update EnvelopeCrypto trait** - Change `network_id: Option<&str>` to `network_public_key: Option<&[u8]>`
2. **Update NodeKeyManager::encrypt_with_envelope** - Remove internal network ID resolution
3. **Update MobileKeyManager::encrypt_with_envelope** - Remove internal network ID resolution
4. **Update FFI functions** - rn_keys_*_encrypt_with_envelope functions
5. **Update all ~40 call sites** - Change to pass network public keys instead of IDs

#### **Phase 2: SerializationContext Overhaul (HIGH PRIORITY)**
6. **Update SerializationContext structure** - Change `network_id: String` to `network_public_key: Vec<u8>`
7. **Update profile_public_key to profile_public_keys** - Support multiple profile keys
8. **Update all SerializationContext constructions** - Add network ID to public key resolution
9. **Update arc_value.rs serialization logic** - Use public keys directly
10. **Update all test files** - Update test SerializationContext constructions

#### **Phase 3: Label Resolver Integration (MEDIUM PRIORITY)**
11. **Replace all static label resolver creation** - Remove hardcoded resolver in node.rs
12. **Update NodeConfig** - Add required LabelResolverConfig field
13. **Implement dynamic label resolver creation** - All resolvers created per-context
14. **Update transport layer** - Remove static resolver, use dynamic creation
15. **Update remote services** - Remove static resolver dependency
16. **Update all encryption/decryption points** - Use context-aware resolvers

### **Network ID Resolution Changes**

#### **Current Flow (Internal Resolution):**
```
SerializationContext { network_id: "network_123", ... }
    ↓
encrypt_with_envelope(data, Some("network_123"), recipients)
    ↓
INTERNAL: keystore.get_network_public_key("network_123")
    ↓
Use resolved public key for encryption
```

#### **New Flow (External Resolution):**
```
TopicPath::network_id() → "network_123"
    ↓
keystore.get_network_public_key("network_123") → network_public_key_bytes
    ↓
SerializationContext { network_public_key: network_public_key_bytes, ... }
    ↓
encrypt_with_envelope(data, Some(&network_public_key_bytes), recipients)
    ↓
DIRECT: Use public key for encryption
```

### **Error Handling Impact**

#### **Current: Late Validation**
```rust
// Network resolution happens INSIDE encrypt_with_envelope
encrypt_with_envelope(data, Some("invalid_network"), recipients)
// Error occurs during encryption attempt
```

#### **Proposed: Early Validation**
```rust
// Network resolution happens BEFORE encrypt_with_envelope
let network_key = keystore.get_network_public_key("invalid_network")?;
// Error occurs immediately with clear message
encrypt_with_envelope(data, Some(&network_key), recipients)
```

### **Files Requiring Updates**

#### **HIGH IMPACT (~40 files):**
- `runar-keys/src/lib.rs` - EnvelopeCrypto trait
- `runar-keys/src/node.rs` - NodeKeyManager implementation
- `runar-keys/src/mobile.rs` - MobileKeyManager implementation
- `runar-serializer/src/traits.rs` - SerializationContext structure
- `runar-serializer/src/arc_value.rs` - Serialization logic
- `runar-ffi/src/lib.rs` - FFI functions
- `runar-nodejs-api/src/lib.rs` - Node.js bindings
- All test files using encrypt_with_envelope

#### **MODERATE IMPACT:**
- `runar-node/src/node.rs` - SerializationContext constructions
- `runar-node/src/services/remote_service.rs` - Service calls
- `runar-transport/src/` - Transport layer usage
- Configuration and setup files

### **Risk Assessment**

#### **HIGH RISK:**
- **Breaking API Change**: Affects core encryption functionality
- **Wide Impact**: ~40+ call sites across multiple crates
- **FFI Compatibility**: Affects external integrations
- **Test Coverage**: Extensive test updates required

#### **MITIGATION STRATEGIES:**
1. **Atomic Changes**: Update trait + all implementations simultaneously
2. **Backward Compatibility**: Consider keeping old API with deprecation warnings
3. **Gradual Migration**: Use feature flags to control API versions
4. **Comprehensive Testing**: Validate all encryption/decryption flows

### Complete Code Replacement Requirements
- **Remove all legacy resolver fields** from Node and service structs
- **Replace all static resolver usage** with dynamic creation calls
- **Update all Arc<dyn LabelResolver> fields** to be created dynamically
- **Remove backward compatibility code** - No legacy fallbacks
- **Update all tests** - No legacy test patterns allowed
- **Update examples and documentation** - Reflect new design only

## Security Considerations

### 1. Label Scope Isolation
- System labels should only be resolvable by system components
- User labels should be scoped to the requesting user's context
- No cross-user label resolution allowed

### 2. Configuration Validation
- Validate system label configurations at startup
- Ensure no reserved label names are used
- Validate network ID consistency across labels

### 3. Dynamic Label Safety
- User profile keys should be validated before use in label resolution
- Prevent injection of system labels by user input
- Rate limit dynamic label creation if needed

## Performance Considerations

### 1. Resolver Creation Cost
- Creating new resolvers per request could be expensive
- Consider resolver caching based on user context
- Use Arc cloning instead of full recreation where possible

### 2. Concurrent Access Patterns
- Maintain DashMap usage for thread-safe concurrent access
- Consider read-write lock patterns for mixed access patterns
- Profile performance impact of dynamic resolver creation

### 3. Memory Usage
- Dynamic resolvers may increase memory usage
- Implement cleanup mechanisms for unused resolvers
- Consider object pooling for frequently used resolver configurations

## Testing Strategy

### 1. Unit Tests - New Design Only
- Test dynamic resolver creation with various user contexts
- Validate required LabelResolverConfig in NodeConfig
- Test label resolution isolation between contexts
- Test failure cases when LabelResolverConfig is missing
- Test system label configuration validation

### 2. Integration Tests - Complete Replacement
- Test end-to-end request flows with user-specific labels
- Validate encryption/decryption with context-aware resolvers
- Test system label configuration via NodeConfig
- Test transport layer with dynamic resolver creation
- Test remote service creation without static resolvers

### 3. No Backward Compatibility Tests
- **REMOVED**: No legacy code testing - complete replacement only
- **REMOVED**: No migration scenario testing - immediate implementation
- **REMOVED**: No compatibility layer testing - all code updated

## Implementation Requirements - All High Priority

### Complete Implementation - No Priority Levels
**ALL COMPONENTS MUST BE UPDATED IMMEDIATELY - Complete Refactor Required:**

1. **NodeConfig extension with LabelResolverConfig** - REQUIRED field, no optional
2. **Dynamic resolver creation function** - Replace all static resolver usage
3. **SerializationContext updates for dynamic resolvers** - Update ALL creation points
4. **Node startup and request handling updates** - Remove hardcoded resolver
5. **Remote service updates** - Remove static resolver dependency completely
6. **Transport layer integration** - Remove static resolver, use dynamic creation
7. **Performance optimization and caching** - Implement immediately for production readiness
8. **Advanced user label features** - Implement core functionality
9. **Resolver pooling and advanced caching** - Required for scalability
10. **Monitoring and observability enhancements** - Production requirements

### No Partial Implementation Allowed
- **ALL components must be updated** before any component can be considered complete
- **No legacy code paths** - Complete replacement only
- **No optional configurations** - All new patterns required
- **No fallback mechanisms** - New design enforced

## Success Metrics - Complete Replacement Only

### Functional Metrics - New Design Only
- ✅ System labels configurable via REQUIRED NodeConfig.LabelResolverConfig
- ✅ User profile keys integrated into label resolution
- ✅ Context-aware encryption/decryption working
- ✅ **REMOVED**: No backward compatibility - Complete replacement achieved
- ✅ All legacy static resolvers removed from codebase
- ✅ All SerializationContext creation points updated
- ✅ All transport layer static resolver usage replaced

### Performance Metrics - New Implementation
- ✅ No regression in request processing latency
- ✅ Memory usage within acceptable bounds
- ✅ Concurrent access performance maintained
- ✅ Dynamic resolver creation performance optimized
- ✅ No performance impact from legacy code paths

### Security Metrics - Complete Implementation
- ✅ Label scope isolation enforced
- ✅ No cross-user label resolution
- ✅ Configuration validation working
- ✅ No security regressions
- ✅ No legacy security vulnerabilities from old patterns
- ✅ All encryption/decryption points use new context-aware design

## Conclusion - Complete Refactor Imperative

**NO BACKWARD COMPATIBILITY - COMPLETE REPLACEMENT REQUIRED**

This design mandates a complete refactor of all label resolver usage throughout the codebase. There are **NO legacy code paths**, **NO phased approaches**, and **NO backward compatibility** - all components must be updated immediately to the new dynamic, context-aware design.

### Key Requirements Enforced:
- **No static label resolvers** - All resolvers created dynamically per context
- **No optional configurations** - LabelResolverConfig is REQUIRED in NodeConfig
- **No legacy fallbacks** - All old patterns completely removed
- **No partial implementations** - All components updated before any are complete

### Implementation Mandate:
- Replace hardcoded resolver in `node.rs` immediately
- Update ALL `SerializationContext` creation points
- Remove ALL `Arc<dyn LabelResolver>` static fields
- Update transport layer to use dynamic resolver creation
- Update remote services to remove static resolver dependency
- Update ALL encryption/decryption points

The key insight is that label resolvers **MUST** be created per-context rather than being static singletons, enabling proper integration of user-specific information while maintaining system-level configuration through REQUIRED NodeConfig.LabelResolverConfig.

**FAILURE TO IMPLEMENT COMPLETE REPLACEMENT WILL RESULT IN INCONSISTENT AND INSECURE LABEL RESOLUTION**
