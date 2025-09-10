# NodeJS API Design Document - Complete Refactor for Dual-Role Implementation

## Overview

This document specifies the required changes to the NodeJS API (`runar-nodejs-api/src/lib.rs`) to align with the latest `runar-keys` and `runar-transporter` crates while implementing the NodeKeyManager dual-role design. The NodeJS API must follow the same patterns as the C FFI and expose all new APIs.

## Current State Analysis

### Working Components (MUST PRESERVE)
- **Transport callbacks** - Currently working, must not break
- **Basic key manager initialization** - `initAsNode()` and `initAsMobile()`
- **Core envelope encryption/decryption** - `nodeEncryptWithEnvelope`, `nodeDecryptEnvelope`
- **Network key management** - `mobile_*` functions for network operations
- **Transport operations** - `Transport` class for QUIC transport
- **Discovery operations** - `Discovery` class for peer discovery

### Issues to Fix
1. **Outdated NodeKeyManager API** - Current API uses old lifecycle patterns
2. **Missing new APIs** - Profile key management, CA Node operations, certificate management
3. **Type mismatches** - Some return types don't match current API
4. **Missing error handling** - New error types not exposed
5. **Inconsistent patterns** - Not following same patterns as C FFI

## Required Changes

### 1. NodeKeyManager Lifecycle Updates (CRITICAL)

#### Current Problem
```rust
// Current NodeJS API (WRONG)
let mut node = NodeKeyManager::new(logger)?; // Generates keys immediately
let state_loaded = node.probe_and_load_state()?;
if !state_loaded {
    node.generate_keys()?; // Generate keys only when needed
}
```

#### Required Fix
```rust
// New NodeJS API (CORRECT)
let node = NodeKeyManager::new(logger)?; // No key generation
let state_loaded = node.probe_and_load_state()?;
if !state_loaded {
    node.generate_keys()?; // Generate keys only when needed
}
```

#### NodeJS Methods to Update
- `initAsNode()` - Update to handle new lifecycle
- `nodeGetKeystoreState()` - Update to handle `Option<String>` return types
- All methods that assume keys exist - Add proper error handling

### 2. New NodeKeyManager APIs (CRITICAL)

#### Profile Key Management
```typescript
// New NodeJS methods needed
export class Keys {
  // Profile key management
  nodeDeriveUserProfileKey(label: string): Uint8Array
  nodeDecryptWithProfile(envelopeData: Uint8Array, profileId: string): Uint8Array
}
```

#### Certificate Management
```typescript
// New NodeJS methods needed
export class Keys {
  // Certificate management
  nodeGetCertificateStatus(): CertificateStatus
  nodeGetQuicCertificateConfig(): QuicCertificateConfig
  nodeValidatePeerCertificate(peerCert: Uint8Array): void
}
```

#### Network Key Management
```typescript
// New NodeJS methods needed
export class Keys {
  // Network key management
  nodeInstallNetworkKey(networkKeyMessage: Uint8Array): void
  nodeGetNetworkAgreement(networkPublicKey: Uint8Array): Uint8Array
  nodeHasNetworkPrivateKey(networkPublicKey: Uint8Array): boolean
}
```

### 3. CA Node APIs (NEW)

#### CA Node Management
```typescript
// New NodeJS class for CA Node operations
export class CaNode {
  constructor(logger: Logger)
  
  // CA Node management
  installIssuingCa(
    issuingCaKey: Uint8Array,
    issuingCaCert: Uint8Array,
    rootCaCert: Uint8Array,
    eaPublicKeys: Uint8Array[]
  ): void
  
  configureEnrollmentAuthority(eaPublicKeys: Uint8Array[]): void
}
```

#### CA Node Operations
```typescript
export class CaNode {
  // Enrollment operations
  handleEnroll(request: Uint8Array, remoteAddr: string): Uint8Array
  
  // Renewal operations
  handleRenew(request: Uint8Array, peerCert: Uint8Array): Uint8Array
  
  // Revocation operations
  handleRevoke(request: Uint8Array, adminSki: string): Uint8Array
  
  // Chain and status operations
  handleChain(networkId: string): Uint8Array
  handleStatus(networkId: string): Uint8Array
  
  // CRL operations
  handleCrl(networkId: string): Uint8Array
}
```

### 4. CA Server APIs (NEW)

#### CA Server Management
```typescript
// New NodeJS class for CA Server operations
export class CaServer {
  constructor(config: CaServerConfig, caNode: CaNode, logger: Logger)
  
  // CA Server management
  configureAdminSkis(adminSkis: string[]): void
  
  // CA Server operations
  start(): Promise<void>
  stop(): Promise<void>
  
  getBootstrapAddr(): string
  getAuthenticatedAddr(): string
}
```

### 5. CA Client APIs (NEW)

#### CA Client Management
```typescript
// New NodeJS class for CA Client operations
export class CaClient {
  constructor(logger: Logger)
  
  // CA Client operations
  enroll(bootstrapAddr: string, request: Uint8Array): Promise<Uint8Array>
  renew(authenticatedAddr: string, request: Uint8Array): Promise<Uint8Array>
  revoke(authenticatedAddr: string, request: Uint8Array): Promise<Uint8Array>
  
  getChain(bootstrapAddr: string, networkId: string): Promise<Uint8Array>
  getStatus(authenticatedAddr: string, networkId: string): Promise<Uint8Array>
  getCrl(authenticatedAddr: string, networkId: string): Promise<Uint8Array>
}
```

### 6. Updated Return Types and Error Handling

#### Updated Return Types
```typescript
// Current (WRONG)
export class Keys {
  nodeGetNodeId(): string
  nodeGetPublicKey(): Uint8Array
}

// New (CORRECT)
export class Keys {
  nodeGetNodeId(): string | null
  nodeGetPublicKey(): Uint8Array | null
  nodeGetStorageKey(): Uint8Array | null
}
```

#### New Error Types
```typescript
// Add new error types for CA operations
export enum RunarError {
  CA_NODE_NOT_INITIALIZED = 'CA_NODE_NOT_INITIALIZED',
  CA_SERVER_NOT_RUNNING = 'CA_SERVER_NOT_RUNNING',
  CA_CLIENT_CONNECTION_FAILED = 'CA_CLIENT_CONNECTION_FAILED',
  CERTIFICATE_VALIDATION_FAILED = 'CERTIFICATE_VALIDATION_FAILED',
  PROFILE_KEY_NOT_FOUND = 'PROFILE_KEY_NOT_FOUND',
  ENROLLMENT_TOKEN_INVALID = 'ENROLLMENT_TOKEN_INVALID',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  ADMIN_NOT_AUTHORIZED = 'ADMIN_NOT_AUTHORIZED'
}
```

### 7. Data Structures for NodeJS

#### New TypeScript interfaces
```typescript
// CA Server Configuration
export interface CaServerConfig {
  bootstrapBind: string
  authenticatedBind: string
  networkId: string
  rateLimitPerMinute: number
  rateLimitPerHour: number
}

// CA Client Configuration
export interface CaClientConfig {
  rootCaCert: Uint8Array
  timeoutSeconds: number
}

// Certificate Status
export interface CertificateStatus {
  isValid: boolean
  notBefore: number
  notAfter: number
  serialHex: string
}

// Profile Key Info
export interface ProfileKeyInfo {
  profileId: string
  publicKey: Uint8Array
}

// Quic Certificate Config
export interface QuicCertificateConfig {
  certificateChain: Uint8Array[]
  privateKey: Uint8Array
}

// Logger interface
export interface Logger {
  // Logger methods as needed
}
```

## Implementation Plan

### Phase 1: Complete NodeJS API Rewrite (CRITICAL)
1. **Delete existing NodeJS API** - Remove all old methods
2. **Create new API structure** - Clean, modern API design following C FFI patterns
3. **Implement core key managers** - NodeKeyManager and MobileKeyManager with proper lifecycle
4. **Add proper error handling** - Comprehensive error types and validation

### Phase 2: NodeKeyManager Dual-Role APIs
1. **Profile key management** - deriveUserProfileKey, decryptWithProfile
2. **Certificate management** - getCertificateStatus, getQuicCertificateConfig
3. **Network key management** - installNetworkKey, getNetworkAgreement
4. **Lifecycle management** - proper key generation and state loading

### Phase 3: CA Node Infrastructure
1. **CA Node creation** - new, installIssuingCa, configureEnrollmentAuthority
2. **CA operations** - handleEnroll, handleRenew, handleRevoke, handleChain, handleStatus, handleCrl
3. **Error handling** - specific error types for CA operations
4. **TypeScript definitions** - proper type definitions for all new APIs

### Phase 4: CA Server/Client Transport
1. **CA Server** - creation, configuration, start/stop, admin management
2. **CA Client** - creation, all CA operations (enroll, renew, revoke, chain, status, CRL)
3. **Transport integration** - proper QUIC transport handling
4. **Configuration** - server and client configuration interfaces

### Phase 5: Testing and Validation
1. **Unit tests** - Test each NodeJS method individually
2. **Integration tests** - Test end-to-end scenarios
3. **TypeScript tests** - Validate type definitions
4. **Performance tests** - Ensure efficient NodeJS API design

## Full Refactor Approach

### No Backward Compatibility
- **Complete rewrite** of NodeJS API to align with latest design
- **Clean, modern API** following current best practices
- **No legacy support** - all APIs are new and properly designed
- **Single source of truth** - NodeJS API directly exposes current crate APIs

### Design Principles
- **Clean API surface** - Only expose what's actually needed
- **Consistent patterns** - All methods follow the same naming and parameter conventions as C FFI
- **Proper error handling** - Comprehensive error types and validation
- **Type safety** - Full TypeScript support with proper type definitions
- **Performance first** - Efficient NodeJS API design with minimal overhead

## API Structure

### Core Classes
```typescript
// Main key management
export class Keys {
  // NodeKeyManager methods
  initAsNode(): void
  nodeDeriveUserProfileKey(label: string): Uint8Array
  nodeDecryptWithProfile(envelopeData: Uint8Array, profileId: string): Uint8Array
  nodeGetCertificateStatus(): CertificateStatus
  nodeGetQuicCertificateConfig(): QuicCertificateConfig
  nodeValidatePeerCertificate(peerCert: Uint8Array): void
  nodeInstallNetworkKey(networkKeyMessage: Uint8Array): void
  nodeGetNetworkAgreement(networkPublicKey: Uint8Array): Uint8Array
  nodeHasNetworkPrivateKey(networkPublicKey: Uint8Array): boolean
  
  // MobileKeyManager methods (existing)
  initAsMobile(): void
  mobileInitializeUserRootKey(): Promise<void>
  // ... other mobile methods
}

// CA Node operations
export class CaNode {
  constructor(logger: Logger)
  installIssuingCa(...): void
  configureEnrollmentAuthority(...): void
  handleEnroll(...): Uint8Array
  handleRenew(...): Uint8Array
  handleRevoke(...): Uint8Array
  handleChain(...): Uint8Array
  handleStatus(...): Uint8Array
  handleCrl(...): Uint8Array
}

// CA Server operations
export class CaServer {
  constructor(config: CaServerConfig, caNode: CaNode, logger: Logger)
  configureAdminSkis(...): void
  start(): Promise<void>
  stop(): Promise<void>
  getBootstrapAddr(): string
  getAuthenticatedAddr(): string
}

// CA Client operations
export class CaClient {
  constructor(logger: Logger)
  enroll(...): Promise<Uint8Array>
  renew(...): Promise<Uint8Array>
  revoke(...): Promise<Uint8Array>
  getChain(...): Promise<Uint8Array>
  getStatus(...): Promise<Uint8Array>
  getCrl(...): Promise<Uint8Array>
}

// Transport (existing, preserved)
export class Transport {
  // ... existing methods preserved
}

// Discovery (existing, preserved)
export class Discovery {
  // ... existing methods preserved
}
```

## Security Considerations

### Input Validation
- All string inputs must be validated for proper encoding
- All buffer inputs must be validated for length and format
- All certificate inputs must be validated for format

### Error Handling
- Never expose internal error details to NodeJS
- Always return appropriate error types
- Log detailed errors internally for debugging

### Memory Management
- Proper handling of Uint8Array conversions
- Efficient serialization/deserialization
- Prevent memory leaks in async operations

## Testing Strategy

### Unit Tests
- Test each new NodeJS method individually
- Test error handling and edge cases
- Test TypeScript type definitions

### Integration Tests
- Test integration with existing transport
- Test end-to-end CA operations
- Test profile key management scenarios

### TypeScript Tests
- Test type definitions compilation
- Test type safety and inference
- Test API documentation generation

## Conclusion

This design provides a comprehensive update to the NodeJS API that:
1. Fixes existing issues with NodeKeyManager lifecycle
2. Exposes all new APIs from the dual-role design
3. Preserves working transport and discovery functionality
4. Follows same patterns as C FFI for consistency
5. Provides full TypeScript support
6. Ensures security and proper error handling

The implementation should follow the phased approach to minimize risk and ensure each component is properly tested before moving to the next phase.
