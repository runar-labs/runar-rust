we have updated the FFI interface to alignw the lates transporter API and also add all the new CA APIS from transporter an Keys crate -> specifiedin this design @FFI_API_DESIGN.md - now we need to do the same for the @runar-nodejs-api/ which shuold match the FFi 100% .. it should have the same APIS have the exact same behaviour.. just using the NAPI standards and best pracfices.. so lets do a detailed design with all the changes neede to bring the @runar-nodejs-api/ to full alignemtn with the FFI API @runar-ffi/  .. and at the end we need an e2e test exactly like the @ffi_e2e_integration_test.rs for the nodeJS native API also.. that provdes that all the APIS work properly and as expected..  thiis is a Analisya and design exercice.. no code changes.. focus on doing a proper details anlasys..  on guesses. no assumtoins. check the code carefuly and check teh document carefuly and lets produce a design details with every functoins name, paramter, return types,, serializxation.. etc etc.. and prduce a complete details desigjn with all the chagne and new things needed in the nodejs native API - add the design to this file @Update_design.md  (do not remove the promp at the top, just add your analisys and design bellow it.



# NodeJS API Alignment with FFI API - Complete Design Analysis

## Executive Summary

The current NodeJS API (`runar-nodejs-api`) is significantly behind the updated FFI API (`runar-ffi`) in terms of functionality. The FFI API has been completely updated to include all CA Node operations, CA Server operations, CA Client operations, certificate management, enrollment token management, and profile key operations. The NodeJS API currently only supports basic key management and transport operations.

**Key Findings:**
- **Missing APIs**: 47+ new API functions need to be added to NodeJS API
- **Architecture Gap**: NodeJS API lacks CA infrastructure, certificate management, and enrollment workflows
- **Test Coverage**: No E2E test equivalent to `ffi_e2e_integration_test.rs`
- **Serialization**: All new APIs use CBOR serialization for complex data structures

## Current State Analysis

### Existing NodeJS API (What's Working)
```typescript
// Current NodeJS API Classes
export class Keys {
  // Basic key management (✅ Working)
  initAsMobile(): void
  initAsNode(): void
  setPersistenceDir(dir: string): void
  mobileInitializeUserRootKey(): Promise<void>
  
  // Envelope encryption (✅ Working)
  mobileEncryptWithEnvelope(data: Uint8Array, networkPublicKey?: Uint8Array, profilePublicKeys: Array<Uint8Array>): Uint8Array
  nodeEncryptWithEnvelope(data: Uint8Array, networkPublicKey?: Uint8Array, profilePublicKeys: Array<Uint8Array>): Uint8Array
  
  // Basic operations (✅ Working)
  nodeGetNodeId(): string
  nodeGetPublicKey(): Uint8Array
  nodeGenerateCsr(): Uint8Array
  nodeInstallCertificate(ncmCbor: Uint8Array): void
  
  // Mobile operations (✅ Working)
  mobileProcessSetupToken(stCbor: Uint8Array): Uint8Array
  mobileDeriveUserProfileKey(label: string): Uint8Array
  mobileGetUserPublicKey(): Uint8Array
  nodeGetAgreementPublicKey(): Uint8Array
}

export class Transport {
  // QUIC transport (✅ Working)
  start(): Promise<void>
  stop(): Promise<void>
  request(path: string, correlationId: string, payload: Uint8Array, destPeerId: string, ...): Promise<Uint8Array>
  publish(path: string, correlationId: string, payload: Uint8Array, destPeerId: string, ...): Promise<void>
}

export class Discovery {
  // mDNS discovery (✅ Working)
  startAnnouncing(): Promise<void>
  stopAnnouncing(): Promise<void>
}
```

### Missing APIs (Critical Gap)
The NodeJS API is missing **ALL** of the following major API categories:

1. **CA Node Management** (12 functions)
2. **CA Server Operations** (7 functions) 
3. **CA Client Operations** (7 functions)
4. **Certificate Authority Creation** (6 functions)
5. **Enrollment Token Management** (2 functions)
6. **Mobile Key Manager Integration** (2 functions)
7. **Certificate Management** (6 functions)
8. **Profile Key Operations** (3 functions)
9. **CA Node Admin Management** (3 functions)

## Detailed API Design

### 1. CA Node Management APIs

#### 1.1 CA Node Class
```typescript
export class CaNode {
  constructor(logger: Logger)
  
  // Core CA Node operations
  installIssuingCa(
    issuingKeyDer: Uint8Array,
    issuingCertDer: Uint8Array, 
    rootCaDer: Uint8Array,
    eaPublicKeysCbor: Uint8Array,
    networkId: string
  ): Promise<void>
  
  configureEnrollmentAuthority(eaPublicKeysCbor: Uint8Array): Promise<void>
  
  // CA Node request handlers
  handleEnroll(
    requestCbor: Uint8Array, 
    remoteAddr: string
  ): Promise<Uint8Array>
  
  handleRenew(
    requestCbor: Uint8Array,
    peerCertDer: Uint8Array
  ): Promise<Uint8Array>
  
  handleRevoke(
    requestCbor: Uint8Array,
    adminSki: string
  ): Promise<Uint8Array>
  
  handleChain(networkId: string): Promise<Uint8Array>
  handleStatus(networkId: string): Promise<Uint8Array>
  handleCrl(networkId: string): Promise<Uint8Array>
  
  // Admin operations
  addAdminSki(ski: string): Promise<void>
  revokeToken(tokenId: string): Promise<void>
  generateCrlLite(): Promise<Uint8Array>
  
  // Resource management
  createShared(): Promise<CaNodeShared>
  free(): void
}
```

#### 1.2 CA Node Shared Class
```typescript
export class CaNodeShared {
  addAdminSki(ski: string): Promise<void>
  free(): void
}
```

### 2. CA Server Operations APIs

#### 2.1 CA Server Class
```typescript
export class CaServer {
  constructor(
    configCbor: Uint8Array,
    sharedCaNode: CaNodeShared,
    logger: Logger
  )
  
  // Server control
  start(): Promise<void>
  stop(): Promise<void>
  
  // Address management
  getBootstrapAddr(): Promise<string>
  getAuthenticatedAddr(): Promise<string>
  
  // Admin configuration
  configureAdminSkis(adminSkisCbor: Uint8Array): Promise<void>
  
  // Resource management
  free(): void
}
```

### 3. CA Client Operations APIs

#### 3.1 CA Client Class
```typescript
export class CaClient {
  constructor(
    configCbor: Uint8Array,
    nodeKeys: Keys,
    logger: Logger
  )
  
  // CA operations
  enroll(
    bootstrapAddr: string,
    requestCbor: Uint8Array
  ): Promise<Uint8Array>
  
  renew(
    authenticatedAddr: string,
    requestCbor: Uint8Array
  ): Promise<Uint8Array>
  
  revoke(
    authenticatedAddr: string,
    requestCbor: Uint8Array
  ): Promise<Uint8Array>
  
  // Information retrieval
  getChain(
    bootstrapAddr: string,
    networkId: string
  ): Promise<Uint8Array>
  
  getStatus(
    authenticatedAddr: string,
    networkId: string
  ): Promise<Uint8Array>
  
  getCrl(
    authenticatedAddr: string,
    networkId: string
  ): Promise<Uint8Array>
  
  // Resource management
  free(): void
}
```

### 4. Certificate Authority Creation APIs

#### 4.1 CA Creation Class
```typescript
export class CaCreator {
  // Root CA creation
  static createRootCa(subject: string): Promise<Ca>
  
  // Issuing CA creation
  static createIssuingCa(
    rootCa: Ca,
    subject: string,
    validityDays: number,
    serial: number
  ): Promise<Ca>
  
  // CA operations
  getCertificateDer(): Uint8Array
  getCertificateSubject(): string
  free(): void
}
```

### 5. Enrollment Token Management APIs

#### 5.1 Enrollment Token Class
```typescript
export class EnrollmentToken {
  // Token generation
  static generate(
    eaKey: Uint8Array,
    tokenId: string,
    networkId: string,
    subject: string,
    notBefore: number,
    expiresAt: number,
    nonce: Uint8Array,
    permissions: Uint8Array
  ): Promise<Uint8Array>
  
  // Token validation
  static validate(
    token: Uint8Array,
    eaPublicKey: Uint8Array
  ): Promise<boolean>
}
```

### 6. Enhanced Keys Class

#### 6.1 Updated Keys Class
```typescript
export class Keys {
  // Existing methods (✅ Keep as-is)
  // ... all existing methods ...
  
  // NEW: State management (following FFI design)
  nodeProbeAndLoadState(): Promise<boolean>
  nodeGenerateKeys(): Promise<void>
  
  // NEW: Certificate management
  nodeGetQuicCertificateConfig(): Promise<Uint8Array>
  nodeGetNodeCertificate(): Promise<Uint8Array>
  nodeInstallCertificateFromMessage(certMessage: Uint8Array): Promise<void>
  
  // NEW: Profile key operations
  nodeDeriveUserProfileKey(label: string): Promise<Uint8Array>
  nodeDecryptWithProfile(
    envelopeCbor: Uint8Array,
    profileId: string
  ): Promise<Uint8Array>
  
  // NEW: Mobile response conversion
  mobileFromEnrollResponse(
    responseCbor: Uint8Array
  ): Promise<Uint8Array>
  
  mobileFromRenewResponse(
    responseCbor: Uint8Array
  ): Promise<Uint8Array>
  
  // NEW: Certificate analysis
  static certificateExtractSki(certDer: Uint8Array): Promise<string>
  static certificateGetSerial(certDer: Uint8Array): Promise<string>
}
```

### 7. Data Structures and Types

#### 7.1 Configuration Types
```typescript
// CA Server Configuration
export interface CaServerConfig {
  bootstrap_bind: string
  authenticated_bind: string
  network_id: string
  rate_limit_per_minute: number
  rate_limit_per_hour: number
}

// CA Client Configuration
export interface CaClientConfigAll {
  bootstrap_server: string
  authenticated_server: string
  network_id: string
  request_timeout_seconds: number
  max_retries: number
  root_ca_der: Uint8Array
  issuing_ca_der: Uint8Array
}

// Certificate Status
export interface CertificateStatus {
  is_valid: boolean
  not_before: number
  not_after: number
  serial_hex: string
}

// Profile Key Info
export interface ProfileKeyInfo {
  profile_id: string
  public_key: Uint8Array
  public_key_len: number
}

// Enrollment Token Parameters
export interface EnrollmentTokenParams {
  token_id: string
  network_id: string
  subject: string
  not_before: number
  expires_at: number
  nonce: Uint8Array
  permissions: Uint8Array
}
```

#### 7.2 Request/Response Types
```typescript
// CA Node Request/Response Types (CBOR-serialized)
export interface CsrEnrollRequest {
  network_id: string
  csr_der: Uint8Array
  enrollment_token: Uint8Array
}

export interface CsrEnrollResponse {
  // CBOR-serialized response
}

export interface RenewRequest {
  network_id: string
  csr_der: Uint8Array
}

export interface RenewResponse {
  // CBOR-serialized response
}

export interface RevokeRequest {
  network_id: string
  certificate_serial: Uint8Array
  reason: string
}

export interface RevokeResponse {
  // CBOR-serialized response
}

export interface ChainResponse {
  // CBOR-serialized response
}

export interface StatusResponse {
  // CBOR-serialized response
}

export interface CrlResponse {
  // CBOR-serialized response
}
```

## Implementation Strategy

### Phase 1: Core Infrastructure (Weeks 1-2)
1. **Add new classes**: `CaNode`, `CaServer`, `CaClient`, `CaCreator`, `EnrollmentToken`
2. **Update Keys class**: Add new methods for state management and certificate operations
3. **Add data structures**: All TypeScript interfaces and types
4. **Update build system**: Ensure NAPI-RS can handle new classes

### Phase 2: CA Node Implementation (Weeks 3-4)
1. **Implement CaNode class**: All CA Node operations
2. **Implement CaNodeShared class**: Shared CA Node reference
3. **Add admin operations**: SKI management, token revocation, CRL generation
4. **Add error handling**: Comprehensive error codes and validation

### Phase 3: CA Server Implementation (Weeks 5-6)
1. **Implement CaServer class**: Server creation, start/stop, address management
2. **Add admin configuration**: Admin SKI configuration
3. **Add QUIC integration**: Real QUIC mTLS server operations
4. **Add rate limiting**: Server-side rate limiting implementation

### Phase 4: CA Client Implementation (Weeks 7-8)
1. **Implement CaClient class**: All client operations
2. **Add configuration management**: CBOR-based configuration
3. **Add QUIC integration**: Real QUIC mTLS client operations
4. **Add error handling**: Client-specific error handling

### Phase 5: Certificate Management (Weeks 9-10)
1. **Implement CaCreator class**: Root CA and Issuing CA creation
2. **Add certificate operations**: Certificate analysis and management
3. **Add enrollment token management**: Token generation and validation
4. **Add mobile integration**: Response conversion functions

### Phase 6: Testing and Validation (Weeks 11-12)
1. **Create E2E test**: Equivalent to `ffi_e2e_integration_test.rs`
2. **Add unit tests**: Individual API function tests
3. **Add integration tests**: Cross-component integration tests
4. **Add performance tests**: Performance validation and benchmarking

## E2E Test Design

### Test Structure
```typescript
// tests/ca_e2e_integration_test.ts
describe('CA E2E Integration Test', () => {
  test('should handle complete CA Node infrastructure with REAL QUIC mTLS', async () => {
    // Phase 1: Setup
    // Phase 2: CA Node and Server
    // Phase 3: Mobile Node CSR and Enrollment
    // Phase 4: Certificate Renewal via REAL QUIC mTLS
    // Phase 5: Certificate Revocation + CRL-lite via REAL QUIC mTLS
    // Phase 6: Status and Chain via REAL QUIC mTLS
    // Phase 7: Profile Key Functionality via REAL QUIC mTLS
    // Phase 8: Rate Limiting via REAL QUIC mTLS
    // Phase 9: Token Revocation via REAL QUIC mTLS
    // Phase 10: Negative Cases via REAL QUIC mTLS
  }, 90000) // 90-second timeout
})
```

### Test Phases (Matching FFI E2E Test)
1. **Setup**: Logger, crypto provider, key handles
2. **CA Node and Server**: CA Node creation, certificate chain, server setup
3. **Mobile Node Enrollment**: CSR generation, enrollment token, certificate installation
4. **Certificate Renewal**: Renewal CSR, mTLS renewal, certificate installation
5. **Certificate Revocation**: Admin SKI setup, revocation, CRL generation
6. **Status and Chain**: CA status, certificate chain retrieval
7. **Profile Key Functionality**: Profile key derivation, encryption/decryption
8. **Rate Limiting**: Multiple enrollment requests, rate limit validation
9. **Token Revocation**: Token revocation, revoked token rejection
10. **Negative Cases**: Invalid tokens, unauthorized operations

## Serialization Strategy

### CBOR Serialization
All complex data structures use CBOR serialization, matching the FFI API:

```typescript
// Example: CA Server Configuration
const config: CaServerConfig = {
  bootstrap_bind: "127.0.0.1:0",
  authenticated_bind: "127.0.0.1:0", 
  network_id: "test_network",
  rate_limit_per_minute: 5,
  rate_limit_per_hour: 30
}

const configCbor = cbor.encode(config)
```

### Type Safety
All CBOR operations are type-safe with proper TypeScript interfaces:

```typescript
// Type-safe CBOR operations
const request: CsrEnrollRequest = {
  network_id: "test_network",
  csr_der: csrBytes,
  enrollment_token: tokenBytes
}

const requestCbor = cbor.encode(request)
const responseCbor = await caClient.enroll(bootstrapAddr, requestCbor)
const response = cbor.decode<CsrEnrollResponse>(responseCbor)
```

## Error Handling Strategy

### Error Codes
All APIs return proper error codes matching the FFI API:

```typescript
// Error codes (matching FFI)
export const ERROR_CODES = {
  CA_NODE_NOT_INITIALIZED: 1001,
  CA_SERVER_NOT_RUNNING: 1002,
  CA_CLIENT_CONNECTION_FAILED: 1003,
  CERTIFICATE_VALIDATION_FAILED: 1004,
  PROFILE_KEY_NOT_FOUND: 1005,
  ENROLLMENT_TOKEN_INVALID: 1006,
  RATE_LIMIT_EXCEEDED: 1007,
  ADMIN_NOT_AUTHORIZED: 1008,
  // ... more error codes
}
```

### Error Handling Pattern
```typescript
try {
  const result = await caClient.enroll(bootstrapAddr, requestCbor)
  return result
} catch (error) {
  if (error.code === ERROR_CODES.RATE_LIMIT_EXCEEDED) {
    // Handle rate limiting
  } else if (error.code === ERROR_CODES.CA_CLIENT_CONNECTION_FAILED) {
    // Handle connection failure
  }
  throw error
}
```

## Memory Management Strategy

### Resource Lifecycle
All resources follow proper lifecycle management:

```typescript
// Resource creation
const caNode = new CaNode(logger)
const caServer = new CaServer(configCbor, sharedCaNode, logger)
const caClient = new CaClient(configCbor, nodeKeys, logger)

// Resource usage
await caServer.start()
const result = await caClient.enroll(bootstrapAddr, requestCbor)

// Resource cleanup
caClient.free()
caServer.free()
caNode.free()
```

### Async Operations
All operations are properly async to match NodeJS patterns:

```typescript
// Async operations
export class CaNode {
  async installIssuingCa(...): Promise<void>
  async handleEnroll(...): Promise<Uint8Array>
  async handleRenew(...): Promise<Uint8Array>
  // ... all operations are async
}
```

## Performance Considerations

### Memory Efficiency
- Use `Uint8Array` for binary data (no unnecessary conversions)
- Implement proper resource cleanup
- Use streaming for large data operations

### Async Performance
- All operations are async to avoid blocking
- Use proper error handling to prevent memory leaks
- Implement timeouts for long-running operations

### CBOR Performance
- Use efficient CBOR serialization/deserialization
- Cache frequently used data structures
- Minimize data copying

## Security Considerations

### Input Validation
- Validate all string inputs for null termination
- Validate all buffer inputs for length
- Validate all certificate inputs for format

### Error Handling
- Never expose internal error details
- Always return appropriate error codes
- Log detailed errors internally for debugging

### Memory Safety
- Proper resource cleanup in error paths
- Prevent memory leaks in async operations
- Use proper TypeScript types for type safety

## Migration Strategy

### Backward Compatibility
- Keep all existing APIs unchanged
- Add new APIs as additional classes
- Maintain existing behavior for current users

### Gradual Migration
- Phase 1: Add new classes alongside existing ones
- Phase 2: Update existing classes with new methods
- Phase 3: Deprecate old patterns (if any)
- Phase 4: Full feature parity with FFI API

## Testing Strategy

### Unit Tests
- Test each new API function individually
- Test error handling and edge cases
- Test memory management and cleanup

### Integration Tests
- Test integration with existing transporter
- Test end-to-end CA operations
- Test profile key management scenarios

### E2E Tests
- Complete E2E test matching `ffi_e2e_integration_test.rs`
- Test all 10 phases of CA operations
- Test REAL QUIC mTLS operations
- Test rate limiting and error handling

### Performance Tests
- Test large data operations
- Test concurrent operations
- Test memory usage and cleanup
- Test CBOR serialization performance

## Conclusion

This design provides a comprehensive roadmap for bringing the NodeJS API into full alignment with the FFI API. The implementation will add 47+ new API functions across 9 major categories, providing complete CA Node infrastructure, certificate management, and enrollment workflows.

**Key Benefits:**
- **100% API Parity**: Complete alignment with FFI API
- **Type Safety**: Full TypeScript support with proper interfaces
- **Performance**: Efficient async operations and memory management
- **Security**: Proper input validation and error handling
- **Testing**: Comprehensive test coverage including E2E tests
- **Maintainability**: Clean architecture following NAPI-RS best practices

**Timeline**: 12 weeks for complete implementation and testing
**Risk Level**: Low (well-defined APIs with clear FFI reference)
**Success Criteria**: All FFI E2E test scenarios pass with NodeJS API

Analysis & Design:
