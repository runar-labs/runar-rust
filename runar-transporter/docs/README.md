# Full Transport End-to-End Test Documentation

## Overview

This directory contains comprehensive documentation for the Full Transport End-to-End test, which validates the complete Runar CA infrastructure with **REAL QUIC mTLS connections**.

## Documentation Structure

### 📋 [Full Transport E2E Design](./full_transport_e2e_design.md)
Complete design document covering:
- Test architecture and components
- Detailed phase descriptions
- Data flow explanations
- Security considerations
- Production readiness validation

### 🔄 [Sequence Diagrams](./sequence_diagrams.md)
Visual representations of all test flows:
- Individual phase sequence diagrams
- Complete end-to-end flow
- Component architecture diagrams
- Data flow and security models

## Quick Reference

### Test Phases
1. **CA Node Infrastructure Setup** - Establish certificate authority
2. **QUIC Transport Setup** - Configure network transport
3. **Enrollment Token Generation** - Create authorization tokens
4. **Mobile Node Enrollment** - Initial certificate issuance
5. **Certificate Renewal** - Certificate lifecycle management
6. **Certificate Revocation** - Revoke compromised certificates
7. **CRL-lite Generation** - Certificate revocation list
8. **CA Status & Chain** - Operational status retrieval
9. **Profile Key Functionality** - User profile key testing
10. **Rate Limiting** - Abuse prevention testing
11. **Token Revocation** - Token lifecycle management
12. **Error Handling** - Security control validation

### Key Components
- **CA Node**: Certificate authority operations
- **CA Server**: QUIC-based server endpoints
- **CA Client**: Mobile node integration
- **QUIC Transport**: Modern secure transport
- **mTLS**: Mutual TLS authentication
- **Device Keystore**: OS-integrated key storage

### Security Features
- ✅ Real QUIC mTLS transport
- ✅ Certificate lifecycle management
- ✅ Rate limiting and abuse prevention
- ✅ Token-based authorization
- ✅ CRL-lite revocation checking
- ✅ Profile key isolation
- ✅ Comprehensive error handling

## Running the Test

```bash
# Run the full transport E2E test
cargo test -p runar_transporter test_full_transport_e2e_quic_mtls -- --nocapture

# Run with specific logging level
RUST_LOG=debug cargo test -p runar_transporter test_full_transport_e2e_quic_mtls -- --nocapture
```

## Test Validation

The test validates 12 critical aspects of the CA infrastructure:

1. **Infrastructure Setup** ✅
2. **QUIC Transport** ✅
3. **Enrollment Process** ✅
4. **Certificate Renewal** ✅
5. **Certificate Revocation** ✅
6. **CRL-lite Generation** ✅
7. **Status & Chain Retrieval** ✅
8. **Profile Key Functionality** ✅
9. **Rate Limiting** ✅
10. **Token Revocation** ✅
11. **Error Handling** ✅
12. **Security Controls** ✅

## Production Readiness

This test serves as the definitive validation that the Runar CA infrastructure is ready for production use with real QUIC mTLS transport, complete certificate lifecycle management, and comprehensive security controls.

## Related Documentation

- [Runar Keys Documentation](../runar-keys/README.md)
- [Runar Transporter Documentation](../runar-transporter/README.md)
- [FFI API Design](../runar-ffi/FFI_API_DESIGN.md)
- [Node.js API Design](../runar-nodejs-api/NODEJS_API_DESIGN.md)
