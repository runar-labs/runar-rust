//! NodeJS Native API End-to-End Integration Tests with REAL QUIC mTLS
//!
//! This test validates the complete CA Node infrastructure using the NodeJS native API with ACTUAL QUIC mTLS connections,
//! including bootstrap enrollment, mTLS participation, renewal, and CRL-lite enforcement.
//!
//! Test phases:
//! 1. CA Node server setup via NodeJS API with REAL QUIC mTLS
//! 2. Mobile node enrollment via NodeJS API with REAL QUIC mTLS
//! 3. Certificate renewal over NodeJS API with REAL QUIC mTLS
//! 4. Certificate revocation and CRL-lite over NodeJS API with REAL QUIC mTLS
//! 5. Profile key interop over NodeJS API with REAL QUIC mTLS
//! 6. Rate limiting over NodeJS API with REAL QUIC mTLS
//! 7. Token revocation over NodeJS API with REAL QUIC mTLS

import { testNodejsFullTransportE2eQuicMtls } from './nodejs_ffi_e2e_integration_test';

describe('NodeJS FFI E2E Integration Tests', () => {
    it('should complete full transport E2E QUIC mTLS test', async () => {
        // Set timeout to 45 seconds to match FFI test timeout
        jest.setTimeout(45000);
        
        await testNodejsFullTransportE2eQuicMtls();
    }, 45000);
});
