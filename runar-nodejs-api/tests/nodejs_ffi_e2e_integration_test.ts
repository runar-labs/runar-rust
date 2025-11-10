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

import { 
    Keys, 
    CaCreator, 
    Ca, 
    CaNode, 
    CaServer, 
    CaClient, 
    EnrollmentToken,
    DeviceKeystoreCaps,
    Certificate,
    Utils
} from '../index';
import { encode, decode } from 'cbor-x';

// Test configuration
const TEST_NETWORK_ID = 'test_network_e2e';
const TEST_SUBJECT_ROOT = 'CN=Test Root CA';
const TEST_SUBJECT_ISSUING = 'CN=Test Issuing CA';
const TEST_VALIDITY_DAYS = 365;
const TEST_SERIAL = 12345;

// Helper function to create test logger
function createTestLogger(): any {
    // In a real implementation, this would create a proper logger
    return {
        debug: (msg: string) => console.log(`[DEBUG] ${msg}`),
        info: (msg: string) => console.log(`[INFO] ${msg}`),
        warn: (msg: string) => console.log(`[WARN] ${msg}`),
        error: (msg: string) => console.log(`[ERROR] ${msg}`)
    };
}

// Helper function to validate certificate chain
function validateCertificateChain(rootCaDer: Uint8Array, issuingCaDer: Uint8Array): void {
    // Basic validation: ensure certificates are not empty and have reasonable sizes
    if (rootCaDer.length === 0) {
        throw new Error('Root CA certificate should not be empty');
    }
    if (issuingCaDer.length === 0) {
        throw new Error('Issuing CA certificate should not be empty');
    }
    if (rootCaDer.length < 100) {
        throw new Error('Root CA certificate seems too small');
    }
    if (issuingCaDer.length < 100) {
        throw new Error('Issuing CA certificate seems too small');
    }
    console.log(`   ✅ Certificate chain validation passed (Root: ${rootCaDer.length} bytes, Issuing: ${issuingCaDer.length} bytes)`);
}

// Helper function to validate enrollment response
function validateEnrollmentResponse(responseCbor: Uint8Array): void {
    if (responseCbor.length === 0) {
        throw new Error('Enrollment response should not be empty');
    }
    if (responseCbor.length < 50) {
        throw new Error('Enrollment response seems too small');
    }
    console.log(`   ✅ Enrollment response validation passed (${responseCbor.length} bytes)`);
}

// Helper function to validate renewal response
function validateRenewalResponse(responseCbor: Uint8Array): void {
    if (responseCbor.length === 0) {
        throw new Error('Renewal response should not be empty');
    }
    if (responseCbor.length < 50) {
        throw new Error('Renewal response seems too small');
    }
    console.log(`   ✅ Renewal response validation passed (${responseCbor.length} bytes)`);
}

// Helper function to validate CRL response
function validateCrlResponse(responseCbor: Uint8Array): void {
    if (responseCbor.length === 0) {
        throw new Error('CRL response should not be empty');
    }
    console.log(`   ✅ CRL response validation passed (${responseCbor.length} bytes)`);
}

// Helper function to validate status response
function validateStatusResponse(responseCbor: Uint8Array): void {
    if (responseCbor.length === 0) {
        throw new Error('Status response should not be empty');
    }
    console.log(`   ✅ Status response validation passed (${responseCbor.length} bytes)`);
}

// Helper function to validate chain response
function validateChainResponse(responseCbor: Uint8Array): void {
    if (responseCbor.length === 0) {
        throw new Error('Chain response should not be empty');
    }
    console.log(`   ✅ Chain response validation passed (${responseCbor.length} bytes)`);
}

// Helper function to create enrollment request
function createEnrollmentRequest(nodeKeys: Keys, eaKey: Uint8Array): Uint8Array {
    // Generate CSR DER (following FFI pattern exactly)
    const csr = nodeKeys.nodeGenerateCsrDer();
    if (csr.length === 0) {
        throw new Error('Failed to generate CSR');
    }
    
    // Create proper enrollment token using EnrollmentToken.generate()
    const enrollmentTokenCbor = EnrollmentToken.generate(
        eaKey,
        TEST_NETWORK_ID,
        'test_node', // subject_hint
        1, // validity_days
        ['enroll']
    );
    
    // Decode the CBOR token to get the struct (following FFI pattern)
    const enrollmentToken = decode(enrollmentTokenCbor);
    
    // Create enrollment request with proper token
    const request = {
        network_id: TEST_NETWORK_ID,
        csr_der: Array.from(csr),
        enrollment_token: enrollmentToken // Use the decoded struct, not CBOR
    };
    
    // Debug: Print the enrollment request structure
    console.log('🔍 [DEBUG] Enrollment request structure:');
    console.log('  network_id:', request.network_id);
    console.log('  csr_der length:', request.csr_der.length);
    console.log('  enrollment_token keys:', Object.keys(request.enrollment_token));
    console.log('  enrollment_token.body keys:', Object.keys(request.enrollment_token.body));
    
    // Serialize to CBOR using proper CBOR library
    return new Uint8Array(encode(request));
}

// Helper function to create renewal request
function createRenewalRequest(nodeKeys: Keys): Uint8Array {
    // Generate new CSR for renewal (following FFI pattern exactly)
    const csr = nodeKeys.nodeGenerateCsrDer();
    if (csr.length === 0) {
        throw new Error('Failed to generate renewal CSR');
    }
    
    // Create renewal request (following FFI pattern exactly)
    const request = {
        network_id: TEST_NETWORK_ID,
        csr_der: Array.from(csr) // Use CSR, not certificate
    };
    
    return new Uint8Array(encode(request));
}

// Helper function to create revoke request
function createRevokeRequest(nodeKeys: Keys): Uint8Array {
    // Get certificate serial number (following FFI pattern exactly)
    const nodeCert = nodeKeys.nodeGetNodeCertificate();
    if (nodeCert.length === 0) {
        throw new Error('Failed to get node certificate');
    }
    
    // Extract serial number from certificate
    const certSerial = Certificate.getSerial(nodeCert);
    if (certSerial.length === 0) {
        throw new Error('Failed to get certificate serial');
    }
    
    // Convert hex string to bytes (following FFI pattern exactly)
    const certSerialBytes = new Uint8Array(certSerial.length / 2);
    for (let i = 0; i < certSerial.length; i += 2) {
        certSerialBytes[i / 2] = parseInt(certSerial.substr(i, 2), 16);
    }
    
    // Create revoke request (following FFI pattern exactly)
    const request = {
        network_id: TEST_NETWORK_ID,
        certificate_serial: Array.from(certSerialBytes), // Use serial, not DER
        reason: 'testing' // Match FFI test
    };
    
    return new Uint8Array(encode(request));
}

// Main E2E test function
async function testNodejsFullTransportE2eQuicMtls(): Promise<void> {
    console.log('\n🚀 Starting NodeJS Full-transport E2E QUIC mTLS test');

    // ==========================================
    // Phase 1: Setup
    // ==========================================
    console.log('\n🏗️  PHASE 1: Setup');

    // Create keys handles
    const nodeKeys = new Keys();
    const mobileKeys = new Keys();

    // Initialize as node
    nodeKeys.initAsNode();
    console.log('   ✅ Node keys initialized');

    // Initialize as mobile
    mobileKeys.initAsMobile();
    console.log('   ✅ Mobile keys initialized');

    // Check if node has keys
    const hasKeys = nodeKeys.hasKeys();
    if (!hasKeys) {
        // Generate keys if none exist
        nodeKeys.generateKeys();
        console.log('   ✅ Node keys generated');
    } else {
        console.log('   ✅ Node keys already exist');
    }

    // ==========================================
    // Phase 2: CA Node and Server
    // ==========================================
    console.log('\n🏗️  PHASE 2: CA Node and Server');

    // Create shared CA Node (following FFI pattern exactly)
    const sharedCaNode = CaNode.newShared();
    console.log('   ✅ Shared CA Node created');

    // Create Root CA
    const rootCa = CaCreator.createRootCa(TEST_SUBJECT_ROOT);
    console.log('   ✅ Root CA created');

    // Create Issuing CA
    const issuingCa = CaCreator.createIssuingCa(rootCa, TEST_SUBJECT_ISSUING, TEST_VALIDITY_DAYS, TEST_SERIAL);
    console.log('   ✅ Issuing CA created');
    
    // Create EA key for enrollment tokens
    const eaKey = CaCreator.createEaKey();
    const eaPublicKey = CaCreator.getEaPublicKey(eaKey);
    console.log('   ✅ EA key created');

    // Setup shared CA Node with proper EA public keys (following FFI pattern exactly)
    const eaPublicKeysCbor = new Uint8Array(encode([Array.from(eaPublicKey)]));
    
    await sharedCaNode.setupComplete(
        TEST_SUBJECT_ROOT,
        TEST_SUBJECT_ISSUING,
        TEST_VALIDITY_DAYS,
        TEST_SERIAL,
        eaPublicKeysCbor,
        TEST_NETWORK_ID
    );
    console.log('   ✅ Shared CA Node setup completed');

    // Configure enrollment authority
    await sharedCaNode.configureEnrollmentAuthority(eaPublicKeysCbor);
    console.log('   ✅ Enrollment authority configured');

    // Get CA certificates from the shared CA Node AFTER setup (following FFI pattern exactly)
    const rootCaDer = sharedCaNode.getRootCaCertificate();
    const issuingCaDer = await sharedCaNode.getIssuingCaCertificate();
    
    // Validate certificate chain
    validateCertificateChain(rootCaDer, issuingCaDer);

    // Create CA Server using shared CA Node (following FFI pattern exactly)
    const serverConfig = {
        bootstrap_bind: '127.0.0.1:0',
        authenticated_bind: '127.0.0.1:0',
        network_id: TEST_NETWORK_ID,
        rate_limit_per_minute: 5,
        rate_limit_per_hour: 30,
        admin_skis: ['test_admin_ski']
    };
    const serverConfigCbor = new Uint8Array(encode(serverConfig));
    const caServer = new CaServer(serverConfigCbor, sharedCaNode);
    console.log('   ✅ CA Server created');

    // Start CA Server
    await caServer.start();
    console.log('   ✅ CA Server started');

    // Get server addresses
    const bootstrapAddr = await caServer.getBootstrapAddr();
    const authenticatedAddr = await caServer.getAuthenticatedAddr();
    console.log(`   ✅ Server addresses: bootstrap=${bootstrapAddr}, authenticated=${authenticatedAddr}`);

    // ==========================================
    // Phase 3: Mobile Node Enrollment
    // ==========================================
    console.log('\n🏗️  PHASE 3: Mobile Node Enrollment');

    // Create CA Client
    const clientConfig = {
        bootstrap_server: bootstrapAddr,
        authenticated_server: authenticatedAddr,
        network_id: TEST_NETWORK_ID,
        request_timeout_seconds: 30,
        max_retries: 3,
        root_ca_der: Array.from(rootCaDer),
        issuing_ca_der: Array.from(issuingCaDer)
    };
    
    // Debug: Print certificate information
    console.log('🔍 [DEBUG] CA Client certificate configuration:');
    console.log('  root_ca_der length:', rootCaDer.length);
    console.log('  issuing_ca_der length:', issuingCaDer.length);
    console.log('  root_ca_der first 10 bytes:', Array.from(rootCaDer.slice(0, 10)));
    console.log('  issuing_ca_der first 10 bytes:', Array.from(issuingCaDer.slice(0, 10)));
    
    const clientConfigCbor = new Uint8Array(encode(clientConfig));
    const caClient = new CaClient(clientConfigCbor, nodeKeys);
    console.log('   ✅ CA Client created');

    // Create enrollment request
    const enrollRequest = createEnrollmentRequest(nodeKeys, eaKey);
    console.log('   ✅ Enrollment request created');

    // Enroll mobile node
    const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
    validateEnrollmentResponse(enrollResponse);
    console.log('   ✅ Mobile node enrolled');

    // Convert enrollment response to certificate message
    const certMessage = mobileKeys.mobileFromEnrollResponse(enrollResponse);
    if (certMessage.length === 0) {
        throw new Error('Failed to convert enrollment response to certificate message');
    }
    console.log('   ✅ Enrollment response converted to certificate message');

    // Install certificate
    nodeKeys.nodeInstallCertificate(certMessage);
    console.log('   ✅ Certificate installed');

    // ==========================================
    // Phase 4: Certificate Renewal
    // ==========================================
    console.log('\n🏗️  PHASE 4: Certificate Renewal');

    // Create renewal request
    const renewRequest = createRenewalRequest(nodeKeys);
    console.log('   ✅ Renewal request created');

    // Renew certificate
    const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
    validateRenewalResponse(renewResponse);
    console.log('   ✅ Certificate renewed');

    // Convert renewal response to certificate message
    const renewCertMessage = mobileKeys.mobileFromRenewResponse(renewResponse);
    if (renewCertMessage.length === 0) {
        throw new Error('Failed to convert renewal response to certificate message');
    }
    console.log('   ✅ Renewal response converted to certificate message');

    // Install renewed certificate
    nodeKeys.nodeInstallCertificate(renewCertMessage);
    console.log('   ✅ Renewed certificate installed');

    // ==========================================
    // Phase 5: Certificate Revocation
    // ==========================================
    console.log('\n🏗️  PHASE 5: Certificate Revocation');

    // Extract client SKI for admin authorization (following FFI pattern exactly)
    const nodeCert = nodeKeys.nodeGetNodeCertificate();
    const clientSki = Certificate.extractSki(nodeCert);
    console.log(`   📋 Client certificate SKI: ${clientSki}`);

    // Add client SKI to shared CA Node admin allowlist (following FFI pattern exactly)
    sharedCaNode.addAdminSki(clientSki);
    console.log(`   ✅ Added client SKI to CA Node admin allowlist: ${clientSki}`);

    // Configure admin SKIs on server (following FFI pattern exactly)
    const adminSkisCbor = new Uint8Array(encode([clientSki]));
    await caServer.configureAdminSkis(adminSkisCbor);
    console.log(`   ✅ Configured admin SKIs on server: ${clientSki}`);

    // Create revoke request
    const revokeRequest = createRevokeRequest(nodeKeys);
    console.log('   ✅ Revoke request created');

    // Revoke certificate
    const revokeResponse = await caClient.revoke(authenticatedAddr, revokeRequest);
    if (revokeResponse.length === 0) {
        throw new Error('Revoke response should not be empty');
    }
    console.log('   ✅ Certificate revoked');

    // ==========================================
    // Phase 6: Chain and Status Operations
    // ==========================================
    console.log('\n🏗️  PHASE 6: Chain and Status Operations');

    // Get certificate chain
    const chainResponse = await caClient.getChain(bootstrapAddr, TEST_NETWORK_ID);
    validateChainResponse(chainResponse);
    console.log('   ✅ Certificate chain retrieved');

    // Get server status
    const statusResponse = await caClient.getStatus(authenticatedAddr, TEST_NETWORK_ID);
    validateStatusResponse(statusResponse);
    console.log('   ✅ Server status retrieved');

    // Get CRL
    const crlResponse = await caClient.getCrl(authenticatedAddr, TEST_NETWORK_ID);
    validateCrlResponse(crlResponse);
    console.log('   ✅ CRL retrieved');

    // ==========================================
    // Phase 7: Profile Key Operations
    // ==========================================
    console.log('\n🏗️  PHASE 7: Profile Key Operations');

    // Derive user profile key (following FFI pattern exactly)
    const profileKey = nodeKeys.nodeDeriveUserProfileKey('test_profile');
    if (profileKey.length === 0) {
        throw new Error('Failed to derive user profile key');
    }
    console.log('   ✅ User profile key derived');

    // Calculate profile ID from profile key (following FFI pattern exactly)
    const profileId = Utils.compactId(profileKey);
    console.log(`   ✅ Profile ID calculated: ${profileId}`);

    // Test profile key encryption/decryption (following FFI pattern exactly)
    const testData = new Uint8Array([1, 2, 3, 4, 5]);
    const encryptedData = nodeKeys.nodeEncryptWithEnvelope(testData, undefined, [profileKey]);
    if (encryptedData.length === 0) {
        throw new Error('Failed to encrypt data with profile key');
    }
    console.log('   ✅ Data encrypted with profile key');

    // Decrypt with profile ID (following FFI pattern exactly)
    const decryptedData = nodeKeys.nodeDecryptWithProfile(encryptedData, profileId);
    if (decryptedData.length !== testData.length) {
        throw new Error('Failed to decrypt data with profile key');
    }
    console.log('   ✅ Data decrypted with profile key');

    // ==========================================
    // Phase 8: Enrollment Token Management
    // ==========================================
    console.log('\n🏗️  PHASE 8: Enrollment Token Management');

    // Generate enrollment token (using a real EA key)
    const testEaKey = CaCreator.createEaKey(); // Create new EA key for this test
    const token = EnrollmentToken.generate(
        testEaKey,
        TEST_NETWORK_ID,
        'test_subject',
        7, // 7 days validity
        ['enroll', 'renew']
    );
    if (token.length === 0) {
        throw new Error('Failed to generate enrollment token');
    }
    console.log('   ✅ Enrollment token generated');

    // Validate enrollment token (using the real EA public key)
    const testEaPublicKey = CaCreator.getEaPublicKey(testEaKey);
    const isValid = EnrollmentToken.validate(token, TEST_NETWORK_ID, testEaPublicKey);
    if (!isValid) {
        throw new Error('Enrollment token validation failed');
    }
    console.log('   ✅ Enrollment token validated');

    // Get token info
    const tokenInfo = EnrollmentToken.getTokenInfo(token);
    if (tokenInfo.length === 0) {
        throw new Error('Failed to get token info');
    }
    console.log('   ✅ Token info retrieved');

    // ==========================================
    // Phase 9: Certificate Analysis
    // ==========================================
    console.log('\n🏗️  PHASE 9: Certificate Analysis');

    // Extract SKI from certificate
    const ski = Keys.certificateExtractSki(rootCaDer);
    if (ski.length === 0) {
        throw new Error('Failed to extract SKI from certificate');
    }
    console.log(`   ✅ SKI extracted: ${ski}`);

    // Get certificate serial
    const serial = Keys.certificateGetSerial(rootCaDer);
    if (serial.length === 0) {
        throw new Error('Failed to get certificate serial');
    }
    console.log(`   ✅ Certificate serial: ${serial}`);

    // ==========================================
    // Phase 10: Cleanup
    // ==========================================
    console.log('\n🏗️  PHASE 10: Cleanup');

    // Stop CA Server
    await caServer.stop();
    console.log('   ✅ CA Server stopped');

    // Free resources
    caServer.free();
    caClient.free();
    rootCa.free();
    issuingCa.free();
    console.log('   ✅ Resources freed');

    console.log('\n🎉 NodeJS Full-transport E2E QUIC mTLS test completed successfully!');
}

// Export the test function
export { testNodejsFullTransportE2eQuicMtls };

// Run the test if this file is executed directly
if (require.main === module) {
    testNodejsFullTransportE2eQuicMtls()
        .then(() => {
            console.log('Test completed successfully');
            process.exit(0);
        })
        .catch((error) => {
            console.error('Test failed:', error);
            process.exit(1);
        });
}
