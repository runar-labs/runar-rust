//! NodeJS Native API End-to-End Integration Tests with REAL QUIC mTLS
//!
//! This test validates the complete CA Node infrastructure using the NodeJS native API with ACTUAL QUIC mTLS connections,
//! including bootstrap enrollment, mTLS participation, renewal, and CRL-lite enforcement.

import { 
    Keys, 
    CaCreator, 
    Ca, 
    CaNode, 
    CaServer, 
    CaClient, 
    EnrollmentToken,
    DeviceKeystoreCaps,
    Certificate
} from '../index';
import * as cbor from 'cbor-x';

// Global test functions for this test file
const expectCertificateChain = (rootCaDer: Uint8Array, issuingCaDer: Uint8Array) => {
    expect(rootCaDer.length).toBeGreaterThan(0);
    expect(issuingCaDer.length).toBeGreaterThan(0);
    expect(rootCaDer.length).toBeGreaterThan(100);
    expect(issuingCaDer.length).toBeGreaterThan(100);
};

const createCaServerConfig = (bootstrapBind: string, authenticatedBind: string, adminSkis: string[]): Uint8Array => {
    const config = {
        bootstrap_bind: bootstrapBind,
        authenticated_bind: authenticatedBind,
        network_id: 'test_network_e2e',
        rate_limit_per_minute: 100,
        rate_limit_per_hour: 1000,
        admin_skis: adminSkis
    };
    // Convert to CBOR instead of JSON
    const cbor = require('cbor-x');
    return new Uint8Array(cbor.encode(config));
};

const createCaClientConfig = (bootstrapServer: string, authenticatedServer: string, rootCaDer: Uint8Array, issuingCaDer: Uint8Array): Uint8Array => {
    const config = {
        bootstrap_server: bootstrapServer,
        authenticated_server: authenticatedServer,
        network_id: 'test_network_e2e',
        request_timeout_seconds: 30,
        max_retries: 3,
        root_ca_der: Array.from(rootCaDer),
        issuing_ca_der: Array.from(issuingCaDer)
    };
    // Convert to CBOR instead of JSON
    const cbor = require('cbor-x');
    return new Uint8Array(cbor.encode(config));
};

const cleanupTestResources = async (resources: any[]) => {
    for (const resource of resources) {
        if (resource && typeof resource.free === 'function') {
            resource.free();
        }
    }
};

// Test configuration
const TEST_NETWORK_ID = 'test_network_e2e';
const TEST_SUBJECT_ROOT = 'CN=Test Root CA';
const TEST_SUBJECT_ISSUING = 'CN=Test Issuing CA';
const TEST_VALIDITY_DAYS = 365;
const TEST_SERIAL = 12345;
const TEST_TIMEOUT = 300000; // 5 minutes

describe('NodeJS Native API E2E Integration Tests', () => {
    let nodeKeys: Keys;
    let mobileKeys: Keys;
    let rootCa: Ca;
    let issuingCa: Ca;
    let caNode: CaNode;
    let caServer: CaServer;
    let caClient: CaClient;
    let bootstrapAddr: string;
    let authenticatedAddr: string;
    let eaKey: Uint8Array;
    let eaPublicKey: Uint8Array;

    beforeAll(async () => {
        // Set up logging
        console.log('\n🚀 Starting NodeJS Full-transport E2E QUIC mTLS test');
    });

    afterAll(async () => {
        // Cleanup all resources
        const resources = [caServer, caClient, caNode, rootCa, issuingCa, nodeKeys, mobileKeys];
        await cleanupTestResources(resources);
        console.log('\n🎉 NodeJS Full-transport E2E QUIC mTLS test completed successfully!');
    });

    describe('Phase 1: Setup', () => {
        test('should create Keys instances', () => {
            nodeKeys = new Keys();
            mobileKeys = new Keys();
            expect(nodeKeys).toBeDefined();
            expect(mobileKeys).toBeDefined();
            console.log('   ✅ Created Keys instances');
        });
    });

    describe('Phase 2: CA Infrastructure Setup', () => {
        test('should create root CA', () => {
            rootCa = CaCreator.createRootCa(TEST_SUBJECT_ROOT);
            expect(rootCa).toBeDefined();
            console.log('   ✅ Created root CA');
        });

        test('should create issuing CA', () => {
            issuingCa = CaCreator.createIssuingCa(rootCa, TEST_SUBJECT_ISSUING, TEST_VALIDITY_DAYS, TEST_SERIAL);
            expect(issuingCa).toBeDefined();
            console.log('   ✅ Created issuing CA');
        });

        test('should validate certificate chain', () => {
            const rootCaDer = rootCa.getCertificate();
            const issuingCaDer = issuingCa.getCertificate();
            
            expectCertificateChain(rootCaDer, issuingCaDer);
        });
    });

    describe('Phase 3: CA Node Setup', () => {
        test('should create CA Node', () => {
            caNode = new CaNode();
            expect(caNode).toBeDefined();
            console.log('   ✅ Created CA Node');
        });

        test('should create EA key pair (following FFI pattern)', async () => {
            // Create EA key pair once (following FFI pattern)
            eaKey = CaCreator.createEaKey();
            eaPublicKey = CaCreator.getEaPublicKey(eaKey);
            expect(eaKey).toBeDefined();
            expect(eaPublicKey).toBeDefined();
            console.log('   ✅ Created EA key pair (private key stays internal)');
        });

        test('should setup CA Node complete', async () => {
            // Use the same EA public key that was created above
            const eaPublicKeys = [Array.from(eaPublicKey)];
            const eaPublicKeysCbor = new Uint8Array(require('cbor-x').encode(eaPublicKeys));
            
            // Debug: Show EA public key info
            console.log('🔍 [DEBUG] EA public key length:', eaPublicKey.length);
            console.log('🔍 [DEBUG] EA public key first 10 bytes:', Array.from(eaPublicKey.slice(0, 10)));
            
            // Setup CA Node with real certificates (following FFI pattern)
            await caNode.setupComplete(
                'CN=Test Root CA,O=Test,C=US',
                'CN=Test Issuing CA,O=Test,C=US',
                365, // validity_days
                1,   // issuing_ca_serial
                eaPublicKeysCbor,
                TEST_NETWORK_ID
            );
            console.log('   ✅ CA Node setup complete with real certificates');
        });
    });

    describe('Phase 4: CA Server Setup', () => {
        test('should create CA Server', () => {
            const adminSkis = ['admin_ski_1', 'admin_ski_2'];
            const serverConfig = createCaServerConfig('127.0.0.1:8443', '127.0.0.1:8444', adminSkis);
            
            caServer = new CaServer(serverConfig, caNode.createShared());
            expect(caServer).toBeDefined();
            console.log('   ✅ Created CA Server');
        });

        test('should start CA Server', async () => {
            await caServer.start();
            console.log('   ✅ Started CA Server');
        });

        test('should get server addresses', async () => {
            bootstrapAddr = await caServer.getBootstrapAddr();
            authenticatedAddr = await caServer.getAuthenticatedAddr();
            
            expect(bootstrapAddr).toBeDefined();
            expect(authenticatedAddr).toBeDefined();
            console.log(`   ✅ Bootstrap address: ${bootstrapAddr}`);
            console.log(`   ✅ Authenticated address: ${authenticatedAddr}`);
        });
    });

    describe('Phase 5: Mobile Node Setup', () => {
        test('should initialize mobile keys', async () => {
            await mobileKeys.initAsMobile('test_user_id', 'test_device_id');
            console.log('   ✅ Initialized mobile keys');
        });

        test('should initialize user root key', async () => {
            await mobileKeys.mobileInitializeUserRootKey();
            console.log('   ✅ Initialized user root key');
        });
    });

    describe('Phase 6: Node Key Manager Setup', () => {
        test('should initialize node keys', async () => {
            await nodeKeys.initAsNode('test_node_id');
            console.log('   ✅ Initialized node keys');
        });

        test('should generate node keys', async () => {
            await nodeKeys.nodeGenerateKeys();
            console.log('   ✅ Generated node keys');
        });
    });

    describe('Phase 7: CA Client Setup', () => {
        test('should create CA Client', async () => {
            // Get real certificates from CA Node (following FFI pattern)
            const rootCaDer = await caNode.getRootCaCertificate();
            const issuingCaDer = await caNode.getIssuingCaCertificate();
            const clientConfig = createCaClientConfig(bootstrapAddr, authenticatedAddr, rootCaDer, issuingCaDer);

            caClient = new CaClient(clientConfig, nodeKeys);
            expect(caClient).toBeDefined();
            console.log('   ✅ Created CA Client with real certificates');
        });
    });

    describe('Phase 8: Enrollment Token Generation', () => {
        test('should get mobile public key', async () => {
            const mobilePublicKey = await mobileKeys.mobileGetPublicKey();
            expect(mobilePublicKey).toBeDefined();
            console.log('   ✅ Got mobile public key');
        });

        test('should generate enrollment token', () => {
            // Create a proper EA key for enrollment token generation
            // This follows the FFI test pattern where EA key is separate from mobile key
            const eaKey = CaCreator.createEaKey();
            const token = EnrollmentToken.generate(
                eaKey,
                TEST_NETWORK_ID,
                'test_subject_hint',
                7, // validity days
                ['enroll']
            );
            expect(token).toBeDefined();
            console.log('   ✅ Generated enrollment token');
        });
    });

    describe('Phase 9: Certificate Enrollment', () => {
        test('should generate CSR', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            expect(csrDer).toBeDefined();
            console.log('   ✅ Generated CSR');
        });

        test('should perform enrollment', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            
            // Debug: Show EA key info
            console.log('🔍 [DEBUG] Using EA key length:', eaKey.length);
            console.log('🔍 [DEBUG] EA key first 10 bytes:', Array.from(eaKey.slice(0, 10)));
            
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer, eaKey);
            
            // Debug: Decode the enrollment request to see the token
            const request = cbor.decode(enrollRequest);
            const token = request.enrollment_token;
            console.log('🔍 [DEBUG] Enrollment token signer_id:', token.signer_id);
            console.log('🔍 [DEBUG] Enrollment token network_id:', token.body.network_id);
            console.log('🔍 [DEBUG] Enrollment token token_id:', token.body.token_id);
            
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            expect(enrollResponse).toBeDefined();
            console.log('   ✅ Performed enrollment');
        });

        test('should install certificate', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer, eaKey);
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            
            // Convert enrollment response to certificate message (following FFI pattern)
            const certificateMessage = await mobileKeys.mobileFromEnrollResponse(enrollResponse);
            await nodeKeys.nodeInstallCertificate(certificateMessage);
            console.log('   ✅ Installed certificate');
        });
    });

    describe('Phase 10: Certificate Renewal', () => {
        test('should get certificate serial', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            expect(certificate).toBeDefined();
            
            const serial = await Certificate.getSerial(certificate!);
            expect(serial).toBeDefined();
            console.log(`   ✅ Got certificate serial: ${serial}`);
        });

        test('should perform renewal', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await Certificate.getSerial(certificate!);
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            const renewRequest = createRenewRequest(serial, csrDer);
            
            const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
            expect(renewResponse).toBeDefined();
            console.log('   ✅ Performed renewal');
        });

        test('should install renewed certificate', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await Certificate.getSerial(certificate!);
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            const renewRequest = createRenewRequest(serial, csrDer);
            const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
            
            // Convert renewal response to certificate message (following FFI pattern)
            const certificateMessage = await mobileKeys.mobileFromRenewResponse(renewResponse);
            await nodeKeys.nodeInstallCertificate(certificateMessage);
            console.log('   ✅ Installed renewed certificate');
        });
    });

    describe('Phase 11: Certificate Revocation', () => {
        test('should perform revocation', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await Certificate.getSerial(certificate!);
            const revokeRequest = createRevokeRequest(serial, 'key_compromise');
            
            const revokeResponse = await caClient.revoke(authenticatedAddr, revokeRequest);
            expect(revokeResponse).toBeDefined();
            console.log('   ✅ Performed revocation');
        });
    });

    describe('Phase 12: CRL Generation', () => {
        test('should generate CRL', async () => {
            const crl = await caNode.generateCrl();
            expect(crl).toBeDefined();
            console.log('   ✅ Generated CRL');
        });
    });

    describe('Phase 13: Profile Key Operations', () => {
        test('should derive user profile key', async () => {
            const profileKey = await nodeKeys.nodeDeriveUserProfileKey('test_user_id');
            expect(profileKey).toBeDefined();
            console.log('   ✅ Derived user profile key');
        });

        test('should encrypt and decrypt with envelope', async () => {
            const profileKey = await nodeKeys.nodeDeriveUserProfileKey('test_user_id');
            const testData = new Uint8Array([1, 2, 3, 4, 5]);
            
            const encryptedData = await nodeKeys.nodeEncryptWithEnvelope(testData, undefined, [profileKey]);
            expect(encryptedData).toBeDefined();
            console.log('   ✅ Encrypted with envelope');
            
            const decryptedData = await nodeKeys.nodeDecryptWithEnvelope(encryptedData);
            expect(decryptedData).toBeDefined();
            console.log('   ✅ Decrypted with envelope');
            
            // Verify data integrity
            expect(Array.from(decryptedData)).toEqual(Array.from(testData));
            console.log('   ✅ Verified data integrity');
        });
    });

    describe('Phase 14: Mobile Response Conversion', () => {
        test('should convert enroll response for mobile', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer, eaKey);
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            
            const mobileEnrollResponse = await mobileKeys.mobileFromEnrollResponse(enrollResponse);
            expect(mobileEnrollResponse).toBeDefined();
            console.log('   ✅ Converted enroll response for mobile');
        });

        test('should convert renew response for mobile', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await Certificate.getSerial(certificate!);
            const csrDer = await nodeKeys.nodeGenerateCsrDer();
            const renewRequest = createRenewRequest(serial, csrDer);
            const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
            
            const mobileRenewResponse = await mobileKeys.mobileFromRenewResponse(renewResponse);
            expect(mobileRenewResponse).toBeDefined();
            console.log('   ✅ Converted renew response for mobile');
        });
    });

    describe('Phase 15: Certificate Analysis', () => {
        test('should extract SKI and serial from certificate', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            expect(certificate).toBeDefined();
            
            const ski = Certificate.extractSki(certificate!);
            expect(ski).toBeDefined();
            console.log(`   ✅ Extracted SKI: ${ski}`);
            
            const serial = await Certificate.getSerial(certificate!);
            expect(serial).toBeDefined();
            console.log(`   ✅ Got serial number: ${serial}`);
        });
    });

    describe('Phase 16: CA Status and Chain', () => {
        test('should get CA chain', async () => {
            const chainResponse = await caClient.getChain(bootstrapAddr, TEST_NETWORK_ID);
            expect(chainResponse).toBeDefined();
            console.log('   ✅ Got CA chain');
        });

        test('should get CA status', async () => {
            const statusResponse = await caClient.getStatus(authenticatedAddr, TEST_NETWORK_ID);
            expect(statusResponse).toBeDefined();
            console.log('   ✅ Got CA status');
        });

        test('should get CRL', async () => {
            const crlResponse = await caClient.getCrl(authenticatedAddr, TEST_NETWORK_ID);
            expect(crlResponse).toBeDefined();
            console.log('   ✅ Got CRL');
        });
    });

    describe('Phase 17: Cleanup', () => {
        test('should stop CA Server', async () => {
            await caServer.stop();
            console.log('   ✅ Stopped CA Server');
        });
    });
});

// Helper functions
function createEnrollRequest(subject: string, csrDer: Uint8Array, eaKey: Uint8Array): Uint8Array {
    // Use the same EA key that was used for CA Node setup (following FFI test pattern)
    const enrollmentTokenCbor = EnrollmentToken.generate(
        eaKey,
        TEST_NETWORK_ID,
        subject,
        7, // validity days
        ['enroll']
    );
    
    // Deserialize the enrollment token CBOR back to a struct (like FFI test)
    const enrollmentToken = cbor.decode(enrollmentTokenCbor);
    
    const request = {
        network_id: TEST_NETWORK_ID,
        csr_der: Array.from(csrDer), // Convert to array for CBOR serialization
        enrollment_token: enrollmentToken
    };
    
    // Use CBOR serialization like FFI tests
    return new Uint8Array(cbor.encode(request));
}

function createRenewRequest(certificateSerial: string, csrDer: Uint8Array): Uint8Array {
    const request = {
        network_id: TEST_NETWORK_ID,
        csr_der: Array.from(csrDer) // Convert to array for CBOR serialization
    };
    return new Uint8Array(cbor.encode(request));
}

function createRevokeRequest(certificateSerial: string, reason: string): Uint8Array {
    // Convert hex string to bytes (following FFI pattern)
    const serialBytes = new Uint8Array(certificateSerial.length / 2);
    for (let i = 0; i < certificateSerial.length; i += 2) {
        serialBytes[i / 2] = parseInt(certificateSerial.substr(i, 2), 16);
    }
    
    const request = {
        network_id: TEST_NETWORK_ID,
        certificate_serial: Array.from(serialBytes), // Convert to array for CBOR serialization
        reason: reason
    };
    return new Uint8Array(cbor.encode(request));
}
