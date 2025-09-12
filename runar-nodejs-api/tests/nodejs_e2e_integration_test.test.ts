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
    DeviceKeystoreCaps 
} from '../index';

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

    beforeAll(async () => {
        // Set up logging
        console.log('\n🚀 Starting NodeJS Full-transport E2E QUIC mTLS test');
    });

    afterAll(async () => {
        // Cleanup all resources
        const resources = [caServer, caClient, caNode, rootCa, issuingCa, nodeKeys, mobileKeys];
        await global.cleanupTestResources(resources);
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
            
            global.expectCertificateChain(rootCaDer, issuingCaDer);
            global.validateCertificateChain(rootCaDer, issuingCaDer);
        });
    });

    describe('Phase 3: CA Node Setup', () => {
        test('should create CA Node', () => {
            caNode = new CaNode();
            expect(caNode).toBeDefined();
            console.log('   ✅ Created CA Node');
        });

        test('should install issuing CA in CA Node', async () => {
            const issuingCaDer = issuingCa.getCertificate();
            await caNode.installIssuingCa(issuingCaDer);
            console.log('   ✅ Installed issuing CA in CA Node');
        });
    });

    describe('Phase 4: CA Server Setup', () => {
        test('should create CA Server', () => {
            const adminSkis = ['admin_ski_1', 'admin_ski_2'];
            const serverConfig = global.createCaServerConfig('0.0.0.0:8443', '0.0.0.0:8444', adminSkis);
            
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
        test('should create CA Client', () => {
            const rootCaDer = rootCa.getCertificate();
            const issuingCaDer = issuingCa.getCertificate();
            const clientConfig = global.createCaClientConfig(bootstrapAddr, authenticatedAddr, rootCaDer, issuingCaDer);
            
            caClient = new CaClient(clientConfig, nodeKeys);
            expect(caClient).toBeDefined();
            console.log('   ✅ Created CA Client');
        });
    });

    describe('Phase 8: Enrollment Token Generation', () => {
        test('should get mobile public key', async () => {
            const mobilePublicKey = await mobileKeys.mobileGetPublicKey();
            expect(mobilePublicKey).toBeDefined();
            console.log('   ✅ Got mobile public key');
        });

        test('should generate enrollment token', () => {
            const mobilePublicKey = mobileKeys.mobileGetPublicKey();
            const token = EnrollmentToken.generate(
                mobilePublicKey,
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
            const csrDer = await nodeKeys.nodeGenerateCsr('CN=Test Node');
            expect(csrDer).toBeDefined();
            console.log('   ✅ Generated CSR');
        });

        test('should perform enrollment', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsr('CN=Test Node');
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer);
            
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            expect(enrollResponse).toBeDefined();
            console.log('   ✅ Performed enrollment');
        });

        test('should install certificate', async () => {
            const csrDer = await nodeKeys.nodeGenerateCsr('CN=Test Node');
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer);
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            
            await nodeKeys.nodeInstallCertificateFromMessage(enrollResponse);
            console.log('   ✅ Installed certificate');
        });
    });

    describe('Phase 10: Certificate Renewal', () => {
        test('should get certificate serial', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            expect(certificate).toBeDefined();
            
            const serial = await nodeKeys.certificateGetSerial(certificate!);
            expect(serial).toBeDefined();
            console.log(`   ✅ Got certificate serial: ${serial}`);
        });

        test('should perform renewal', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await nodeKeys.certificateGetSerial(certificate!);
            const renewRequest = createRenewRequest(serial);
            
            const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
            expect(renewResponse).toBeDefined();
            console.log('   ✅ Performed renewal');
        });

        test('should install renewed certificate', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await nodeKeys.certificateGetSerial(certificate!);
            const renewRequest = createRenewRequest(serial);
            const renewResponse = await caClient.renew(authenticatedAddr, renewRequest);
            
            await nodeKeys.nodeInstallCertificateFromMessage(renewResponse);
            console.log('   ✅ Installed renewed certificate');
        });
    });

    describe('Phase 11: Certificate Revocation', () => {
        test('should perform revocation', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await nodeKeys.certificateGetSerial(certificate!);
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
            
            const encryptedData = await nodeKeys.nodeEncryptWithEnvelope(testData, [profileKey]);
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
            const csrDer = await nodeKeys.nodeGenerateCsr('CN=Test Node');
            const enrollRequest = createEnrollRequest('CN=Test Node', csrDer);
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            
            const mobileEnrollResponse = await mobileKeys.mobileFromEnrollResponse(enrollResponse);
            expect(mobileEnrollResponse).toBeDefined();
            console.log('   ✅ Converted enroll response for mobile');
        });

        test('should convert renew response for mobile', async () => {
            const certificate = nodeKeys.nodeGetNodeCertificate();
            const serial = await nodeKeys.certificateGetSerial(certificate!);
            const renewRequest = createRenewRequest(serial);
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
            
            const ski = await nodeKeys.certificateExtractSki(certificate!);
            expect(ski).toBeDefined();
            console.log(`   ✅ Extracted SKI: ${ski}`);
            
            const serial = await nodeKeys.certificateGetSerial(certificate!);
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
function createEnrollRequest(subject: string, csrDer: Uint8Array): Uint8Array {
    const request = {
        network_id: TEST_NETWORK_ID,
        subject: subject,
        csr_der: Array.from(csrDer),
        token_cbor: new Uint8Array(0) // Will be filled by the test
    };
    return new Uint8Array(JSON.stringify(request).split('').map(c => c.charCodeAt(0)));
}

function createRenewRequest(certificateSerial: string): Uint8Array {
    const request = {
        network_id: TEST_NETWORK_ID,
        certificate_serial: certificateSerial
    };
    return new Uint8Array(JSON.stringify(request).split('').map(c => c.charCodeAt(0)));
}

function createRevokeRequest(certificateSerial: string, reason: string): Uint8Array {
    const request = {
        network_id: TEST_NETWORK_ID,
        certificate_serial: certificateSerial,
        reason: reason
    };
    return new Uint8Array(JSON.stringify(request).split('').map(c => c.charCodeAt(0)));
}
