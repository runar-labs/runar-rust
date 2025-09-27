//! Certificate Trust Test
//! This test verifies that the CA Server and CA Client can establish a trusted connection

import { 
    Keys, 
    CaCreator, 
    Ca, 
    CaNode, 
    CaServer, 
    CaClient, 
    EnrollmentToken,
    DeviceKeystoreCaps,
    setLogLevel
} from '../index';
import * as cbor from 'cbor-x';

// Configure logging to TRACE level (following FFI pattern)
setLogLevel(5); // 5 = trace level

describe('Certificate Trust Test', () => {
    let rootCa: Ca;
    let issuingCa: Ca;
    let caNode: CaNode;
    let caServer: CaServer;
    let caClient: CaClient;
    let nodeKeys: Keys;
    let mobileKeys: Keys;
    let bootstrapAddr: string;
    let authenticatedAddr: string;

    beforeAll(async () => {
        // Create root CA
        rootCa = CaCreator.createRootCa('CN=Test Root CA,O=Test,C=US');
        expect(rootCa).toBeDefined();
        console.log('✅ Created root CA');

        // Create issuing CA
        issuingCa = CaCreator.createIssuingCa(rootCa, 'CN=Test Issuing CA,O=Test,C=US', 365, 1);
        expect(issuingCa).toBeDefined();
        console.log('✅ Created issuing CA');

        // Create CA Node
        caNode = new CaNode();
        expect(caNode).toBeDefined();
        console.log('✅ Created CA Node');

        // Setup CA Node with real certificates
        const eaKey = CaCreator.createEaKey();
        const eaPublicKeys = cbor.encode([Array.from(eaKey)]);
        
        await caNode.setupComplete(
            'CN=Test Root CA,O=Test,C=US',
            'CN=Test Issuing CA,O=Test,C=US',
            365,
            1,
            eaPublicKeys,
            'test_network'
        );
        console.log('✅ CA Node setup complete');

        // Get certificates from CA Node
        const rootCaDer = await caNode.getRootCaCertificate();
        const issuingCaDer = await caNode.getIssuingCaCertificate();
        console.log(`✅ Got certificates: Root CA (${rootCaDer.length} bytes), Issuing CA (${issuingCaDer.length} bytes)`);
        
        // Debug: Check what certificates the CA Node actually has
        console.log('🔍 CA Node certificates after setup:');
        console.log(`  Root CA: ${rootCaDer.length} bytes`);
        console.log(`  Issuing CA: ${issuingCaDer.length} bytes`);

        // Create CA Server AFTER CA Node is fully set up (following FFI pattern)
        const adminSkis = ['admin_ski_1'];
        const serverConfig = createCaServerConfig('127.0.0.1:8443', '127.0.0.1:8444', adminSkis);
        caServer = new CaServer(serverConfig, caNode.createShared());
        expect(caServer).toBeDefined();
        console.log('✅ Created CA Server with real certificates');

        // Start CA Server
        await caServer.start();
        bootstrapAddr = await caServer.getBootstrapAddr();
        authenticatedAddr = await caServer.getAuthenticatedAddr();
        console.log(`✅ CA Server started: ${bootstrapAddr}, ${authenticatedAddr}`);

        // Create node keys
        nodeKeys = new Keys();
        await nodeKeys.initAsNode('test_node_id');
        await nodeKeys.nodeGenerateKeys();
        console.log('✅ Created node keys');

        // Create CA Client with real certificates
        const clientConfig = createCaClientConfig(bootstrapAddr, authenticatedAddr, rootCaDer, issuingCaDer);
        caClient = new CaClient(clientConfig, nodeKeys);
        expect(caClient).toBeDefined();
        console.log('✅ Created CA Client');

        // Create mobile keys
        mobileKeys = new Keys();
        await mobileKeys.initAsMobile('test_user_id', 'test_device_id');
        console.log('✅ Created mobile keys');
    });

    afterAll(async () => {
        if (caServer) {
            await caServer.stop();
            console.log('✅ Stopped CA Server');
        }
    });

    test('should establish trusted connection', async () => {
        // Generate CSR
        const csrDer = await nodeKeys.nodeGenerateCsr('CN=Test Node');
        expect(csrDer).toBeDefined();
        console.log('✅ Generated CSR');

        // Create enrollment request
        const enrollRequest = createEnrollRequest('CN=Test Node', csrDer);
        expect(enrollRequest).toBeDefined();
        console.log('✅ Created enrollment request');

        // Attempt enrollment
        try {
            const enrollResponse = await caClient.enroll(bootstrapAddr, enrollRequest);
            expect(enrollResponse).toBeDefined();
            console.log('✅ Enrollment successful - certificate trust is working!');
        } catch (error) {
            console.error('❌ Enrollment failed:', error);
            throw error;
        }
    });
});

// Helper functions
function createCaServerConfig(bootstrapBind: string, authenticatedBind: string, adminSkis: string[]): Uint8Array {
    const config = {
        bootstrap_bind: bootstrapBind,
        authenticated_bind: authenticatedBind,
        network_id: 'test_network',
        rate_limit_per_minute: 100,
        rate_limit_per_hour: 1000,
        admin_skis: adminSkis
    };
    return new Uint8Array(cbor.encode(config));
}

function createCaClientConfig(bootstrapServer: string, authenticatedServer: string, rootCaDer: Uint8Array, issuingCaDer: Uint8Array): Uint8Array {
    const config = {
        bootstrap_server: bootstrapServer,
        authenticated_server: authenticatedServer,
        network_id: 'test_network',
        request_timeout_seconds: 30,
        max_retries: 3,
        root_ca_der: Array.from(rootCaDer),
        issuing_ca_der: Array.from(issuingCaDer)
    };
    return new Uint8Array(cbor.encode(config));
}

function createEnrollRequest(subject: string, csrDer: Uint8Array): Uint8Array {
    const eaKey = CaCreator.createEaKey();
    const enrollmentTokenCbor = EnrollmentToken.generate(
        eaKey,
        'test_network',
        subject,
        7,
        ['enroll']
    );
    
    const enrollmentToken = cbor.decode(enrollmentTokenCbor);
    
    const request = {
        network_id: 'test_network',
        csr_der: Array.from(csrDer),
        enrollment_token: enrollmentToken
    };
    
    return new Uint8Array(cbor.encode(request));
}
