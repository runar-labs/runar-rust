import { encode, decode } from 'cbor-x';
import { 
  setLogLevel, 
  Keys, 
  Transport, 
  Utils 
} from '../index';

describe('NodeJS FFI Transport Simple Test', () => {
  test('basic_transport_creation', async () => {
    console.log('🔗 Testing Basic NodeJS Transport Creation');

    // Set up logging to match FFI test
    setLogLevel(5); // 5 = trace level
    console.log('   ✅ Log level set to TRACE');

    // Create keys
    const keys = new Keys();
    keys.initAsNode();
    await keys.generateKeys(); // Generate keys before using
    console.log('   ✅ Keys created and initialized as node');

    // Set node info
    const nodeInfo = {
      node_public_key: [],
      network_ids: [],
      addresses: [],
      node_metadata: {
        services: [],
        subscriptions: []
      },
      version: 0
    };
    const nodeInfoBuf = new Uint8Array(encode(nodeInfo));
    keys.setLocalNodeInfo(nodeInfoBuf);
    console.log('   ✅ Node info set');

    // Generate CSR and install certificate (needed for transport)
    const csr = keys.nodeGenerateCsr();
    console.log('   ✅ CSR generated');
    
    // Create mobile keys for processing setup token
    const mobileKeys = new Keys();
    mobileKeys.initAsMobile();
    const certMessage = mobileKeys.mobileProcessSetupToken(csr);
    console.log('   ✅ Setup token processed');
    
    keys.nodeInstallCertificate(certMessage);
    console.log('   ✅ Certificate installed');

    // Create a simple CA for transport certificates
    const { CaCreator } = await import('../index');
    const rootCa = CaCreator.createRootCa('CN=Test Root CA,O=Test,C=US');
    const issuingCa = CaCreator.createIssuingCa(rootCa, 'CN=Test Issuing CA,O=Test,C=US', 365, 1);
    
    const rootCaCert = rootCa.getCertificate();
    const issuingCaCert = issuingCa.getCertificate();
    
    // Create transport options (TransportOptions struct, not CBOR)
    const transportOptions = {
      bindAddr: '127.0.0.1:0', // Let system assign port
    };
    console.log('   ✅ Transport options created');

    // Create transport
    const transport = new Transport(keys, transportOptions);
    console.log('   ✅ Transport created');

    // Start transport
    await transport.start();
    console.log('   ✅ Transport started');

    // Get local address
    const localAddr = await transport.getLocalAddr();
    console.log(`   📍 Transport local address: ${localAddr}`);

    // Test native Transport methods exist
    expect(typeof transport.getLocalAddr).toBe('function');
    expect(typeof transport.pollEvent).toBe('function');
    expect(typeof transport.request).toBe('function');
    expect(typeof transport.publish).toBe('function');
    expect(typeof transport.completeRequest).toBe('function');
    console.log('   ✅ Native Transport methods verified');

    // Test poll_event returns null when no events (as expected)
    const event = await transport.pollEvent();
    expect(event).toBeNull();
    console.log('   ✅ Poll event returns null as expected');

    // Stop transport
    await transport.stop();
    console.log('   ✅ Transport stopped');

    console.log('   🎉 Basic transport test completed successfully!');
  }, 30000);
});
