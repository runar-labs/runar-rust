import { encode, decode } from 'cbor-x';
import {
  setLogLevel,
  setLoggerNodeId,
  Keys,
  Transport,
  TransportOptions,
  Utils
} from '../index';

describe('Two Transports Request Response Test (FFI Equivalent)', () => {
  test('two_transports_request_response', async () => {
    console.log('🔗 Testing Two Transports Request/Response (100% aligned with FFI)');

    // Set up logging to match FFI test exactly
    setLogLevel(5); // 5 = trace level
    setLoggerNodeId('two-transports-test'); // Set node ID for logger context
    console.log('   ✅ Log level set to TRACE');
    console.log('   ✅ Logger node ID set to two-transports-test');

    // Create keys_a (node A)
    const keysA = new Keys();
    keysA.initAsNode();
    await keysA.generateKeys();
    console.log('   ✅ Keys A initialized and generated');

    // Create keys_b (node B)
    const keysB = new Keys();
    keysB.initAsNode();
    await keysB.generateKeys();
    console.log('   ✅ Keys B initialized and generated');

    // Set node info for both A and B (following FFI pattern)
    const nodeInfo = {
      node_public_key: new Uint8Array(0),
      network_ids: [],
      addresses: [],
      node_metadata: {
        services: [],
        subscriptions: []
      },
      version: 0
    };
    
    const nodeInfoCbor = encode(nodeInfo);
    console.log(`   ✅ Node info CBOR data length: ${nodeInfoCbor.length}`);
    console.log(`   ✅ Node info CBOR data: ${Array.from(nodeInfoCbor).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

    // Create mobile keys for processing setup tokens (following FFI pattern)
    const mobileKeys = new Keys();
    mobileKeys.initAsMobile();
    console.log('   ✅ Mobile keys created');

    // Install certificate for A
    console.log('   📋 Installing certificate for A...');
    const csrA = keysA.nodeGenerateCsr();
    const ncmA = mobileKeys.mobileProcessSetupToken(csrA);
    keysA.nodeInstallCertificate(ncmA);
    console.log('   ✅ Certificate installed for A');

    // Install certificate for B
    console.log('   📋 Installing certificate for B...');
    const csrB = keysB.nodeGenerateCsr();
    const ncmB = mobileKeys.mobileProcessSetupToken(csrB);
    keysB.nodeInstallCertificate(ncmB);
    console.log('   ✅ Certificate installed for B');

    // Create transport options (following FFI pattern)
    const transportOptions: TransportOptions = {
      bindAddr: "127.0.0.1:0",
      maxMessageSize: 65536
    };
    console.log('   ✅ Transport options created');

    // Create transport A
    console.log('   🚀 Creating transport A...');
    const transportA = new Transport(keysA, transportOptions);
    await transportA.start();
    const addrA = await transportA.getLocalAddr();
    console.log(`   ✅ Transport A started on ${addrA}`);

    // Create transport B
    console.log('   🚀 Creating transport B...');
    const transportB = new Transport(keysB, transportOptions);
    await transportB.start();
    console.log('   ✅ Transport B started');

    // Get public key from A for peer connection
    const publicKeyA = keysA.nodeGetPublicKey();
    console.log(`   ✅ Public key A: ${Array.from(publicKeyA).map(b => b.toString(16).padStart(2, '0')).join('')}`);

    // Create peer info for connection (following FFI pattern)
    const peerInfo = {
      public_key: Array.from(publicKeyA),
      addresses: [addrA]
    };
    const peerInfoCbor = encode(peerInfo);
    console.log('   ✅ Peer info created for connection');

    // Connect transport B to transport A
    console.log('   🔗 Connecting transport B to transport A...');
    await transportB.connectPeer(peerInfoCbor);
    console.log('   ✅ Transport B connected to transport A');

    const peerId = Utils.compactId(publicKeyA);
    console.log(`   ✅ Peer ID: ${peerId}`);

    // Set up request callback for transport A (server side)
    transportA.onRequest(async (request) => {
      console.log('   📨 Request received on transport A:', request);
      
      // Echo back the payload
      const responsePayload = new Uint8Array(Buffer.from('world'));
      return {
        payload: responsePayload,
        correlationId: request.correlationId
      };
    });
    console.log('   ✅ Request callback registered on transport A');

    // Wait a moment for connection to establish
    await new Promise(resolve => setTimeout(resolve, 100));

    // Test request/response flow
    console.log('   📤 Sending request from transport B to transport A...');
    const requestPayload = new Uint8Array(Buffer.from("hello"));
    const response = await transportB.request(
      "/echo",
      "c1",
      requestPayload,
      peerId
    );
    console.log('   ✅ Request sent and response received');
    console.log(`   ✅ Response payload: ${Buffer.from(response).toString()}`);

    // Verify response
    expect(Buffer.from(response).toString()).toBe('hello');
    console.log('   ✅ Request/response verification passed');

    // Test publish/subscribe flow
    console.log('   📢 Testing publish/subscribe flow...');
    
    // Publish event from transport B to transport A
    const eventPayload = new Uint8Array(Buffer.from("test event data"));
    await transportB.publish(
      "/events/test",
      "pub1",
      eventPayload,
      peerId
    );
    console.log('   ✅ Event published from transport B');

    // Note: In a real implementation, transport A would receive the event
    // For now, we just verify that the publish call succeeds
    console.log('   ✅ Publish/subscribe flow completed');

    // Cleanup
    console.log('   🧹 Cleaning up...');
    await transportB.stop();
    await transportA.stop();
    console.log('   ✅ Transports stopped');

    console.log('   🎉 All tests passed! Two transports request/response test completed successfully');
  }, 45000); // 45 second timeout
});
