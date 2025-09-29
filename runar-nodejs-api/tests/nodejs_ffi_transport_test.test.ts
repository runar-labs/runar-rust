import { encode, decode } from 'cbor-x';
import { 
  setLogLevel, 
  setLoggerNodeId,
  Keys, 
  Transport, 
  Utils 
} from '../index';

describe('NodeJS FFI Transport Test', () => {
  test('two_transports_request_response', async () => {
    console.log('🔗 Testing NodeJS FFI Transport Request/Response (100% aligned with FFI)');

    // Set up logging to match FFI test exactly
    setLogLevel(5); // 5 = trace level
    setLoggerNodeId('nodejs-test'); // Set node ID for logger context
    console.log('   ✅ Log level set to TRACE');
    console.log('   ✅ Logger node ID set to nodejs-test');

    // Create keys_a (node A)
    const keysA = new Keys();
    keysA.initAsNode();
    keysA.generateKeys(); // Generate keys before using
    console.log('   ✅ Keys A created and initialized as node');

    // Create keys_b (node B) 
    const keysB = new Keys();
    keysB.initAsNode();
    keysB.generateKeys(); // Generate keys before using
    console.log('   ✅ Keys B created and initialized as node');

    // Set node info for B (following FFI pattern exactly)
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
    console.log(`   📋 Node info CBOR data length: ${nodeInfoBuf.length}`);
    console.log(`   📋 Node info CBOR data: ${Array.from(nodeInfoBuf).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
    
    keysB.setLocalNodeInfo(nodeInfoBuf);
    console.log('   ✅ Node info set for keys B');

    // Create mobile keys for processing setup tokens (following FFI pattern exactly)
    const keysC = new Keys();
    keysC.initAsMobile();
    console.log('   ✅ Keys C created and initialized as mobile');

    // Set node info for A (following FFI pattern exactly)
    keysA.setLocalNodeInfo(nodeInfoBuf);
    console.log('   ✅ Node info set for keys A');

    // Generate CSR for A and process with mobile keys (following FFI pattern exactly)
    const csrA = keysA.nodeGenerateCsr();
    console.log('   ✅ CSR generated for keys A');
    
    const certMessageA = keysC.mobileProcessSetupToken(csrA);
    console.log('   ✅ Setup token processed for keys A');
    
    keysA.nodeInstallCertificate(certMessageA);
    console.log('   ✅ Certificate installed for keys A');

    // Generate CSR for B and process with mobile keys (following FFI pattern exactly)
    const csrB = keysB.nodeGenerateCsr();
    console.log('   ✅ CSR generated for keys B');
    
    const certMessageB = keysC.mobileProcessSetupToken(csrB);
    console.log('   ✅ Setup token processed for keys B');
    
    keysB.nodeInstallCertificate(certMessageB);
    console.log('   ✅ Certificate installed for keys B');

    // Create transport options (following FFI pattern exactly - NO root_certificates in options)
    const transportOptions = {
      bind_addr: '127.0.0.1:0', // Let system assign port
      max_message_size: 65536
    };
    const optionsBuf = new Uint8Array(encode(transportOptions));
    console.log('   ✅ Transport options created');

    // Create transport A (following FFI pattern exactly)
    const transportA = new Transport(keysA, optionsBuf);
    await transportA.start();
    console.log('   ✅ Transport A started');

    // Get local address for A (following FFI pattern exactly)
    const localAddrA = await transportA.getLocalAddr();
    console.log(`   📍 Transport A local address: ${localAddrA}`);

    // Create transport B (following FFI pattern exactly)
    const transportB = new Transport(keysB, optionsBuf);
    await transportB.start();
    console.log('   ✅ Transport B started');

    // Get public key of A (following FFI pattern exactly)
    const publicKeyA = keysA.nodeGetPublicKey();
    console.log(`   🔑 Public key A length: ${publicKeyA.length} bytes`);

    // Create peer info for A (following FFI pattern exactly)
    const peerInfo = {
      public_key: Array.from(publicKeyA),
      addresses: [localAddrA]
    };
    const peerInfoCbor = new Uint8Array(encode(peerInfo));
    console.log('   ✅ Peer info created for A');

    // Connect B to A (following FFI pattern exactly)
    await transportB.connectPeer(peerInfoCbor);
    console.log('   ✅ Transport B connected to A');

    // Calculate peer ID (following FFI pattern exactly)
    const peerId = Utils.compactId(publicKeyA);
    console.log(`   🆔 Peer ID: ${peerId}`);

    // Create request parameters (following FFI pattern exactly)
    const requestParams = {
      path: '/echo',
      correlation_id: 'c1',
      payload: Array.from(Buffer.from('hello')),
      dest_peer_id: peerId,
      network_public_key: null,
      profile_public_keys: []
    };
    const requestParamsCbor = new Uint8Array(encode(requestParams));
    console.log('   ✅ Request parameters created');

    // Send request from B to A (following FFI pattern exactly)
    await transportB.requestFfi(requestParamsCbor);
    console.log('   ✅ Request sent from B to A');

    // Poll events on A to receive request (following FFI pattern exactly)
    let requestId: string | null = null;
    let requestReceived = false;
    
    for (let i = 0; i < 50; i++) {
      const event = await transportA.pollEvent();
      console.log(`   🔍 Poll ${i}: event length = ${event.length}`);
      if (event && event.length > 0) {
        const eventData = decode(event);
        console.log(`   📨 Event received on A: ${JSON.stringify(eventData)}`);
        
            if (eventData.type === 'RequestReceived') {
              requestId = eventData.request_id; // Extract request ID from request_id (following FFI pattern exactly)
              requestReceived = true;
              console.log(`   ✅ Request received on A with ID: ${requestId}`);
              break;
            }
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    expect(requestReceived).toBe(true);
    expect(requestId).toBeTruthy();

    // Create complete request parameters (following FFI pattern exactly)
    const completeParams = {
      request_id: requestId!,
      response_payload: Array.from(Buffer.from('world')),
      profile_public_keys: []
    };
    const completeParamsCbor = new Uint8Array(encode(completeParams));
    console.log('   ✅ Complete request parameters created');

    // Complete request on A (following FFI pattern exactly)
    await transportA.completeRequestFfi(completeParamsCbor);
    console.log('   ✅ Request completed on A');

    // Poll events on B to receive response (following FFI pattern exactly)
    let responseReceived = false;
    
    for (let i = 0; i < 50; i++) {
      const event = await transportB.pollEvent();
      if (event && event.length > 0) {
        const eventData = decode(event);
        console.log(`   📨 Event received on B: ${JSON.stringify(eventData)}`);
        
        if (eventData.type === 'ResponseReceived') {
          responseReceived = true;
          console.log('   ✅ Response received on B');
          break;
        }
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    expect(responseReceived).toBe(true);

    // Test publish/subscribe flow (following FFI pattern exactly)
    console.log('   📡 Testing publish/subscribe flow...');

    // Create publish parameters (following FFI pattern exactly)
    const publishParams = {
      path: '/events/test',
      correlation_id: 'pub1',
      payload: Array.from(Buffer.from('test event data')),
      dest_peer_id: peerId,
      network_public_key: null
    };
    const publishParamsCbor = new Uint8Array(encode(publishParams));
    console.log('   ✅ Publish parameters created');

    // Publish event from B to A (following FFI pattern exactly)
    await transportB.publishFfi(publishParamsCbor);
    console.log('   ✅ Event published from B to A');

    // Poll events on A to receive event (following FFI pattern exactly)
    let eventReceived = false;
    
    for (let i = 0; i < 50; i++) {
      const event = await transportA.pollEvent();
      if (event && event.length > 0) {
        const eventData = decode(event);
        console.log(`   📨 Event received on A: ${JSON.stringify(eventData)}`);
        
        if (eventData.type === 'EventReceived') {
          // Verify the event payload (following FFI pattern exactly)
          expect(Buffer.from(eventData.payload).toString()).toBe('test event data');
          expect(eventData.path).toBe('/events/test');
          eventReceived = true;
          console.log('   ✅ Event received and validated on A');
          break;
        }
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    expect(eventReceived).toBe(true);

    // Cleanup (following FFI pattern exactly)
    await transportB.stop();
    console.log('   ✅ Transport B stopped');
    
    await transportA.stop();
    console.log('   ✅ Transport A stopped');

    console.log('   🎉 NodeJS FFI Transport test completed successfully!');
  }, 60000);
});
