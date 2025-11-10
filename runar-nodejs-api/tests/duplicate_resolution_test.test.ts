import { encode, decode } from 'cbor-x';
import {
  setLogLevel,
  setLoggerNodeId,
  Keys,
  Transport,
  TransportOptions,
  Utils
} from '../index';

describe('Duplicate Resolution Test (Aligned with quic_transport_test.rs)', () => {
  test('duplicate_resolution_simultaneous_dial', async () => {
    console.log('🔄 Testing Duplicate Resolution with Simultaneous Dial');

    // Set up logging
    setLogLevel(4); // debug level
    setLoggerNodeId('dup_test');
    console.log('   ✅ Log level set to DEBUG');

    // ==================================================
    // STEP 1: Initialize Certificate Infrastructure
    // ==================================================
    console.log('   🛡️ Initializing Certificate Infrastructure...');

    const mobileCA = new Keys();
    mobileCA.initAsMobile();

    const node1Keys = new Keys();
    node1Keys.initAsNode();
    await node1Keys.generateKeys();
    
    const setupToken1 = node1Keys.nodeGenerateCsr();
    const cert1 = mobileCA.mobileProcessSetupToken(setupToken1);
    node1Keys.nodeInstallCertificate(cert1);

    const node2Keys = new Keys();
    node2Keys.initAsNode();
    await node2Keys.generateKeys();
    
    const setupToken2 = node2Keys.nodeGenerateCsr();
    const cert2 = mobileCA.mobileProcessSetupToken(setupToken2);
    node2Keys.nodeInstallCertificate(cert2);

    const node1PublicKey = node1Keys.nodeGetPublicKey();
    const node2PublicKey = node2Keys.nodeGetPublicKey();
    const node1Id = Utils.compactId(node1PublicKey);
    const node2Id = Utils.compactId(node2PublicKey);

    console.log(`   ✅ Node 1 ID: ${node1Id}`);
    console.log(`   ✅ Node 2 ID: ${node2Id}`);

    // ==================================================
    // STEP 2: Create Lifecycle Event Tracking
    // ==================================================
    console.log('   📊 Setting up Lifecycle Event Tracking...');

    const events1: Array<{peer: string, connected: boolean}> = [];
    const events2: Array<{peer: string, connected: boolean}> = [];

    console.log('   ✅ Lifecycle event tracking initialized');

    // ==================================================
    // STEP 3: Create Transport 1 with Lifecycle Callbacks
    // ==================================================
    console.log('   🚀 Creating Transport 1...');

    const transportOptions: TransportOptions = {
      bindAddr: "127.0.0.1:0",
      maxMessageSize: 1024
    };

    const transport1 = new Transport(node1Keys, transportOptions);

    // Set up request handler
    transport1.onRequest(async (request) => {
      return {
        payload: request.payload, // Echo back
        correlationId: request.correlationId
      };
    });

    // Set up event handler
    transport1.onEvent((event) => {
      // No-op
    });

    // Set up peer connected callback for Transport 1
    transport1.onPeerConnected((peerId, nodeInfo) => {
      console.log(`   🔗 [Transport1] Peer connected: ${peerId}`);
      events1.push({ peer: peerId, connected: true });
    });

    // Set up peer disconnected callback for Transport 1
    transport1.onPeerDisconnected((peerId) => {
      console.log(`   🔌 [Transport1] Peer disconnected: ${peerId}`);
      events1.push({ peer: peerId, connected: false });
    });

    console.log('   ✅ Transport 1 created');

    // ==================================================
    // STEP 4: Create Transport 2 with Lifecycle Callbacks
    // ==================================================
    console.log('   🚀 Creating Transport 2...');

    const transport2 = new Transport(node2Keys, transportOptions);

    // Set up request handler
    transport2.onRequest(async (request) => {
      return {
        payload: request.payload, // Echo back
        correlationId: request.correlationId
      };
    });

    // Set up event handler
    transport2.onEvent((event) => {
      // No-op
    });

    // Set up peer connected callback for Transport 2
    transport2.onPeerConnected((peerId, nodeInfo) => {
      console.log(`   🔗 [Transport2] Peer connected: ${peerId}`);
      events2.push({ peer: peerId, connected: true });
    });

    // Set up peer disconnected callback for Transport 2
    transport2.onPeerDisconnected((peerId) => {
      console.log(`   🔌 [Transport2] Peer disconnected: ${peerId}`);
      events2.push({ peer: peerId, connected: false });
    });

    console.log('   ✅ Transport 2 created');

    // ==================================================
    // STEP 5: Start Both Transports
    // ==================================================
    console.log('   🚀 Starting both transports...');

    await transport1.start();
    await transport2.start();
    console.log('   ✅ Both transports started');

    // Wait for transports to be ready
    await new Promise(resolve => setTimeout(resolve, 150));

    // ==================================================
    // STEP 6: Repeated Simultaneous Dial Rounds
    // ==================================================
    console.log('   🔄 Testing repeated simultaneous dial rounds...');

    // Get actual addresses of both transports
    const transport1Addr = await transport1.getLocalAddr();
    const transport2Addr = await transport2.getLocalAddr();
    console.log(`   ✅ Transport 1 address: ${transport1Addr}`);
    console.log(`   ✅ Transport 2 address: ${transport2Addr}`);

    const peerInfo1 = {
      public_key: Array.from(node1PublicKey),
      addresses: [transport1Addr]
    };
    const peerInfo1Cbor = encode(peerInfo1);

    const peerInfo2 = {
      public_key: Array.from(node2PublicKey),
      addresses: [transport2Addr]
    };
    const peerInfo2Cbor = encode(peerInfo2);

    // Perform 5 rounds of simultaneous dials
    for (let round = 1; round <= 5; round++) {
      console.log(`   🔄 Round ${round}/5: Simultaneous dial...`);
      
      // Simultaneous dial
      const [result1, result2] = await Promise.allSettled([
        transport1.connectPeer(peerInfo2Cbor),
        transport2.connectPeer(peerInfo1Cbor)
      ]);

      // Log results
      if (result1.status === 'fulfilled') {
        console.log(`   ✅ Transport 1 dial successful in round ${round}`);
      } else {
        console.log(`   ❌ Transport 1 dial failed in round ${round}: ${result1.reason}`);
      }

      if (result2.status === 'fulfilled') {
        console.log(`   ✅ Transport 2 dial successful in round ${round}`);
      } else {
        console.log(`   ❌ Transport 2 dial failed in round ${round}: ${result2.reason}`);
      }

      // Wait between rounds
      await new Promise(resolve => setTimeout(resolve, 120));
    }

    console.log('   ✅ All simultaneous dial rounds completed');

    // ==================================================
    // STEP 7: Allow Final Settling
    // ==================================================
    console.log('   ⏳ Allowing final settling...');
    await new Promise(resolve => setTimeout(resolve, 300));
    console.log('   ✅ Final settling completed');

    // ==================================================
    // STEP 8: Verify Connection Stability
    // ==================================================
    console.log('   ✅ Verifying connection stability...');

    // Check that both transports are connected
    const isConnected1 = await transport1.isConnected(node2Id);
    const isConnected2 = await transport2.isConnected(node1Id);

    expect(isConnected1).toBe(true);
    expect(isConnected2).toBe(true);
    console.log('   ✅ Both directions are connected after simultaneous dial');

    // ==================================================
    // STEP 9: Test Bidirectional Requests
    // ==================================================
    console.log('   📤 Testing bidirectional requests...');

    // Request from Transport 1 to Transport 2
    const requestPayload1 = new Uint8Array(Buffer.from("test from t1"));
    const response1 = await transport1.request(
      "test:echo/req",
      "corr1",
      requestPayload1,
      node2Id
    );
    console.log(`   ✅ Request 1 response: ${Buffer.from(response1).toString()}`);

    // Request from Transport 2 to Transport 1
    const requestPayload2 = new Uint8Array(Buffer.from("test from t2"));
    const response2 = await transport2.request(
      "test:echo/req",
      "corr2",
      requestPayload2,
      node1Id
    );
    console.log(`   ✅ Request 2 response: ${Buffer.from(response2).toString()}`);

    // Verify responses
    expect(Buffer.from(response1).toString()).toBe("test from t1");
    expect(Buffer.from(response2).toString()).toBe("test from t2");
    console.log('   ✅ Bidirectional requests successful');

    // ==================================================
    // STEP 10: Verify No Flapping
    // ==================================================
    console.log('   🔍 Verifying no connection flapping...');

    const connectedEvents1 = events1.filter(e => e.connected);
    const disconnectedEvents1 = events1.filter(e => !e.connected);
    const connectedEvents2 = events2.filter(e => e.connected);
    const disconnectedEvents2 = events2.filter(e => !e.connected);

    console.log(`   📊 Transport 1 - Connected: ${connectedEvents1.length}, Disconnected: ${disconnectedEvents1.length}`);
    console.log(`   📊 Transport 2 - Connected: ${connectedEvents2.length}, Disconnected: ${disconnectedEvents2.length}`);

    // Should see exactly one Up per side, and no Down
    expect(connectedEvents1.length).toBe(1);
    expect(disconnectedEvents1.length).toBe(0);
    expect(connectedEvents2.length).toBe(1);
    expect(disconnectedEvents2.length).toBe(0);
    console.log('   ✅ No connection flapping detected');

    // ==================================================
    // STEP 11: Cleanup
    // ==================================================
    console.log('   🧹 Cleaning up...');

    await transport1.stop();
    await transport2.stop();
    console.log('   ✅ Both transports stopped');

    console.log('   🎉 All duplicate resolution tests passed!');
  }, 60000); // 60 second timeout
});
