import { encode, decode } from 'cbor-x';
import {
  setLogLevel,
  setLoggerNodeId,
  Keys,
  Transport,
  TransportOptions,
  Utils
} from '../index';

describe('Lifecycle Callbacks Test (Aligned with quic_transport_test.rs)', () => {
  test('lifecycle_callbacks_test', async () => {
    console.log('🔄 Testing Lifecycle Callbacks (Aligned with quic_transport_test.rs)');

    // Set up logging
    setLogLevel(4); // debug level
    setLoggerNodeId('lifecycle_test');
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
    console.log('   🚀 Creating Transport 1 with Lifecycle Callbacks...');

    const transportOptions: TransportOptions = {
      bindAddr: "127.0.0.1:0",
      maxMessageSize: 1024
    };

    const transport1 = new Transport(node1Keys, transportOptions);

    // Set up request handler (no-op)
    transport1.onRequest(async (request) => {
      return {
        payload: new Uint8Array(0),
        correlationId: request.correlationId
      };
    });

    // Set up event handler (no-op)
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

    console.log('   ✅ Transport 1 created with lifecycle callbacks');

    // ==================================================
    // STEP 4: Create Transport 2 with Lifecycle Callbacks
    // ==================================================
    console.log('   🚀 Creating Transport 2 with Lifecycle Callbacks...');

    const transport2 = new Transport(node2Keys, transportOptions);

    // Set up request handler (no-op)
    transport2.onRequest(async (request) => {
      return {
        payload: new Uint8Array(0),
        correlationId: request.correlationId
      };
    });

    // Set up event handler (no-op)
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

    console.log('   ✅ Transport 2 created with lifecycle callbacks');

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
    // STEP 6: Connect 1 -> 2 and Wait for on_up
    // ==================================================
    console.log('   🔗 Connecting Transport 1 to Transport 2...');

    // Get the actual address of transport 2
    const transport2Addr = await transport2.getLocalAddr();
    console.log(`   ✅ Transport 2 address: ${transport2Addr}`);

    const peerInfo = {
      public_key: Array.from(node2PublicKey),
      addresses: [transport2Addr]
    };
    const peerInfoCbor = encode(peerInfo);

    await transport1.connectPeer(peerInfoCbor);
    console.log('   ✅ Transport 1 connected to Transport 2');

    // Wait for on_up callbacks
    await new Promise(resolve => setTimeout(resolve, 300));
    console.log('   ✅ Waiting for peer connected callbacks...');

    // ==================================================
    // STEP 7: Verify on_up Callbacks
    // ==================================================
    console.log('   ✅ Verifying peer connected callbacks...');

    const connectedEvents1 = events1.filter(e => e.connected);
    const connectedEvents2 = events2.filter(e => e.connected);

    console.log(`   📊 Transport 1 connected events: ${connectedEvents1.length}`);
    console.log(`   📊 Transport 2 connected events: ${connectedEvents2.length}`);

    // Check that both transports see the connection
    const t1SeesT2 = connectedEvents1.some(e => e.peer === node2Id);
    const t2SeesT1 = connectedEvents2.some(e => e.peer === node1Id);

    expect(t1SeesT2).toBe(true);
    expect(t2SeesT1).toBe(true);
    console.log('   ✅ Both transports see peer connected events');

    // ==================================================
    // STEP 8: Stop Transport 2 and Wait for on_down
    // ==================================================
    console.log('   🛑 Stopping Transport 2...');

    await transport2.stop();
    console.log('   ✅ Transport 2 stopped');

    // Wait for on_down callback
    await new Promise(resolve => setTimeout(resolve, 400));
    console.log('   ✅ Waiting for peer disconnected callbacks...');

    // ==================================================
    // STEP 9: Verify on_down Callback
    // ==================================================
    console.log('   ✅ Verifying peer disconnected callbacks...');

    const disconnectedEvents1 = events1.filter(e => !e.connected);
    console.log(`   📊 Transport 1 disconnected events: ${disconnectedEvents1.length}`);

    const t1SeesT2Disconnected = disconnectedEvents1.some(e => e.peer === node2Id);
    expect(t1SeesT2Disconnected).toBe(true);
    console.log('   ✅ Transport 1 sees Transport 2 disconnected');

    // ==================================================
    // STEP 10: Restart Transport 2 and Reconnect
    // ==================================================
    console.log('   🔄 Restarting Transport 2...');

    await transport2.start();
    console.log('   ✅ Transport 2 restarted');

    // Wait for transport to be ready
    await new Promise(resolve => setTimeout(resolve, 150));

    // Reconnect
    console.log('   🔗 Reconnecting Transport 1 to Transport 2...');
    await transport1.connectPeer(peerInfoCbor);
    console.log('   ✅ Transport 1 reconnected to Transport 2');

    // Wait for on_up callbacks
    await new Promise(resolve => setTimeout(resolve, 400));
    console.log('   ✅ Waiting for second peer connected callbacks...');

    // ==================================================
    // STEP 11: Verify Second on_up Callback
    // ==================================================
    console.log('   ✅ Verifying second peer connected callbacks...');

    const finalConnectedEvents1 = events1.filter(e => e.connected);
    const finalConnectedEvents2 = events2.filter(e => e.connected);

    console.log(`   📊 Final Transport 1 connected events: ${finalConnectedEvents1.length}`);
    console.log(`   📊 Final Transport 2 connected events: ${finalConnectedEvents2.length}`);

    // Should see at least 2 connected events for Transport 1 (initial + after restart)
    expect(finalConnectedEvents1.length).toBeGreaterThanOrEqual(2);
    console.log('   ✅ Transport 1 sees multiple peer connected events');

    // ==================================================
    // STEP 12: Test Callback Removal
    // ==================================================
    console.log('   🗑️ Testing Callback Removal...');

    // Remove all callbacks
    transport1.removePeerConnectedCallback();
    transport1.removePeerDisconnectedCallback();
    transport2.removePeerConnectedCallback();
    transport2.removePeerDisconnectedCallback();
    console.log('   ✅ All lifecycle callbacks removed');

    // ==================================================
    // STEP 13: Cleanup
    // ==================================================
    console.log('   🧹 Cleaning up...');

    await transport1.stop();
    await transport2.stop();
    console.log('   ✅ Both transports stopped');

    console.log('   🎉 All lifecycle callback tests passed!');
  }, 60000); // 60 second timeout
});
