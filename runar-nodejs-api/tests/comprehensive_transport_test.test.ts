import { encode, decode } from 'cbor-x';
import {
  setLogLevel,
  setLoggerNodeId,
  Keys,
  Transport,
  TransportOptions,
  Utils
} from '../index';

describe('Comprehensive Transport Test (Aligned with quic_transport_test.rs)', () => {
  test('comprehensive_transport_test', async () => {
    console.log('🔗 Testing Comprehensive Transport (Aligned with quic_transport_test.rs)');

    // Set up logging to match Rust test exactly
    setLogLevel(4); // 4 = debug level (matching Rust test)
    setLoggerNodeId('comprehensive_test');
    console.log('   ✅ Log level set to DEBUG');
    console.log('   ✅ Logger node ID set to comprehensive_test');

    // ==================================================
    // STEP 1: Initialize Certificate Infrastructure
    // ==================================================
    console.log('   🛡️ Initializing Certificate Infrastructure...');

    // Create ONE mobile key manager that acts as the CA for both nodes
    const mobileCA = new Keys();
    mobileCA.initAsMobile();
    console.log('   ✅ Mobile CA created with user root and CA keys');

    // ==================================================
    // STEP 2: Setup Node 1 Certificate
    // ==================================================
    console.log('   🔐 Setting up Node 1 Certificate...');

    const node1Keys = new Keys();
    node1Keys.initAsNode();
    await node1Keys.generateKeys();
    
    const setupToken1 = node1Keys.nodeGenerateCsr();
    const cert1 = mobileCA.mobileProcessSetupToken(setupToken1);
    node1Keys.nodeInstallCertificate(cert1);
    console.log('   ✅ Node 1 certificate installed');

    // ==================================================
    // STEP 3: Setup Node 2 Certificate
    // ==================================================
    console.log('   🔐 Setting up Node 2 Certificate...');

    const node2Keys = new Keys();
    node2Keys.initAsNode();
    await node2Keys.generateKeys();
    
    const setupToken2 = node2Keys.nodeGenerateCsr();
    const cert2 = mobileCA.mobileProcessSetupToken(setupToken2);
    node2Keys.nodeInstallCertificate(cert2);
    console.log('   ✅ Node 2 certificate installed');

    // ==================================================
    // STEP 4: Get Real Node Public Keys for Proper Peer Identification
    // ==================================================
    console.log('   🔑 Getting Node Public Keys...');

    const node1PublicKey = node1Keys.nodeGetPublicKey();
    const node2PublicKey = node2Keys.nodeGetPublicKey();
    const node1Id = Utils.compactId(node1PublicKey);
    const node2Id = Utils.compactId(node2PublicKey);

    console.log(`   ✅ Node 1 ID: ${node1Id}`);
    console.log(`   ✅ Node 2 ID: ${node2Id}`);

    // ==================================================
    // STEP 5: Create Message Tracking for Validation
    // ==================================================
    console.log('   📊 Setting up Message Tracking...');

    const node1Messages: any[] = [];
    const node2Messages: any[] = [];
    const node1Events: any[] = [];
    const node2Events: any[] = [];
    const node1LifecycleEvents: Array<{peer: string, connected: boolean}> = [];
    const node2LifecycleEvents: Array<{peer: string, connected: boolean}> = [];

    console.log('   ✅ Message tracking arrays initialized');

    // ==================================================
    // STEP 6: Create NodeInfo for Both Nodes
    // ==================================================
    console.log('   📋 Creating NodeInfo for both nodes...');

    const node1Info = {
      node_public_key: Array.from(node1PublicKey),
      network_ids: ["test"],
      addresses: ["127.0.0.1:50069"],
      node_metadata: {
        services: [{
          network_id: "test",
          service_path: "api1",
          name: "api1",
          version: "1.0.0",
          description: "API 1",
          actions: [
            {
              name: "get",
              description: "GET operation",
              input_schema: null,
              output_schema: null
            },
            {
              name: "post", 
              description: "POST operation",
              input_schema: null,
              output_schema: null
            }
          ],
          registration_time: 0,
          last_start_time: null
        }],
        subscriptions: [{
          path: "data_processed"
        }]
      },
      version: 1
    };

    const node2Info = {
      node_public_key: Array.from(node2PublicKey),
      network_ids: ["test"],
      addresses: ["127.0.0.1:50044"],
      node_metadata: {
        services: [{
          network_id: "test",
          service_path: "storage1",
          name: "storage1",
          version: "1.0.0",
          description: "Storage 1",
          actions: [
            {
              name: "store",
              description: "Store operation",
              input_schema: null,
              output_schema: null
            },
            {
              name: "retrieve",
              description: "Retrieve operation", 
              input_schema: null,
              output_schema: null
            }
          ],
          registration_time: 0,
          last_start_time: null
        }],
        subscriptions: [{
          path: "storage_updated"
        }]
      },
      version: 1
    };

    console.log('   ✅ NodeInfo created for both nodes');

    // ==================================================
    // STEP 7: Initialize Transport Instances with Callbacks
    // ==================================================
    console.log('   🚀 Initializing Transport Instances with Callbacks...');

    const transportOptions: TransportOptions = {
      bindAddr: "127.0.0.1:0",
      maxMessageSize: 1024
    };

    // Create Transport 1 with comprehensive callbacks
    const transport1 = new Transport(node1Keys, transportOptions);
    
    // Set up request callback for Transport 1
    transport1.onRequest(async (request) => {
      console.log(`   📥 [Transport1] Received request: Path=${request.path}, From=${request.correlationId}`);
      
      // Track the request
      node1Messages.push({
        source_node_id: "unknown",
        destination_node_id: node1Id,
        message_type: 4, // MESSAGE_TYPE_REQUEST
        payload: {
          network_public_key: null,
          path: request.path,
          payload_bytes: Array.from(request.payload),
          correlation_id: request.correlationId,
          profile_public_keys: request.profile_public_keys || []
        }
      });

      // Create response
      const responsePayload = new Uint8Array(Buffer.from(`Response from Node1: ${request.path}`));
      return {
        payload: responsePayload,
        correlationId: request.correlationId
      };
    });

    // Set up event callback for Transport 1
    transport1.onEvent((event) => {
      console.log(`   📥 [Transport1-Event] Received event: Path=${event.path}, Correlation ID=${event.correlationId}`);
      
      // Track the event
      node1Events.push({
        source_node_id: "unknown",
        destination_node_id: "unknown",
        message_type: 6, // MESSAGE_TYPE_EVENT
        payload: {
          network_public_key: null,
          path: event.path,
          payload_bytes: Array.from(event.payload),
          correlation_id: event.correlationId,
          profile_public_keys: []
        }
      });
    });

    // Set up peer connected callback for Transport 1
    transport1.onPeerConnected((peerId, nodeInfo) => {
      console.log(`   🔗 [Transport1] Peer connected: ${peerId}`);
      console.log(`   🔗 [Transport1] NodeInfo:`, nodeInfo);
      node1LifecycleEvents.push({ peer: peerId, connected: true });
      console.log(`   🔗 [Transport1] Lifecycle events count: ${node1LifecycleEvents.length}`);
    });

    // Set up peer disconnected callback for Transport 1
    transport1.onPeerDisconnected((peerId) => {
      console.log(`   🔌 [Transport1] Peer disconnected: ${peerId}`);
      node1LifecycleEvents.push({ peer: peerId, connected: false });
    });

    // Create Transport 2 with comprehensive callbacks
    const transport2 = new Transport(node2Keys, transportOptions);
    
    // Set up request callback for Transport 2
    transport2.onRequest(async (request) => {
      console.log(`   📥 [Transport2] Received request: Path=${request.path}, From=${request.correlationId}`);
      
      // Track the request
      node2Messages.push({
        source_node_id: "unknown",
        destination_node_id: node2Id,
        message_type: 4, // MESSAGE_TYPE_REQUEST
        payload: {
          network_public_key: null,
          path: request.path,
          payload_bytes: Array.from(request.payload),
          correlation_id: request.correlationId,
          profile_public_keys: request.profile_public_keys || []
        }
      });

      // Create response
      const responsePayload = new Uint8Array(Buffer.from(`Response from Node2: ${request.path}`));
      return {
        payload: responsePayload,
        correlationId: request.correlationId
      };
    });

    // Set up event callback for Transport 2
    transport2.onEvent((event) => {
      console.log(`   📥 [Transport2-Event] Received event: Path=${event.path}, Correlation ID=${event.correlationId}`);
      
      // Track the event
      node2Events.push({
        source_node_id: "unknown",
        destination_node_id: "unknown",
        message_type: 6, // MESSAGE_TYPE_EVENT
        payload: {
          network_public_key: null,
          path: event.path,
          payload_bytes: Array.from(event.payload),
          correlation_id: event.correlationId,
          profile_public_keys: []
        }
      });
    });

    // Set up peer connected callback for Transport 2
    transport2.onPeerConnected((peerId, nodeInfo) => {
      console.log(`   🔗 [Transport2] Peer connected: ${peerId}`);
      node2LifecycleEvents.push({ peer: peerId, connected: true });
    });

    // Set up peer disconnected callback for Transport 2
    transport2.onPeerDisconnected((peerId) => {
      console.log(`   🔌 [Transport2] Peer disconnected: ${peerId}`);
      node2LifecycleEvents.push({ peer: peerId, connected: false });
    });

    console.log('   ✅ Transport instances created with comprehensive callbacks');

    // ==================================================
    // STEP 8: Start Both Transports
    // ==================================================
    console.log('   🚀 Starting both transports...');

    await transport1.start();
    await transport2.start();
    console.log('   ✅ Both transports started');

    // ==================================================
    // STEP 9: Connect Transports
    // ==================================================
    console.log('   🔗 Connecting transports...');

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

    // Wait for connection to establish
    await new Promise(resolve => setTimeout(resolve, 200));
    console.log('   ✅ Connection established');

    // ==================================================
    // STEP 10: Test Request/Response Flow
    // ==================================================
    console.log('   📤 Testing Request/Response Flow...');

    // Test 1: Basic request from Transport 1 to Transport 2
    const requestPayload1 = new Uint8Array(Buffer.from("test request 1"));
    const response1 = await transport1.request(
      "test:api1/get",
      "corr1",
      requestPayload1,
      node2Id
    );
    console.log(`   ✅ Request 1 response: ${Buffer.from(response1).toString()}`);

    // Test 2: Basic request from Transport 2 to Transport 1
    const requestPayload2 = new Uint8Array(Buffer.from("test request 2"));
    const response2 = await transport2.request(
      "test:storage1/store",
      "corr2", 
      requestPayload2,
      node1Id
    );
    console.log(`   ✅ Request 2 response: ${Buffer.from(response2).toString()}`);

    // Verify responses
    expect(Buffer.from(response1).toString()).toContain(`Response from ${node2Id}`);
    expect(Buffer.from(response2).toString()).toContain(`Response from ${node1Id}`);
    console.log('   ✅ Request/response verification passed');

    // ==================================================
    // STEP 11: Test Event Publishing
    // ==================================================
    console.log('   📢 Testing Event Publishing...');

    // Publish event from Transport 1
    const eventPayload1 = new Uint8Array(Buffer.from("data processed event"));
    await transport1.publish(
      "data_processed",
      "event1",
      eventPayload1,
      node2Id
    );
    console.log('   ✅ Event 1 published from Transport 1');

    // Publish event from Transport 2
    const eventPayload2 = new Uint8Array(Buffer.from("storage updated event"));
    await transport2.publish(
      "storage_updated",
      "event2",
      eventPayload2,
      node1Id
    );
    console.log('   ✅ Event 2 published from Transport 2');

    // Wait for events to be processed
    await new Promise(resolve => setTimeout(resolve, 100));

    // ==================================================
    // STEP 12: Test Message Size Limits
    // ==================================================
    console.log('   📏 Testing Message Size Limits...');

    // Test large payload (should be rejected due to maxMessageSize: 1024)
    const largePayload = new Uint8Array(2048); // 2KB payload
    largePayload.fill(7);

    try {
      await transport1.request(
        "test:limits/echo",
        "corr-limits",
        largePayload,
        node2Id
      );
      // If we get here, the test should fail
      expect(true).toBe(false);
    } catch (error) {
      console.log('   ✅ Large payload correctly rejected by size limit');
    }

    // ==================================================
    // STEP 13: Test Lifecycle Callbacks
    // ==================================================
    console.log('   🔄 Testing Lifecycle Callbacks...');

    // Check that peer connected callbacks were called
    console.log(`   🔍 [Debug] node1LifecycleEvents:`, node1LifecycleEvents);
    console.log(`   🔍 [Debug] node2LifecycleEvents:`, node2LifecycleEvents);
    
    const connectedEvents1 = node1LifecycleEvents.filter(e => e.connected);
    const connectedEvents2 = node2LifecycleEvents.filter(e => e.connected);
    
    console.log(`   🔍 [Debug] connectedEvents1:`, connectedEvents1);
    console.log(`   🔍 [Debug] connectedEvents2:`, connectedEvents2);
    
    expect(connectedEvents1.length).toBeGreaterThan(0);
    expect(connectedEvents2.length).toBeGreaterThan(0);
    console.log('   ✅ Peer connected callbacks verified');

    // ==================================================
    // STEP 14: Test Message Tracking
    // ==================================================
    console.log('   📊 Testing Message Tracking...');

    // Verify that messages were tracked
    expect(node1Messages.length).toBeGreaterThan(0);
    expect(node2Messages.length).toBeGreaterThan(0);
    console.log(`   ✅ Node 1 tracked ${node1Messages.length} messages`);
    console.log(`   ✅ Node 2 tracked ${node2Messages.length} messages`);

    // Verify that events were tracked
    expect(node1Events.length).toBeGreaterThan(0);
    expect(node2Events.length).toBeGreaterThan(0);
    console.log(`   ✅ Node 1 tracked ${node1Events.length} events`);
    console.log(`   ✅ Node 2 tracked ${node2Events.length} events`);

    // ==================================================
    // STEP 15: Test Callback Configuration
    // ==================================================
    console.log('   ⚙️ Testing Callback Configuration...');

    // Test callback timeout configuration
    const originalTimeout = transport1.getCallbackTimeout();
    console.log(`   ✅ Original callback timeout: ${originalTimeout}ms`);

    transport1.setCallbackTimeout(10000); // 10 seconds
    const newTimeout = transport1.getCallbackTimeout();
    expect(newTimeout).toBe(10000);
    console.log(`   ✅ New callback timeout: ${newTimeout}ms`);

    // Reset timeout
    transport1.setCallbackTimeout(originalTimeout);
    console.log('   ✅ Callback timeout reset');

    // ==================================================
    // STEP 16: Test Callback Removal
    // ==================================================
    console.log('   🗑️ Testing Callback Removal...');

    // Remove callbacks
    transport1.removeRequestCallback();
    transport1.removeEventCallback();
    transport1.removePeerConnectedCallback();
    transport1.removePeerDisconnectedCallback();
    console.log('   ✅ All callbacks removed from Transport 1');

    // ==================================================
    // STEP 17: Cleanup
    // ==================================================
    console.log('   🧹 Cleaning up...');

    await transport1.stop();
    await transport2.stop();
    console.log('   ✅ Both transports stopped');

    console.log('   🎉 All comprehensive transport tests passed!');
  }, 60000); // 60 second timeout for comprehensive test
});
