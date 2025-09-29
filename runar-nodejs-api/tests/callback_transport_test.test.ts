import { Keys, Transport, TransportOptions, TransportRequest, TransportResponse } from '../index';

describe('Transport Callback Pattern Test', () => {
  test('should create transport with callback pattern', async () => {
    console.log('🔗 Testing Transport Callback Pattern');

    // Create keys
    const keys = new Keys();
    keys.initAsNode();
    await keys.generateKeys();

    // Create transport options
    const options: TransportOptions = {
      bindAddr: "127.0.0.1:0",
      enableRequestCallbacks: true,
      enableEventCallbacks: true,
      enablePeerCallbacks: true
    };

    // Create transport
    const transport = new Transport(keys, options);
    console.log('   ✅ Transport created with callback pattern');

    // Register callbacks
    transport.onRequest(async (request: TransportRequest) => {
      console.log(`   📨 Received request: ${request.path} from ${request.sourceNodeId}`);
      return {
        payload: new Uint8Array(Buffer.from("Echo response")),
        correlationId: request.correlationId
      };
    });

    transport.onEvent((event) => {
      console.log(`   📢 Received event: ${event.path} from ${event.sourceNodeId}`);
    });

    transport.onPeerConnected((peerId, nodeInfo) => {
      console.log(`   🤝 Peer connected: ${peerId}`);
    });

    transport.onPeerDisconnected((peerId) => {
      console.log(`   👋 Peer disconnected: ${peerId}`);
    });

    console.log('   ✅ Callbacks registered successfully');

    // Start transport
    await transport.start();
    console.log('   ✅ Transport started successfully');

    // Get local address
    const localAddr = await transport.getLocalAddr();
    console.log(`   ✅ Local address: ${localAddr}`);

    // Stop transport
    await transport.stop();
    console.log('   ✅ Transport stopped successfully');

    console.log('🎉 Transport Callback Pattern Test Completed Successfully!');
  }, 30000);
});
