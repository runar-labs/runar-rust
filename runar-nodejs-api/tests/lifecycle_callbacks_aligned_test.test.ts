import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { 
  Keys, 
  Transport, 
  setLogLevel,
  Utils,
  type TransportRequest,
  type TransportEvent,
  type PeerConnectedEnvelope,
  type PeerDisconnectedEnvelope
} from '../index';
import { encode } from 'cbor-x';

describe('Lifecycle Callbacks Aligned Test', () => {
  let mobileCA: Keys;
  let nodeKeyManager1: Keys;
  let nodeKeyManager2: Keys;
  let transport1: Transport;
  let transport2: Transport;
  let node1Id: string;
  let node2Id: string;

  // Event tracking arrays - mirroring Rust test structure
  let node1LifecycleEvents: Array<{ peerId: string; connected: boolean }> = [];
  let node2LifecycleEvents: Array<{ peerId: string; connected: boolean }> = [];

  beforeEach(async () => {
    // Set log level to match Rust test (2 = Warn level)
    setLogLevel(2);

    // Initialize mobile CA (acts as CA for both nodes)
    mobileCA = new Keys();
    mobileCA.initAsMobile();

    // Create node 1 key manager and generate certificate
    nodeKeyManager1 = new Keys();
    nodeKeyManager1.initAsNode();
    await nodeKeyManager1.generateKeys();
    const csr1 = nodeKeyManager1.nodeGenerateCsr();
    const cert1 = mobileCA.mobileProcessSetupToken(csr1);
    nodeKeyManager1.nodeInstallCertificate(cert1);

    // Create node 2 key manager and generate certificate
    nodeKeyManager2 = new Keys();
    nodeKeyManager2.initAsNode();
    await nodeKeyManager2.generateKeys();
    const csr2 = nodeKeyManager2.nodeGenerateCsr();
    const cert2 = mobileCA.mobileProcessSetupToken(csr2);
    nodeKeyManager2.nodeInstallCertificate(cert2);

    // Get node public keys and IDs
    const node1PublicKey = nodeKeyManager1.nodeGetPublicKey();
    const node2PublicKey = nodeKeyManager2.nodeGetPublicKey();
    node1Id = Utils.compactId(node1PublicKey);
    node2Id = Utils.compactId(node2PublicKey);

    // Reset event tracking arrays
    node1LifecycleEvents = [];
    node2LifecycleEvents = [];

    // Create NodeInfo objects - mirroring Rust test structure
    const node1Info = {
      nodePublicKey: node1PublicKey,
      networkIds: ['test'],
      addresses: ['127.0.0.1:50131'],
      nodeMetadata: {
        services: [],
        subscriptions: []
      },
      version: 0
    };

    const node2Info = {
      nodePublicKey: node2PublicKey,
      networkIds: ['test'],
      addresses: ['127.0.0.1:50132'],
      nodeMetadata: {
        services: [],
        subscriptions: []
      },
      version: 0
    };

    // Create request handler - no-op response like in Rust test
    const requestHandler = (req: TransportRequest) => {
      return {
        correlationId: req.correlationId,
        path: req.path,
        payload: Buffer.from([]) // Empty response
      };
    };

    // Create event handler - no-op like in Rust test
    const eventHandler = (event: TransportEvent) => {
      // No-op
    };

    // Create lifecycle callbacks - mirroring Rust test structure
    const node1PeerConnected = (envelope: PeerConnectedEnvelope) => {
      node1LifecycleEvents.push({ peerId: envelope.peerId, connected: true });
    };

    const node1PeerDisconnected = (envelope: PeerDisconnectedEnvelope) => {
      node1LifecycleEvents.push({ peerId: envelope.peerId, connected: false });
    };

    const node2PeerConnected = (envelope: PeerConnectedEnvelope) => {
      node2LifecycleEvents.push({ peerId: envelope.peerId, connected: true });
    };

    const node2PeerDisconnected = (envelope: PeerDisconnectedEnvelope) => {
      node2LifecycleEvents.push({ peerId: envelope.peerId, connected: false });
    };

    // Create transports with lifecycle callbacks
    transport1 = new Transport(nodeKeyManager1, { bindAddr: '127.0.0.1:50131' });
    transport2 = new Transport(nodeKeyManager2, { bindAddr: '127.0.0.1:50132' });

    // Register callbacks
    transport1.onRequest(requestHandler);
    transport1.onEvent(eventHandler);
    transport1.onPeerConnected(node1PeerConnected);
    transport1.onPeerDisconnected(node1PeerDisconnected);

    transport2.onRequest(requestHandler);
    transport2.onEvent(eventHandler);
    transport2.onPeerConnected(node2PeerConnected);
    transport2.onPeerDisconnected(node2PeerDisconnected);

    // Start both transports
    await transport1.start();
    await transport2.start();

    // Wait for initialization - mirroring Rust test timing
    await new Promise(resolve => setTimeout(resolve, 150));
  });

  afterEach(async () => {
    if (transport1) {
      await transport1.stop();
    }
    if (transport2) {
      await transport2.stop();
    }
  });

  it('should handle lifecycle callbacks (connect, disconnect, reconnect)', async () => {
    // Test timeout watchdog - mirroring Rust test
    const watchdog = setTimeout(() => {
      throw new Error('test_quic_lifecycle_callbacks timed out');
    }, 5000);

    try {
      // Connect 1 -> 2 - mirroring Rust test
      const peerInfo = encode({ 
        public_key: Array.from(nodeKeyManager2.nodeGetPublicKey()), 
        addresses: ['127.0.0.1:50132'] 
      });
      await transport1.connectPeer(peerInfo);

      // Wait for on_up - mirroring Rust test timing
      await new Promise(resolve => setTimeout(resolve, 300));

      // Check that both sides see the connection - mirroring Rust assertions
      const node1EventsAfterConnect = [...node1LifecycleEvents];
      const node2EventsAfterConnect = [...node2LifecycleEvents];

      expect(node1EventsAfterConnect.some(e => e.peerId === node2Id && e.connected)).toBe(true);
      expect(node2EventsAfterConnect.some(e => e.peerId === node1Id && e.connected)).toBe(true);

      // Stop t2, expect on_down at t1 after grace period - mirroring Rust test
      await transport2.stop();
      await new Promise(resolve => setTimeout(resolve, 400));

      const node1EventsAfterStop = [...node1LifecycleEvents];
      expect(node1EventsAfterStop.some(e => e.peerId === node2Id && !e.connected)).toBe(true);

      // Restart t2 and reconnect - mirroring Rust test
      await transport2.start();
      await new Promise(resolve => setTimeout(resolve, 150));

      await transport1.connectPeer(peerInfo);
      await new Promise(rewift/tree/swift_ffi_2/swift-ffisolve => setTimeout(resolve, 400));

      // Check that t1 sees second on_up for t2 after restart - mirroring Rust assertion
      const node1EventsAfterReconnect = [...node1LifecycleEvents];
      const connectedEvents = node1EventsAfterReconnect.filter(e => e.peerId === node2Id && e.connected);
      expect(connectedEvents.length).toBeGreaterThanOrEqual(2);

    } finally {
      clearTimeout(watchdog);
    }
  }, 10000); // 10 second timeout to match Rust test
});
