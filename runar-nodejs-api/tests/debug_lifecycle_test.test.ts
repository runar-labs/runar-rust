import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { 
  Keys, 
  Transport, 
  setLogLevel,
  Utils
} from '../index';
import { encode } from 'cbor-x';

describe('Debug Lifecycle Test', () => {
  let mobileCA: Keys;
  let nodeKeyManager1: Keys;
  let nodeKeyManager2: Keys;
  let transport1: Transport;
  let transport2: Transport;
  let node1Id: string;
  let node2Id: string;

  // Event tracking
  let node1ConnectedEvents: string[] = [];
  let node1DisconnectedEvents: string[] = [];

  beforeEach(async () => {
    setLogLevel(2); // Warn level

    // Initialize mobile CA
    mobileCA = new Keys();
    mobileCA.initAsMobile();

    // Create node 1
    nodeKeyManager1 = new Keys();
    nodeKeyManager1.initAsNode();
    await nodeKeyManager1.generateKeys();
    const csr1 = nodeKeyManager1.nodeGenerateCsr();
    const cert1 = mobileCA.mobileProcessSetupToken(csr1);
    nodeKeyManager1.nodeInstallCertificate(cert1);

    // Create node 2
    nodeKeyManager2 = new Keys();
    nodeKeyManager2.initAsNode();
    await nodeKeyManager2.generateKeys();
    const csr2 = nodeKeyManager2.nodeGenerateCsr();
    const cert2 = mobileCA.mobileProcessSetupToken(csr2);
    nodeKeyManager2.nodeInstallCertificate(cert2);

    // Get IDs
    const node1PublicKey = nodeKeyManager1.nodeGetPublicKey();
    const node2PublicKey = nodeKeyManager2.nodeGetPublicKey();
    node1Id = Utils.compactId(node1PublicKey);
    node2Id = Utils.compactId(node2PublicKey);

    // Reset events
    node1ConnectedEvents = [];
    node1DisconnectedEvents = [];

    // Create transports
    transport1 = new Transport(nodeKeyManager1, { bindAddr: '127.0.0.1:50131' });
    transport2 = new Transport(nodeKeyManager2, { bindAddr: '127.0.0.1:50132' });

    // Register callbacks with console.log to debug
    transport1.onPeerConnected((envelope) => {
      console.log('🔗 Node1 PeerConnected callback called:', envelope.peerId);
      node1ConnectedEvents.push(envelope.peerId);
    });

    transport1.onPeerDisconnected((envelope) => {
      console.log('🔌 Node1 PeerDisconnected callback called:', envelope.peerId);
      node1DisconnectedEvents.push(envelope.peerId);
    });

    // Simple request handler
    transport1.onRequest((req) => {
      return {
        correlationId: req.correlationId,
        path: req.path,
        payload: Buffer.from([])
      };
    });

    transport2.onRequest((req) => {
      return {
        correlationId: req.correlationId,
        path: req.path,
        payload: Buffer.from([])
      };
    });

    // Start transports
    await transport1.start();
    await transport2.start();

    // Wait for initialization
    await new Promise(resolve => setTimeout(resolve, 150));
  });

  afterEach(async () => {
    if (transport1) await transport1.stop();
    if (transport2) await transport2.stop();
  });

  it('should call peer connected callback', async () => {
    console.log('🔍 Starting connection test...');
    console.log('Node1 ID:', node1Id);
    console.log('Node2 ID:', node2Id);

    // Connect
    const peerInfo = encode({ 
      public_key: Array.from(nodeKeyManager2.nodeGetPublicKey()), 
      addresses: ['127.0.0.1:50132'] 
    });
    
    console.log('🔗 Connecting...');
    await transport1.connectPeer(peerInfo);

    // Wait for callbacks
    console.log('⏳ Waiting for callbacks...');
    await new Promise(resolve => setTimeout(resolve, 500));

    console.log('📊 Results:');
    console.log('Connected events:', node1ConnectedEvents);
    console.log('Disconnected events:', node1DisconnectedEvents);

    // Check if any connected events were received
    expect(node1ConnectedEvents.length).toBeGreaterThan(0);
  }, 10000);
});

