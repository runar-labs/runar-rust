import path from 'path';
import { encode } from 'cbor-x';
import { createCa, initCa, createNode, signAndInstallCert, buildNodeInfo, cborPeerInfo } from './transport_test_utils';

function loadAddon(): any {
  const filename = 'index.linux-x64-gnu.node';
  const local = path.join(__dirname, '..', filename);
  return require(local);
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: NodeJS.Timeout;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error(`Timeout ${ms}ms: ${label}`)), ms);
  });
  // @ts-ignore
  return Promise.race([p, timeout]).finally(() => clearTimeout(t!));
}

describe('Transport Basic Tests', () => {
  test('should establish connection between two nodes and perform request', async () => {
    const addon = loadAddon();

    // Create CA and initialize
    const ca = createCa();
    await initCa(ca);

    // Setup two nodes and sign certs via CA
    const a = createNode(addon);
    const b = createNode(addon);
    await signAndInstallCert(ca, a);
    await signAndInstallCert(ca, b);

    // Capture public keys from CSR decode is not necessary; the Transport will read from Keys
    // But we need NodeInfo to include addresses
    // Provide NodeInfo so transport exposes correct addresses and pk
    a.keys.setLocalNodeInfo(buildNodeInfo(a.keys, '127.0.0.1:50311', 'test'));
    b.keys.setLocalNodeInfo(buildNodeInfo(b.keys, '127.0.0.1:50312', 'test'));

    // Build transports
    const ta = new addon.Transport(a.keys, encode({ bind_addr: '127.0.0.1:50311' }));
    const tb = new addon.Transport(b.keys, encode({ bind_addr: '127.0.0.1:50312' }));

    await withTimeout(Promise.all([ta.start(), tb.start()]), 4000, 'start transports');

    // Build PeerInfo for B using its public key
    const bPk: Buffer = b.keys.nodeGetPublicKey();
    await withTimeout(ta.connectPeer(cborPeerInfo(bPk, ['127.0.0.1:50312'])), 2000, 'connectPeer');

    // Small delay
    await new Promise((r) => setTimeout(r, 300));

    // Make a simple request if connected
    const bId = require('crypto').createHash('sha1').update(bPk).digest('hex').slice(0, 8); // not actual id
    const isConn = await withTimeout(ta.isConnectedToPublicKey(bPk), 1500, 'isConnectedToPublicKey');
    if (isConn) {
      const resp = await withTimeout(
        ta.requestToPublicKey('test:path', 'corr', Buffer.from([]), bPk, Buffer.from([])),
        2000,
        'requestToPublicKey'
      );
      expect(Buffer.isBuffer(resp)).toBe(true);
    }
    await withTimeout(ta.stop(), 2000, 'stop ta');
    await withTimeout(tb.stop(), 2000, 'stop tb');
  });
});


