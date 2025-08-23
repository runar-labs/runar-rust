import path from 'path';
import { encode } from 'cbor-x';
import { createCa, initCa, createNode, signAndInstallCert, buildNodeInfo } from './transport_test_utils';

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

describe('Discovery Basic Tests', () => {
  test('should discover and connect nodes via multicast discovery', async () => {
    const addon = loadAddon();

    // CA
    const ca = createCa();
    await initCa(ca);

    // Nodes and certs
    const a = createNode(addon);
    const b = createNode(addon);
    await signAndInstallCert(ca, a);
    await signAndInstallCert(ca, b);

    // Local node info and transports
    const addrA = '127.0.0.1:50511';
    const addrB = '127.0.0.1:50512';
    a.keys.setLocalNodeInfo(buildNodeInfo(a.keys, addrA, 'test'));
    b.keys.setLocalNodeInfo(buildNodeInfo(b.keys, addrB, 'test'));

    const ta = new addon.Transport(a.keys, encode({ bind_addr: addrA }));
    const tb = new addon.Transport(b.keys, encode({ bind_addr: addrB }));
    await withTimeout(Promise.all([ta.start(), tb.start()]), 5000, 'start transports');

    // Discovery instances
    const uniquePort = 49000 + Math.floor(Math.random() * 500);
    const multicastGroup = `239.10.10.10:${uniquePort}`;
    const discOpts = {
      local_addresses: [addrA],
      multicast_group: multicastGroup,
      announce_interval_ms: 80,
      discovery_timeout_ms: 800,
      debounce_window_ms: 120,
      use_multicast: true,
      local_network_only: true,
    };
    const discOptsB = { ...discOpts, local_addresses: [addrB] };

    const da = new addon.Discovery(a.keys, encode(discOpts));
    const db = new addon.Discovery(b.keys, encode(discOptsB));

    await withTimeout(da.init(encode(discOpts)), 2000, 'discovery init A');
    await withTimeout(db.init(encode(discOptsB)), 2000, 'discovery init B');
    await withTimeout(da.bindEventsToTransport(ta), 2000, 'bind discovery A');
    await withTimeout(db.bindEventsToTransport(tb), 2000, 'bind discovery B');

    await withTimeout(da.startAnnouncing(), 2000, 'announce A');
    // slight stagger
    await new Promise((r) => setTimeout(r, 150));
    await withTimeout(db.startAnnouncing(), 2000, 'announce B');

    // Wait for discovery/connect
    const bPk: Buffer = b.keys.nodeGetPublicKey();
    const aPk: Buffer = a.keys.nodeGetPublicKey();

    // Retry loop within timeout window
    const deadline = Date.now() + 6000;
    let connectedAB = false;
    while (Date.now() < deadline) {
      // either side connected to the other is fine
      const aConn = await ta.isConnectedToPublicKey(bPk);
      const bConn = await tb.isConnectedToPublicKey(aPk);
      if (aConn || bConn) {
        connectedAB = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 120));
    }

    expect(connectedAB).toBe(true);

    // Cleanup
    await withTimeout(da.stopAnnouncing(), 2000, 'stop announce A');
    await withTimeout(db.stopAnnouncing(), 2000, 'stop announce B');
    await withTimeout(ta.stop(), 2000, 'stop ta');
    await withTimeout(tb.stop(), 2000, 'stop tb');
  });
});


