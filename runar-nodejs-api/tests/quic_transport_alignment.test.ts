import { encode } from 'cbor-x'
import {
  setLogLevel,
  Keys,
  Transport,
  TransportOptions,
  Utils
} from '../index'

// Align NodeJS API transporter behavior with Rust quic_transport_test.rs

jest.setTimeout(45000)

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function setupNodeWithCert(keys: Keys, ca: Keys) {
  keys.initAsNode()
  await keys.generateKeys()
  const csr = keys.nodeGenerateCsr()
  const cert = ca.mobileProcessSetupToken(csr)
  keys.nodeInstallCertificate(cert)
}

describe('QUIC Transport alignment with Rust tests', () => {
  test('test_quic_transport (aligned)', async () => {
    setLogLevel(3) // Info

    // CA
    const mobileCA = new Keys()
    mobileCA.initAsMobile()

    // Nodes with certs
    const node1 = new Keys()
    const node2 = new Keys()
    await setupNodeWithCert(node1, mobileCA)
    await setupNodeWithCert(node2, mobileCA)

    const node1Pk = node1.nodeGetPublicKey()
    const node2Pk = node2.nodeGetPublicKey()
    const id1 = Utils.compactId(node1Pk)
    const id2 = Utils.compactId(node2Pk)

    const t1 = new Transport(node1, { bindAddr: '127.0.0.1:50069', maxMessageSize: 1024 } as TransportOptions)
    const t2 = new Transport(node2, { bindAddr: '127.0.0.1:50044', maxMessageSize: 1024 } as TransportOptions)

    // Simple echo on t2
    t2.onRequest(async (req: any) => {
      await t2.completeRequest(req.requestId, new TextEncoder().encode('ok'), [])
    })

    await t1.start()
    await t2.start()

    // Connect t1 -> t2
    const peerInfo = encode({ public_key: Array.from(node2Pk), addresses: ['127.0.0.1:50044'] })
    await t1.connectPeer(peerInfo)

    // Request t1->t2
    const resp = await t1.request(
      '$registry/services/list',
      'test_corr_1',
      new Uint8Array([]),
      id2,
      undefined,
      []
    )
    expect(resp instanceof Uint8Array).toBeTruthy()

    await t1.stop()
    await t2.stop()
  })

  test('test_dial_cancel_on_inbound_connect (aligned)', async () => {
    setLogLevel(2)

    const mobileCA = new Keys()
    mobileCA.initAsMobile()
    const k1 = new Keys()
    const k2 = new Keys()
    await setupNodeWithCert(k1, mobileCA)
    await setupNodeWithCert(k2, mobileCA)

    const pk1 = k1.nodeGetPublicKey()
    const pk2 = k2.nodeGetPublicKey()
    const id1 = Utils.compactId(pk1)
    const id2 = Utils.compactId(pk2)

    const t1 = new Transport(k1, { bindAddr: '127.0.0.1:50151', maxMessageSize: 1024 } as TransportOptions)
    const t2 = new Transport(k2, { bindAddr: '127.0.0.1:50152', maxMessageSize: 1024 } as TransportOptions)

    // echo on both
    t1.onRequest(async (req: any) => { await t1.completeRequest(req.requestId, new TextEncoder().encode('ok'), []) })
    t2.onRequest(async (req: any) => { await t2.completeRequest(req.requestId, new TextEncoder().encode('ok'), []) })

    await t1.start()
    await t2.start()

    const p1 = encode({ public_key: Array.from(pk1), addresses: ['127.0.0.1:50151'] })
    const p2 = encode({ public_key: Array.from(pk2), addresses: ['127.0.0.1:50152'] })

    // Start outbound, then inbound quickly
    const dial1 = t1.connectPeer(p2)
    await sleep(10)
    await t2.connectPeer(p1)
    await dial1.catch(() => {})

    await sleep(300)

    expect(await t1.isConnected(id2) || await t2.isConnected(id1)).toBeTruthy()

    // Simple request either direction should work
    const path = '$registry/services/list'
    const payload = new Uint8Array([])
    const r1 = await t1.request(path, 'test_corr_1', payload, id2, undefined, [])
    const ok = r1 instanceof Uint8Array ? true : false
    if (!ok) {
      const r2 = await t2.request(path, 'test_corr_2', payload, id1, undefined, [])
      expect(r2 instanceof Uint8Array).toBeTruthy()
    }

    await t1.stop()
    await t2.stop()
  })

  test('test_quic_duplicate_resolution_simultaneous_dial (aligned)', async () => {
    setLogLevel(2)

    const mobileCA = new Keys()
    mobileCA.initAsMobile()
    const k1 = new Keys()
    const k2 = new Keys()
    await setupNodeWithCert(k1, mobileCA)
    await setupNodeWithCert(k2, mobileCA)
    const pk1 = k1.nodeGetPublicKey()
    const pk2 = k2.nodeGetPublicKey()
    const id1 = Utils.compactId(pk1)
    const id2 = Utils.compactId(pk2)

    const t1 = new Transport(k1, { bindAddr: '127.0.0.1:50111', maxMessageSize: 1024 } as TransportOptions)
    const t2 = new Transport(k2, { bindAddr: '127.0.0.1:50112', maxMessageSize: 1024 } as TransportOptions)
    t1.onRequest(async (req: any) => { await t1.completeRequest(req.requestId, req.payload, []) })
    t2.onRequest(async (req: any) => { await t2.completeRequest(req.requestId, req.payload, []) })
    await t1.start(); await t2.start()

    const p1 = encode({ public_key: Array.from(pk1), addresses: ['127.0.0.1:50111'] })
    const p2 = encode({ public_key: Array.from(pk2), addresses: ['127.0.0.1:50112'] })

    await Promise.all([ t1.connectPeer(p2), t2.connectPeer(p1) ])
    await sleep(150)

    // Expect both connected
    expect(await t1.isConnected(id2) && await t2.isConnected(id1)).toBeTruthy()

    // Concurrent requests both directions
    const payload = new TextEncoder().encode('x')
    const [r1, r2] = await Promise.all([
      t1.request('test:echo/req', 'corr1', payload, id2, undefined, [pk1]),
      t2.request('test:echo/req', 'corr2', payload, id1, undefined, [pk2])
    ])
    expect(r1 instanceof Uint8Array && r2 instanceof Uint8Array).toBeTruthy()

    await t1.stop(); await t2.stop()
  })
})


