import os from 'os';
import fs from 'fs';
import path from 'path';
import { encode, decode } from 'cbor-x';

function loadAddon(): any {
  const filename = 'index.linux-x64-gnu.node';
  const local = path.join(__dirname, '..', filename);
  return require(local);
}

export function createCa(): { addon: any; rootCa: any; issuingCa: any; caNode: any; tmpDir: string } {
  const addon = loadAddon();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-ca-'));
  
  // Create proper CA infrastructure like E2E test
  const rootCa = addon.CaCreator.createRootCa('CN=Test Root CA,O=Test,C=US');
  const issuingCa = addon.CaCreator.createIssuingCa(rootCa, 'CN=Test Issuing CA,O=Test,C=US', 365, 1);
  const caNode = new addon.CaNode();
  
  return { addon, rootCa, issuingCa, caNode, tmpDir: tmp };
}

export async function initCa(ca: { addon: any; rootCa: any; issuingCa: any; caNode: any }): Promise<void> {
  // Setup CA Node with real certificates
  const eaKey = ca.addon.CaCreator.createEaKey();
  const eaPublicKey = ca.addon.CaCreator.getEaPublicKey(eaKey);
  const eaPublicKeysCbor = new Uint8Array(encode([Array.from(eaPublicKey)]));
  
  // Store the EA key for later use
  ca.eaKey = eaKey;
  
  await ca.caNode.setupComplete(
    'CN=Test Root CA,O=Test,C=US',
    'CN=Test Issuing CA,O=Test,C=US',
    365, // validity_days
    1,   // issuing_ca_serial
    eaPublicKeysCbor,
    'test_network'
  );
  
  // Configure enrollment authority
  await ca.caNode.configureEnrollmentAuthority(eaPublicKeysCbor);
}

export function createNode(addon: any): { keys: any; tmpDir: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-node-'));
  const keys = new addon.Keys();
  keys.setPersistenceDir(tmp);
  keys.enableAutoPersist(true);
  keys.initAsNode(); // Initialize as node manager like Rust tests
  return { keys, tmpDir: tmp };
}

export function buildNodeInfo(keys: any, address: string, network: string): Buffer {
  const pk: Buffer = keys.nodeGetPublicKey();
  const ni = {
    node_public_key: Array.from(pk.values()),
    network_ids: [network],
    addresses: [address],
    node_metadata: { services: [], subscriptions: [] },
    version: 0,
  };
  return encode(ni);
}

export async function signAndInstallCert(ca: { addon: any; caNode: any }, node: { keys: any }): Promise<void> {
  // Generate node keys
  node.keys.nodeGenerateKeys();
  
  // Create CA Server and Client for enrollment
  const adminSkis = ['admin_ski_1'];
  const serverConfig = new Uint8Array(encode({
    bootstrap_bind: '127.0.0.1:8443',
    authenticated_bind: '127.0.0.1:8444',
    network_id: 'test_network',
    rate_limit_per_minute: 100,
    rate_limit_per_hour: 1000,
    admin_skis: adminSkis
  }));
  
  const caServer = new ca.addon.CaServer(serverConfig, ca.caNode.createShared());
  await caServer.start();
  
  // Create CA Client
  const rootCaCert = ca.caNode.getRootCaCertificate();
  const issuingCaCert = await ca.caNode.getIssuingCaCertificate();
  const clientConfig = new Uint8Array(encode({
    bootstrap_server: '127.0.0.1:8443',
    authenticated_server: '127.0.0.1:8444',
    network_id: 'test_network',
    request_timeout_seconds: 30,
    max_retries: 3,
    root_ca_der: Array.from(rootCaCert),
    issuing_ca_der: Array.from(issuingCaCert)
  }));
  
  const caClient = new ca.addon.CaClient(clientConfig, node.keys);
  
  // Generate CSR and enroll
  const csrDer = node.keys.nodeGenerateCsrDer();
  const enrollmentTokenCbor = ca.addon.EnrollmentToken.generate(
    ca.eaKey, // Use same EA key as CA Node
    'test_network',
    'CN=Test Node',
    7, // validity days
    ['enroll']
  );
  
  // Decode the CBOR token to get the struct (following FFI pattern)
  const enrollmentToken = decode(enrollmentTokenCbor);
  
  const enrollRequest = new Uint8Array(encode({
    network_id: 'test_network',
    csr_der: Array.from(csrDer),
    enrollment_token: enrollmentToken // Use the struct directly, not re-encoded CBOR
  }));
  
  const enrollResponse = await caClient.enroll('127.0.0.1:8443', enrollRequest);
  
  // Convert and install certificate
  const mobileKeys = new ca.addon.Keys();
  mobileKeys.initAsMobile();
  await mobileKeys.mobileInitializeUserRootKey();
  
  const certificateMessage = await mobileKeys.mobileFromEnrollResponse(enrollResponse);
  await node.keys.nodeInstallCertificate(certificateMessage);
  
  // Debug: Check if certificate was installed
  try {
    const nodeCert = node.keys.nodeGetNodeCertificate();
    console.log(`   ✅ Certificate installed successfully: ${nodeCert.length} bytes`);
  } catch (e) {
    console.log(`   ❌ Certificate installation failed: ${e}`);
  }
  
  // Cleanup
  await caServer.stop();
}

export function cborPeerInfo(publicKey: Buffer, addresses: string[]): Buffer {
  return encode({ public_key: Array.from(publicKey.values()), addresses });
}

export function cborNodeInfoRaw(ni: any): Buffer { return encode(ni); }


