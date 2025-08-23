import os from 'os';
import fs from 'fs';
import path from 'path';
import { encode } from 'cbor-x';

function loadAddon(): any {
  const filename = 'index.linux-x64-gnu.node';
  const local = path.join(__dirname, '..', filename);
  return require(local);
}

export function createCa(): { addon: any; keys: any; tmpDir: string } {
  const addon = loadAddon();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-ca-'));
  const keys = new addon.Keys();
  keys.setPersistenceDir(tmp);
  keys.enableAutoPersist(true);
  return { addon, keys, tmpDir: tmp };
}

export async function initCa(ca: { keys: any }): Promise<void> {
  await ca.keys.mobileInitializeUserRootKey();
}

export function createNode(addon: any): { keys: any; tmpDir: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-node-'));
  const keys = new addon.Keys();
  keys.setPersistenceDir(tmp);
  keys.enableAutoPersist(true);
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

export async function signAndInstallCert(ca: { keys: any }, node: { keys: any }): Promise<void> {
  const st: Buffer = node.keys.nodeGenerateCsr();
  const certMsg: Buffer = ca.keys.mobileProcessSetupToken(st);
  node.keys.nodeInstallCertificate(certMsg);
}

export function cborPeerInfo(publicKey: Buffer, addresses: string[]): Buffer {
  return encode({ public_key: Array.from(publicKey.values()), addresses });
}

export function cborNodeInfoRaw(ni: any): Buffer { return encode(ni); }


