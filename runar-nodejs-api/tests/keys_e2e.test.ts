import os from 'os';
import fs from 'fs';
import path from 'path';
import {decode} from 'cbor-x';

function loadAddon(): any {
  const filename = 'index.linux-x64-gnu.node';
  const local = path.join(__dirname, '..', filename);
  return require(local);
}

const mod: any = loadAddon();

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: NodeJS.Timeout;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error(`Timeout ${ms}ms: ${label}`)), ms);
  });
  // @ts-ignore
  return Promise.race([p, timeout]).finally(() => clearTimeout(t!));
}

describe('Keys End-to-End Tests', () => {
  test('should perform complete mobile-node key exchange flow', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-e2e-'));
    const keys = new mod.Keys();
    keys.setPersistenceDir(tmp);
    keys.enableAutoPersist(true);

    // Mobile side: initialize user root key
    await withTimeout(keys.mobileInitializeUserRootKey(), 3000, 'mobileInitializeUserRootKey');

    // Node side: generate CSR/setup token (CBOR)
    const stCbor: Buffer = keys.nodeGenerateCsr();
    const setupToken = decode(stCbor) as {
      node_public_key: Uint8Array;
      node_agreement_public_key: Uint8Array;
      csr_der: Uint8Array;
      node_id: string;
    };

    // Mobile: process setup token → certificate message (CBOR)
    const ncmCbor: Buffer = keys.mobileProcessSetupToken(stCbor);

    // Node: install certificate
    keys.nodeInstallCertificate(ncmCbor);

    // Mobile: create a network and generate network key
    const networkId: string = keys.mobileGenerateNetworkDataKey();

    // Mobile: create network key message for node using node agreement pk from setup token
    const nodeAgreementPk = Buffer.from(setupToken.node_agreement_public_key);
    const nkmCbor: Buffer = keys.mobileCreateNetworkKeyMessage(networkId, nodeAgreementPk);

    // Node: install network key
    keys.nodeInstallNetworkKey(nkmCbor);

    // Mobile: derive two profile keys
    const personalPk: Buffer = keys.mobileDeriveUserProfileKey('personal');
    const workPk: Buffer = keys.mobileDeriveUserProfileKey('work');

    // Envelope encrypt data for network and two profile recipients
    const data = Buffer.from('This is a test message that should be encrypted and decrypted');
    const eedCbor: Buffer = keys.encryptWithEnvelope(data, networkId, [personalPk, workPk]);

    // Node: decrypt envelope
    const decryptedByNode: Buffer = keys.decryptEnvelope(eedCbor);
    expect(decryptedByNode.equals(data)).toBe(true);

    // Local storage encryption/decryption
    const fileData = Buffer.from('This is some secret file content that should be encrypted on the node.');
    const encLocal: Buffer = keys.encryptLocalData(fileData);
    expect(encLocal.equals(fileData)).toBe(false);
    const decLocal: Buffer = keys.decryptLocalData(encLocal);
    expect(decLocal.equals(fileData)).toBe(true);
  });
});
