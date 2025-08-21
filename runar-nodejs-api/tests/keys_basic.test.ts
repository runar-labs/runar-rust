import os from 'os';
import fs from 'fs';
import path from 'path';

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

describe('Keys Basic Tests', () => {
  test('should initialize mobile keystore and perform basic operations', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-api-'));
    const keys = new mod.Keys();
    keys.setPersistenceDir(tmp);
    keys.enableAutoPersist(true);

    await withTimeout(keys.mobileInitializeUserRootKey(), 3000, 'mobileInitializeUserRootKey');

    const data = Buffer.from('hello world');
    const enc: Buffer = keys.encryptLocalData(data);
    expect(Buffer.isBuffer(enc)).toBe(true);
    expect(enc.equals(data)).toBe(false);
    
    const dec: Buffer = keys.decryptLocalData(enc);
    expect(dec.equals(data)).toBe(true);

    await withTimeout(keys.flushState(), 2000, 'flushState');
    await withTimeout(keys.wipePersistence(), 2000, 'wipePersistence');
  });

  test('should manage symmetric keys properly', () => {
    const keys = new mod.Keys();
    
    // Test ensure_symmetric_key for different services
    const key1 = keys.ensureSymmetricKey('test_service_1');
    const key2 = keys.ensureSymmetricKey('test_service_2');
    const key1_retrieved = keys.ensureSymmetricKey('test_service_1');
    
    expect(Buffer.isBuffer(key1)).toBe(true);
    expect(key1.length).toBe(32);
    expect(Buffer.isBuffer(key2)).toBe(true);
    expect(key2.length).toBe(32);
    expect(Buffer.isBuffer(key1_retrieved)).toBe(true);
    expect(key1_retrieved.length).toBe(32);
    
    // Keys should be different for different services
    expect(key1.equals(key2)).toBe(false);
    // Same service should return the same key
    expect(key1.equals(key1_retrieved)).toBe(true);
  });
});
