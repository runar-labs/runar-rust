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

async function main(): Promise<void> {
  const watchdog = setTimeout(() => {
    console.error('keys_basic.test timed out');
    process.exit(1);
  }, 8000);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-api-'));
  const keys = new mod.Keys();
  keys.setPersistenceDir(tmp);
  keys.enableAutoPersist(true);

  await withTimeout(keys.mobileInitializeUserRootKey(), 3000, 'mobileInitializeUserRootKey');

  const data = Buffer.from('hello world');
  const enc: Buffer = keys.encryptLocalData(data);
  if (!Buffer.isBuffer(enc) || enc.equals(data)) throw new Error('encryptLocalData failed');
  const dec: Buffer = keys.decryptLocalData(enc);
  if (!dec.equals(data)) throw new Error('decryptLocalData failed');

  // Test ensure_symmetric_key
  const key1 = keys.ensureSymmetricKey('test_service_1');
  const key2 = keys.ensureSymmetricKey('test_service_2');
  const key1_retrieved = keys.ensureSymmetricKey('test_service_1');
  
  if (!Buffer.isBuffer(key1) || key1.length !== 32) throw new Error('ensure_symmetric_key failed: invalid key1');
  if (!Buffer.isBuffer(key2) || key2.length !== 32) throw new Error('ensure_symmetric_key failed: invalid key2');
  if (!Buffer.isBuffer(key1_retrieved) || key1_retrieved.length !== 32) throw new Error('ensure_symmetric_key failed: invalid key1_retrieved');
  
  // Keys should be different for different services
  if (key1.equals(key2)) throw new Error('ensure_symmetric_key failed: different services should have different keys');
  // Same service should return the same key
  if (!key1.equals(key1_retrieved)) throw new Error('ensure_symmetric_key failed: same service should return the same key');

  await withTimeout(keys.flushState(), 2000, 'flushState');
  await withTimeout(keys.wipePersistence(), 2000, 'wipePersistence');

  console.log('keys_basic TS OK');
  clearTimeout(watchdog);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
