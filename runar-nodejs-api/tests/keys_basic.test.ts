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

  await withTimeout(keys.flushState(), 2000, 'flushState');
  await withTimeout(keys.wipePersistence(), 2000, 'wipePersistence');

  console.log('keys_basic TS OK');
  clearTimeout(watchdog);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
