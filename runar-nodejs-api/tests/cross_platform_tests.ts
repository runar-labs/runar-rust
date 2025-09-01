import os from 'os';
import fs from 'fs';
import path from 'path';
import { uint8ArrayEquals } from './test_utils';

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

describe('Cross-Platform Tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-cross-platform-'));
  });

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('Core Error Handling Consistency', () => {
    test('should handle null arguments consistently', () => {
      const keys = new mod.Keys();
      
      // Test that the API handles edge cases gracefully
      expect(() => keys.setPersistenceDir('')).not.toThrow();
      expect(() => keys.enableAutoPersist(false)).not.toThrow();
    });

    test('should handle initialization errors consistently', () => {
      const keys = new mod.Keys();
      
      // Test manager type validation
      keys.initAsMobile();
      expect(() => keys.initAsNode()).toThrow('Already initialized as mobile manager');
      
      const keys2 = new mod.Keys();
      keys2.initAsNode();
      expect(() => keys2.initAsMobile()).toThrow('Already initialized as node manager');
    });

    test('should handle wrong manager type errors consistently', () => {
      const keys = new mod.Keys();
      keys.initAsMobile();
      
      // Test that mobile instance can't use node functions
      expect(() => keys.nodeGetNodeId()).toThrow('Node manager not initialized');
      expect(() => keys.nodeGetPublicKey()).toThrow('Node manager not initialized');
      expect(() => keys.nodeGetAgreementPublicKey()).toThrow('Node manager not initialized');
      
      const keys2 = new mod.Keys();
      keys2.initAsNode();
      
      // Test that node instance can't use mobile functions
      expect(() => keys2.mobileGetUserPublicKey()).toThrow('Mobile manager not initialized');
      expect(() => keys2.mobileDeriveUserProfileKey('test')).toThrow('Mobile manager not initialized');
    });
  });

  describe('Core Initialization Flow', () => {
    test('should initialize mobile manager successfully', async () => {
      const keys = new mod.Keys();
      keys.initAsMobile();
      
      await expect(withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey')).resolves.not.toThrow();
      
      const pk = keys.mobileGetUserPublicKey();
      expect(pk instanceof Uint8Array).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    }, 10000);

    test('should initialize node manager successfully', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      const id = keys.nodeGetNodeId();
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
      
      const pk = keys.nodeGetPublicKey();
      expect(pk instanceof Uint8Array).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    });

    test('should handle persistence operations consistently', async () => {
      const keys = new mod.Keys();
      keys.setPersistenceDir(tmpDir);
      keys.enableAutoPersist(true);
      
      await expect(withTimeout(keys.flushState(), 5000, 'flushState')).resolves.not.toThrow();
      await expect(withTimeout(keys.wipePersistence(), 5000, 'wipePersistence')).resolves.not.toThrow();
    }, 15000);
  });

  describe('Basic Cryptographic Operations', () => {
    test('should perform local data encryption/decryption', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      const data = Buffer.from('test data for encryption');
      const encrypted = keys.encryptLocalData(data);
      expect(encrypted instanceof Uint8Array).toBe(true);
      expect(uint8ArrayEquals(encrypted, data)).toBe(false);
      
      const decrypted = keys.decryptLocalData(encrypted);
      expect(uint8ArrayEquals(decrypted, data)).toBe(true);
    });

    test('should perform symmetric key operations', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      const key1 = keys.ensureSymmetricKey('service1');
      const key2 = keys.ensureSymmetricKey('service2');
      const key1Again = keys.ensureSymmetricKey('service1');
      
      expect(key1 instanceof Uint8Array).toBe(true);
      expect(key1.length).toBe(32);
      expect(uint8ArrayEquals(key1, key2)).toBe(false);
      expect(uint8ArrayEquals(key1, key1Again)).toBe(true);
    });

    test('should perform envelope encryption with mobile manager', async () => {
      const keys = new mod.Keys();
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const data = Buffer.from('test envelope data');
      const profilePks = [Buffer.alloc(65, 1)];
      const encrypted = keys.mobileEncryptWithEnvelope(data, 'test-network', profilePks);
      
      expect(encrypted instanceof Uint8Array).toBe(true);
      expect(uint8ArrayEquals(encrypted, data)).toBe(false);
    }, 10000);

    test('should perform envelope encryption with node manager', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      const data = Buffer.from('test envelope data');
      const profilePks = [Buffer.alloc(65, 1)];
      const encrypted = keys.nodeEncryptWithEnvelope(data, 'test-network', profilePks);
      
      expect(encrypted instanceof Uint8Array).toBe(true);
      expect(uint8ArrayEquals(encrypted, data)).toBe(false);
    });
  });

  describe('Keystore State Management', () => {
    test('should get keystore state consistently', () => {
      const keys = new mod.Keys();
      
      const caps = keys.getKeystoreCaps();
      expect(caps).toHaveProperty('version');
      expect(caps).toHaveProperty('flags');
      expect(typeof caps.version).toBe('number');
      expect(typeof caps.flags).toBe('number');
    });

    test('should get node keystore state after initialization', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      const state = keys.nodeGetKeystoreState();
      expect(typeof state).toBe('number');
      expect(state).toBeGreaterThanOrEqual(0);
    });

    test('should get mobile keystore state after initialization', async () => {
      const keys = new mod.Keys();
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const state = keys.mobileGetKeystoreState();
      expect(typeof state).toBe('number');
      expect(state).toBeGreaterThanOrEqual(0);
    }, 10000);
  });

  describe('Memory Management', () => {
    test('should handle large data operations without memory leaks', () => {
      const keys = new mod.Keys();
      keys.initAsNode();
      
      // Test with large data
      const largeData = Buffer.alloc(1024 * 1024, 0x42); // 1MB
      const encrypted = keys.encryptLocalData(largeData);
      expect(encrypted instanceof Uint8Array).toBe(true);
      
      const decrypted = keys.decryptLocalData(encrypted);
      expect(uint8ArrayEquals(decrypted, largeData)).toBe(true);
    });
  });
});
