import { 
  loadAddon, 
  createTempDir, 
  cleanupTempDir, 
  withTimeout,
  createMobileKeys,
  createNodeKeys,
  uint8ArrayEquals
} from './test_utils';

const mod = loadAddon();

describe('Keys Basic Tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    cleanupTempDir(tmpDir);
  });

  test('should create and initialize basic key instances', () => {
    const mobileKeys = new mod.Keys();
    const nodeKeys = new mod.Keys();
    
    expect(mobileKeys).toBeDefined();
    expect(nodeKeys).toBeDefined();
    expect(typeof mobileKeys.initAsMobile).toBe('function');
    expect(typeof nodeKeys.initAsNode).toBe('function');
  });

  test('should handle basic persistence operations', () => {
    const keys = new mod.Keys();
    
    expect(() => keys.setPersistenceDir(tmpDir)).not.toThrow();
    expect(() => keys.enableAutoPersist(true)).not.toThrow();
    expect(() => keys.enableAutoPersist(false)).not.toThrow();
  });

  test('should perform basic symmetric key operations', () => {
    const keys = new mod.Keys();
    keys.initAsNode();
    
    const key1 = keys.ensureSymmetricKey('test-service');
    expect(key1 instanceof Uint8Array).toBe(true);
    expect(key1.length).toBe(32);
    
    const key2 = keys.ensureSymmetricKey('test-service');
    expect(uint8ArrayEquals(key1, key2)).toBe(true);
    
    const key3 = keys.ensureSymmetricKey('different-service');
    expect(uint8ArrayEquals(key1, key3)).toBe(false);
  });

  test('should handle basic keystore capabilities', () => {
    const keys = new mod.Keys();
    const caps = keys.getKeystoreCaps();
    
    expect(caps).toHaveProperty('version');
    expect(caps).toHaveProperty('flags');
    expect(typeof caps.version).toBe('number');
    expect(typeof caps.flags).toBe('number');
  });
});
