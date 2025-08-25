import os from 'os';
import fs from 'fs';
import path from 'path';

/**
 * Load the native addon module
 */
export function loadAddon(): any {
  const filename = 'index.linux-x64-gnu.node';
  const local = path.join(__dirname, '..', filename);
  return require(local);
}

/**
 * Create a temporary directory for testing
 */
export function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'runar-nodejs-test-'));
}

/**
 * Clean up a temporary directory
 */
export function cleanupTempDir(tmpDir: string): void {
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Timeout wrapper for async operations
 */
export function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: NodeJS.Timeout;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error(`Timeout ${ms}ms: ${label}`)), ms);
  });
  // @ts-ignore
  return Promise.race([p, timeout]).finally(() => clearTimeout(t!));
}

/**
 * Create a mock public key buffer for testing
 */
export function createMockPublicKey(size: number = 65): Buffer {
  return Buffer.alloc(size, 1);
}

/**
 * Create a mock profile key for testing
 */
export function createMockProfileKey(): Buffer {
  return Buffer.alloc(65, 2);
}

/**
 * Create test data buffer
 */
export function createTestData(size: number = 1024): Buffer {
  return Buffer.alloc(size, 0x42); // Fill with 'B'
}

/**
 * Create a mock setup token for testing
 */
export function createMockSetupToken(): any {
  return {
    node_id: 'test-node-' + Date.now(),
    node_public_key: createMockPublicKey(),
    node_agreement_public_key: createMockPublicKey(),
    csr_der: Buffer.alloc(100, 3)
  };
}

/**
 * Create a mock network key message for testing
 */
export function createMockNetworkKeyMessage(): Buffer {
  return Buffer.alloc(100, 4);
}

/**
 * Create a mock certificate message for testing
 */
export function createMockCertificateMessage(): Buffer {
  return Buffer.alloc(100, 5);
}

/**
 * Create a fresh Keys instance with mobile initialization
 */
export async function createMobileKeys(tmpDir?: string): Promise<any> {
  const mod = loadAddon();
  const keys = new mod.Keys(); // Fresh instance
  
  if (tmpDir) {
    keys.setPersistenceDir(tmpDir);
    keys.enableAutoPersist(true);
  }
  
  keys.initAsMobile();
  await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
  
  return keys;
}

/**
 * Create a fresh Keys instance with node initialization
 */
export function createNodeKeys(tmpDir?: string): any {
  const mod = loadAddon();
  const keys = new mod.Keys(); // Fresh instance
  
  if (tmpDir) {
    keys.setPersistenceDir(tmpDir);
    keys.enableAutoPersist(true);
  }
  
  keys.initAsNode();
  return keys;
}

/**
 * Create a fresh Keys instance without initialization
 */
export function createFreshKeys(tmpDir?: string): any {
  const mod = loadAddon();
  const keys = new mod.Keys(); // Fresh instance
  
  if (tmpDir) {
    keys.setPersistenceDir(tmpDir);
    keys.enableAutoPersist(true);
  }
  
  return keys;
}

/**
 * Performance measurement utility
 */
export function measurePerformance<T>(
  fn: () => T,
  iterations: number = 1000
): { result: T; avgTimeMs: number; totalTimeMs: number } {
  const start = performance.now();
  let result: T;
  
  for (let i = 0; i < iterations; i++) {
    result = fn();
  }
  
  const totalTime = performance.now() - start;
  const avgTime = totalTime / iterations;
  
  return {
    result: result!,
    avgTimeMs: avgTime,
    totalTimeMs: totalTime
  };
}

/**
 * Memory usage measurement utility
 */
export function measureMemoryUsage<T>(fn: () => T): { result: T; memoryUsage: NodeJS.MemoryUsage } {
  const before = process.memoryUsage();
  const result = fn();
  const after = process.memoryUsage();
  
  return {
    result,
    memoryUsage: {
      rss: after.rss - before.rss,
      heapTotal: after.heapTotal - before.heapTotal,
      heapUsed: after.heapUsed - before.heapUsed,
      external: after.external - before.external,
      arrayBuffers: after.arrayBuffers - before.arrayBuffers
    }
  };
}
