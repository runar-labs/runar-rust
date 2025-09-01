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
 * Create test data buffer for encryption/decryption tests
 */
export function createTestData(size: number = 1024): Buffer {
  return Buffer.alloc(size, 0x42); // Fill with 'B'
}

/**
 * Create a fresh Keys instance with mobile initialization
 */
export function createMobileKeys(tmpDir?: string): Promise<any> {
  console.log('🔄 Creating mobile keys instance...');
  const startTime = Date.now();
  
  return new Promise((resolve, reject) => {
    try {
      console.log('  📱 Creating new Keys instance...');
      const mod = loadAddon();
      const keys = new mod.Keys();
      console.log('  ✅ Keys instance created');
      
      if (tmpDir) {
        console.log('  📁 Setting persistence directory...');
        keys.setPersistenceDir(tmpDir);
        keys.enableAutoPersist(true);
        console.log('  ✅ Persistence configured');
      }

      console.log('  🔧 Initializing as mobile manager...');
      keys.initAsMobile();
      console.log('  ✅ Mobile manager initialized');
      
      console.log('  🔑 Initializing user root key...');
      keys.mobileInitializeUserRootKey().then(() => {
        console.log('  ✅ User root key initialized');
        const duration = Date.now() - startTime;
        console.log(`  ⏱️  Mobile keys creation completed in ${duration}ms`);
        resolve(keys);
      }).catch((error: any) => {
        const duration = Date.now() - startTime;
        console.log(`  ❌ User root key initialization failed after ${duration}ms:`, error);
        reject(error);
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      console.log(`  ❌ Mobile keys creation failed after ${duration}ms:`, error);
      reject(error);
    }
  });
}

/**
 * Create a fresh Keys instance with node initialization
 */
export function createNodeKeys(tmpDir?: string): any {
  console.log('🔄 Creating node keys instance...');
  const startTime = Date.now();
  
  try {
    console.log('  🖥️  Creating new Keys instance...');
    const mod = loadAddon();
    const keys = new mod.Keys();
    console.log('  ✅ Keys instance created');
    
    if (tmpDir) {
      console.log('  📁 Setting persistence directory...');
      keys.setPersistenceDir(tmpDir);
      keys.enableAutoPersist(true);
      console.log('  ✅ Persistence configured');
    }

    console.log('  🔧 Initializing as node manager...');
    keys.initAsNode();
    console.log('  ✅ Node manager initialized');
    
    const duration = Date.now() - startTime;
    console.log(`  ⏱️  Node keys creation completed in ${duration}ms`);
    return keys;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`  ❌ Node keys creation failed after ${duration}ms:`, error);
    throw error;
  }
}

/**
 * Create a fresh Keys instance without initialization
 */
export function createFreshKeys(tmpDir?: string): any {
  console.log('🔄 Creating fresh keys instance...');
  const startTime = Date.now();
  
  try {
    console.log('  🆕 Creating new Keys instance...');
    const mod = loadAddon();
    const keys = new mod.Keys();
    console.log('  ✅ Keys instance created');
    
    if (tmpDir) {
      console.log('  📁 Setting persistence directory...');
      keys.setPersistenceDir(tmpDir);
      keys.enableAutoPersist(true);
      console.log('  ✅ Persistence configured');
    }
    
    const duration = Date.now() - startTime;
    console.log(`  ⏱️  Fresh keys creation completed in ${duration}ms`);
    return keys;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`  ❌ Fresh keys creation failed after ${duration}ms:`, error);
    throw error;
  }
}

/**
 * TestEnvironment class for proper test isolation and management
 * Each test gets its own isolated instances to prevent cross-contamination
 */
export class TestEnvironment {
  private constructor(
    private mobileKeys: any,
    private nodeKeys: any,
    private networkId: string,
    private tmpDir: string
  ) {}

  /**
   * Factory method for mobile-only tests
   */
  static async createMobileOnly(tmpDir?: string): Promise<TestEnvironment> {
    const dir = tmpDir || createTempDir();
    const mobileKeys = await createTestMobileKeys(dir);
    const networkId = mobileKeys.mobileGenerateNetworkDataKey();
    
    return new TestEnvironment(mobileKeys, null, networkId, dir);
  }

  /**
   * Factory method for node-only tests
   */
  static async createNodeOnly(tmpDir?: string): Promise<TestEnvironment> {
    const dir = tmpDir || createTempDir();
    const nodeKeys = createTestNodeKeys(dir);
    
    return new TestEnvironment(null, nodeKeys, '', dir);
  }

  /**
   * Factory method for full environment (mobile + node)
   */
  static async createFullEnvironment(tmpDir?: string): Promise<TestEnvironment> {
    const dir = tmpDir || createTempDir();
    
    // Create mobile first
    const mobileKeys = await createTestMobileKeys(dir);
    const networkId = mobileKeys.mobileGenerateNetworkDataKey();
    
    // Create node and set it up with mobile
    const nodeKeys = createTestNodeKeys(dir);
    const setupToken = nodeKeys.nodeGenerateCsr();
    
    // Mobile processes setup token
    const certMessage = mobileKeys.mobileProcessSetupToken(setupToken);
    nodeKeys.nodeInstallCertificate(certMessage);
    
    // Mobile creates and installs network key
    const networkKeyMessage = mobileKeys.mobileCreateNetworkKeyMessage(
      networkId, 
      nodeKeys.nodeGetAgreementPublicKey()
    );
    nodeKeys.nodeInstallNetworkKey(networkKeyMessage);
    
    return new TestEnvironment(mobileKeys, nodeKeys, networkId, dir);
  }

  // Accessors
  getMobileKeys(): any { return this.mobileKeys; }
  getNodeKeys(): any { return this.nodeKeys; }
  getNetworkId(): string { return this.networkId; }

  /**
   * Cleanup method - removes temporary directory
   */
  cleanup(): void {
    cleanupTempDir(this.tmpDir);
  }
}

/**
 * Create test mobile keys with proper initialization
 */
export async function createTestMobileKeys(tmpDir?: string): Promise<any> {
  const mod = loadAddon();
  const keys = new mod.Keys();
  
  if (tmpDir) {
    keys.setPersistenceDir(tmpDir);
    keys.enableAutoPersist(true);
  }
  
  keys.initAsMobile();
  await keys.mobileInitializeUserRootKey();
  
  return keys;
}

/**
 * Create test node keys with proper initialization
 */
export function createTestNodeKeys(tmpDir?: string): any {
  const mod = loadAddon();
  const keys = new mod.Keys();
  
  if (tmpDir) {
    keys.setPersistenceDir(tmpDir);
    keys.enableAutoPersist(true);
  }
  
  keys.initAsNode();
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
