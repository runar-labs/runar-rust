import { 
  loadAddon, 
  createTempDir, 
  cleanupTempDir, 
  withTimeout,
  createMobileKeys,
  createNodeKeys,
  uint8ArrayEquals
} from './test_utils';

describe('Discovery Basic Tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    cleanupTempDir(tmpDir);
  });

  test('should handle discovery state management', async () => {
    console.log('💾 Testing Discovery State Management');

    const mobileKeys = await createMobileKeys(tmpDir);
    const nodeKeys = createNodeKeys(tmpDir);

    // Test state persistence - this matches the Rust test pattern
    const mobileState = mobileKeys.mobileGetKeystoreState();
    const nodeState = nodeKeys.nodeGetKeystoreState();

    expect(typeof mobileState).toBe('number');
    expect(typeof nodeState).toBe('number');
    expect(mobileState).toBeGreaterThanOrEqual(0);
    expect(nodeState).toBeGreaterThanOrEqual(0);

    console.log('   ✅ Discovery state management successful');
  }, 30000);

  test('should handle basic key validation for discovery', async () => {
    console.log('🔑 Testing Basic Key Validation for Discovery');

    const mobileKeys = await createMobileKeys(tmpDir);
    const nodeKeys = createNodeKeys(tmpDir);

    // Test that we have valid keys for discovery operations
    // This matches the Rust test pattern of validating key setup
    const mobilePk = mobileKeys.mobileGetUserPublicKey();
    nodeKeys.nodeGenerateKeys(); // Generate keys after initialization
    const nodePk = nodeKeys.nodeGetPublicKey();
    const nodeAgreementPk = nodeKeys.nodeGetAgreementPublicKey();

    expect(mobilePk instanceof Uint8Array).toBe(true);
    expect(nodePk instanceof Uint8Array).toBe(true);
    expect(nodeAgreementPk instanceof Uint8Array).toBe(true);
    expect(mobilePk.length).toBeGreaterThan(0);
    expect(nodePk.length).toBeGreaterThan(0);
    expect(nodeAgreementPk.length).toBeGreaterThan(0);

    // Verify keys are different (as they should be)
    expect(uint8ArrayEquals(mobilePk, nodePk)).toBe(false);

    console.log('   ✅ Basic key validation successful');
  }, 30000);

  test('should handle network setup for discovery', async () => {
    console.log('🌐 Testing Network Setup for Discovery');

    const mobileKeys = await createMobileKeys(tmpDir);
    
    // Generate network for discovery - this matches the Rust pattern
    const networkPublicKey = mobileKeys.mobileGenerateNetworkDataKey();
    expect(networkPublicKey).toBeInstanceOf(Uint8Array);
    expect(networkPublicKey.length).toBeGreaterThan(0);

    // Test network public key installation and retrieval
    // This simulates the network setup needed for discovery
    const testPk = Buffer.alloc(65, 0x42); // Use valid key format
    expect(() => mobileKeys.mobileInstallNetworkPublicKey(testPk)).not.toThrow();

    // Generate a network key pair for the mobile keys to have a private key
    const mobileNetworkKey = mobileKeys.mobileGenerateNetworkDataKey();
    expect(mobileNetworkKey instanceof Uint8Array).toBe(true);
    expect(mobileNetworkKey.length).toBeGreaterThan(0);

    // Now check if the mobile keys have a network private key for the generated public key
    const networkPk = mobileKeys.mobileHasNetworkPrivateKey(mobileNetworkKey);
    expect(typeof networkPk).toBe('boolean');
    expect(networkPk).toBe(true);

    console.log('   ✅ Network setup for discovery successful');
  }, 30000);
});


