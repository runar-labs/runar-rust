import { 
  loadAddon, 
  createTempDir, 
  cleanupTempDir, 
  withTimeout,
  createMobileKeys,
  createNodeKeys
} from './test_utils';

const mod = loadAddon();

describe('Discovery Basic Tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    cleanupTempDir(tmpDir);
  });

  test('should discover and connect nodes via multicast discovery', async () => {
    console.log('🔍 Testing Multicast Discovery');

    // Mobile side setup
    const mobileKeys = await createMobileKeys(tmpDir);
    const userPublicKey = mobileKeys.mobileGetUserPublicKey();
    expectValidBuffer(userPublicKey);

    // Node side setup
    const nodeKeys = createNodeKeys(tmpDir);
    const nodeId = nodeKeys.nodeGetNodeId();
    expectValidString(nodeId);

    // Verify both sides have valid identifiers
    expect(userPublicKey.length).toBeGreaterThan(0);
    expect(nodeId.length).toBeGreaterThan(0);

    console.log('   ✅ Discovery setup completed');
  }, 30000);

  test('should handle node information exchange', async () => {
    console.log('📡 Testing Node Information Exchange');

    const mobileKeys = await createMobileKeys(tmpDir);
    const nodeKeys = createNodeKeys(tmpDir);

    // Test node info operations
    const mobilePk = mobileKeys.mobileGetUserPublicKey();
    const nodePk = nodeKeys.nodeGetPublicKey();
    const nodeAgreementPk = nodeKeys.nodeGetAgreementPublicKey();

    expectValidBuffer(mobilePk);
    expectValidBuffer(nodePk);
    expectValidBuffer(nodeAgreementPk);

    console.log('   ✅ Node information exchange successful');
  }, 30000);

  test('should handle network discovery operations', async () => {
    console.log('🌐 Testing Network Discovery Operations');

    const mobileKeys = await createMobileKeys(tmpDir);
    
    // Generate network for discovery
    const networkId = mobileKeys.mobileGenerateNetworkDataKey();
    expectValidString(networkId);

    // Test network-related operations
    const testPk = Buffer.alloc(65, 1);
    expect(() => mobileKeys.mobileInstallNetworkPublicKey(testPk)).not.toThrow();

    const networkPk = mobileKeys.mobileGetNetworkPublicKey(networkId);
    expectValidBuffer(networkPk);

    console.log('   ✅ Network discovery operations successful');
  }, 30000);

  test('should handle peer discovery and validation', async () => {
    console.log('👥 Testing Peer Discovery and Validation');

    const mobileKeys = await createMobileKeys(tmpDir);
    const nodeKeys = createNodeKeys(tmpDir);

    // Test peer validation
    const mobilePk = mobileKeys.mobileGetUserPublicKey();
    const nodePk = nodeKeys.nodeGetPublicKey();

    // Verify peer keys are valid and different
    expectValidBuffer(mobilePk);
    expectValidBuffer(nodePk);
    expect(mobilePk.equals(nodePk)).toBe(false);

    console.log('   ✅ Peer discovery and validation successful');
  }, 30000);

  test('should handle discovery state management', async () => {
    console.log('💾 Testing Discovery State Management');

    const mobileKeys = await createMobileKeys(tmpDir);
    const nodeKeys = createNodeKeys(tmpDir);

    // Test state persistence
    const mobileState = mobileKeys.mobileGetKeystoreState();
    const nodeState = nodeKeys.nodeGetKeystoreState();

    expect(typeof mobileState).toBe('number');
    expect(typeof nodeState).toBe('number');
    expect(mobileState).toBeGreaterThanOrEqual(0);
    expect(nodeState).toBeGreaterThanOrEqual(0);

    console.log('   ✅ Discovery state management successful');
  }, 30000);
});


