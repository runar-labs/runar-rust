import fs from 'fs';
import { 
  loadAddon, 
  createTempDir, 
  cleanupTempDir, 
  withTimeout,
  createFreshKeys
} from './test_utils';

const mod = loadAddon();

describe('Comprehensive API Tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTempDir();
  });

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('Initialization Tests', () => {
    test('should initialize as mobile manager successfully', () => {
      const keys = createFreshKeys(tmpDir);
      expect(() => keys.initAsMobile()).not.toThrow();
    });

    test('should initialize as node manager successfully', () => {
      const keys = createFreshKeys(tmpDir);
      expect(() => keys.initAsNode()).not.toThrow();
    });

    test('should prevent double initialization with different types', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      expect(() => keys.initAsNode()).toThrow('Already initialized as mobile manager');
    });

    test('should prevent double initialization with different types (reverse)', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      expect(() => keys.initAsMobile()).toThrow('Already initialized as node manager');
    });
  });

  describe('Persistence Tests', () => {
    test('should set persistence directory successfully', () => {
      const keys = createFreshKeys(tmpDir);
      expect(() => keys.setPersistenceDir(tmpDir)).not.toThrow();
    });

    test('should enable auto persist successfully', () => {
      const keys = createFreshKeys(tmpDir);
      expect(() => keys.enableAutoPersist(true)).not.toThrow();
      expect(() => keys.enableAutoPersist(false)).not.toThrow();
    });

    test('should wipe persistence successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.setPersistenceDir(tmpDir);
      await expect(withTimeout(keys.wipePersistence(), 5000, 'wipePersistence')).resolves.not.toThrow();
    });

    test('should flush state successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.setPersistenceDir(tmpDir);
      await expect(withTimeout(keys.flushState(), 5000, 'flushState')).resolves.not.toThrow();
    });
  });

  describe('Keystore State Tests', () => {
    test('should get node keystore state successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const state = keys.nodeGetKeystoreState();
      expect(typeof state).toBe('number');
      expect(state).toBeGreaterThanOrEqual(0);
    });

    test('should get mobile keystore state successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const state = keys.mobileGetKeystoreState();
      expect(typeof state).toBe('number');
      expect(state).toBeGreaterThanOrEqual(0);
    }, 10000);

    test('should get keystore capabilities successfully', () => {
      const keys = createFreshKeys(tmpDir);
      const caps = keys.getKeystoreCaps();
      expect(caps).toHaveProperty('version');
      expect(caps).toHaveProperty('flags');
      expect(typeof caps.version).toBe('number');
      expect(typeof caps.flags).toBe('number');
    });
  });

  describe('Mobile Key Management Tests', () => {
    test('should initialize user root key successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await expect(withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey')).resolves.not.toThrow();
    }, 10000);

    test('should get user public key after initialization', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const pk = keys.mobileGetUserPublicKey();
      expect(Buffer.isBuffer(pk)).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    }, 10000);

    test('should derive user profile key successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const pk = keys.mobileDeriveUserProfileKey('personal');
      expect(Buffer.isBuffer(pk)).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    }, 10000);

    test('should generate network data key successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const networkId = keys.mobileGenerateNetworkDataKey();
      expect(typeof networkId).toBe('string');
      expect(networkId.length).toBeGreaterThan(0);
    }, 10000);

    test('should install network public key successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const testPk = Buffer.alloc(65, 1); // Mock public key
      expect(() => keys.mobileInstallNetworkPublicKey(testPk)).not.toThrow();
    }, 10000);

    test('should get network public key successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const testPk = Buffer.alloc(65, 1); // Mock public key
      keys.mobileInstallNetworkPublicKey(testPk);
      const networkId = keys.mobileGenerateNetworkDataKey();
      const pk = keys.mobileGetNetworkPublicKey(networkId);
      expect(Buffer.isBuffer(pk)).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    }, 10000);

    test('should create network key message successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      const testPk = Buffer.alloc(65, 1); // Mock public key
      const msg = keys.mobileCreateNetworkKeyMessage('test-network', testPk);
      expect(Buffer.isBuffer(msg)).toBe(true);
      expect(msg.length).toBeGreaterThan(0);
    }, 10000);

    test('should process setup token successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      // Create a mock setup token
      const mockSetupToken = {
        node_id: 'test-node',
        node_public_key: Buffer.alloc(65, 1),
        node_agreement_public_key: Buffer.alloc(65, 1),
        csr_der: Buffer.alloc(100, 1)
      };
      const stCbor = Buffer.from(JSON.stringify(mockSetupToken));
      
      const certMsg = keys.mobileProcessSetupToken(stCbor);
      expect(Buffer.isBuffer(certMsg)).toBe(true);
      expect(certMsg.length).toBeGreaterThan(0);
    }, 10000);
  });

  describe('Node Key Management Tests', () => {
    test('should get node ID successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const id = keys.nodeGetNodeId();
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });

    test('should get node public key successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const pk = keys.nodeGetPublicKey();
      expect(Buffer.isBuffer(pk)).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    });

    test('should get node agreement public key successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const pk = keys.nodeGetAgreementPublicKey();
      expect(Buffer.isBuffer(pk)).toBe(true);
      expect(pk.length).toBeGreaterThan(0);
    });

    test('should generate CSR successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const csr = keys.nodeGenerateCsr();
      expect(Buffer.isBuffer(csr)).toBe(true);
      expect(csr.length).toBeGreaterThan(0);
    });

    test('should install network key successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const mockNkm = Buffer.alloc(100, 1); // Mock network key message
      expect(() => keys.nodeInstallNetworkKey(mockNkm)).not.toThrow();
    });

    test('should install certificate successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const mockCert = Buffer.alloc(100, 1); // Mock certificate message
      expect(() => keys.nodeInstallCertificate(mockCert)).not.toThrow();
    });
  });

  describe('Encryption/Decryption Tests', () => {
    test('should encrypt local data successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const data = Buffer.from('test data');
      const encrypted = keys.encryptLocalData(data);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    });

    test('should decrypt local data successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const data = Buffer.from('test data');
      const encrypted = keys.encryptLocalData(data);
      const decrypted = keys.decryptLocalData(encrypted);
      expect(decrypted.equals(data)).toBe(true);
    });

    test('should encrypt for public key successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const data = Buffer.from('test data');
      const recipientPk = Buffer.alloc(65, 1);
      const encrypted = keys.encryptForPublicKey(data, recipientPk);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    });

    test('should encrypt for network successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const data = Buffer.from('test data');
      const encrypted = keys.encryptForNetwork(data, 'test-network');
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    });

    test('should decrypt network data successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const data = Buffer.from('test data');
      const encrypted = keys.encryptForNetwork(data, 'test-network');
      const decrypted = keys.decryptNetworkData(encrypted);
      expect(decrypted.equals(data)).toBe(true);
    });

    test('should encrypt message for mobile successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const message = Buffer.from('test message');
      const mobilePk = Buffer.alloc(65, 1);
      const encrypted = keys.encryptMessageForMobile(message, mobilePk);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(message)).toBe(false);
    });

    test('should decrypt message from mobile successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const message = Buffer.from('test message');
      const mobilePk = Buffer.alloc(65, 1);
      const encrypted = keys.encryptMessageForMobile(message, mobilePk);
      const decrypted = keys.decryptMessageFromMobile(encrypted);
      expect(decrypted.equals(message)).toBe(true);
    });
  });

  describe('Envelope Encryption Tests', () => {
    test('should encrypt with envelope using mobile manager successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.mobileEncryptWithEnvelope(data, 'test-network', profilePks);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    }, 10000);

    test('should encrypt with envelope using node manager successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.nodeEncryptWithEnvelope(data, 'test-network', profilePks);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    });

    test('should decrypt envelope using mobile manager successfully', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.mobileEncryptWithEnvelope(data, 'test-network', profilePks);
      const decrypted = keys.mobileDecryptEnvelope(encrypted);
      expect(decrypted.equals(data)).toBe(true);
    }, 10000);

    test('should decrypt envelope using node manager successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.nodeEncryptWithEnvelope(data, 'test-network', profilePks);
      const decrypted = keys.nodeDecryptEnvelope(encrypted);
      expect(decrypted.equals(data)).toBe(true);
    });

    test('should maintain backward compatibility with encryptWithEnvelope', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.encryptWithEnvelope(data, 'test-network', profilePks);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(encrypted.equals(data)).toBe(false);
    }, 10000);

    test('should maintain backward compatibility with decryptEnvelope', async () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      await withTimeout(keys.mobileInitializeUserRootKey(), 5000, 'mobileInitializeUserRootKey');
      
      const data = Buffer.from('test data');
      const profilePks = [Buffer.alloc(65, 1), Buffer.alloc(65, 2)];
      const encrypted = keys.encryptWithEnvelope(data, 'test-network', profilePks);
      const decrypted = keys.decryptEnvelope(encrypted);
      expect(decrypted.equals(data)).toBe(true);
    }, 10000);
  });

  describe('Symmetric Key Tests', () => {
    test('should ensure symmetric key successfully', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const key = keys.ensureSymmetricKey('test-service');
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32); // 256-bit key
    });

    test('should return same key for same service name', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const key1 = keys.ensureSymmetricKey('test-service');
      const key2 = keys.ensureSymmetricKey('test-service');
      expect(key1.equals(key2)).toBe(true);
    });

    test('should return different keys for different service names', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsNode();
      const key1 = keys.ensureSymmetricKey('service-1');
      const key2 = keys.ensureSymmetricKey('service-2');
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('Label Mapping Tests', () => {
    test('should set label mapping successfully', () => {
      const keys = createFreshKeys(tmpDir);
      const mockMapping = {
        'label1': { key: Buffer.alloc(32, 1), info: 'info1' },
        'label2': { key: Buffer.alloc(32, 2), info: 'info2' }
      };
      const mappingCbor = Buffer.from(JSON.stringify(mockMapping));
      expect(() => keys.setLabelMapping(mappingCbor)).not.toThrow();
    });
  });

  describe('Local Node Info Tests', () => {
    test('should set local node info successfully', () => {
      const keys = createFreshKeys(tmpDir);
      const mockNodeInfo = {
        node_public_key: Buffer.alloc(65, 1),
        network_ids: ['network1'],
        addresses: ['127.0.0.1:8080'],
        node_metadata: { services: [], subscriptions: [] },
        version: 1
      };
      const nodeInfoCbor = Buffer.from(JSON.stringify(mockNodeInfo));
      expect(() => keys.setLocalNodeInfo(nodeInfoCbor)).not.toThrow();
    });
  });

  describe('Error Handling Tests', () => {
    test('should throw error when mobile manager not initialized for mobile operations', () => {
      const keys = createFreshKeys(tmpDir);
      // Don't initialize as mobile
      expect(() => keys.mobileGetUserPublicKey()).toThrow('Mobile manager not initialized');
    });

    test('should throw error when node manager not initialized for node operations', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile(); // Initialize as mobile instead
      expect(() => keys.nodeGetNodeId()).toThrow('Node manager not initialized');
    });

    test('should throw error when trying to use wrong manager type', () => {
      const keys = createFreshKeys(tmpDir);
      keys.initAsMobile();
      expect(() => keys.nodeEncryptWithEnvelope(Buffer.from('test'), 'network', [])).toThrow('Node manager not initialized');
    });
  });
});
