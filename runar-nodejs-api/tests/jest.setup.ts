// Jest setup file for NodeJS API E2E tests

// Set up global test timeout
jest.setTimeout(300000); // 5 minutes

// Global test utilities
global.createTestLogger = () => {
  return {
    debug: (msg: string) => console.log(`[DEBUG] ${msg}`),
    info: (msg: string) => console.log(`[INFO] ${msg}`),
    warn: (msg: string) => console.log(`[WARN] ${msg}`),
    error: (msg: string) => console.log(`[ERROR] ${msg}`)
  };
};

// Global test configuration
global.TEST_CONFIG = {
  NETWORK_ID: 'test_network_e2e',
  SUBJECT_ROOT: 'CN=Test Root CA',
  SUBJECT_ISSUING: 'CN=Test Issuing CA',
  VALIDITY_DAYS: 365,
  SERIAL: 12345,
  TIMEOUT: 300000
};

// Global test helpers
global.validateCertificateChain = (rootCaDer: Uint8Array, issuingCaDer: Uint8Array): void => {
  if (rootCaDer.length === 0) {
    throw new Error('Root CA certificate should not be empty');
  }
  if (issuingCaDer.length === 0) {
    throw new Error('Issuing CA certificate should not be empty');
  }
  if (rootCaDer.length < 100) {
    throw new Error(`Root CA certificate seems too small: ${rootCaDer.length} bytes`);
  }
  if (issuingCaDer.length < 100) {
    throw new Error(`Issuing CA certificate seems too small: ${issuingCaDer.length} bytes`);
  }
  console.log(`   ✅ Root CA certificate: ${rootCaDer.length} bytes`);
  console.log(`   ✅ Issuing CA certificate: ${issuingCaDer.length} bytes`);
  console.log('   ✅ Certificate chain validation passed (basic checks)');
};

// Global test data generators
global.createCaClientConfig = (bootstrapServer: string, authenticatedServer: string, rootCaDer: Uint8Array, issuingCaDer: Uint8Array): Uint8Array => {
  const config = {
    bootstrap_server: bootstrapServer,
    authenticated_server: authenticatedServer,
    network_id: global.TEST_CONFIG.NETWORK_ID,
    request_timeout_seconds: 30,
    max_retries: 3,
    root_ca_der: Array.from(rootCaDer),
    issuing_ca_der: Array.from(issuingCaDer)
  };
  return new Uint8Array(JSON.stringify(config).split('').map(c => c.charCodeAt(0)));
};

global.createCaServerConfig = (bootstrapBind: string, authenticatedBind: string, adminSkis: string[]): Uint8Array => {
  const config = {
    bootstrap_bind: bootstrapBind,
    authenticated_bind: authenticatedBind,
    network_id: global.TEST_CONFIG.NETWORK_ID,
    rate_limit_per_minute: 100,
    rate_limit_per_hour: 1000,
    admin_skis: adminSkis
  };
  return new Uint8Array(JSON.stringify(config).split('').map(c => c.charCodeAt(0)));
};

// Global test assertions
global.expectCertificateChain = (rootCaDer: Uint8Array, issuingCaDer: Uint8Array) => {
  expect(rootCaDer.length).toBeGreaterThan(0);
  expect(issuingCaDer.length).toBeGreaterThan(0);
  expect(rootCaDer.length).toBeGreaterThan(100);
  expect(issuingCaDer.length).toBeGreaterThan(100);
};

// Global test cleanup
global.cleanupTestResources = async (resources: any[]) => {
  for (const resource of resources) {
    if (resource && typeof resource.free === 'function') {
      resource.free();
    }
  }
};
