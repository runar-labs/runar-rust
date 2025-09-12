# NodeJS Native API E2E Integration Tests

This directory contains comprehensive end-to-end integration tests for the Runar NodeJS Native API. These tests validate the complete CA Node infrastructure using the NodeJS native API with ACTUAL QUIC mTLS connections.

## Test Overview

The E2E tests cover the following phases:

1. **Setup** - Create Keys instances
2. **CA Infrastructure Setup** - Create root and issuing CAs
3. **CA Node Setup** - Create and configure CA Node
4. **CA Server Setup** - Start CA Server with QUIC mTLS
5. **Mobile Node Setup** - Initialize mobile key manager
6. **Node Key Manager Setup** - Initialize node key manager
7. **CA Client Setup** - Create CA client for operations
8. **Enrollment Token Generation** - Generate enrollment tokens
9. **Certificate Enrollment** - Enroll nodes with certificates
10. **Certificate Renewal** - Renew certificates
11. **Certificate Revocation** - Revoke certificates
12. **CRL Generation** - Generate Certificate Revocation Lists
13. **Profile Key Operations** - Test profile key encryption/decryption
14. **Mobile Response Conversion** - Convert responses for mobile
15. **Certificate Analysis** - Extract SKI and serial numbers
16. **CA Status and Chain** - Get CA status and certificate chain
17. **Cleanup** - Stop services and free resources

## Prerequisites

- Node.js 18+ 
- TypeScript 5.0+
- Rust toolchain (for building the native module)
- The Runar NodeJS native module must be built

## Installation

```bash
# Install dependencies
npm install

# Build the native module (if not already built)
cd ..
npm run build
```

## Running Tests

### Run all tests
```bash
npm test
```

### Run tests in watch mode
```bash
npm run test:watch
```

### Run specific test file
```bash
npx jest nodejs_e2e_integration_test.test.ts
```

### Run with verbose output
```bash
npx jest --verbose
```

## Test Configuration

The tests use the following configuration:

- **Network ID**: `test_network_e2e`
- **Root CA Subject**: `CN=Test Root CA`
- **Issuing CA Subject**: `CN=Test Issuing CA`
- **Validity Days**: 365
- **Test Timeout**: 5 minutes
- **Bootstrap Port**: 8443
- **Authenticated Port**: 8444

## Test Structure

### Main Test File
- `nodejs_e2e_integration_test.test.ts` - Jest-based E2E tests with proper setup/teardown

### Configuration Files
- `package.json` - Test dependencies and scripts
- `tsconfig.json` - TypeScript configuration
- `jest.config.js` - Jest test runner configuration
- `jest.setup.ts` - Jest setup and global utilities

### Helper Functions
- `createTestLogger()` - Creates test logger
- `validateCertificateChain()` - Validates certificate chain
- `createCaClientConfig()` - Creates CA client configuration
- `createCaServerConfig()` - Creates CA server configuration
- `createEnrollRequest()` - Creates enrollment request
- `createRenewRequest()` - Creates renewal request
- `createRevokeRequest()` - Creates revocation request

## Test Data

The tests use the following test data:

- **User ID**: `test_user_id`
- **Device ID**: `test_device_id`
- **Node ID**: `test_node_id`
- **Admin SKIs**: `['admin_ski_1', 'admin_ski_2']`
- **Subject Hint**: `test_subject_hint`
- **Token Permissions**: `['enroll']`
- **Validity Days**: 7 days for tokens

## Error Handling

The tests include comprehensive error handling:

- **Timeout handling** - 5-minute timeout for E2E tests
- **Resource cleanup** - Automatic cleanup of all resources
- **Error validation** - Proper error code validation
- **Certificate validation** - Basic certificate chain validation

## Debugging

To debug tests:

1. **Enable verbose logging**:
   ```bash
   npx jest --verbose
   ```

2. **Run single test**:
   ```bash
   npx jest --testNamePattern="should create root CA"
   ```

3. **Debug with Node.js**:
   ```bash
   node --inspect-brk node_modules/.bin/jest --runInBand
   ```

## Performance

- **Test Timeout**: 5 minutes per test suite
- **Sequential Execution**: Tests run sequentially to avoid conflicts
- **Resource Management**: Proper cleanup prevents resource leaks
- **Memory Management**: All resources are properly freed

## Troubleshooting

### Common Issues

1. **Native module not found**:
   - Ensure the native module is built: `npm run build`
   - Check that the module is properly linked

2. **Port conflicts**:
   - Tests use ports 8443 and 8444
   - Ensure these ports are available

3. **Timeout errors**:
   - Increase timeout in `jest.config.js`
   - Check for hanging processes

4. **Certificate errors**:
   - Ensure proper certificate chain validation
   - Check certificate expiration

### Debug Output

The tests provide detailed console output:

- `[DEBUG]` - Debug information
- `[INFO]` - General information
- `[WARN]` - Warning messages
- `[ERROR]` - Error messages

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Add proper error handling
3. Include cleanup in `afterAll`
4. Add descriptive test names
5. Include console output for debugging

## License

This test suite is part of the Runar project and follows the same license terms.
