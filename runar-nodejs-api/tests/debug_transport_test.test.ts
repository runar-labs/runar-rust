import { Keys, Transport, TransportOptions, setLogLevel, setLoggerNodeId } from '../index';

describe('Debug Transport Test', () => {
  test('step by step transport creation', async () => {
    console.log('🔍 Debug Transport Creation Step by Step');

    // Step 1: Set up logging
    console.log('   Step 1: Setting up logging...');
    setLogLevel(5); // trace level
    setLoggerNodeId('debug-test');
    console.log('   ✅ Logging configured');

    // Step 2: Create and initialize keys
    console.log('   Step 2: Creating and initializing keys...');
    const keys = new Keys();
    console.log('   ✅ Keys object created');
    
    keys.initAsNode();
    console.log('   ✅ Keys initialized as node');
    
    await keys.generateKeys();
    console.log('   ✅ Keys generated');

    // Step 2.5: Install certificate (required for Transport creation)
    console.log('   Step 2.5: Installing certificate...');
    try {
      // Create mobile keys for processing setup token (following FFI pattern)
      const mobileKeys = new Keys();
      mobileKeys.initAsMobile();
      console.log('   ✅ Mobile keys created');
      
      // Generate CSR
      const csr = keys.nodeGenerateCsr();
      console.log('   ✅ CSR generated');
      
      // Process setup token using mobile keys
      const ncm = mobileKeys.mobileProcessSetupToken(csr);
      console.log('   ✅ Setup token processed');
      
      // Install certificate
      keys.nodeInstallCertificate(ncm);
      console.log('   ✅ Certificate installed');
    } catch (error) {
      console.error('   ❌ Certificate installation failed:', error);
      throw error;
    }

    // Step 3: Create transport options
    console.log('   Step 3: Creating transport options...');
    const options: TransportOptions = {
      bindAddr: "127.0.0.1:0"
    };
    console.log('   ✅ Transport options created:', options);

    // Step 4: Try to create transport (this is where it fails)
    console.log('   Step 4: Creating transport...');
    try {
      const transport = new Transport(keys, options);
      console.log('   ✅ Transport created successfully!');
      
      // If we get here, try to start it
      console.log('   Step 5: Starting transport...');
      await transport.start();
      console.log('   ✅ Transport started successfully!');
      
      // Get local address
      const localAddr = await transport.getLocalAddr();
      console.log(`   ✅ Local address: ${localAddr}`);
      
      // Stop transport
      await transport.stop();
      console.log('   ✅ Transport stopped');
      
    } catch (error) {
      console.error('   ❌ Transport creation failed:', error);
      throw error;
    }

    // Step 6: Test completed
    console.log('   Step 6: Test completed successfully');
    
    console.log('   🎉 All steps completed successfully!');
  });
});
