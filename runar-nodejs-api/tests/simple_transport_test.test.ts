import { Keys, Transport, TransportOptions } from '../index';

describe('Simple Transport Test', () => {
  test('should create transport without callbacks', async () => {
    console.log('🔗 Testing Simple Transport Creation');

    // Create keys
    const keys = new Keys();
    keys.initAsNode();
    await keys.generateKeys();

    // Create transport options
    const options: TransportOptions = {
      bindAddr: "127.0.0.1:0"
    };

    // Create transport
    const transport = new Transport(keys, options);
    console.log('   ✅ Transport created successfully');

    // Start transport
    await transport.start();
    console.log('   ✅ Transport started successfully');

    // Get local address
    const localAddr = await transport.getLocalAddr();
    console.log(`   ✅ Local address: ${localAddr}`);

    // Stop transport
    await transport.stop();
    console.log('   ✅ Transport stopped successfully');

    console.log('🎉 Simple Transport Test Completed Successfully!');
  }, 30000);
});
