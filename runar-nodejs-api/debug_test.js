const { Keys } = require('./index');

async function debugTest() {
    console.log('🔍 Debug Test: What does mobileGenerateNetworkDataKey return?');
    
    const keys = new Keys();
    keys.initAsMobile();
    await keys.mobileInitializeUserRootKey();
    
    const result = keys.mobileGenerateNetworkDataKey();
    console.log('Result type:', typeof result);
    console.log('Result constructor:', result.constructor.name);
    console.log('Result value:', result);
    console.log('Result length:', result.length);
    console.log('Is Uint8Array?', result instanceof Uint8Array);
    console.log('Is Buffer?', result instanceof Buffer);
    
    if (typeof result === 'string') {
        console.log('String length:', result.length);
        console.log('First 10 chars:', result.substring(0, 10));
    } else if (result instanceof Uint8Array || result instanceof Buffer) {
        console.log('Bytes length:', result.length);
        console.log('First 10 bytes:', Array.from(result.slice(0, 10)));
    }
}

debugTest().catch(console.error);
