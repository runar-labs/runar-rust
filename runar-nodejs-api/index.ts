// Change to CommonJS
const runar = require('./index.linux-x64-gnu.node');

const k = new runar.Keys();
console.log(k.nodeGetNodeId());

k.encryptWithEnvelope(Buffer.from('data'), null, []).then(console.log).catch(console.error);

// Add tests for Transport, etc.
