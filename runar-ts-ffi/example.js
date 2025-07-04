// Example usage of the Runar TypeScript FFI
import { JsNode } from './index.js';

async function main() {
  console.log('Creating Runar node...');
  const node = new JsNode();

  console.log('Starting node...');
  await node.start();

  console.log('Adding math service...');
  const mathService = {
    name: 'math-service',
    path: 'math',
    version: '1.0.0',
    description: 'Math operations service',
    actions: {
      add: true,   // Enable the add action
      echo: true   // Enable echo action too
    }
  };

  await node.addService(mathService);

  console.log('Testing math service...');
  const result = await node.request('math/add', { a: 10, b: 5 });
  console.log('10 + 5 =', result);

  console.log('Testing echo service...');
  const echoResult = await node.request('math/echo', { message: 'Hello from JS!' });
  console.log('Echo result:', echoResult);

  console.log('Publishing event...');
  await node.publish('test/event', { data: 'test payload' });

  console.log('Stopping node...');
  await node.stop();

  console.log('Example completed successfully!');
}

main().catch(console.error); 