import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { JsNode } from '../index';
import { attachDispatcher, dispatchToRust, detachDispatcher } from '../ts/dispatcher';

describe('Dispatcher message-bus bridge', () => {
  let node: JsNode;
  let testCallback: any;

  beforeAll(async () => {
    console.log('attachDispatcher value:', attachDispatcher);
    // Register the global JS dispatcher via aggregator. This must only be done once.
    testCallback = async (...args: any[]) => {
      console.log('[TESTLOG] Dispatcher arguments:', args);
      const [, msg] = args; // first arg is potential error/null, second is actual message
      if (!msg || msg.type !== 'action') {
        console.log('[TESTLOG] Ignoring message');
        return; // Ignore any initialization or unknown messages
      }

      if (msg.service === 'math_service') {
        let result;
        if (msg.action === 'add') {
          const { a, b } = msg.payload ?? {};
          result = a + b;
        } else if (msg.action === 'multiply') {
          const { a, b } = msg.payload ?? {};
          result = a * b;
        } else {
          return;
        }
        const resp = await dispatchToRust({
          id: msg.id,
          type: 'response',
          payload: result,
        });
        console.log('[TESTLOG] dispatchToRust returned:', resp);
      }
    };
    attachDispatcher(testCallback);
  });

  afterAll(async () => {
    detachDispatcher(testCallback);
    // nothing to cleanup – dispatcher lives for process lifetime
  });

  it('should round-trip an add action', async () => {
    node = new JsNode();

    // Add the service BEFORE starting the node so that its actions are fully initialized.
    const svcObj = {
      name: 'Math Service',
      servicePath: 'math_service',
      version: '1.0.0',
      description: 'A simple math service implemented in JS',
      actions: ['add', 'multiply'],
    } as any;
    console.log('svcObj', svcObj);
    await node.addService(svcObj);

    await node.start();

    const result = await node.request('math_service/add', { a: 5, b: 3 });
    expect(result).toBe(8);

    await node.stop();
  }, 15000);
}); 