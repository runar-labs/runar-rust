import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RunarNode } from '../ts/runtime';
import { createNodeTestConfig } from '../index';

describe('High-level RunarNode API', () => {
  let node: RunarNode;

  beforeAll(async () => {
    const config = createNodeTestConfig();
    node = new RunarNode(config);

    await node.addService({
      name: 'Math Service Name',
      path: 'math_service',
      version: '1.0.0',
      description: 'Math operations',
      actions: {
        add: async ({ a, b }: any, context: any) => {
          const multiplyResult = await context.request('math_service/multiply', { a: 10, b: 8 });
          context.logger.info(`Multiply result: ${multiplyResult}`);
          return a + b + multiplyResult;
        },
        multiply: async ({ a, b }: any) => a * b,
      },
    });
  });

  afterAll(async () => {
    await node.stop();
  });

  it('handles add action', async () => {
    const result = await node.request('math_service/add', { a: 4, b: 6 });
    expect(result).toBe(90);
  });

  it('handles multiply action', async () => {
    const result = await node.request('math_service/multiply', { a: 3, b: 5 });
    expect(result).toBe(15);
  });
}); 