// High-level TypeScript wrapper around the low-level JsNode FFI.
// This lets apps register services with real async functions instead of string names.

import { JsNode, createNodeTestConfig, createNodeConfig, JsNodeConfig } from '../index';
import { attachDispatcher, detachDispatcher, dispatchToRust } from './dispatcher';

type LoggerLike = { info: (...args: any[]) => void; };

/**
 * Shape of a high-level service definition exposed to JS callers.
 */
export interface ServiceDefinition {
  /** Human-readable service name (metadata only) */
  name: string;
  /** Route prefix used for requests (e.g. "math_service"). */
  path: string;
  /** Semantic version (e.g. "1.0.0"). */
  version: string;
  /** Human description passed to Rust for discovery. */
  description: string;
  /** Map of action name -> async handler */
  actions: Record<string, (payload: any, ctx: any) => any | Promise<any>>;
}

/**
 * High-level runtime that hides the dispatcher plumbing.
 */
export class RunarNode {
  private readonly node: JsNode;
  private readonly services = new Map<string, ServiceDefinition>();
  private initialized = false;
  private dispatcherCb: any;

  constructor(config?: JsNodeConfig) {
    this.node = new JsNode(config);
  }

  private async ensureInitialized(): Promise<void> {
    if (this.initialized) return;

    this.dispatcherCb = async (err: any, msg: any) => {
      if (err) {
        // eslint-disable-next-line no-console
        console.error('[Runar FFI] Dispatcher error (RunarNode handler):', err);
        return;
      }
      if (!msg || msg.type !== 'action') return;
      const svc = this.services.get(msg.service);
      const handler = svc?.actions?.[msg.action];
      let payload: any;
      try {
        if (!svc || !handler) throw new Error(`Unknown action ${msg.service}/${msg.action}`);
        payload = await handler(msg.payload, this.makeCtx());
      } catch (e: any) {
        payload = { error: String(e?.message ?? e) };
      }
      await dispatchToRust({ id: msg.id, type: 'response', payload });
    };

    attachDispatcher(this.dispatcherCb);
    await this.node.start();
    this.initialized = true;
  }

  private makeCtx() {
    return {
      request: (p: string, pl?: any) => this.request(p, pl),
      publish: (t: string, d?: any) => this.publish(t, d),
      logger: console as LoggerLike,
    };
  }

  /** Add a new service whose actions are real JS functions. */
  async addService(def: ServiceDefinition): Promise<void> {
    await this.ensureInitialized();
    if (!def?.path || Object.keys(def.actions ?? {}).length === 0) throw new Error('Invalid service');

    const versionStr = String(def.version ?? '1.0.0');
    this.services.set(def.path, { ...def, version: versionStr });

    await this.node.addService({
      name: def.name,
      servicePath: def.path,
      version: versionStr,
      description: def.description,
      networkId: undefined,
      actions: Object.keys(def.actions),
    });
  }

  async request(path: string, payload?: any): Promise<any> {
    await this.ensureInitialized();
    const idx = path.indexOf('/');
    if (idx > 0) {
      const svc = this.services.get(path.slice(0, idx));
      const local = svc?.actions?.[path.slice(idx + 1)];
      if (local) return local(payload, this.makeCtx());
    }
    return this.node.request(path, payload);
  }

  async publish(topic: string, data?: any): Promise<void> {
    await this.ensureInitialized();
    return this.node.publish(topic, data);
  }

  async stop(): Promise<void> {
    if (this.dispatcherCb) detachDispatcher(this.dispatcherCb);
    await this.node.stop();
    this.initialized = false;
  }
}

 