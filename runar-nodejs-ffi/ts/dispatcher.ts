import { registerJsDispatch, dispatchToRust } from '../index';

export type DispatcherCallback = (err: any, msg: any) => void;

const callbacks: DispatcherCallback[] = [];
let registered = false;

export function attachDispatcher(cb: DispatcherCallback) {
  callbacks.push(cb);
  if (!registered) {
    try {
      registerJsDispatch((err: any, msg: any) => {
        for (const fn of callbacks) {
          try {
            fn(err, msg);
          } catch (innerErr) {
            // eslint-disable-next-line no-console
            console.error('[Runar FFI] Dispatcher callback error:', innerErr);
          }
        }
      });
      registered = true;
    } catch (err: any) {
      if (typeof err?.message === 'string' && err.message.includes('Dispatcher already registered')) {
        registered = true;
      } else {
        throw err;
      }
    }
  }
}

export function detachDispatcher(cb: DispatcherCallback) {
  const idx = callbacks.indexOf(cb);
  if (idx !== -1) {
    callbacks.splice(idx, 1);
  }
}

export { dispatchToRust }; 