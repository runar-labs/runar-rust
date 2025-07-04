// JavaScript entry point for the Runar TypeScript FFI
// This file loads the native module and provides the public API

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('./runar-ts-ffi.node');

export const { JsNode, JsLogger } = native;
export default native; 