// Logging macros for the Runar system
//
// These macros will be replaced by direct Logger usage.
// DEPRECATED: Do not use these macros - use context.info() or other logger methods directly.

// The macros have been removed because:
// 1. Thread-local state is an anti-pattern in async code
// 2. Proper context-based logging is now available
// 3. Only the Node should create root loggers
// 4. Loggers should be passed explicitly via context objects

// Instead of these macros, please use:
// - context.info("message") when you have a context
// - logger.info("message") when you have a logger instance
// - Node-derived loggers for components via node.create_service_logger()
