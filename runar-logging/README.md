# Runar Logging

Logging utilities and macros for the Runar framework.

This crate provides:
- Component-based structured logging
- Context-aware logging for services
- Node ID tracking through logger inheritance
- Support for action and event path tracing
- Compile-time efficient logging macros

## Usage

```rust
use runar_logging::{Logger, Component, log_info, log_debug};

// Create a root logger
let logger = Logger::new_root(Component::Node);

// Create a child logger for a service
let service_logger = logger.with_component(Component::Service);

// Use the logger
log_info!(service_logger, "Service started successfully");
log_debug!(service_logger, "Processing request id={id}", id = 123);
```

## Features

- **Zero-overhead when disabled**: Logging macros check log levels at compile time
- **Structured logging**: Component-based categorization
- **Context inheritance**: Child loggers inherit parent context
- **Performance optimized**: Avoids allocations when logging is disabled
