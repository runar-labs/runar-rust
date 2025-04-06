# Test Fixtures

This directory contains test fixtures used by the Rust Node test suite. These fixtures provide standardized implementations of services and utilities for testing various aspects of the system.

## Directory Structure

The fixtures are organized as follows:

```
/fixtures
  ├── services/        # Consolidated service implementations
  │   ├── base_services.rs   # Common base services (SimpleTestService, CounterService)
  │   ├── event_publisher.rs # Publisher service for event testing
  │   ├── event_subscriber.rs # Subscriber service for event testing
  │   ├── ship_service.rs    # Ship service for event testing
  │   └── mod.rs            # Exports all services
  ├── events/         # Event-specific test fixtures
  │   ├── base_station_service.rs # Original base station service 
  │   └── ship_service.rs    # Original ship service
  └── direct_api/     # Direct API implementations (no macros)
      ├── auth_service.rs    # Authentication service implementation
      ├── math_service.rs    # Math service implementation
      └── mod.rs            # Exports direct API services
```

## Service Implementations

### Consolidated Services (services/)

The `services/` directory contains standardized, refactored service implementations that follow consistent patterns:

- **base_services.rs**: Contains generic service implementations for basic testing:
  - `SimpleTestService`: A simple echo service that responds to any action
  - `CounterService`: A service that maintains a counter value

- **event_publisher.rs**: Dedicated publisher service for testing events
  - Publishes events to specified topics
  - Tracks published events for verification

- **event_subscriber.rs**: Dedicated subscriber service for testing event reception
  - Subscribes to specified topics
  - Stores received events for verification
  - Provides actions to retrieve received events

- **ship_service.rs**: A service that simulates a ship that can land and take off
  - Publishes events when the ship lands or takes off
  - Used in the simple_events test

### Direct API Implementations (direct_api/)

The `direct_api/` directory contains implementations that use the direct API approach (no macros):

- **auth_service.rs**: Authentication service for testing login/logout flows
- **math_service.rs**: Mathematical service for testing computation

## Best Practices

When writing tests:

1. Use the consolidated service implementations from `services/` for new tests
2. Follow the same patterns for consistency
3. Use strong typing and proper error handling
4. Add detailed documentation for new services

## Examples

See the `simple_events.rs` test for an example of how to use these fixtures in tests.

## Test Utilities Consolidation

To improve maintainability and reduce duplication, the test utilities have been consolidated into a single location at `/tests/utils/`. This includes:

- Migration of legacy utilities from `/tests/test_utils/mod.rs` to `/tests/utils/legacy_test_utils.rs`
- Structured organization of utilities into focused modules
- Backward compatibility support to prevent breaking existing tests

### Using the Consolidated Utilities

When writing new tests, prefer to import utilities from the consolidated modules:

```rust
// Import utilities from the consolidated location
use crate::utils::node_utils::create_test_node;
use crate::utils::event_utils::create_event_data;
```

The consolidated utilities are organized by function:

- `node_utils.rs` - Node creation and management
- `event_utils.rs` - Event testing utilities
- `test_helpers.rs` - Request/response helpers
- `test_logging.rs` - Logging utilities for tests
- `modernized_test_utils.rs` - Modern macro-based service testing

The legacy utilities remain available for backward compatibility but should be gradually phased out in favor of the modular approach:

```rust
// Legacy way (still supported but not recommended for new tests)
use test_utils::SimpleTestService;
use test_utils::create_test_node;

// Modern way (preferred)
use crate::utils::legacy_test_utils::SimpleTestService;
use crate::utils::node_utils::create_test_node;
```

See the `/tests/utils/README.md` for more details on the consolidated utilities.
