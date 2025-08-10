# Runar Examples and Test Utilities

This crate provides examples and test utilities for the Runar P2P stack, including a comprehensive mobile simulator for testing end-to-end scenarios.

## Mobile Simulator

The mobile simulator provides utilities for simulating realistic mobile behavior with the mobile key manager, allowing examples and tests to easily set up scenarios with master mobiles and multiple user mobiles.

### Features

- **Master Mobile**: Simulates the mobile device that sets up the network and can issue certificates
- **User Mobiles**: Simulates multiple user mobile devices with different profile keys
- **Node Configuration**: Creates properly configured node instances that work with the mobile simulation
- **Label Resolvers**: Provides encryption/decryption context for realistic access control scenarios

### Basic Usage

```rust
use runar_examples::{create_simple_mobile_simulation, create_test_environment};

// Create a simple simulation with one user
let simulator = create_simple_mobile_simulation()?;

// Or create a complete test environment with node config
let (simulator, node_config) = create_test_environment()?;

// Add additional users
simulator.add_user_mobile("bob", &["personal", "work"])?;

// Create label resolvers for encryption
let (mobile_resolver, node_resolver) = simulator.create_label_resolvers()?;

// Print simulation summary
simulator.print_summary();
```

### Advanced Usage

```rust
use runar_examples::MobileSimulator;
use runar_common::logging::{Component, Logger};
use std::sync::Arc;

// Create a custom simulation
let logger = Arc::new(Logger::new_root(Component::System, "my-sim"));
let mut simulator = MobileSimulator::new(logger)?;

// Add multiple users with different profiles
simulator.add_user_mobile("alice", &["personal", "work", "family"])?;
simulator.add_user_mobile("bob", &["personal", "work"])?;
simulator.add_user_mobile("charlie", &["personal"])?;

// Create node configuration
let node_config = simulator.create_node_config()?;

// Access specific users
let alice_mobile = simulator.get_user_mobile("alice").unwrap();
let master_mobile = simulator.get_master_mobile();
```

### Examples

- **Simple Example**: Basic service demonstration with mobile simulator
- **Microservices Demo**: More complex example with multiple services

### Running Examples

```bash
# Run the simple example
cargo run --example simple

# Run tests
cargo test
```

## Architecture

The mobile simulator consists of several key components:

1. **MasterMobile**: The mobile device that owns the network and can issue certificates
2. **MobileDevice**: Individual user mobile devices with profile keys
3. **MobileSimulator**: The main orchestrator that manages the simulation

### Key Concepts

- **Network ID**: Unique identifier for the network created by the master mobile
- **Profile Keys**: User-specific keys derived from the root key for different contexts (personal, work, etc.)
- **Label Resolvers**: Maps encryption labels to actual keys for access control
- **Node Configuration**: Pre-configured node instances that can work with the mobile simulation

### Use Cases

- **End-to-End Testing**: Test complete workflows involving multiple mobile devices and nodes
- **Access Control Testing**: Verify encryption/decryption with different key ownership scenarios
- **Integration Testing**: Test how different components work together in realistic scenarios
- **Example Development**: Create examples that demonstrate real-world usage patterns

## Contributing

When adding new examples or test utilities:

1. Follow the existing patterns for mobile simulation setup
2. Use the convenience functions like `create_test_environment()` when possible
3. Add appropriate tests for new functionality
4. Update this README with new features or examples
