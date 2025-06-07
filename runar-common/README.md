# Runar Common

Runar Common is a shared utility library for the Runar ecosystem, providing common functionality used across various Runar components. This library serves as the foundation for consistent implementations and shared code across the Runar project.

## Features

- **Error Handling**: Standardized error types and handling mechanisms
- **Serialization Utilities**: Common serialization and deserialization helpers
- **Data Structures**: Reusable data structures optimized for Runar's use cases
- **Async Utilities**: Helpers for working with asynchronous code
- **Cryptography**: Basic cryptographic functions and utilities
- **Config Management**: Configuration handling and validation
- **Testing Utilities**: Common testing infrastructure and mocks

## Usage

Add runar_common to your Cargo.toml:

```toml
[dependencies]
runar_common = { git = "https://github.com/runar-labs/rust-mono", package = "runar_common" }
```

### Basic Example

```rust
use runar_common::error::Result;
use runar_common::config::Configuration;

fn main() -> Result<()> {
    // Use common utilities
    let config = Configuration::from_file("config.toml")?;
    
    // Access configuration values
    let value = config.get("some.nested.key").unwrap_or_default();
    
    println!("Config value: {}", value);
    Ok(())
}
```

## Structure

The library is organized into several modules:

- `error`: Error types and result aliases
- `utils`: General utility functions
- `crypto`: Cryptographic utilities
- `config`: Configuration management
- `serialization`: Serialization helpers
- `testing`: Testing utilities

## Contributing

When adding functionality to Runar Common, ensure that:

1. The functionality is needed by multiple components in the Runar ecosystem
2. It follows the established patterns and conventions
3. It is well-tested and documented
4. It doesn't introduce unnecessary dependencies

## License

This project is licensed under the MIT License - see the LICENSE file for details.
