# Runar Framework Examples

This directory contains examples demonstrating various features and patterns of the Runar framework.

## Available Examples

### Node API Example
A comprehensive example demonstrating proper service implementation and registration using the Runar Node API.

**Features demonstrated:**
- Creating and configuring a node
- Creating a custom service that handles events
- Proper service registration using `add_service()`
- Making service requests using the request-based API
- Using `vmap!` for clean parameter extraction
- Proper service implementation following the `AbstractService` trait
- Event handling and storage

**To run this example:**
```bash
cargo run --example node_api_example
```

### Macro Example
A comprehensive example demonstrating proper usage of Runar macros for service definition and integration.

**Features demonstrated:**
- Using the `service!` macro to define services
- Proper field initialization in service structs
- Implementing action handlers with the `action!` macro
- Subscribing to events with the `sub!` macro
- Service-to-service communication via events
- Complete task management application with analytics

**To run this example:**
```bash
cargo run --example macro_example
```

## Running Examples

Each example can be run using Cargo:

```bash
cargo run --example <example_name>
```

## Best Practices Shown in Examples

The examples in this directory follow Runar's architectural guidelines and best practices:

1. **Service Definition**: Services are defined using the `AbstractService` trait or the `service!` macro, properly implementing all required methods.

2. **Service Registration**: Services are registered using the `add_service()` method instead of deprecated approaches.

3. **Request-Based API**: Examples use the request-based API pattern for service interactions, avoiding direct access to service methods.

4. **Event-Driven Communication**: Where applicable, examples demonstrate how to use Runar's event system for communication between services.

5. **Clean Parameter Extraction**: Examples show how to use the `vmap!` macro for safely extracting parameters with default values.

6. **Field Initialization**: Services properly initialize fields in their struct definitions, following best practices.

## Adding New Examples

When adding new examples, please follow these guidelines:

1. Place your example file in the `examples/` directory
2. Follow the naming convention: `feature_name_example.rs`
3. Include thorough documentation in your example explaining what it demonstrates
4. Mark "correct" patterns with ✅ in comments to highlight proper usage
5. Consider adding your example to this README file
